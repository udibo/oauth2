/**
 * Contract test suites for {@link PasskeyStore} and
 * {@link PasskeyChallengeStore} implementations.
 *
 * `PasskeyService` relies on three atomic operations: `addPasskey` (credential
 * uniqueness and the per-user cap in one step), `recordUse` (compare-and-set
 * on the sign count), and the challenge store's `take` (read-and-delete, which
 * makes a challenge single-use). These suites check each with concurrent
 * calls.
 *
 * @example Verify database-backed stores
 * ```ts
 * import {
 *   runPasskeyChallengeStoreContractTests,
 *   runPasskeyStoreContractTests,
 * } from "@udibo/oauth2/testing/contract";
 * import type {
 *   PasskeyChallengeStore,
 *   PasskeyStore,
 * } from "@udibo/oauth2/identity/passkeys";
 *
 * declare function freshPasskeyStore(): Promise<PasskeyStore>;
 * declare function freshChallengeStore(): Promise<PasskeyChallengeStore>;
 *
 * runPasskeyStoreContractTests({ makeStore: freshPasskeyStore });
 * runPasskeyChallengeStoreContractTests({ makeStore: freshChallengeStore });
 * ```
 *
 * @module
 */

import { beforeEach, describe, expect, it } from "vitest";
import type {
  Passkey,
  PasskeyChallengeStore,
  PasskeyStore,
} from "../../identity/passkeys/service.ts";
import { CONCURRENT_CALLERS, race } from "./_race.ts";

/** Options for {@link runPasskeyStoreContractTests}. */
export interface PasskeyStoreContractOptions {
  /** Returns a fresh, empty store for each test. */
  makeStore(): Promise<PasskeyStore> | PasskeyStore;
  /**
   * The user the cases act on, in your application's id format; it must name
   * a user that exists when your rows reference a users table. Defaults to
   * `"user-1"`.
   */
  userId?: string;
  /** A second, distinct user. Defaults to `"user-2"`. */
  otherUserId?: string;
  /** Overrides the outer `describe` name. Defaults to `"PasskeyStore contract"`. */
  describeName?: string;
}

/** Options for {@link runPasskeyChallengeStoreContractTests}. */
export interface PasskeyChallengeStoreContractOptions {
  /** Returns a fresh, empty store for each test. */
  makeStore(): Promise<PasskeyChallengeStore> | PasskeyChallengeStore;
  /**
   * Overrides the outer `describe` name. Defaults to
   * `"PasskeyChallengeStore contract"`.
   */
  describeName?: string;
}

function passkey(
  userId: string,
  credentialId: string,
  rpId = "login.example.com",
): Passkey {
  return {
    credentialId,
    userId,
    rpId,
    publicKey: new Uint8Array([1, 2, 3, 4]),
    signCount: 0,
    transports: ["internal", "hybrid"],
    aaguid: "00000000-0000-0000-0000-000000000000",
    multiDevice: true,
    backedUp: true,
    name: "Laptop",
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    lastUsedAt: null,
  };
}

/**
 * Runs the {@link PasskeyStore} contract suite. Call it from your own test
 * file; it registers `describe` / `it` blocks.
 */
export function runPasskeyStoreContractTests(
  options: PasskeyStoreContractOptions,
): void {
  const USER = options.userId ?? "user-1";
  const OTHER_USER = options.otherUserId ?? "user-2";

  describe(options.describeName ?? "PasskeyStore contract", () => {
    let store: PasskeyStore;

    beforeEach(async () => {
      store = await options.makeStore();
    });

    it("stores and returns a passkey with its fields intact", async () => {
      expect(await store.addPasskey(passkey(USER, "cred-a"), 25)).toBe("added");
      const found = await store.findPasskey("cred-a");
      expect(found).toStrictEqual(passkey(USER, "cred-a"));
    });

    it("lists a user's passkeys oldest first, filtered by RP ID", async () => {
      await store.addPasskey(
        {
          ...passkey(USER, "cred-a"),
          createdAt: new Date("2026-01-01T00:00:00.000Z"),
        },
        25,
      );
      await store.addPasskey(
        {
          ...passkey(USER, "cred-b", "other.example.com"),
          createdAt: new Date("2026-01-02T00:00:00.000Z"),
        },
        25,
      );
      await store.addPasskey(passkey(OTHER_USER, "cred-c"), 25);
      const all = await store.listPasskeys(USER);
      expect(all.map((stored) => stored.credentialId)).toStrictEqual([
        "cred-a",
        "cred-b",
      ]);
      const scoped = await store.listPasskeys(USER, "login.example.com");
      expect(scoped.map((stored) => stored.credentialId)).toStrictEqual([
        "cred-a",
      ]);
    });

    it("refuses a credential id that is already registered", async () => {
      await store.addPasskey(passkey(USER, "cred-a"), 25);
      expect(await store.addPasskey(passkey(OTHER_USER, "cred-a"), 25)).toBe(
        "duplicate",
      );
      expect((await store.findPasskey("cred-a"))?.userId).toBe(USER);
    });

    it("refuses a passkey over the per-user limit", async () => {
      await store.addPasskey(passkey(USER, "cred-a"), 2);
      await store.addPasskey(passkey(USER, "cred-b"), 2);
      expect(await store.addPasskey(passkey(USER, "cred-c"), 2)).toBe(
        "limit_reached",
      );
      expect(await store.addPasskey(passkey(OTHER_USER, "cred-d"), 2)).toBe(
        "added",
      );
    });

    it("holds the per-user limit under concurrent registration", async () => {
      const results = await race((caller) =>
        store.addPasskey(passkey(USER, `cred-${caller}`), 3),
      );
      expect(results.filter((result) => result === "added")).toHaveLength(3);
      expect(await store.listPasskeys(USER)).toHaveLength(3);
    });

    it("adds one passkey when the same credential races itself", async () => {
      const results = await race(() =>
        store.addPasskey(passkey(USER, "cred-a"), 25),
      );
      expect(results.filter((result) => result === "added")).toHaveLength(1);
      expect(results.filter((result) => result === "duplicate")).toHaveLength(
        CONCURRENT_CALLERS - 1,
      );
    });

    it("records a use only while the sign count still matches", async () => {
      await store.addPasskey(passkey(USER, "cred-a"), 25);
      const usedAt = new Date("2026-02-01T00:00:00.000Z");
      expect(
        await store.recordUse("cred-a", {
          previousSignCount: 0,
          signCount: 5,
          backedUp: false,
          usedAt,
        }),
      ).toBe(true);
      const stored = await store.findPasskey("cred-a");
      expect(stored?.signCount).toBe(5);
      expect(stored?.backedUp).toBe(false);
      expect(stored?.lastUsedAt).toStrictEqual(usedAt);
      expect(
        await store.recordUse("cred-a", {
          previousSignCount: 0,
          signCount: 6,
          backedUp: false,
          usedAt,
        }),
      ).toBe(false);
      expect((await store.findPasskey("cred-a"))?.signCount).toBe(5);
    });

    it("lets one of several concurrent uses with the same counter win", async () => {
      await store.addPasskey(passkey(USER, "cred-a"), 25);
      const results = await race((caller) =>
        store.recordUse("cred-a", {
          previousSignCount: 0,
          signCount: caller + 1,
          backedUp: true,
          usedAt: new Date(),
        }),
      );
      expect(results.filter(Boolean)).toHaveLength(1);
    });

    it("renames and removes only the owner's passkey", async () => {
      await store.addPasskey(passkey(USER, "cred-a"), 25);
      expect(await store.renamePasskey(OTHER_USER, "cred-a", "Mine")).toBe(
        false,
      );
      expect(await store.removePasskey(OTHER_USER, "cred-a")).toBe(false);
      expect(await store.renamePasskey(USER, "cred-a", "Phone")).toBe(true);
      expect((await store.findPasskey("cred-a"))?.name).toBe("Phone");
      expect(await store.removePasskey(USER, "cred-a")).toBe(true);
      expect(await store.findPasskey("cred-a")).toBe(undefined);
      expect(await store.removePasskey(USER, "cred-a")).toBe(false);
    });
  });
}

/**
 * Runs the {@link PasskeyChallengeStore} contract suite. Call it from your own
 * test file; it registers `describe` / `it` blocks.
 */
export function runPasskeyChallengeStoreContractTests(
  options: PasskeyChallengeStoreContractOptions,
): void {
  describe(options.describeName ?? "PasskeyChallengeStore contract", () => {
    let store: PasskeyChallengeStore;
    const challenge = {
      challenge: "c2lnbi1tZQ",
      ceremony: "authentication" as const,
      rpId: "login.example.com",
      userId: "user-1",
      expiresAt: Date.now() + 60_000,
    };

    beforeEach(async () => {
      store = await options.makeStore();
    });

    it("returns a stored challenge once", async () => {
      await store.put("ceremony-1", challenge);
      expect(await store.take("ceremony-1")).toStrictEqual(challenge);
      expect(await store.take("ceremony-1")).toBe(undefined);
    });

    it("returns undefined for an unknown ceremony", async () => {
      expect(await store.take("missing")).toBe(undefined);
    });

    it("hands a challenge to exactly one of several concurrent takers", async () => {
      await store.put("ceremony-1", challenge);
      const results = await race(() => store.take("ceremony-1"));
      expect(results.filter((result) => result !== undefined)).toHaveLength(1);
    });
  });
}
