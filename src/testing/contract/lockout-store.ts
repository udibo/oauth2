/**
 * Contract test suite for {@link LockoutStore} implementations — the
 * per-account failure counter behind `AccountLockout`.
 *
 * `AccountLockout` counts each sign-in attempt with `increment` before its
 * password is checked, and admits the attempt only on the count `increment`
 * returns. A store that lets concurrent attempts share a count admits one extra
 * guess for every attempt sharing it: the brute-force floor the lockout is
 * meant to be moves up by however many attempts an attacker can land at once.
 *
 * The optional `lock` and `release` cases run when the store implements the
 * method and are skipped, with a note naming the gap, when it does not.
 *
 * @example Verify a database-backed store
 * ```ts
 * import { runLockoutStoreContractTests } from "@udibo/oauth2/testing/contract";
 * import type { LockoutStore } from "@udibo/oauth2/identity";
 *
 * declare function freshLockoutStore(): Promise<LockoutStore>;
 *
 * runLockoutStoreContractTests({
 *   describeName: "DrizzleLockoutStore satisfies LockoutStore contract",
 *   makeStore: freshLockoutStore,
 * });
 * ```
 *
 * @module
 */

import { assert, beforeEach, describe, expect, it } from "vitest";
import type { LockoutStore } from "../../identity/lockout.ts";

/** Options for {@link runLockoutStoreContractTests}. */
export interface LockoutStoreContractOptions {
  /**
   * Returns a fresh, empty store for each test. Isolation is required — a
   * failure count surviving into the next test shifts every count the suite
   * asserts.
   */
  makeStore(): Promise<LockoutStore> | LockoutStore;
  /**
   * The account the cases act on, in your application's id format. A store
   * that keeps the count on the user's own row needs it to name a user that
   * exists. Defaults to `"user-1"`.
   */
  userId?: string;
  /**
   * A second account, distinct from {@link LockoutStoreContractOptions.userId},
   * whose count must stay apart from the first. Defaults to `"user-2"`.
   */
  otherUserId?: string;
  /**
   * Set to `true` to require the optional {@link LockoutStore.lock}: the suite
   * then fails a store that does not implement it. Left unset, the `lock`
   * cases run when the store implements it and are skipped with a note when
   * it does not.
   */
  lock?: boolean;
  /**
   * Set to `true` to require the optional {@link LockoutStore.release}: the
   * suite then fails a store that does not implement it. Left unset, the
   * `release` cases run when the store implements it and are skipped with a
   * note when it does not.
   */
  release?: boolean;
  /**
   * Overrides the name passed to the outer `describe` block. Defaults to
   * `"LockoutStore contract"`.
   */
  describeName?: string;
}

/**
 * Runs the {@link LockoutStore} contract suite. Call it from your own test
 * file — it registers `describe` / `it` blocks the test runner picks up.
 *
 * `now` is passed explicitly on every call, so the lock-expiry cases are
 * clock-free and never need a timer.
 */
export function runLockoutStoreContractTests(
  options: LockoutStoreContractOptions,
): void {
  const USER = options.userId ?? "user-1";
  const OTHER_USER = options.otherUserId ?? "user-2";

  describe(options.describeName ?? "LockoutStore contract", () => {
    let store: LockoutStore;
    let now: number;

    beforeEach(async () => {
      store = await options.makeStore();
      now = Date.now();
    });

    describe("get", () => {
      it("returns undefined for an account with no record", async () => {
        expect(await store.get(USER)).toBe(undefined);
      });
    });

    describe("increment", () => {
      it("records the first failure as one", async () => {
        const result = await store.increment(USER, now);
        expect(result.failures).toStrictEqual(1);
        expect(result.lockedUntil).toBe(undefined);
        expect((await store.get(USER))?.failures).toStrictEqual(1);
      });

      it("adds one failure per call", async () => {
        await store.increment(USER, now);
        await store.increment(USER, now);
        expect((await store.increment(USER, now)).failures).toStrictEqual(3);
      });

      it("counts each account on its own", async () => {
        await store.increment(USER, now);
        await store.increment(USER, now);
        expect((await store.increment(OTHER_USER, now)).failures).toStrictEqual(
          1,
        );
      });

      it("keeps an active lock while counting the failure", async () => {
        const lockedUntil = now + 60_000;
        await store.set(USER, { failures: 10, lockedUntil });
        const result = await store.increment(USER, now);
        expect(result.failures).toStrictEqual(11);
        expect(
          result.lockedUntil,
          "a failed attempt against a locked account must not extend or drop " +
            "the lock the store is holding",
        ).toBe(lockedUntil);
      });

      it("starts a fresh count once the lock has expired", async () => {
        await store.set(USER, { failures: 10, lockedUntil: now - 1 });
        const result = await store.increment(USER, now);
        expect(result.failures).toStrictEqual(1);
        expect(
          result.lockedUntil,
          "an expired lock must be dropped, not carried into the next window",
        ).toBe(undefined);
      });

      it("gives every concurrent failure its own count", async () => {
        const results = await Promise.all(
          Array.from({ length: 5 }, () => store.increment(USER, now)),
        );
        expect(
          results.map((result) => result.failures).sort((a, b) => a - b),
          "sign-in is admitted on the returned count — concurrent attempts " +
            "sharing a count each get another guess past the threshold",
        ).toStrictEqual([1, 2, 3, 4, 5]);
        expect((await store.get(USER))?.failures).toStrictEqual(5);
      });

      it("gives every concurrent attempt against an active lock its own count", async () => {
        const lockedUntil = now + 60_000;
        await store.set(USER, { failures: 3, lockedUntil });
        const results = await Promise.all(
          Array.from({ length: 4 }, () => store.increment(USER, now)),
        );
        expect(
          results.map((result) => result.failures).sort((a, b) => a - b),
        ).toStrictEqual([4, 5, 6, 7]);
        expect(
          results.map((result) => result.lockedUntil),
          "every attempt counted during the lock must see it, or one is " +
            "admitted to the password check",
        ).toStrictEqual([lockedUntil, lockedUntil, lockedUntil, lockedUntil]);
      });
    });

    describe("set", () => {
      it("persists the record as given", async () => {
        const lockedUntil = now + 60_000;
        await store.set(USER, { failures: 10, lockedUntil });
        const record = await store.get(USER);
        expect(record?.failures).toStrictEqual(10);
        expect(record?.lockedUntil).toBe(lockedUntil);
      });

      it("replaces a record that was already there", async () => {
        await store.increment(USER, now);
        await store.set(USER, { failures: 4 });
        const record = await store.get(USER);
        expect(record?.failures).toStrictEqual(4);
        expect(record?.lockedUntil).toBe(undefined);
      });
    });

    describe("lock (optional)", () => {
      const NOT_IMPLEMENTED =
        "lock is not implemented — AccountLockout falls back to set, so an " +
        "over-budget attempt can re-lock an account a concurrent sign-in reset";

      if (options.lock) {
        it("is implemented", () => {
          assert(
            typeof store.lock === "function",
            `${NOT_IMPLEMENTED}. Implement it, or drop \`lock: true\`.`,
          );
        });
      }

      it("locks the account while its count stands, keeping the count", async ({
        skip,
      }) => {
        if (!store.lock) return skip(NOT_IMPLEMENTED);
        for (let i = 0; i < 3; i++) await store.increment(USER, now);
        const lockedUntil = now + 60_000;
        expect(await store.lock(USER, { failures: 3, lockedUntil }, now)).toBe(
          true,
        );
        const record = await store.get(USER);
        expect(record?.failures).toStrictEqual(3);
        expect(record?.lockedUntil).toBe(lockedUntil);
      });

      it("locks when later attempts counted past the lock's own count", async ({
        skip,
      }) => {
        if (!store.lock) return skip(NOT_IMPLEMENTED);
        for (let i = 0; i < 5; i++) await store.increment(USER, now);
        expect(
          await store.lock(
            USER,
            { failures: 3, lockedUntil: now + 60_000 },
            now,
          ),
        ).toBe(true);
        expect((await store.get(USER))?.failures).toStrictEqual(5);
      });

      it("refuses once the account was cleared", async ({ skip }) => {
        if (!store.lock) return skip(NOT_IMPLEMENTED);
        for (let i = 0; i < 3; i++) await store.increment(USER, now);
        await store.clear(USER);
        expect(
          await store.lock(
            USER,
            { failures: 3, lockedUntil: now + 60_000 },
            now,
          ),
          "a lock computed before a successful sign-in must not land after it",
        ).toBe(false);
        expect(await store.get(USER)).toBe(undefined);
      });

      it("refuses once a fresh count started below the lock's count", async ({
        skip,
      }) => {
        if (!store.lock) return skip(NOT_IMPLEMENTED);
        for (let i = 0; i < 3; i++) await store.increment(USER, now);
        await store.clear(USER);
        await store.increment(USER, now);
        expect(
          await store.lock(
            USER,
            { failures: 3, lockedUntil: now + 60_000 },
            now,
          ),
        ).toBe(false);
        const record = await store.get(USER);
        expect(record?.failures).toStrictEqual(1);
        expect(record?.lockedUntil).toBe(undefined);
      });

      it("locks only the account it is given", async ({ skip }) => {
        if (!store.lock) return skip(NOT_IMPLEMENTED);
        for (let i = 0; i < 3; i++) await store.increment(USER, now);
        await store.increment(OTHER_USER, now);
        await store.lock(USER, { failures: 3, lockedUntil: now + 60_000 }, now);
        expect((await store.get(OTHER_USER))?.lockedUntil).toBe(undefined);
      });
    });

    describe("release (optional)", () => {
      const NOT_IMPLEMENTED =
        "release is not implemented — an attempt whose password was never " +
        "checked stays counted toward the lockout";
      const MAX_ATTEMPTS = 3;

      if (options.release) {
        it("is implemented", () => {
          assert(
            typeof store.release === "function",
            `${NOT_IMPLEMENTED}. Implement it, or drop \`release: true\`.`,
          );
        });
      }

      it("takes back one counted attempt", async ({ skip }) => {
        if (!store.release) return skip(NOT_IMPLEMENTED);
        await store.increment(USER, now);
        await store.increment(USER, now);
        await store.release(USER, MAX_ATTEMPTS, now);
        expect((await store.get(USER, now))?.failures).toStrictEqual(1);
        expect((await store.increment(USER, now)).failures).toStrictEqual(2);
      });

      it("leaves no count behind for the last attempt", async ({ skip }) => {
        if (!store.release) return skip(NOT_IMPLEMENTED);
        await store.increment(USER, now);
        await store.release(USER, MAX_ATTEMPTS, now);
        expect((await store.get(USER, now))?.failures ?? 0).toStrictEqual(0);
        expect((await store.increment(USER, now)).failures).toStrictEqual(1);
      });

      it("never takes the count below zero", async ({ skip }) => {
        if (!store.release) return skip(NOT_IMPLEMENTED);
        await store.release(USER, MAX_ATTEMPTS, now);
        await store.release(USER, MAX_ATTEMPTS, now);
        expect((await store.get(USER, now))?.failures ?? 0).toStrictEqual(0);
        expect((await store.increment(USER, now)).failures).toStrictEqual(1);
      });

      it("drops the lock once the count falls below maxAttempts", async ({
        skip,
      }) => {
        if (!store.release) return skip(NOT_IMPLEMENTED);
        await store.set(USER, {
          failures: MAX_ATTEMPTS,
          lockedUntil: now + 60_000,
        });
        await store.release(USER, MAX_ATTEMPTS, now);
        const record = await store.get(USER, now);
        expect(record?.failures).toStrictEqual(MAX_ATTEMPTS - 1);
        expect(
          record?.lockedUntil,
          "a lock the counted attempts no longer reach must not stand",
        ).toBe(undefined);
      });

      it("keeps the lock while the count still reaches maxAttempts", async ({
        skip,
      }) => {
        if (!store.release) return skip(NOT_IMPLEMENTED);
        const lockedUntil = now + 60_000;
        await store.set(USER, { failures: MAX_ATTEMPTS + 1, lockedUntil });
        await store.release(USER, MAX_ATTEMPTS, now);
        const record = await store.get(USER, now);
        expect(record?.failures).toStrictEqual(MAX_ATTEMPTS);
        expect(record?.lockedUntil).toBe(lockedUntil);
      });

      it("takes back exactly one attempt per release among concurrent attempts", async ({
        skip,
      }) => {
        if (!store.release) return skip(NOT_IMPLEMENTED);
        for (let i = 0; i < 5; i++) await store.increment(USER, now);
        const release = store.release.bind(store);
        await Promise.all([
          ...Array.from({ length: 3 }, () => release(USER, 100, now)),
          ...Array.from({ length: 3 }, () => store.increment(USER, now)),
        ]);
        expect(
          (await store.get(USER, now))?.failures,
          "a read-modify-write lets a release overwrite a concurrent " +
            "attempt's count",
        ).toStrictEqual(5);
      });

      it("takes back one attempt per concurrent release", async ({ skip }) => {
        if (!store.release) return skip(NOT_IMPLEMENTED);
        for (let i = 0; i < 5; i++) await store.increment(USER, now);
        const release = store.release.bind(store);
        await Promise.all(
          Array.from({ length: 3 }, () => release(USER, 100, now)),
        );
        expect(
          (await store.get(USER, now))?.failures,
          "a read-modify-write lets concurrent releases share one decrement",
        ).toStrictEqual(2);
      });

      it("leaves a record whose lock has expired as it is", async ({
        skip,
      }) => {
        if (!store.release) return skip(NOT_IMPLEMENTED);
        await store.set(USER, { failures: MAX_ATTEMPTS, lockedUntil: now - 1 });
        await store.release(USER, MAX_ATTEMPTS, now);
        expect(
          (await store.increment(USER, now)).failures,
          "the expired lock's window is over, so the next attempt starts a " +
            "fresh count",
        ).toStrictEqual(1);
      });

      it("releases only the account it is given", async ({ skip }) => {
        if (!store.release) return skip(NOT_IMPLEMENTED);
        await store.increment(USER, now);
        await store.increment(OTHER_USER, now);
        await store.release(USER, MAX_ATTEMPTS, now);
        expect((await store.get(OTHER_USER, now))?.failures).toStrictEqual(1);
      });
    });

    describe("clear", () => {
      it("drops the account's failures and lock", async () => {
        await store.set(USER, { failures: 10, lockedUntil: now + 60_000 });
        await store.clear(USER);
        expect(await store.get(USER)).toBe(undefined);
        expect((await store.increment(USER, now)).failures).toStrictEqual(1);
      });

      it("clears only the account it is given", async () => {
        await store.increment(USER, now);
        await store.increment(OTHER_USER, now);
        await store.clear(USER);
        expect((await store.get(OTHER_USER))?.failures).toStrictEqual(1);
      });

      it("is a no-op for an account with no record", async () => {
        await store.clear(USER);
        expect(await store.get(USER)).toBe(undefined);
      });
    });
  });
}
