/**
 * Contract test suite for {@link AuthRequestStorage} implementations — the
 * short-lived map from an authorization request's `state` to the PKCE verifier
 * it was built with.
 *
 * The load-bearing method is the optional `take`: `DirectClient` claims the
 * record with it before calling the token endpoint, so of two callbacks racing
 * on one `state` only one reaches it. Only an atomic read-and-remove survives
 * concurrent callers taking one record. This suite races eight of them on one
 * record.
 *
 * @example Verify a Redis-backed store
 * ```ts
 * import { runAuthRequestStorageContractTests } from "@udibo/oauth2/testing/contract";
 * import type { AuthRequestStorage } from "@udibo/oauth2/client";
 *
 * declare function freshAuthRequestStorage(): Promise<AuthRequestStorage>;
 *
 * runAuthRequestStorageContractTests({
 *   describeName: "RedisAuthRequestStorage satisfies AuthRequestStorage contract",
 *   makeStore: freshAuthRequestStorage,
 * });
 * ```
 *
 * @example Verify a store shared between users, whose `clear()` removes only expired records
 * ```ts
 * import { runAuthRequestStorageContractTests } from "@udibo/oauth2/testing/contract";
 * import type { AuthRequestStorage } from "@udibo/oauth2/client";
 *
 * declare function freshSharedAuthRequestStorage(): Promise<AuthRequestStorage>;
 *
 * runAuthRequestStorageContractTests({
 *   describeName: "SharedAuthRequestStorage satisfies AuthRequestStorage contract",
 *   makeStore: freshSharedAuthRequestStorage,
 *   clear: "scoped",
 * });
 * ```
 *
 * @module
 */

import { assert, assertEquals, assertStrictEquals } from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";

import type {
  AuthRequestRecord,
  AuthRequestStorage,
} from "../../client/storage.ts";
import { CONCURRENT_CALLERS, race } from "./_race.ts";

/** Options for {@link runAuthRequestStorageContractTests}. */
export interface AuthRequestStorageContractOptions {
  /**
   * Returns a fresh, empty store for each test. Isolation is required — a
   * record surviving into the next test makes the single-use checks
   * meaningless.
   */
  makeStore(): Promise<AuthRequestStorage> | AuthRequestStorage;
  /**
   * Set to `false` when the store deliberately omits the optional
   * {@link AuthRequestStorage.take}. The suite then registers an ignored case
   * naming what is not covered — two callbacks racing on one `state` can both
   * redeem it — instead of passing in silence. Defaults to `true`, so a store
   * that meant to implement it and does not fails loudly.
   */
  take?: boolean;
  /**
   * What the store's {@link AuthRequestStorage.clear} removes. Defaults to
   * `"all"`: every record, as a store private to one browser or session
   * does. Pass `"scoped"` for a store shared between users whose `clear()`
   * deliberately removes less — only expired records, say — because a
   * `DirectClient` clears it on every sign-out, and removing everything would
   * cancel other users' sign-ins still in progress. The suite then drops the
   * clear-everything case and instead requires that `clear()` leaves every
   * record still inside its lifetime readable and redeemable, and removes a
   * record created at the epoch (`createdAt: 0`), which is past any lifetime.
   */
  clear?: "all" | "scoped";
  /**
   * Overrides the name passed to the outer `describe` block. Defaults to
   * `"AuthRequestStorage contract"`.
   */
  describeName?: string;
}

function record(overrides: Partial<AuthRequestRecord> = {}): AuthRequestRecord {
  return {
    codeVerifier: "verifier-1",
    returnTo: "/dashboard",
    scope: "openid profile",
    createdAt: Date.now(),
    ...overrides,
  };
}

/**
 * Runs the {@link AuthRequestStorage} contract suite. Call it from your own
 * test file — it registers `describe` / `it` blocks the test runner picks up.
 *
 * The concurrency cases take one `state` from eight callers at once. A store
 * whose `take` reads, awaits, then deletes hands the record to more than one
 * of them and fails in practice — a race is probabilistic, so a lucky
 * interleaving can still pass a single run.
 */
export function runAuthRequestStorageContractTests(
  options: AuthRequestStorageContractOptions,
): void {
  const expectTake = options.take ?? true;
  const clearScope = options.clear ?? "all";

  describe(options.describeName ?? "AuthRequestStorage contract", () => {
    let store: AuthRequestStorage;

    beforeEach(async () => {
      store = await options.makeStore();
    });

    describe("set / get / delete / clear", () => {
      it("returns null for an unknown state", async () => {
        assertStrictEquals(await store.get("no-such-state"), null);
      });

      it("round-trips every field of a stored record", async () => {
        const stored = record();
        await store.set("state-1", stored);
        assertEquals(await store.get("state-1"), stored);
      });

      it("keeps records under different states independent", async () => {
        await store.set("state-1", record({ codeVerifier: "verifier-1" }));
        await store.set("state-2", record({ codeVerifier: "verifier-2" }));
        assertStrictEquals(
          (await store.get("state-1"))?.codeVerifier,
          "verifier-1",
        );
        assertStrictEquals(
          (await store.get("state-2"))?.codeVerifier,
          "verifier-2",
        );
      });

      it("deletes one record and leaves the others", async () => {
        await store.set("state-1", record());
        await store.set("state-2", record());
        await store.delete("state-1");
        assertStrictEquals(await store.get("state-1"), null);
        assert(
          await store.get("state-2") !== null,
          "delete must remove only the named state",
        );
      });

      if (clearScope === "all") {
        it("clears every record", async () => {
          await store.set("state-1", record());
          await store.set("state-2", record());
          await store.clear();
          assertStrictEquals(await store.get("state-1"), null);
          assertStrictEquals(await store.get("state-2"), null);
        });
      } else {
        it('leaves every in-progress record in place (clear: "scoped")', async () => {
          const first = record({ codeVerifier: "verifier-1" });
          const second = record({ codeVerifier: "verifier-2" });
          await store.set("state-1", first);
          await store.set("state-2", second);
          await store.clear();
          const message =
            "clear() on a shared store must not cancel another user's sign-in " +
            "that is still in progress";
          assertEquals(await store.get("state-2"), second, message);
          assertEquals(
            expectTake
              ? await store.take!("state-1")
              : await store.get("state-1"),
            first,
            message,
          );
        });

        it('removes a record past any lifetime (clear: "scoped")', async () => {
          await store.set("expired", record({ createdAt: 0 }));
          await store.clear();
          assertStrictEquals(
            await store.get("expired"),
            null,
            "a scoped clear() must still remove expired records",
          );
        });
      }
    });

    if (expectTake) {
      describe("take", () => {
        it("is implemented", () => {
          assert(
            typeof store.take === "function",
            "take is optional, but without it DirectClient falls back to " +
              "get then delete, and two callbacks racing on one state can " +
              "both redeem it. Implement it, or pass `take: false` to record " +
              "the gap.",
          );
        });

        it("returns the record and removes it", async () => {
          const stored = record();
          await store.set("state-1", stored);
          assertEquals(await store.take!("state-1"), stored);
          assertStrictEquals(
            await store.get("state-1"),
            null,
            "a taken record must not be readable again",
          );
          assertStrictEquals(await store.take!("state-1"), null);
        });

        it("returns null for an unknown state", async () => {
          assertStrictEquals(await store.take!("no-such-state"), null);
        });

        it(`hands one record to exactly one of ${CONCURRENT_CALLERS} concurrent takes`, async () => {
          const stored = record();
          await store.set("state-1", stored);
          const results = await race(() => store.take!("state-1"));
          const winners = results.filter((result) => result !== null);
          assertStrictEquals(
            winners.length,
            1,
            "a state is single-use — callbacks racing on it must not each " +
              "receive the PKCE verifier",
          );
          assertEquals(winners[0], stored);
          assertStrictEquals(await store.get("state-1"), null);
        });

        it("hands each record to its own taker when two states are taken concurrently", async () => {
          await store.set("state-1", record({ codeVerifier: "verifier-1" }));
          await store.set("state-2", record({ codeVerifier: "verifier-2" }));
          const [first, second] = await Promise.all([
            store.take!("state-1"),
            store.take!("state-2"),
          ]);
          assertStrictEquals(first?.codeVerifier, "verifier-1");
          assertStrictEquals(second?.codeVerifier, "verifier-2");
        });
      });
    } else {
      it({
        name:
          "take is not implemented — two callbacks racing on one state can both redeem it (take: false)",
        ignore: true,
        fn: () => {},
      });
    }
  });
}
