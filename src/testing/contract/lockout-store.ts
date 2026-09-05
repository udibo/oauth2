/**
 * Contract test suite for {@link LockoutStore} implementations — the
 * per-account failure counter behind `AccountLockout`.
 *
 * `AccountLockout` locks on the failure count `increment` returns, so a store
 * that lets concurrent failed sign-ins share a count undershoots the threshold:
 * the brute-force floor the lockout is meant to be moves up by however many
 * attempts an attacker can land at once.
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

import { assertEquals, assertStrictEquals } from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";

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
   * Overrides the name passed to the outer `describe` block. Defaults to
   * `"LockoutStore contract"`.
   */
  describeName?: string;
}

const USER = "user-1";
const OTHER_USER = "user-2";

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
  describe(options.describeName ?? "LockoutStore contract", () => {
    let store: LockoutStore;
    let now: number;

    beforeEach(async () => {
      store = await options.makeStore();
      now = Date.now();
    });

    describe("get", () => {
      it("returns undefined for an account with no record", async () => {
        assertStrictEquals(await store.get(USER), undefined);
      });
    });

    describe("increment", () => {
      it("records the first failure as one", async () => {
        const result = await store.increment(USER, now);
        assertEquals(result.failures, 1);
        assertStrictEquals(result.lockedUntil, undefined);
        assertEquals((await store.get(USER))?.failures, 1);
      });

      it("adds one failure per call", async () => {
        await store.increment(USER, now);
        await store.increment(USER, now);
        assertEquals((await store.increment(USER, now)).failures, 3);
      });

      it("counts each account on its own", async () => {
        await store.increment(USER, now);
        await store.increment(USER, now);
        assertEquals((await store.increment(OTHER_USER, now)).failures, 1);
      });

      it("keeps an active lock while counting the failure", async () => {
        const lockedUntil = now + 60_000;
        await store.set(USER, { failures: 10, lockedUntil });
        const result = await store.increment(USER, now);
        assertEquals(result.failures, 11);
        assertStrictEquals(
          result.lockedUntil,
          lockedUntil,
          "a failed attempt against a locked account must not extend or drop " +
            "the lock the store is holding",
        );
      });

      it("starts a fresh count once the lock has expired", async () => {
        await store.set(USER, { failures: 10, lockedUntil: now - 1 });
        const result = await store.increment(USER, now);
        assertEquals(result.failures, 1);
        assertStrictEquals(
          result.lockedUntil,
          undefined,
          "an expired lock must be dropped, not carried into the next window",
        );
      });

      it("gives every concurrent failure its own count", async () => {
        const results = await Promise.all(
          Array.from({ length: 5 }, () => store.increment(USER, now)),
        );
        assertEquals(
          results.map((result) => result.failures).sort((a, b) => a - b),
          [1, 2, 3, 4, 5],
          "the lockout triggers on the returned count — concurrent failures " +
            "sharing a count undershoot the threshold",
        );
        assertEquals((await store.get(USER))?.failures, 5);
      });
    });

    describe("set", () => {
      it("persists the record as given", async () => {
        const lockedUntil = now + 60_000;
        await store.set(USER, { failures: 10, lockedUntil });
        const record = await store.get(USER);
        assertEquals(record?.failures, 10);
        assertStrictEquals(record?.lockedUntil, lockedUntil);
      });

      it("replaces a record that was already there", async () => {
        await store.increment(USER, now);
        await store.set(USER, { failures: 4 });
        const record = await store.get(USER);
        assertEquals(record?.failures, 4);
        assertStrictEquals(record?.lockedUntil, undefined);
      });
    });

    describe("clear", () => {
      it("drops the account's failures and lock", async () => {
        await store.set(USER, { failures: 10, lockedUntil: now + 60_000 });
        await store.clear(USER);
        assertStrictEquals(await store.get(USER), undefined);
        assertEquals((await store.increment(USER, now)).failures, 1);
      });

      it("clears only the account it is given", async () => {
        await store.increment(USER, now);
        await store.increment(OTHER_USER, now);
        await store.clear(USER);
        assertEquals((await store.get(OTHER_USER))?.failures, 1);
      });

      it("is a no-op for an account with no record", async () => {
        await store.clear(USER);
        assertStrictEquals(await store.get(USER), undefined);
      });
    });
  });
}
