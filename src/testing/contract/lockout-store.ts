import { beforeEach, describe, expect, it } from "vitest";
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
          "the lockout triggers on the returned count — concurrent failures " +
            "sharing a count undershoot the threshold",
        ).toStrictEqual([1, 2, 3, 4, 5]);
        expect((await store.get(USER))?.failures).toStrictEqual(5);
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
