/**
 * Contract test suite for {@link RateLimitStore} implementations — the shared
 * counter behind `RateLimiter`.
 *
 * The limiter allows or denies on the count `increment` returns, so a store
 * that lets two concurrent attempts read the same count raises the effective
 * threshold by exactly the burst the limiter exists to catch. That is the case
 * this suite exists for.
 *
 * @example Verify a Redis-backed store
 * ```ts
 * import { runRateLimitStoreContractTests } from "@udibo/oauth2/testing/contract";
 * import type { RateLimitStore } from "@udibo/oauth2/identity";
 *
 * declare function freshRateLimitStore(): Promise<RateLimitStore>;
 *
 * runRateLimitStoreContractTests({
 *   describeName: "RedisRateLimitStore satisfies RateLimitStore contract",
 *   makeStore: freshRateLimitStore,
 * });
 * ```
 *
 * @module
 */

import { assert, beforeEach, describe, expect, it } from "vitest";
import type { RateLimitStore } from "../../identity/rate-limit.ts";

/** Options for {@link runRateLimitStoreContractTests}. */
export interface RateLimitStoreContractOptions {
  /**
   * Returns a fresh, empty store for each test. Isolation is required — a
   * counter surviving into the next test shifts every count the suite asserts.
   */
  makeStore(): Promise<RateLimitStore> | RateLimitStore;
  /**
   * How far `resetAt` may sit from `now + windowMs`, in ms — headroom for a
   * store whose backend rounds a TTL (Redis rounds to whole seconds). Defaults
   * to 1000.
   */
  resetAtToleranceMs?: number;
  /**
   * Overrides the name passed to the outer `describe` block. Defaults to
   * `"RateLimitStore contract"`.
   */
  describeName?: string;
}

const KEY = "signin:1.2.3.4";
const OTHER_KEY = "signin:5.6.7.8";
const WINDOW_MS = 60_000;

/**
 * Runs the {@link RateLimitStore} contract suite. Call it from your own test
 * file — it registers `describe` / `it` blocks the test runner picks up.
 *
 * `now` is passed explicitly on every call, so the window cases are clock-free
 * and never need a timer.
 */
export function runRateLimitStoreContractTests(
  options: RateLimitStoreContractOptions,
): void {
  const tolerance = options.resetAtToleranceMs ?? 1000;

  describe(options.describeName ?? "RateLimitStore contract", () => {
    let store: RateLimitStore;
    let now: number;

    beforeEach(async () => {
      store = await options.makeStore();
      now = Date.now();
    });

    describe("increment", () => {
      it("opens a window at count 1 that ends one window from now", async () => {
        const result = await store.increment(KEY, WINDOW_MS, now);
        expect(result.count).toStrictEqual(1);
        expect(
          Math.abs(result.resetAt - (now + WINDOW_MS)),
        ).toBeLessThanOrEqual(tolerance);
      });

      it("counts up within the window without moving its end", async () => {
        const first = await store.increment(KEY, WINDOW_MS, now);
        const second = await store.increment(KEY, WINDOW_MS, now + 10);
        const third = await store.increment(KEY, WINDOW_MS, now + 20);
        expect([second.count, third.count]).toStrictEqual([2, 3]);
        expect(
          [second.resetAt, third.resetAt],
          "a fixed window ends when it ends — hits inside it must not push " +
            "the reset out",
        ).toStrictEqual([first.resetAt, first.resetAt]);
      });

      it("opens a fresh window once the previous one has lapsed", async () => {
        const first = await store.increment(KEY, WINDOW_MS, now);
        const after = first.resetAt + 1;
        const result = await store.increment(KEY, WINDOW_MS, after);
        expect(result.count).toStrictEqual(1);
        expect(
          Math.abs(result.resetAt - (after + WINDOW_MS)),
        ).toBeLessThanOrEqual(tolerance);
      });

      it("counts each key on its own", async () => {
        await store.increment(KEY, WINDOW_MS, now);
        await store.increment(KEY, WINDOW_MS, now);
        const other = await store.increment(OTHER_KEY, WINDOW_MS, now);
        expect(other.count).toStrictEqual(1);
      });

      it("gives every concurrent hit its own count", async () => {
        const results = await Promise.all(
          Array.from({ length: 5 }, () => store.increment(KEY, WINDOW_MS, now)),
        );
        expect(
          results.map((result) => result.count).sort((a, b) => a - b),
          "the limiter decides on the returned count — concurrent hits " +
            "sharing a count are exactly the burst that slips past the " +
            "threshold",
        ).toStrictEqual([1, 2, 3, 4, 5]);
        const next = await store.increment(KEY, WINDOW_MS, now);
        expect(next.count, "no hit may be lost to a stale read").toStrictEqual(
          6,
        );
      });
    });

    describe("reset", () => {
      it("sends the key back to a fresh window", async () => {
        await store.increment(KEY, WINDOW_MS, now);
        await store.increment(KEY, WINDOW_MS, now);
        await store.reset(KEY);
        const result = await store.increment(KEY, WINDOW_MS, now);
        expect(result.count).toStrictEqual(1);
        expect(
          Math.abs(result.resetAt - (now + WINDOW_MS)),
        ).toBeLessThanOrEqual(tolerance);
      });

      it("clears only the key it is given", async () => {
        await store.increment(KEY, WINDOW_MS, now);
        await store.increment(OTHER_KEY, WINDOW_MS, now);
        await store.reset(KEY);
        const other = await store.increment(OTHER_KEY, WINDOW_MS, now);
        expect(other.count).toStrictEqual(2);
      });

      it("is a no-op for a key with no counter", async () => {
        await store.reset("never-seen");
        const result = await store.increment("never-seen", WINDOW_MS, now);
        assert(result.count === 1);
      });
    });
  });
}
