import { assert, describe, expect, it } from "vitest";
import { rejection } from "../_test_assert.ts";
import { IdentityError } from "./errors.ts";
import type { IdentityEvent } from "./events.ts";
import {
  enforceRateLimit,
  MemoryRateLimitStore,
  RateLimiter,
  type RateLimiterLike,
} from "./rate-limit.ts";

describe("RateLimiter", () => {
  it("allows up to the limit, then blocks within the window", async () => {
    const limiter = new RateLimiter({ limit: 3, windowMs: 1000 });
    const t0 = 1_000_000;
    for (let i = 1; i <= 3; i++) {
      const r = await limiter.check("k", t0);
      expect(r.allowed).toStrictEqual(true);
      expect(r.remaining).toStrictEqual(3 - i);
    }
    const blocked = await limiter.check("k", t0);
    expect(blocked.allowed).toStrictEqual(false);
    expect(blocked.remaining).toStrictEqual(0);
    expect(blocked.retryAfterMs).toStrictEqual(1000);
  });

  it("starts a fresh window after it elapses", async () => {
    const limiter = new RateLimiter({ limit: 1, windowMs: 1000 });
    const t0 = 1_000_000;
    expect((await limiter.check("k", t0)).allowed).toStrictEqual(true);
    expect((await limiter.check("k", t0)).allowed).toStrictEqual(false);
    expect((await limiter.check("k", t0 + 1001)).allowed).toStrictEqual(true);
  });

  it("tracks keys independently and reset() clears one", async () => {
    const limiter = new RateLimiter({ limit: 1, windowMs: 1000 });
    const t0 = 1_000_000;
    expect((await limiter.check("a", t0)).allowed).toStrictEqual(true);
    expect((await limiter.check("b", t0)).allowed).toStrictEqual(true);
    expect((await limiter.check("a", t0)).allowed).toStrictEqual(false);
    await limiter.reset("a");
    expect((await limiter.check("a", t0)).allowed).toStrictEqual(true);
  });
});

describe("MemoryRateLimitStore", () => {
  const t0 = 1_000_000;

  it("keeps the bucket map bounded when unique keys flood in", async () => {
    const store = new MemoryRateLimitStore();
    for (let i = 0; i < 12_000; i++) {
      await store.increment(`signin:attacker-${i}`, 60_000, t0);
    }
    assert(
      store.size <= 10_000,
      `expected the map to stay capped, saw ${store.size} buckets`,
    );
    assert(store.size > 0);
  });

  it("sweeps lapsed buckets as writes accumulate", async () => {
    const store = new MemoryRateLimitStore();
    for (let i = 0; i < 50; i++) {
      await store.increment(`lapsing:${i}`, 1_000, t0);
    }
    expect(store.size).toStrictEqual(50);

    const later = t0 + 2_000;
    for (let i = 0; i < 1_000; i++) {
      await store.increment("still-live", 60_000, later);
    }
    expect(store.size).toStrictEqual(1);
  });

  it("reclaims lapsed buckets at capacity before touching live ones", async () => {
    const store = new MemoryRateLimitStore();
    for (let i = 0; i < 10_000; i++) {
      await store.increment(`lapsing:${i}`, 1_000, t0);
    }
    expect(store.size).toStrictEqual(10_000);

    const later = t0 + 5_000;
    for (let i = 0; i < 5_000; i++) {
      await store.increment(`live:${i}`, 60_000, later);
    }
    expect(store.size).toStrictEqual(5_000);
    expect(
      (await store.increment("live:0", 60_000, later)).count,
    ).toStrictEqual(2);
  });

  it("evicts the coldest bucket first when every bucket is live", async () => {
    const store = new MemoryRateLimitStore();
    await store.increment("warm", 60 * 60_000, t0);
    await store.increment("warm", 60 * 60_000, t0);
    for (let i = 0; i < 10_000; i++) {
      await store.increment(`cold:${i}`, 60 * 60_000, t0);
    }

    expect(
      (await store.increment("warm", 60 * 60_000, t0)).count,
    ).toStrictEqual(3);
  });

  it("keeps a blocking counter through a unique-key flood", async () => {
    const store = new MemoryRateLimitStore();
    const limit = 10;
    const victim = "signin:victim@example.com";
    for (let i = 0; i < limit; i++) {
      await store.increment(victim, 15 * 60_000, t0);
    }

    for (let i = 0; i < 40_000; i++) {
      await store.increment(`pwreset:junk-${i}@x.com`, 15 * 60_000, t0);
    }

    const next = await store.increment(victim, 15 * 60_000, t0);
    expect(next.count).toStrictEqual(limit + 1);
    assert(
      next.count > limit,
      "the flood reset the victim's window — cap eviction discarded a blocking counter",
    );
    assert(store.size <= 10_000);
  });

  it("does not lose counts under concurrent increments", async () => {
    const store = new MemoryRateLimitStore();
    const hits = await Promise.all(
      Array.from({ length: 100 }, () => store.increment("k", 60_000, t0)),
    );
    expect(hits.map((hit) => hit.count).sort((a, b) => a - b)).toStrictEqual(
      Array.from({ length: 100 }, (_, i) => i + 1),
    );
  });
});

describe("enforceRateLimit", () => {
  function countingLimiter(allowAfter: number): RateLimiterLike & {
    checks: string[];
    resets: string[];
  } {
    let hits = 0;
    const checks: string[] = [];
    const resets: string[] = [];
    return {
      checks,
      resets,
      check(key) {
        checks.push(key);
        const allowed = ++hits <= allowAfter;
        return Promise.resolve({
          allowed,
          remaining: allowed ? allowAfter - hits : 0,
          resetAt: 0,
          retryAfterMs: allowed ? 0 : 4_242,
        });
      },
      reset(key) {
        resets.push(key);
        return Promise.resolve();
      },
    };
  }

  function options(rateLimiter: RateLimiterLike | undefined, enforce: boolean) {
    const events: IdentityEvent[] = [];
    return {
      events,
      config: {
        rateLimiter,
        key: "signin:a@b.co",
        message: "Too many attempts.",
        enforce,
        event: {
          type: "sign_in.rate_limited",
          identifier: "a@b.co",
        } as const,
        emit: (event: IdentityEvent) => {
          events.push(event);
          return Promise.resolve();
        },
      },
    };
  }

  it("accepts a plain-object limiter and consults it", async () => {
    const limiter = countingLimiter(1);
    const { config } = options(limiter, true);

    await enforceRateLimit(config);
    expect(limiter.checks).toStrictEqual(["signin:a@b.co"]);
  });

  it("throws rate_limited with the limiter's retryAfterMs once it blocks", async () => {
    const limiter = countingLimiter(0);
    const { config, events } = options(limiter, true);

    const error = await rejection(
      () => enforceRateLimit(config),
      IdentityError,
    );
    expect(error.code).toStrictEqual("rate_limited");
    expect(error.retryAfterMs).toStrictEqual(4_242);
    expect(events.length).toStrictEqual(1);
    expect(events[0]?.type).toStrictEqual("sign_in.rate_limited");
  });

  it("still throttles a flow whose service has no event seam", async () => {
    const limiter = countingLimiter(0);
    const error = await rejection(
      () =>
        enforceRateLimit({
          rateLimiter: limiter,
          key: "otp:signin:a@b.co",
          message: "Too many attempts.",
          enforce: true,
        }),
      IdentityError,
    );
    expect(error.code).toStrictEqual("rate_limited");
    expect(error.retryAfterMs).toStrictEqual(4_242);
    expect(limiter.checks).toStrictEqual(["otp:signin:a@b.co"]);
  });

  it("emits without throwing in log-only mode", async () => {
    const { config, events } = options(countingLimiter(0), false);

    await enforceRateLimit(config);
    expect(events.length).toStrictEqual(1);
    assert(events[0]?.type === "sign_in.rate_limited");
    expect(events[0].enforced).toStrictEqual(false);
  });

  it("is a no-op without a limiter", async () => {
    const { config, events } = options(undefined, true);

    await enforceRateLimit(config);
    expect(events.length).toStrictEqual(0);
  });

  it("traps a throwing check as rate_limited under enforcement", async () => {
    const throwing: RateLimiterLike = {
      check: () => Promise.reject(new Error("limiter backend down")),
      reset: () => Promise.resolve(),
    };
    const { config } = options(throwing, true);

    const error = await rejection(
      () => enforceRateLimit(config),
      IdentityError,
    );
    expect(error.code).toStrictEqual("rate_limited");
  });

  it("lets the attempt through when the check throws in log-only mode", async () => {
    const throwing: RateLimiterLike = {
      check: () => Promise.reject(new Error("limiter backend down")),
      reset: () => Promise.resolve(),
    };
    const { config, events } = options(throwing, false);

    await enforceRateLimit(config);
    expect(events.length).toStrictEqual(0);
  });

  it("preserves an IdentityError the limiter throws itself", async () => {
    const throwing: RateLimiterLike = {
      check: () =>
        Promise.reject(new IdentityError("invalid_token", "bad key")),
      reset: () => Promise.resolve(),
    };
    const { config } = options(throwing, true);

    const error = await rejection(
      () => enforceRateLimit(config),
      IdentityError,
    );
    expect(error.code).toStrictEqual("invalid_token");
  });
});
