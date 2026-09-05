import { assert, assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

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
      assertEquals(r.allowed, true);
      assertEquals(r.remaining, 3 - i);
    }
    const blocked = await limiter.check("k", t0);
    assertEquals(blocked.allowed, false);
    assertEquals(blocked.remaining, 0);
    assertEquals(blocked.retryAfterMs, 1000);
  });

  it("starts a fresh window after it elapses", async () => {
    const limiter = new RateLimiter({ limit: 1, windowMs: 1000 });
    const t0 = 1_000_000;
    assertEquals((await limiter.check("k", t0)).allowed, true);
    assertEquals((await limiter.check("k", t0)).allowed, false);
    assertEquals((await limiter.check("k", t0 + 1001)).allowed, true);
  });

  it("tracks keys independently and reset() clears one", async () => {
    const limiter = new RateLimiter({ limit: 1, windowMs: 1000 });
    const t0 = 1_000_000;
    assertEquals((await limiter.check("a", t0)).allowed, true);
    assertEquals((await limiter.check("b", t0)).allowed, true);
    assertEquals((await limiter.check("a", t0)).allowed, false);
    await limiter.reset("a");
    assertEquals((await limiter.check("a", t0)).allowed, true);
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
    assertEquals(store.size, 50);

    const later = t0 + 2_000;
    for (let i = 0; i < 1_000; i++) {
      await store.increment("still-live", 60_000, later);
    }
    assertEquals(store.size, 1);
  });

  it("reclaims lapsed buckets at capacity before touching live ones", async () => {
    const store = new MemoryRateLimitStore();
    for (let i = 0; i < 10_000; i++) {
      await store.increment(`lapsing:${i}`, 1_000, t0);
    }
    assertEquals(store.size, 10_000);

    const later = t0 + 5_000;
    for (let i = 0; i < 5_000; i++) {
      await store.increment(`live:${i}`, 60_000, later);
    }
    assertEquals(store.size, 5_000);
    assertEquals((await store.increment("live:0", 60_000, later)).count, 2);
  });

  it("evicts the coldest bucket first when every bucket is live", async () => {
    const store = new MemoryRateLimitStore();
    await store.increment("warm", 60 * 60_000, t0);
    await store.increment("warm", 60 * 60_000, t0);
    for (let i = 0; i < 10_000; i++) {
      await store.increment(`cold:${i}`, 60 * 60_000, t0);
    }

    assertEquals((await store.increment("warm", 60 * 60_000, t0)).count, 3);
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
    assertEquals(next.count, limit + 1);
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
    assertEquals(
      hits.map((hit) => hit.count).sort((a, b) => a - b),
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
    assertEquals(limiter.checks, ["signin:a@b.co"]);
  });

  it("throws rate_limited with the limiter's retryAfterMs once it blocks", async () => {
    const limiter = countingLimiter(0);
    const { config, events } = options(limiter, true);

    const error = await assertRejects(
      () => enforceRateLimit(config),
      IdentityError,
    );
    assertEquals(error.code, "rate_limited");
    assertEquals(error.retryAfterMs, 4_242);
    assertEquals(events.length, 1);
    assertEquals(events[0]?.type, "sign_in.rate_limited");
  });

  it("still throttles a flow whose service has no event seam", async () => {
    const limiter = countingLimiter(0);
    const error = await assertRejects(
      () =>
        enforceRateLimit({
          rateLimiter: limiter,
          key: "otp:signin:a@b.co",
          message: "Too many attempts.",
          enforce: true,
        }),
      IdentityError,
    );
    assertEquals(error.code, "rate_limited");
    assertEquals(error.retryAfterMs, 4_242);
    assertEquals(limiter.checks, ["otp:signin:a@b.co"]);
  });

  it("emits without throwing in log-only mode", async () => {
    const { config, events } = options(countingLimiter(0), false);

    await enforceRateLimit(config);
    assertEquals(events.length, 1);
    assert(events[0]?.type === "sign_in.rate_limited");
    assertEquals(events[0].enforced, false);
  });

  it("is a no-op without a limiter", async () => {
    const { config, events } = options(undefined, true);

    await enforceRateLimit(config);
    assertEquals(events.length, 0);
  });

  it("traps a throwing check as rate_limited under enforcement", async () => {
    const throwing: RateLimiterLike = {
      check: () => Promise.reject(new Error("limiter backend down")),
      reset: () => Promise.resolve(),
    };
    const { config } = options(throwing, true);

    const error = await assertRejects(
      () => enforceRateLimit(config),
      IdentityError,
    );
    assertEquals(error.code, "rate_limited");
  });

  it("lets the attempt through when the check throws in log-only mode", async () => {
    const throwing: RateLimiterLike = {
      check: () => Promise.reject(new Error("limiter backend down")),
      reset: () => Promise.resolve(),
    };
    const { config, events } = options(throwing, false);

    await enforceRateLimit(config);
    assertEquals(events.length, 0);
  });

  it("preserves an IdentityError the limiter throws itself", async () => {
    const throwing: RateLimiterLike = {
      check: () =>
        Promise.reject(new IdentityError("invalid_token", "bad key")),
      reset: () => Promise.resolve(),
    };
    const { config } = options(throwing, true);

    const error = await assertRejects(
      () => enforceRateLimit(config),
      IdentityError,
    );
    assertEquals(error.code, "invalid_token");
  });
});
