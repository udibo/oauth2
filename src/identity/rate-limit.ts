/**
 * Fixed-window rate limiting for auth endpoints — throttle sign-in attempts,
 * forgot-password requests, etc. Two seams sit here: {@link RateLimitStore}
 * swaps the counter storage (a {@link MemoryRateLimitStore} ships for
 * dev/single-process; back it with Redis/DB to share limits across instances),
 * and {@link RateLimiterLike} swaps the limiter itself when a fixed window is
 * not the algorithm you want. Tenant-agnostic: scope by keying on whatever you
 * like (IP, identifier, `tenant:ip`).
 *
 * @module
 */

import { IdentityError } from "./errors.ts";
import type { IdentityEvent, RateLimitedEventInit } from "./events.ts";

/** Pluggable counter store for {@link RateLimiter}. */
export interface RateLimitStore {
  /**
   * Increment `key`'s counter within its current window, returning the new
   * count and when the window resets. Implementations start a fresh window
   * (count 1, `resetAt = now + windowMs`) when none is active, and report the
   * same `resetAt` for every hit inside one window — a window that slides
   * forward on each hit never resets under sustained traffic. Must be atomic
   * (a single statement / compare-and-set in shared stores) — a
   * read-modify-write here lets concurrent attempts lose counts and slip past
   * the threshold, which is exactly the burst the limiter exists to catch.
   *
   * Key cardinality is caller-controlled and often derived from
   * unauthenticated request input, so bound what you keep: a TTL per key on
   * Redis, a scheduled delete past `resetAt` on SQL.
   */
  increment(
    key: string,
    windowMs: number,
    now: number,
  ): Promise<{ count: number; resetAt: number }>;
  /** Clear `key`'s counter (e.g. on a successful sign-in). */
  reset(key: string): Promise<void>;
}

/** The outcome of a {@link RateLimiter.check}. */
export interface RateLimitResult {
  /** Whether this hit is within the limit. */
  allowed: boolean;
  /** Hits remaining in the current window (0 when blocked). */
  remaining: number;
  /** When the window resets, epoch ms. */
  resetAt: number;
  /** ms until the caller may retry (0 when allowed). */
  retryAfterMs: number;
}

/**
 * The limiter contract every identity flow accepts — the bring-your-own-limiter
 * seam. {@link RateLimiter} is the shipped fixed-window implementation and
 * satisfies it; implement this directly to run a sliding window, a token
 * bucket, IP reputation, or a limiter you already operate. Everything but the
 * {@link RateLimitResult} is yours: the window arithmetic and the allow/deny
 * decision never leave your implementation.
 *
 * Prefer {@link RateLimitStore} when you only need the built-in fixed window to
 * be shared across instances — that seam swaps storage, not the algorithm.
 *
 * @example
 * ```ts
 * import type { RateLimiterLike } from "@udibo/oauth2/identity";
 *
 * declare const myLimiter: {
 *   consume(key: string): Promise<{ ok: boolean; msBeforeNext: number }>;
 *   delete(key: string): Promise<void>;
 * };
 *
 * const rateLimiter: RateLimiterLike = {
 *   async check(key, now = Date.now()) {
 *     const { ok, msBeforeNext } = await myLimiter.consume(key);
 *     return {
 *       allowed: ok,
 *       remaining: 0,
 *       resetAt: now + msBeforeNext,
 *       retryAfterMs: ok ? 0 : msBeforeNext,
 *     };
 *   },
 *   reset: (key) => myLimiter.delete(key),
 * };
 * ```
 */
export interface RateLimiterLike {
  /** Record a hit for `key` and report whether it is within the limit. */
  check(key: string, now?: number): Promise<RateLimitResult>;
  /** Clear `key`'s counter (e.g. on a successful sign-in). */
  reset(key: string): Promise<void>;
}

/** Options for {@link RateLimiter}. */
export interface RateLimiterOptions {
  /** Max hits per window. Defaults to 10 — a sane sign-in floor. */
  limit?: number;
  /** Window length in ms. Defaults to 15 minutes. */
  windowMs?: number;
  /** Counter storage. Defaults to {@link MemoryRateLimitStore}. */
  store?: RateLimitStore;
}

const DEFAULT_LIMIT = 10;
const DEFAULT_WINDOW_MS = 15 * 60 * 1000;

/**
 * Fixed-window limiter — the default {@link RateLimiterLike}, deliberately
 * feature-frozen as a floor rather than a product. Swap in your own
 * `RateLimiterLike` for anything the fixed window cannot express.
 *
 * @example
 * ```ts
 * const limiter = new RateLimiter({ limit: 5, windowMs: 15 * 60_000 });
 * const r = await limiter.check(`signin:${ip}`);
 * if (!r.allowed) throw new IdentityError("rate_limited", undefined, { retryAfterMs: r.retryAfterMs });
 * // …on success: await limiter.reset(`signin:${ip}`);
 * ```
 */
export class RateLimiter implements RateLimiterLike {
  readonly #limit: number;
  readonly #windowMs: number;
  readonly #store: RateLimitStore;

  /** Fixes the `limit`/`windowMs` and the backing store (defaults to {@linkcode MemoryRateLimitStore}). */
  constructor(options: RateLimiterOptions = {}) {
    this.#limit = options.limit ?? DEFAULT_LIMIT;
    this.#windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;
    this.#store = options.store ?? new MemoryRateLimitStore();
  }

  /** Record a hit for `key` and report whether it is within the limit. */
  async check(key: string, now: number = Date.now()): Promise<RateLimitResult> {
    const { count, resetAt } = await this.#store.increment(
      key,
      this.#windowMs,
      now,
    );
    const allowed = count <= this.#limit;
    return {
      allowed,
      remaining: Math.max(0, this.#limit - count),
      resetAt,
      retryAfterMs: allowed ? 0 : Math.max(0, resetAt - now),
    };
  }

  /** Clear `key`'s counter. */
  reset(key: string): Promise<void> {
    return this.#store.reset(key);
  }
}

/**
 * How a throttled flow reports hitting its limit. Both halves travel together
 * or neither does — supplying one without the other would type-check into a
 * silently dropped audit event.
 */
type RateLimitReport =
  | {
    /** The flow's `*.rate_limited` event, minus the fields filled in here. */
    event: RateLimitedEventInit;
    /** The service's event emitter (already hook-safe, never throws). */
    emit: (event: IdentityEvent) => Promise<void>;
  }
  | {
    /** Omitted in a flow whose service exposes no event seam. */
    event?: never;
    emit?: never;
  };

/** Options for {@link enforceRateLimit}. */
export type EnforceRateLimitOptions =
  & {
    /** The limiter to check; `undefined` disables throttling entirely. */
    rateLimiter: RateLimiterLike | undefined;
    /** The limiter key (e.g. `signin:${identifier}`, `mfa:verify:${userId}`). */
    key: string;
    /** The `IdentityError` message when the limit is hit under enforcement. */
    message: string;
    /** `false` (log-only mode) emits the event but lets the attempt through. */
    enforce: boolean;
  }
  & RateLimitReport;

/**
 * The shared throttle sequence every identity-layer flow uses: check the
 * limiter, and when the limit is hit emit the flow's `*.rate_limited` event
 * (when the caller supplies `event` + `emit`) and — under enforcement — throw.
 * No-op without a limiter.
 *
 * A BYO {@link RateLimiterLike.check} that **throws** is trapped: under
 * enforcement it surfaces as the same `rate_limited` error (fail closed, so a
 * broken limiter denies rather than leaking a raw error), and in log-only mode
 * it is logged and lets the attempt through (the mode's promise never to
 * block). A limiter that itself throws an {@link IdentityError} is preserved.
 *
 * @throws {IdentityError} `rate_limited` (with `retryAfterMs`) when the limit
 * is hit and `enforce` is `true`.
 */
export async function enforceRateLimit(
  options: EnforceRateLimitOptions,
): Promise<void> {
  if (!options.rateLimiter) return;
  let result: RateLimitResult;
  try {
    result = await options.rateLimiter.check(options.key);
  } catch (error) {
    if (error instanceof IdentityError) throw error;
    if (!options.enforce) {
      console.error(
        "[@udibo/oauth2] rate limiter check failed (log-only, allowing):",
        error instanceof Error ? error.message : error,
      );
      return;
    }
    throw new IdentityError("rate_limited", options.message, { cause: error });
  }
  if (result.allowed) return;
  if (options.event && options.emit) {
    await options.emit({
      ...options.event,
      retryAfterMs: result.retryAfterMs,
      enforced: options.enforce,
    });
  }
  if (options.enforce) {
    throw new IdentityError("rate_limited", options.message, {
      retryAfterMs: result.retryAfterMs,
    });
  }
}

const MAX_BUCKETS = 10_000;
const SWEEP_INTERVAL = 1_000;
const EVICTION_TARGET = 9_000;

/**
 * In-memory {@link RateLimitStore} for dev / single-process use. Counters are
 * per-process, so replicas do not share limits — back {@link RateLimiter} with
 * Redis or a database in production.
 *
 * Bounded on purpose: limiter keys are built from unauthenticated request
 * input, so the store is capped at 10,000 buckets and evicts to stay under it.
 * Eviction takes lapsed buckets first, then the buckets with the fewest hits,
 * so a unique-key flood discards its own counters rather than one that is
 * close to blocking. The residual is real: an attacker able to push ~10,000
 * keys above a live counter's hit count can still displace it.
 */
export class MemoryRateLimitStore implements RateLimitStore {
  #buckets = new Map<string, { count: number; resetAt: number }>();
  #writesSinceSweep = 0;

  /**
   * How many buckets are currently retained — never more than the 10,000-bucket
   * cap. Exposed so a test or a dev-time probe can see the guardrail working;
   * it is not part of the {@link RateLimitStore} contract.
   */
  get size(): number {
    return this.#buckets.size;
  }

  /**
   * Bump `key`'s counter, opening a fresh window when the current one has
   * lapsed. Atomic by virtue of being synchronous in a single process. May
   * evict other keys' buckets to stay under the store's capacity.
   */
  increment(
    key: string,
    windowMs: number,
    now: number,
  ): Promise<{ count: number; resetAt: number }> {
    let bucket = this.#buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      this.#buckets.set(key, bucket);
    }
    bucket.count++;
    this.#collect(now);
    return Promise.resolve({ count: bucket.count, resetAt: bucket.resetAt });
  }

  /** Forget `key`'s bucket so its next hit starts a new window. */
  reset(key: string): Promise<void> {
    this.#buckets.delete(key);
    return Promise.resolve();
  }

  #collect(now: number): void {
    if (++this.#writesSinceSweep >= SWEEP_INTERVAL) this.#dropLapsed(now);
    if (this.#buckets.size <= MAX_BUCKETS) return;
    this.#dropLapsed(now);
    if (this.#buckets.size <= MAX_BUCKETS) return;
    this.#dropColdest(this.#buckets.size - EVICTION_TARGET);
  }

  #dropLapsed(now: number): void {
    this.#writesSinceSweep = 0;
    for (const [key, bucket] of this.#buckets) {
      if (bucket.resetAt <= now) this.#buckets.delete(key);
    }
  }

  #dropColdest(count: number): void {
    const ordered = [...this.#buckets].sort((a, b) =>
      a[1].count - b[1].count || a[1].resetAt - b[1].resetAt
    );
    for (const [key] of ordered.slice(0, count)) this.#buckets.delete(key);
  }
}
