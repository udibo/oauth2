/**
 * Failed-attempt account lockout — the brute-force floor for sign-in.
 *
 * Distinct from rate limiting: the {@link RateLimiter} throttles *attempts per
 * window* keyed however you like (identifier, IP), while lockout tracks
 * *consecutive failures per account* and locks the account for a cooldown once
 * a threshold is crossed. Storage is a pluggable {@link LockoutStore}
 * (a {@link MemoryLockoutStore} ships for dev/single-process; back it with your
 * database to share state across instances — e.g. columns on your users table,
 * which also gives admins visibility).
 *
 * `AccountLockout` is a pure state machine: it never decides whether to block.
 * `IdentityService` consults it and applies its `protectionMode`
 * (enforce vs log-only), so adopters can observe lockout behavior before
 * turning it on.
 *
 * @module
 */

/** Per-account lockout state. */
export interface LockoutRecord {
  /** Consecutive failed sign-in attempts since the last success/unlock. */
  failures: number;
  /** When the active lock expires (epoch ms); absent when not locked. */
  lockedUntil?: number;
}

/** Pluggable per-account state store for {@link AccountLockout}. */
export interface LockoutStore {
  /** The account's current record, or `undefined` when it has none. */
  get(userId: string): Promise<LockoutRecord | undefined>;
  /**
   * Add one failure and return the new record: an expired lock resets the
   * count to 1 and drops the lock; otherwise `failures + 1` with any active
   * lock kept. Must be atomic (a single statement / compare-and-set in shared
   * stores) — a read-modify-write here lets concurrent failed attempts lose
   * counts and undershoot the lockout threshold.
   */
  increment(userId: string, now: number): Promise<LockoutRecord>;
  /**
   * Persist the account's record, replacing any existing one rather than
   * merging: a record with no `lockedUntil` leaves the account unlocked.
   */
  set(userId: string, record: LockoutRecord): Promise<void>;
  /** Clear the account's record (successful sign-in or unlock). */
  clear(userId: string): Promise<void>;
}

/** Options for {@link AccountLockout}. */
export interface AccountLockoutOptions {
  /** Consecutive failures that trigger a lock. Defaults to 10. */
  maxAttempts?: number;
  /** How long a lock lasts, in ms. Defaults to 15 minutes. */
  lockDurationMs?: number;
  /** State storage. Defaults to {@link MemoryLockoutStore}. */
  store?: LockoutStore;
}

/** The outcome of {@link AccountLockout.recordFailure}. */
export interface LockoutFailureResult {
  /** Consecutive failures after this one. */
  failures: number;
  /** Whether the account is now locked. */
  locked: boolean;
  /** Whether THIS failure crossed the threshold and created the lock. */
  justLocked: boolean;
  /** When the lock expires (epoch ms); absent when not locked. */
  lockedUntil?: number;
}

/** The outcome of {@link AccountLockout.status}. */
export interface LockoutStatus {
  /** Whether an unexpired lock is active. */
  locked: boolean;
  /** Consecutive failures recorded so far. */
  failures: number;
  /** When the active lock expires (epoch ms); absent when not locked. */
  lockedUntil?: number;
}

/**
 * The lockout contract {@link IdentityService} accepts — the
 * bring-your-own-policy seam, symmetric with `RateLimiterLike`.
 * {@link AccountLockout} is the shipped consecutive-failure implementation and
 * satisfies it; implement this directly for a different policy (exponential
 * backoff, per-IP lockout, a lockout your admin tooling already owns).
 *
 * Prefer {@link LockoutStore} when you only need the built-in policy to be
 * shared across instances — that seam swaps storage, not the state machine.
 * Like the class, an implementation decides state only: whether a locked
 * account is refused is `IdentityService`'s `protectionMode`, never yours.
 *
 * @example
 * ```ts
 * import type { AccountLockoutLike } from "@udibo/oauth2/identity";
 *
 * declare const backoff: {
 *   read(userId: string): Promise<{ failures: number; until?: number }>;
 *   bump(userId: string): Promise<{ failures: number; until?: number }>;
 *   clear(userId: string): Promise<void>;
 * };
 *
 * const lockout: AccountLockoutLike = {
 *   async status(userId, now = Date.now()) {
 *     const { failures, until } = await backoff.read(userId);
 *     const locked = until !== undefined && until > now;
 *     return { locked, failures, lockedUntil: locked ? until : undefined };
 *   },
 *   async recordFailure(userId, now = Date.now()) {
 *     const { failures, until } = await backoff.bump(userId);
 *     const locked = until !== undefined && until > now;
 *     return { failures, locked, justLocked: locked, lockedUntil: until };
 *   },
 *   reset: (userId) => backoff.clear(userId),
 * };
 * ```
 */
export interface AccountLockoutLike {
  /** The account's current lock state. An expired lock must read as unlocked. */
  status(userId: string, now?: number): Promise<LockoutStatus>;
  /**
   * Record one failed attempt and report the resulting state. `justLocked` must
   * be true for exactly one attempt per lock — `IdentityService` fires the
   * lockout event and any unlock email off it.
   */
  recordFailure(userId: string, now?: number): Promise<LockoutFailureResult>;
  /** Clear the account's failures and any lock (successful sign-in, unlock). */
  reset(userId: string): Promise<void>;
}

const DEFAULT_MAX_ATTEMPTS = 10;
const DEFAULT_LOCK_DURATION_MS = 15 * 60 * 1000;

/**
 * Consecutive-failure lockout with safe defaults (10 failures → 15-minute
 * lock) — the default {@link AccountLockoutLike}. Wire into
 * {@link IdentityService} via its `lockout` option; call {@link reset} from
 * your unlock flow.
 */
export class AccountLockout implements AccountLockoutLike {
  readonly #maxAttempts: number;
  readonly #lockDurationMs: number;
  readonly #store: LockoutStore;

  /** Fixes thresholds and the backing store (defaults to {@linkcode MemoryLockoutStore}). */
  constructor(options: AccountLockoutOptions = {}) {
    this.#maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.#lockDurationMs = options.lockDurationMs ?? DEFAULT_LOCK_DURATION_MS;
    this.#store = options.store ?? new MemoryLockoutStore();
  }

  /** The account's current lock state. An expired lock reads as not locked. */
  async status(
    userId: string,
    now: number = Date.now(),
  ): Promise<LockoutStatus> {
    const record = await this.#store.get(userId);
    if (!record) return { locked: false, failures: 0 };
    const locked = record.lockedUntil !== undefined && record.lockedUntil > now;
    return {
      locked,
      failures: record.failures,
      lockedUntil: locked ? record.lockedUntil : undefined,
    };
  }

  /**
   * Record one failed attempt, locking the account when the consecutive-failure
   * threshold is crossed. An attempt after a lock expired starts a fresh count.
   */
  async recordFailure(
    userId: string,
    now: number = Date.now(),
  ): Promise<LockoutFailureResult> {
    const record = await this.#store.increment(userId, now);
    const { failures } = record;

    if (record.lockedUntil !== undefined && record.lockedUntil > now) {
      return {
        failures,
        locked: true,
        justLocked: false,
        lockedUntil: record.lockedUntil,
      };
    }

    if (failures >= this.#maxAttempts) {
      const lockedUntil = now + this.#lockDurationMs;
      await this.#store.set(userId, { failures, lockedUntil });
      // Concurrent attempts can overshoot the threshold before the lock lands;
      // only the attempt that hits it exactly reports justLocked, so the
      // lockout event (and any unlock email) fires once.
      return {
        failures,
        locked: true,
        justLocked: failures === this.#maxAttempts,
        lockedUntil,
      };
    }

    return { failures, locked: false, justLocked: false };
  }

  /** Clear the account's failures and any lock (successful sign-in, unlock). */
  reset(userId: string): Promise<void> {
    return this.#store.clear(userId);
  }
}

/** In-memory {@link LockoutStore} for dev / single-process use. */
export class MemoryLockoutStore implements LockoutStore {
  #records = new Map<string, LockoutRecord>();

  /** The stored record for `userId`, if any. */
  get(userId: string): Promise<LockoutRecord | undefined> {
    return Promise.resolve(this.#records.get(userId));
  }

  /** Add one failure synchronously (atomic in a single-process store). */
  increment(userId: string, now: number): Promise<LockoutRecord> {
    const record = this.#records.get(userId);
    const lockExpired = record?.lockedUntil !== undefined &&
      record.lockedUntil <= now;
    const next: LockoutRecord = record && !lockExpired
      ? {
        failures: record.failures + 1,
        ...(record.lockedUntil !== undefined
          ? { lockedUntil: record.lockedUntil }
          : {}),
      }
      : { failures: 1 };
    this.#records.set(userId, next);
    return Promise.resolve(next);
  }

  /** Store `record` for `userId`. */
  set(userId: string, record: LockoutRecord): Promise<void> {
    this.#records.set(userId, record);
    return Promise.resolve();
  }

  /** Drop `userId`'s record. */
  clear(userId: string): Promise<void> {
    this.#records.delete(userId);
    return Promise.resolve();
  }
}
