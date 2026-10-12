/**
 * Failed-attempt account lockout — the brute-force floor for sign-in.
 *
 * Distinct from rate limiting: the {@link RateLimiter} throttles *attempts per
 * window* keyed however you like (identifier, IP), while lockout tracks
 * *consecutive failures per account* and locks the account for a cooldown once
 * a threshold is crossed. Storage is a pluggable {@link LockoutStore} with no
 * default: back it with storage every instance shares — e.g. columns on your
 * users table, which also gives admins visibility — or pass the bounded
 * {@link MemoryLockoutStore} for a single process, tests and local
 * development.
 *
 * `AccountLockout` only records state: it never decides whether to block.
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
  /**
   * The account's current record, or `undefined` when it has none.
   * `AccountLockout` passes the clock it was given as `now`, for a store that
   * expires records; a store that keeps them until cleared can ignore it.
   */
  get(userId: string, now?: number): Promise<LockoutRecord | undefined>;
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
  /**
   * Where failure counts and locks live. Required, because a lockout only
   * holds if every instance that serves sign-in reads the same records:
   *
   * - A {@link LockoutStore} over storage every instance shares, such as
   *   columns on your users table. Its `increment` must be atomic.
   * - {@link MemoryLockoutStore} for a single process, tests and local
   *   development. Each instance counts its own failures, so behind a load
   *   balancer an attacker gets `maxAttempts` guesses per instance and a lock
   *   on one instance does not stop sign-in on another.
   */
  store: LockoutStore;
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

const MISSING_LOCKOUT_STORE =
  "AccountLockout requires options.store. Pass a LockoutStore over storage " +
  "every instance shares, such as columns on your users table, or " +
  "MemoryLockoutStore for a single process, tests and local development.";

/**
 * Consecutive-failure lockout with safe defaults (10 failures → 15-minute
 * lock) — the shipped {@link AccountLockoutLike}. Wire into
 * {@link IdentityService} via its `lockout` option, which resets it on a
 * successful sign-in, password reset, or {@link IdentityService.unlockAccount};
 * call {@link reset} yourself only from an unlock flow of your own.
 */
export class AccountLockout implements AccountLockoutLike {
  readonly #maxAttempts: number;
  readonly #lockDurationMs: number;
  readonly #store: LockoutStore;

  /**
   * Fixes the thresholds and the backing store.
   *
   * @throws {TypeError} When {@linkcode AccountLockoutOptions.store} is
   * missing.
   */
  constructor(options: AccountLockoutOptions) {
    if (!options?.store) throw new TypeError(MISSING_LOCKOUT_STORE);
    this.#maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.#lockDurationMs = options.lockDurationMs ?? DEFAULT_LOCK_DURATION_MS;
    this.#store = options.store;
  }

  /** The account's current lock state. An expired lock reads as not locked. */
  async status(
    userId: string,
    now: number = Date.now(),
  ): Promise<LockoutStatus> {
    const record = await this.#store.get(userId, now);
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

/** Options for {@link MemoryLockoutStore}. */
export interface MemoryLockoutStoreOptions {
  /**
   * How long a record is kept after its last failure, in ms. A record past it
   * reads as absent, so the next failure starts a fresh count, but a record is
   * never dropped while its lock is active. Defaults to 24 hours; `Infinity`
   * keeps records until they are cleared or evicted.
   */
  ttlMs?: number;
  /**
   * Most records held at once. Defaults to 10,000; `Infinity` never evicts by
   * count.
   */
  maxEntries?: number;
}

interface MemoryLockoutEntry {
  record: LockoutRecord;
  touchedAt: number;
}

const DEFAULT_LOCKOUT_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_LOCKOUT_RECORDS = 10_000;
const LOCKOUT_SWEEP_INTERVAL = 1_000;

/**
 * In-memory {@link LockoutStore} for a single process, tests and local
 * development. Records live in the process that wrote them, so instances do
 * not share failures or locks; pass a store over shared storage when more
 * than one instance serves sign-in.
 *
 * Bounded so it cannot grow without limit: a record expires
 * {@link MemoryLockoutStoreOptions.ttlMs} after its last failure unless its
 * lock is still active, and a write beyond
 * {@link MemoryLockoutStoreOptions.maxEntries} first drops expired records,
 * then evicts one: unlocked records before locked ones, the fewest failures
 * first, then the longest idle; among locked records, the lock that ends
 * soonest. The residual is real: failures against more than `maxEntries`
 * other accounts that each end locked can evict an active lock.
 */
export class MemoryLockoutStore implements LockoutStore {
  readonly #entries = new Map<string, MemoryLockoutEntry>();
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  #writesSinceSweep = 0;

  /**
   * Configures the TTL (24 hours by default) and the record cap (10,000 by
   * default).
   *
   * @throws {RangeError} When `ttlMs` is not a positive number or `Infinity`,
   * or `maxEntries` is neither a positive integer nor `Infinity`.
   */
  constructor(options: MemoryLockoutStoreOptions = {}) {
    this.#ttlMs = options.ttlMs ?? DEFAULT_LOCKOUT_TTL_MS;
    this.#maxEntries = options.maxEntries ?? DEFAULT_MAX_LOCKOUT_RECORDS;
    if (!(this.#ttlMs > 0)) {
      throw new RangeError(
        "MemoryLockoutStore ttlMs must be a positive number or Infinity, " +
          `got ${this.#ttlMs}.`,
      );
    }
    if (
      this.#maxEntries !== Infinity &&
      !(Number.isInteger(this.#maxEntries) && this.#maxEntries > 0)
    ) {
      throw new RangeError(
        "MemoryLockoutStore maxEntries must be a positive integer or " +
          `Infinity, got ${this.#maxEntries}.`,
      );
    }
  }

  /**
   * How many records are currently retained — never more than `maxEntries`.
   * Exposed so a test or a dev-time probe can see the bound working; it is not
   * part of the {@link LockoutStore} contract.
   */
  get size(): number {
    return this.#entries.size;
  }

  /** The stored record for `userId`, or `undefined` once it has expired. */
  get(
    userId: string,
    now: number = Date.now(),
  ): Promise<LockoutRecord | undefined> {
    const entry = this.#entries.get(userId);
    if (entry && this.#expired(entry, now)) {
      this.#entries.delete(userId);
      return Promise.resolve(undefined);
    }
    return Promise.resolve(entry?.record);
  }

  /**
   * Add one failure synchronously (atomic in a single-process store). May
   * drop expired records and evict another account's record to stay under
   * `maxEntries`.
   */
  increment(userId: string, now: number): Promise<LockoutRecord> {
    const entry = this.#entries.get(userId);
    const record =
      entry && !this.#expired(entry, now) ? entry.record : undefined;
    const lockExpired =
      record?.lockedUntil !== undefined && record.lockedUntil <= now;
    const next: LockoutRecord =
      record && !lockExpired
        ? {
            failures: record.failures + 1,
            ...(record.lockedUntil !== undefined
              ? { lockedUntil: record.lockedUntil }
              : {}),
          }
        : { failures: 1 };
    this.#entries.set(userId, { record: next, touchedAt: now });
    this.#collect(userId, now);
    return Promise.resolve(next);
  }

  /**
   * Store `record` for `userId`, keeping the time of its last failure; a
   * record for an account with none is timed from now.
   */
  set(userId: string, record: LockoutRecord): Promise<void> {
    const touchedAt = this.#entries.get(userId)?.touchedAt ?? Date.now();
    this.#entries.set(userId, { record, touchedAt });
    this.#collect(userId, touchedAt);
    return Promise.resolve();
  }

  /** Drop `userId`'s record. */
  clear(userId: string): Promise<void> {
    this.#entries.delete(userId);
    return Promise.resolve();
  }

  #expired(entry: MemoryLockoutEntry, now: number): boolean {
    const { lockedUntil } = entry.record;
    if (lockedUntil !== undefined && lockedUntil > now) return false;
    return now - entry.touchedAt >= this.#ttlMs;
  }

  #collect(written: string, now: number): void {
    if (++this.#writesSinceSweep >= LOCKOUT_SWEEP_INTERVAL) {
      this.#dropExpired(now);
    }
    if (this.#entries.size <= this.#maxEntries) return;
    this.#dropExpired(now);
    while (this.#entries.size > this.#maxEntries) {
      const victim = this.#evictionCandidate(written, now);
      if (victim === undefined) return;
      this.#entries.delete(victim);
    }
  }

  #dropExpired(now: number): void {
    this.#writesSinceSweep = 0;
    for (const [userId, entry] of this.#entries) {
      if (this.#expired(entry, now)) this.#entries.delete(userId);
    }
  }

  #evictionCandidate(written: string, now: number): string | undefined {
    let victim: [string, MemoryLockoutEntry] | undefined;
    for (const candidate of this.#entries) {
      if (candidate[0] === written) continue;
      if (!victim || evictsBefore(candidate[1], victim[1], now)) {
        victim = candidate;
      }
    }
    return victim?.[0];
  }
}

function lockEnd(entry: MemoryLockoutEntry, now: number): number | undefined {
  const { lockedUntil } = entry.record;
  return lockedUntil !== undefined && lockedUntil > now
    ? lockedUntil
    : undefined;
}

function evictsBefore(
  a: MemoryLockoutEntry,
  b: MemoryLockoutEntry,
  now: number,
): boolean {
  const aLock = lockEnd(a, now);
  const bLock = lockEnd(b, now);
  if (aLock === undefined && bLock !== undefined) return true;
  if (aLock !== undefined && bLock === undefined) return false;
  if (aLock !== undefined && bLock !== undefined) return aLock < bLock;
  if (a.record.failures !== b.record.failures) {
    return a.record.failures < b.record.failures;
  }
  return a.touchedAt < b.touchedAt;
}
