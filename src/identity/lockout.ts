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
  /**
   * Consecutive sign-in attempts counted since the last success/unlock. An
   * attempt is counted before its password is checked, so an attempt still in
   * flight is included until a success clears the record.
   */
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
   * Add one attempt and return the new record: an expired lock resets the
   * count to 1 and drops the lock; otherwise `failures + 1` with any active
   * lock kept. `AccountLockout` calls it before the password is checked and
   * admits the attempt only on the count it returns, so it must be atomic (a
   * single statement / compare-and-set in shared stores) and return the
   * post-increment count: a read-modify-write lets concurrent attempts share a
   * count, and each one sharing it is another guess past `maxAttempts`.
   */
  increment(userId: string, now: number): Promise<LockoutRecord>;
  /**
   * Persist the account's record, replacing any existing one rather than
   * merging: a record with no `lockedUntil` leaves the account unlocked.
   */
  set(userId: string, record: LockoutRecord): Promise<void>;
  /**
   * Optional: lock the account until `record.lockedUntil` only while its stored
   * count is still at least `record.failures`, keeping the stored count, and
   * resolve whether the lock was written. It must be one conditional write
   * (`UPDATE … SET locked_until = $until WHERE failures >= $failures`, checking
   * the row count), never a read then a write. `now` is the clock `increment`
   * was given, for a store that expires records.
   *
   * `AccountLockout` calls it instead of {@link LockoutStore.set} when an
   * attempt's count reaches `maxAttempts`. Without it, the lock is an
   * unconditional `set` after `increment`, so an over-budget attempt whose
   * lock lands after a concurrent {@link LockoutStore.clear} re-locks an
   * account that just signed in, and no lockout event reports it.
   */
  lock?(
    userId: string,
    record: LockoutRecord & { lockedUntil: number },
    now: number,
  ): Promise<boolean>;
  /**
   * Optional: take back one attempt `increment` counted, as one atomic write:
   * `failures - 1` (never below zero), dropping `lockedUntil` when the new
   * count is below `maxAttempts`
   * (`UPDATE … SET failures = failures - 1, locked_until = CASE WHEN
   * failures - 1 < $max THEN NULL ELSE locked_until END WHERE failures > 0`).
   * An account with no live record is left as it is; a record left at zero
   * may be kept or dropped. `now` is the clock `increment` was given, for a
   * store that expires records.
   *
   * `AccountLockout.releaseAttempt` calls it for an attempt whose password was
   * never checked. Without it the attempt stays counted.
   */
  release?(userId: string, maxAttempts: number, now: number): Promise<void>;
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
   * lockout event and any unlock email off it. `IdentityService` calls it after
   * a wrong password only when {@link AccountLockoutLike.reserveAttempt} is
   * absent.
   */
  recordFailure(userId: string, now?: number): Promise<LockoutFailureResult>;
  /**
   * Count one sign-in attempt atomically before its password is checked, and
   * report the resulting state the way {@link AccountLockoutLike.recordFailure}
   * does. `IdentityService` checks the password only when the result is
   * unlocked or `justLocked` — the attempt that reaches the threshold is still
   * checked — and refuses the rest under `"enforce"`. A wrong password then
   * fires the lockout event off the reservation's `justLocked`; a success
   * calls {@link AccountLockoutLike.reset}; an attempt that throws stays
   * counted and, when its reservation was `justLocked`, still fires the
   * lockout event.
   *
   * Optional. Without it `IdentityService` reads
   * {@link AccountLockoutLike.status} and calls `recordFailure` only after a
   * wrong password, so concurrent guesses that all read the account unlocked
   * are each checked and can exceed the threshold. {@link AccountLockout}
   * implements it.
   */
  reserveAttempt?(userId: string, now?: number): Promise<LockoutFailureResult>;
  /**
   * Take back one attempt {@link AccountLockoutLike.reserveAttempt} counted,
   * because its password was never checked, and resolve whether it is no
   * longer counted. Undo any lock that attempt's count created, unless the
   * attempts still counted reach the threshold on their own.
   *
   * Optional, and used only alongside `reserveAttempt`. `IdentityService`
   * calls it when a legacy verifier throws `PasswordNotCheckedError`. When it
   * is absent or resolves `false`, the attempt stays counted and, when its
   * reservation was `justLocked`, the lockout event still fires.
   * {@link AccountLockout} implements it when its store implements
   * {@link LockoutStore.release}.
   */
  releaseAttempt?(userId: string, now?: number): Promise<boolean>;
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
  recordFailure(
    userId: string,
    now: number = Date.now(),
  ): Promise<LockoutFailureResult> {
    return this.#count(userId, now);
  }

  /**
   * Count one sign-in attempt before its password is checked, with the same
   * accounting as {@link recordFailure}: of any number of concurrent attempts,
   * only the first `maxAttempts` come back unlocked or `justLocked`.
   */
  reserveAttempt(
    userId: string,
    now: number = Date.now(),
  ): Promise<LockoutFailureResult> {
    return this.#count(userId, now);
  }

  /**
   * Take back one attempt {@link reserveAttempt} counted whose password was
   * never checked, dropping the lock when the remaining count is below
   * `maxAttempts`. Resolves `false`, leaving the attempt counted, when the
   * store does not implement {@link LockoutStore.release}.
   */
  async releaseAttempt(
    userId: string,
    now: number = Date.now(),
  ): Promise<boolean> {
    if (!this.#store.release) return false;
    await this.#store.release(userId, this.#maxAttempts, now);
    return true;
  }

  async #count(
    userId: string,
    now: number = Date.now(),
    recounted = false,
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
      if (!(await this.#lock(userId, { failures, lockedUntil }, now))) {
        if (!recounted) return this.#count(userId, now, true);
        return { failures, locked: false, justLocked: false };
      }
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

  async #lock(
    userId: string,
    record: LockoutRecord & { lockedUntil: number },
    now: number,
  ): Promise<boolean> {
    if (this.#store.lock) return this.#store.lock(userId, record, now);
    await this.#store.set(userId, record);
    return true;
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

  /**
   * Lock `userId` until `record.lockedUntil` when its live record still
   * counts at least `record.failures`; resolves whether it did.
   */
  lock(
    userId: string,
    record: LockoutRecord & { lockedUntil: number },
    now: number,
  ): Promise<boolean> {
    const entry = this.#entries.get(userId);
    if (
      !entry ||
      this.#expired(entry, now) ||
      entry.record.failures < record.failures
    ) {
      return Promise.resolve(false);
    }
    entry.record = { ...entry.record, lockedUntil: record.lockedUntil };
    return Promise.resolve(true);
  }

  /**
   * Take back one counted attempt for `userId`, dropping its lock once the
   * count falls below `maxAttempts`. A record that reaches zero is dropped.
   */
  release(userId: string, maxAttempts: number, now: number): Promise<void> {
    const entry = this.#entries.get(userId);
    if (!entry || this.#expired(entry, now)) return Promise.resolve();
    const failures = entry.record.failures - 1;
    const { lockedUntil } = entry.record;
    if (failures <= 0) {
      this.#entries.delete(userId);
    } else {
      entry.record =
        lockedUntil !== undefined && failures >= maxAttempts
          ? { failures, lockedUntil }
          : { failures };
    }
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
