/**
 * Session stores used by {@link HonoBff}.
 *
 * Two shapes are supported:
 *
 * - **Stateful**: the cookie holds a random session id; tokens live in a
 *   server-side store keyed by that id ({@link MemorySessionStore}, or
 *   your own DB-backed {@link SessionStore}). Pros: instant revocation,
 *   tiny cookie, leaked session id is useless outside your server. Cons:
 *   needs a store to scale horizontally.
 *
 * - **Stateless** ({@link EncryptedCookieSessionStore}): the cookie value
 *   *is* the encrypted token bundle (AES-GCM with a server-held secret),
 *   no server-side storage needed. Pros: no infrastructure beyond the
 *   secret. Cons: revocation requires `/revoke` + cookie clear, cookie
 *   grows with token size, key rotation needs care.
 *
 * A raw "token in cookie" store is deliberately **not** shipped: a leaked
 * log line containing the cookie would yield a working bearer token. The
 * AES-GCM encryption in the stateless store keeps the tokens unreadable, but
 * a leaked encrypted cookie still works as a session cookie against the BFF
 * until it expires.
 *
 * @module
 */

import { InvalidGrantError } from "../../../errors.ts";
import type { TokenBundle, UserInfoClaims } from "../../../client/mod.ts";
import { sealJson, unsealJson } from "../../../utils/crypto.ts";
import { deriveCookieKey, SESSION_COOKIE_KEY_INFO } from "./_cookie-keys.ts";

/** The data a BFF persists per session. */
export interface SessionData {
  /** The current token bundle (access token + expiry + scope + id_token). */
  tokens: TokenBundle;
  /** The refresh token, if one was issued. */
  refreshToken?: string;
  /**
   * Cached user claims surfaced by `GET /auth/session` without exposing
   * tokens to the browser. Populated at callback time from the id_token's
   * claims, as replaced by `HonoBffOptions.resolveUser` when configured.
   */
  user?: UserInfoClaims | null;
  /**
   * The OP session id (`sid` claim from the id_token), when present. Used to
   * target a single session during OIDC Back-Channel Logout; matching falls
   * back to the subject (`user.sub`) when the logout_token carries no `sid`.
   */
  sid?: string;
  /** When the session was created (epoch ms). */
  createdAt: number;
  /** When the session was last updated (epoch ms). */
  updatedAt: number;
}

/**
 * Optional {@link SessionStore} capability: destroy sessions by subject and/or
 * OP session id, for an OIDC Back-Channel Logout receiver. A store opts in by
 * implementing this method (it is duck-typed at runtime). Stateful stores
 * (server-side records) can; stateless stores (e.g.
 * {@link EncryptedCookieSessionStore}) cannot enumerate their sessions, so they
 * omit it and the BFF's `/auth/backchannel` route stays unavailable.
 */
export interface BackchannelLogoutStore {
  /**
   * Destroy every session matching a validated logout_token. When `sid` is
   * given, only the session(s) with that OP session id are destroyed; otherwise
   * all sessions for `sub` are destroyed. Returns the number destroyed. Back a
   * persistent implementation with an index on `sid`/`sub`.
   */
  destroyByLogout(criteria: { sub?: string; sid?: string }): Promise<number>;
}

/** Whether a store implements the {@link BackchannelLogoutStore} capability. */
export function supportsBackchannelLogout(
  store: SessionStore,
): store is SessionStore & BackchannelLogoutStore {
  return (
    typeof (store as Partial<BackchannelLogoutStore>).destroyByLogout ===
    "function"
  );
}

/**
 * Optional {@link SessionStore} capability: one token refresh at a time per
 * session, across every instance that shares the store. A store opts in by
 * implementing this method (it is duck-typed at runtime).
 *
 * Without it, `HonoBff` shares a refresh only between requests on the same
 * instance. Two instances that refresh one session at once both present its
 * refresh token: against an authorization server that rotates refresh tokens,
 * the loser's exchange fails, or trips reuse detection and revokes the whole
 * rotation family, and the user is signed out. With it, the BFF re-reads the
 * session while it holds the lock and uses a peer's fresh tokens instead of
 * spending the refresh token again. Implement it on any store more than one
 * instance shares. {@link EncryptedCookieSessionStore} cannot: its sessions
 * live in each browser's cookie, with nothing on the server to lock.
 */
export interface RefreshLockStore {
  /**
   * Runs `refresh` while no other `withRefreshLock` call for the same
   * `cookieValue`, on any instance, is running, and settles with its result.
   * Calls for other sessions must not wait on each other.
   *
   * - The lock is keyed by the cookie value, so it holds only for a store
   *   whose `update` returns the cookie value it was given. A store that
   *   issues a new value on update cannot implement it.
   * - The lock must not block this store's own `read`, `update` or `destroy`:
   *   `refresh` reads, writes and can destroy the session it locks.
   * - Release it when `refresh` settles, including when it throws.
   * - The lock covers the whole refresh: the token request and the store's
   *   own reads and writes. With `DirectClient` a refresh can take about 30
   *   seconds when its discovery cache is cold, since discovery tries two
   *   well-known paths and every request has a 10-second deadline. If the
   *   lock expires when its holder dies, expire it only after that plus the
   *   store's own I/O, or renew it while `refresh` runs.
   * - Pass `refresh` a {@link RefreshLease} for this call. The parameter is
   *   optional only so stores written before it keep compiling. `HonoBff` writes
   *   and destroys the session through it, so a holder that lost the lock
   *   (it stalled past the expiry and another instance took it) can no
   *   longer overwrite or end the session that instance refreshed. A store
   *   that calls `refresh()` with no lease still works, but a lock that
   *   expires mid-refresh then lets the former holder's write or sign-out
   *   land on top of the new holder's. `runSessionStoreContractTests` fails
   *   such a store unless its options declare that the lock never expires.
   * - Reject when the lock cannot be acquired within a bound you choose.
   *   `HonoBff` then answers `502` `temporarily_unavailable` and keeps the
   *   session.
   *
   * Keep the lock beside the session record, so the lease's conditional
   * write is one atomic compare-and-set on that record: for example a lease
   * token and a lease expiry on the session row, taken by an update that
   * matches only when no unexpired lease is set, and checked by the lease's
   * `update` and `destroy`. Never hold a database transaction open across
   * `refresh`: it spans a network call to the authorization server. Key the
   * lock by the same key the store keys its records by — the digest, never
   * the raw cookie value, plus any prefix or scope the store adds to it.
   */
  withRefreshLock<T>(
    cookieValue: string,
    refresh: (lease?: RefreshLease) => Promise<T>,
  ): Promise<T>;
}

/**
 * The fence a {@link RefreshLockStore} passes to the refresh it runs: an
 * `update` and a `destroy` of the locked session that take effect only while
 * this call still holds the lock. The lease is current from when the call
 * acquires the lock until the call releases the lock or another call takes
 * it; a store may also end it when the lock expires. Once another call has
 * taken the lock, the lease is never current again.
 */
export interface RefreshLease {
  /**
   * Writes the locked session like {@link SessionStore.update}, as one atomic
   * step that also checks this lease is current. Resolves with the cookie
   * value to set.
   *
   * @throws {InvalidGrantError} When the lease is no longer current, or the
   * session is missing, expired or revoked. It never creates or restores a
   * session.
   */
  update(data: SessionData): Promise<string>;
  /**
   * Destroys the locked session, as one atomic step, only while this lease
   * is current and the session still stores `refreshToken`. `HonoBff` calls
   * it after the authorization server refuses that refresh token.
   *
   * @returns `true` when it destroyed the session; `false` when it destroyed
   * nothing, because the lease is no longer current, the session stores a
   * different refresh token, or the session no longer exists.
   */
  destroy(refreshToken: string): Promise<boolean>;
}

/** Whether a store implements the {@link RefreshLockStore} capability. */
export function supportsRefreshLock(
  store: SessionStore,
): store is SessionStore & RefreshLockStore {
  return (
    typeof (store as Partial<RefreshLockStore>).withRefreshLock === "function"
  );
}

/**
 * Default session lifetime — 14 days — shared by
 * {@link EncryptedCookieSessionStore} and `HonoBff`'s
 * `sessionMaxAgeMs`, so a BFF built with neither configured has a cookie
 * and a server-side session that expire together.
 *
 * Long enough that an app used weekly never nags; short enough that a
 * credential left on an unattended phone dies on its own. Set both knobs if
 * your product wants a different window.
 */
export const DEFAULT_SESSION_MAX_AGE_MS: number = 14 * 24 * 60 * 60 * 1000;

/**
 * Optional {@link SessionStore} capability: the store enforces a maximum
 * session age, in milliseconds, and says what it is.
 *
 * `HonoBff` reads it to refuse a configuration whose session cookie would die
 * before the sessions this store keeps serving — the pairing that leaves a user
 * signed out while their session is still listed as active. Expose it from a
 * DB-backed store to get that check; omit it and the BFF falls back to its own
 * `sessionMaxAgeMs` bound.
 */
export interface BoundedSessionStore {
  /** Maximum age, in ms, past which this store stops honoring a session. */
  readonly maxAgeMs: number;
}

/**
 * The maximum session age a store enforces, or `undefined` when it does not
 * advertise one (see {@link BoundedSessionStore}).
 */
export function sessionStoreMaxAgeMs(store: SessionStore): number | undefined {
  const maxAgeMs = (store as Partial<BoundedSessionStore>).maxAgeMs;
  return typeof maxAgeMs === "number" && Number.isFinite(maxAgeMs)
    ? maxAgeMs
    : undefined;
}

/**
 * Session persistence contract for {@link HonoBff}.
 *
 * Implementations may be stateful (cookie holds a session id, data lives
 * server-side) or stateless (cookie holds the encrypted payload itself).
 * `create` / `update` return the cookie value to set; `read` takes a
 * cookie value and returns the data (or `null` if the cookie doesn't
 * correspond to a live session). `destroy` removes a session.
 */
export interface SessionStore {
  /** Create a new session and return the cookie value to set. */
  create(data: SessionData): Promise<string>;
  /** Read an existing session's data, or `null` if not found / invalid. */
  read(cookieValue: string): Promise<SessionData | null>;
  /**
   * Update an existing session's data. Returns the new cookie value to
   * set (may be the same as `cookieValue` for stateful stores; changes
   * with every update for stateless stores). Stateful implementations must
   * atomically reject missing, expired or revoked sessions with
   * `InvalidGrantError`; updating must never create or restore a session.
   */
  update(cookieValue: string, data: SessionData): Promise<string>;
  /** Destroy the session identified by `cookieValue`. */
  destroy(cookieValue: string): Promise<void>;
}

/** Options for {@link MemorySessionStore}. */
export interface MemorySessionStoreOptions {
  /**
   * How long a `withRefreshLock` call holds the lock without renewing it, in
   * milliseconds. The store renews it every third of this while the refresh
   * runs. A lease that still lapses, because its holder's timers were
   * starved, is lost at once: another call may take the lock, and the lost
   * lease's `update` and `destroy` are refused.
   *
   * Defaults to no expiry, which is right for one process: a holder cannot
   * die without the store dying with it. Set it in tests that model an
   * instance losing its lock mid-refresh. Must be a positive number no
   * larger than 2147483647 (2^31 − 1, the longest timer delay).
   */
  refreshLeaseMs?: number;
  /**
   * How long `withRefreshLock` waits for a lock another call holds, in
   * milliseconds, before it rejects. `HonoBff` then answers `502` and keeps
   * the session. Defaults to waiting until the lock is released or expires.
   * Must be a positive number no larger than 2147483647 (2^31 − 1, the
   * longest timer delay).
   */
  refreshLockWaitMs?: number;
}

interface MemoryLease {
  expiresAt: number;
}

const MAX_TIMER_MS = 2 ** 31 - 1;

function timerMs(name: string, value: number | undefined): number {
  if (value === undefined) return Infinity;
  if (!(value > 0 && value <= MAX_TIMER_MS)) {
    throw new RangeError(
      `${name} must be a positive number of milliseconds no larger than ` +
        `${MAX_TIMER_MS}, got ${value}. Leave it unset for no limit.`,
    );
  }
  return value;
}

/**
 * In-memory stateful session store. Data is lost when the process
 * restarts. Suitable for single-process development or tests; use a
 * persistent store in production.
 */
export class MemorySessionStore
  implements SessionStore, BackchannelLogoutStore, RefreshLockStore
{
  #sessions = new Map<string, SessionData>();
  #leases = new Map<string, MemoryLease>();
  #lockWaiters = new Map<string, Set<() => void>>();
  #leaseMs: number;
  #lockWaitMs: number;

  /**
   * @throws {RangeError} When `refreshLeaseMs` or `refreshLockWaitMs` is not
   * a positive number of at most 2^31 − 1 milliseconds.
   */
  constructor(options: MemorySessionStoreOptions = {}) {
    this.#leaseMs = timerMs("refreshLeaseMs", options.refreshLeaseMs);
    this.#lockWaitMs = timerMs("refreshLockWaitMs", options.refreshLockWaitMs);
  }

  /** Stores the session under a fresh random id and returns it as the cookie value. */
  create(data: SessionData): Promise<string> {
    const id = crypto.randomUUID();
    this.#sessions.set(id, data);
    return Promise.resolve(id);
  }

  /** Looks up the session by its id, or `null` if no live session matches. */
  read(cookieValue: string): Promise<SessionData | null> {
    return Promise.resolve(this.#sessions.get(cookieValue) ?? null);
  }

  /** Replaces the stored data in place; the cookie value (session id) is unchanged. */
  update(cookieValue: string, data: SessionData): Promise<string> {
    if (!this.#sessions.has(cookieValue)) {
      return Promise.reject(
        new InvalidGrantError("session is no longer active"),
      );
    }
    this.#sessions.set(cookieValue, data);
    return Promise.resolve(cookieValue);
  }

  /** Removes the session record for the given id. */
  destroy(cookieValue: string): Promise<void> {
    this.#sessions.delete(cookieValue);
    return Promise.resolve();
  }

  /**
   * Runs `refresh` once no other call holds the session's lock, so every
   * `HonoBff` sharing this store object refreshes a session once. Calls for
   * other sessions run alongside. `refresh` gets a {@link RefreshLease} that
   * writes and destroys the session only while this call holds the lock.
   *
   * @throws {Error} When the lock stays held past
   * {@linkcode MemorySessionStoreOptions.refreshLockWaitMs}.
   */
  async withRefreshLock<T>(
    cookieValue: string,
    refresh: (lease: RefreshLease) => Promise<T>,
  ): Promise<T> {
    const lease = await this.#acquire(cookieValue);
    const renewal = Number.isFinite(this.#leaseMs)
      ? setInterval(() => {
          if (this.#holds(cookieValue, lease)) {
            lease.expiresAt = Date.now() + this.#leaseMs;
          } else {
            clearInterval(renewal);
          }
        }, this.#leaseMs / 3)
      : undefined;
    try {
      return await refresh(this.#fence(cookieValue, lease));
    } finally {
      clearInterval(renewal);
      if (this.#leases.get(cookieValue) === lease) {
        this.#leases.delete(cookieValue);
      }
      this.#wakeLockWaiters(cookieValue);
    }
  }

  async #acquire(cookieValue: string): Promise<MemoryLease> {
    const deadline = Date.now() + this.#lockWaitMs;
    for (;;) {
      const now = Date.now();
      const held = this.#leases.get(cookieValue);
      if (!held || held.expiresAt <= now) {
        const lease = { expiresAt: now + this.#leaseMs };
        this.#leases.set(cookieValue, lease);
        return lease;
      }
      if (now >= deadline) {
        throw new Error("timed out waiting for the session's refresh lock");
      }
      await this.#lockChange(
        cookieValue,
        Math.min(held.expiresAt, deadline) - now,
      );
    }
  }

  #lockChange(cookieValue: string, timeoutMs: number): Promise<void> {
    const { promise, resolve } = Promise.withResolvers<void>();
    const waiters = this.#lockWaiters.get(cookieValue) ?? new Set();
    this.#lockWaiters.set(cookieValue, waiters);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const wake = (): void => {
      clearTimeout(timer);
      waiters.delete(wake);
      if (
        waiters.size === 0 &&
        this.#lockWaiters.get(cookieValue) === waiters
      ) {
        this.#lockWaiters.delete(cookieValue);
      }
      resolve();
    };
    waiters.add(wake);
    if (Number.isFinite(timeoutMs)) timer = setTimeout(wake, timeoutMs);
    return promise;
  }

  #wakeLockWaiters(cookieValue: string): void {
    for (const wake of [...(this.#lockWaiters.get(cookieValue) ?? [])]) {
      wake();
    }
  }

  #holds(cookieValue: string, lease: MemoryLease): boolean {
    return (
      this.#leases.get(cookieValue) === lease && lease.expiresAt > Date.now()
    );
  }

  #fence(cookieValue: string, lease: MemoryLease): RefreshLease {
    return {
      update: (data) =>
        this.#holds(cookieValue, lease)
          ? this.update(cookieValue, data)
          : Promise.reject(
              new InvalidGrantError("the session's refresh lock was lost"),
            ),
      destroy: (refreshToken) => {
        const session = this.#sessions.get(cookieValue);
        if (
          !session ||
          session.refreshToken !== refreshToken ||
          !this.#holds(cookieValue, lease)
        ) {
          return Promise.resolve(false);
        }
        this.#sessions.delete(cookieValue);
        return Promise.resolve(true);
      },
    };
  }

  /**
   * Destroys the sessions a validated logout_token targets: the specific `sid`
   * when given, otherwise every session for `sub`. Returns the number
   * destroyed.
   */
  destroyByLogout(criteria: { sub?: string; sid?: string }): Promise<number> {
    const { sub, sid } = criteria;
    let destroyed = 0;
    for (const [id, data] of this.#sessions) {
      const match =
        sid !== undefined
          ? data.sid === sid
          : sub !== undefined && data.user?.sub === sub;
      if (match) {
        this.#sessions.delete(id);
        destroyed++;
      }
    }
    return Promise.resolve(destroyed);
  }
}

/** Options for {@link EncryptedCookieSessionStore}. */
export interface EncryptedCookieSessionStoreOptions {
  /**
   * Server-held secret(s) used to derive the AES-256 key(s). Each must have at
   * least 32 bytes of entropy; pass a base64 / hex string or raw bytes.
   *
   * Prefer a secret of its own, separate from the one given to
   * `EncryptedCookieAuthRequestStorage`. Sharing one is still safe: each store
   * derives its key with HKDF-SHA-256 under its own label, so neither store
   * opens the other's cookie.
   *
   * Pass an **ordered list** to rotate the secret without signing everyone out:
   * the **first** entry is current — every cookie is sealed under it — and
   * `read` tries each entry in turn, so a cookie sealed under a still-listed
   * older secret keeps unsealing. Rotate by deploying `[newSecret, oldSecret]`,
   * then drop `oldSecret` once the grace window (at least {@linkcode maxAgeMs},
   * or your longest session lifetime) has elapsed. This is the session-store
   * analog of a multi-key JWKS grace window. With a single secret, rotating it
   * signs everyone out.
   */
  secret: string | Uint8Array | Array<string | Uint8Array>;
  /**
   * Maximum age of a sealed cookie, in milliseconds: `read` returns `null` for
   * any cookie sealed longer ago than this — even if it decrypts — bounding how
   * long a captured cookie stays useful without any server-side state. This
   * does **not** make `destroy` real; it only caps the window.
   *
   * Defaults to {@link DEFAULT_SESSION_MAX_AGE_MS} (14 days). There is no
   * unbounded setting: an encrypted bearer cookie nobody can revoke must expire
   * on its own. Pass a larger value for a longer window, and set the BFF's
   * `sessionMaxAgeMs` to match — `HonoBff` throws when its session cookie
   * would die before the sessions this store keeps accepting.
   *
   * `update` re-seals with a fresh stamp, so this is an **inactivity** window
   * for a session the BFF keeps refreshing. Must be a positive number of
   * milliseconds.
   */
  maxAgeMs?: number;
}

interface SealedSession {
  issuedAt: number;
  data: SessionData;
}

function isSealedSession(value: unknown): value is SealedSession {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as SealedSession).issuedAt === "number" &&
    typeof (value as SealedSession).data === "object" &&
    (value as SealedSession).data !== null
  );
}

/**
 * Stateless session store. The cookie value is the AES-GCM-encrypted
 * JSON-serialized {@link SessionData}. No server-side storage needed.
 *
 * Security notes:
 * - Each secret must have at least 256 bits of entropy. A weak secret defeats
 *   the confidentiality of the cookie.
 * - The key is derived from the secret with HKDF-SHA-256 under a label of this
 *   store's own, so a cookie sealed by another store under the same secret
 *   does not open here.
 * - `read` accepts only what `create` sealed: a cookie that is malformed,
 *   foreign, or the wrong shape reads as `null`.
 * - AES-GCM provides authenticated encryption; tampered cookies fail `read`
 *   (returns `null`).
 * - `destroy` is a no-op on the server — the cookie must be cleared in the
 *   client response for the session to end, and the refresh token should be
 *   revoked at the authorization server. Genuine server-side revocation is not
 *   achievable statelessly; choose a DB-backed {@link SessionStore} for that.
 *   {@linkcode EncryptedCookieSessionStoreOptions.maxAgeMs} — 14 days unless
 *   you set it — bounds the window a captured cookie stays useful but does not
 *   make `destroy` real.
 * - Rotate the secret without a fleet-wide sign-out by passing an ordered list;
 *   see {@linkcode EncryptedCookieSessionStoreOptions.secret}.
 *
 * @example Rotating the secret with a grace window
 * ```ts
 * // Deploy with the new secret first, the old one second: new cookies seal
 * // under NEW, cookies still sealed under OLD keep unsealing until you drop it.
 * const store = new EncryptedCookieSessionStore({
 *   secret: [process.env.SESSION_SECRET!, process.env.SESSION_SECRET_OLD!],
 *   maxAgeMs: 7 * 24 * 60 * 60 * 1000,
 * });
 * ```
 */
export class EncryptedCookieSessionStore
  implements SessionStore, BoundedSessionStore
{
  #secrets: Array<string | Uint8Array>;
  #keyPromises: Array<Promise<CryptoKey> | undefined>;
  #maxAgeMs: number;

  /**
   * Derives each AES-256 key on first use and reuses it for every later
   * operation. The first secret is current (used to seal); all are tried on
   * read.
   *
   * @throws {Error} When the secret list is empty, or when
   * {@linkcode EncryptedCookieSessionStoreOptions.maxAgeMs} is not a positive
   * finite number of milliseconds.
   */
  constructor(options: EncryptedCookieSessionStoreOptions) {
    const secrets = Array.isArray(options.secret)
      ? options.secret
      : [options.secret];
    if (secrets.length === 0) {
      throw new Error("secret must not be an empty list.");
    }
    const maxAgeMs = options.maxAgeMs ?? DEFAULT_SESSION_MAX_AGE_MS;
    if (!Number.isFinite(maxAgeMs) || maxAgeMs <= 0) {
      throw new Error(
        "maxAgeMs must be a positive number of milliseconds, got " +
          `${options.maxAgeMs}. A cookie nobody can revoke has to expire on ` +
          "its own; pass a larger value for a longer window.",
      );
    }
    this.#secrets = secrets;
    this.#keyPromises = secrets.map(() => undefined);
    this.#maxAgeMs = maxAgeMs;
  }

  /**
   * The maximum age, in ms, past which a sealed cookie stops unsealing.
   * Defaults to {@link DEFAULT_SESSION_MAX_AGE_MS}; `HonoBff` reads it to
   * check that its session cookie outlives the sessions this store accepts.
   */
  get maxAgeMs(): number {
    return this.#maxAgeMs;
  }

  #key(index: number): Promise<CryptoKey> {
    return (this.#keyPromises[index] ??= deriveCookieKey(
      this.#secrets[index],
      SESSION_COOKIE_KEY_INFO,
    ));
  }

  /** Encrypts the session into the cookie value under the current secret; there is no server-side record. */
  async create(data: SessionData): Promise<string> {
    const sealed: SealedSession = { issuedAt: Date.now(), data };
    return await sealJson(await this.#key(0), sealed);
  }

  /**
   * Decrypts the cookie value, trying each configured secret in turn. Returns
   * `null` if it is tampered, malformed, sealed with an unknown secret or by
   * another store, not in the shape `create` seals, or sealed longer ago than
   * {@linkcode EncryptedCookieSessionStoreOptions.maxAgeMs}.
   */
  async read(cookieValue: string): Promise<SessionData | null> {
    for (let index = 0; index < this.#secrets.length; index++) {
      const unsealed = await unsealJson<unknown>(
        await this.#key(index),
        cookieValue,
      );
      if (unsealed === null) continue;
      if (!isSealedSession(unsealed)) return null;
      return this.#isExpired(unsealed.issuedAt) ? null : unsealed.data;
    }
    return null;
  }

  #isExpired(issuedAt: number): boolean {
    return Date.now() - issuedAt > this.#maxAgeMs;
  }

  /** Re-encrypts the data into a fresh cookie value under the current secret. */
  update(_cookieValue: string, data: SessionData): Promise<string> {
    return this.create(data);
  }

  /** Stateless — the server has nothing to destroy. The caller must clear the cookie. */
  destroy(_cookieValue: string): Promise<void> {
    return Promise.resolve();
  }
}
