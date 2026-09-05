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
 * AES-GCM encryption in the stateless store is what makes that pattern
 * safe.
 *
 * @module
 */

import { InvalidGrantError } from "../../../errors.ts";
import type { TokenBundle, UserInfoClaims } from "../../../client/mod.ts";
import { deriveAesKey, sealJson, unsealJson } from "../../../utils/crypto.ts";

/** The data a BFF persists per session. */
export interface SessionData {
  /** The current token bundle (access token + expiry + scope + id_token). */
  tokens: TokenBundle;
  /** The refresh token, if one was issued. */
  refreshToken?: string;
  /**
   * Cached user claims surfaced by `GET /auth/session` without exposing
   * tokens to the browser. Populated from the id_token or the userinfo
   * endpoint at callback time.
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
  return typeof (store as Partial<BackchannelLogoutStore>).destroyByLogout ===
    "function";
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

/**
 * In-memory stateful session store. Data is lost when the process
 * restarts. Suitable for single-process development or tests; use a
 * persistent store in production.
 */
export class MemorySessionStore
  implements SessionStore, BackchannelLogoutStore {
  #sessions = new Map<string, SessionData>();

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
   * Destroys the sessions a validated logout_token targets: the specific `sid`
   * when given, otherwise every session for `sub`. Returns the number
   * destroyed.
   */
  destroyByLogout(
    criteria: { sub?: string; sid?: string },
  ): Promise<number> {
    const { sub, sid } = criteria;
    let destroyed = 0;
    for (const [id, data] of this.#sessions) {
      const match = sid !== undefined
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
   * Pass an **ordered list** to rotate the secret without signing everyone out:
   * the **first** entry is current — every cookie is sealed under it — and
   * `read` tries each entry in turn, so a cookie sealed under a still-listed
   * older secret keeps unsealing. Rotate by deploying `[newSecret, oldSecret]`,
   * then drop `oldSecret` once the grace window (at least {@linkcode maxAgeMs},
   * or your longest session lifetime) has elapsed. This is the session-store
   * analog of a multi-key JWKS grace window. A single secret behaves exactly as
   * before — a fleet-wide forced sign-out on rotation.
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
   *
   * The store stamps each cookie with a seal time at `create`/`update`; a
   * pre-rotation cookie sealed before this field existed has no stamp and falls
   * back to its own `updatedAt`, so old cookies are bounded too rather than
   * grandfathered as unbounded.
   */
  maxAgeMs?: number;
}

interface SealedSession {
  issuedAt: number;
  data: SessionData;
}

function isSealedSession(value: unknown): value is SealedSession {
  return typeof value === "object" && value !== null &&
    typeof (value as SealedSession).issuedAt === "number" &&
    typeof (value as SealedSession).data === "object" &&
    (value as SealedSession).data !== null;
}

/**
 * Stateless session store. The cookie value is the AES-GCM-encrypted
 * JSON-serialized {@link SessionData}. No server-side storage needed.
 *
 * Security notes:
 * - Each secret must have at least 256 bits of entropy. A weak secret defeats
 *   the confidentiality of the cookie.
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
 *   secret: [Deno.env.get("SESSION_SECRET")!, Deno.env.get("SESSION_SECRET_OLD")!],
 *   maxAgeMs: 7 * 24 * 60 * 60 * 1000,
 * });
 * ```
 */
export class EncryptedCookieSessionStore
  implements SessionStore, BoundedSessionStore {
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
    return this.#keyPromises[index] ??= deriveAesKey(this.#secrets[index]);
  }

  /** Encrypts the session into the cookie value under the current secret; there is no server-side record. */
  async create(data: SessionData): Promise<string> {
    const sealed: SealedSession = { issuedAt: Date.now(), data };
    return await sealJson(await this.#key(0), sealed);
  }

  /**
   * Decrypts the cookie value, trying each configured secret in turn. Returns
   * `null` if it is tampered, malformed, sealed with an unknown secret, or
   * sealed longer ago than
   * {@linkcode EncryptedCookieSessionStoreOptions.maxAgeMs}.
   */
  async read(cookieValue: string): Promise<SessionData | null> {
    for (let index = 0; index < this.#secrets.length; index++) {
      const unsealed = await unsealJson<SealedSession | SessionData>(
        await this.#key(index),
        cookieValue,
      );
      if (unsealed === null) continue;
      if (isSealedSession(unsealed)) {
        return this.#isExpired(unsealed.issuedAt) ? null : unsealed.data;
      }
      const legacy = unsealed as SessionData;
      return this.#isExpired(legacy.updatedAt ?? legacy.createdAt)
        ? null
        : legacy;
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
