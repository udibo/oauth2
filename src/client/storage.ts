/**
 * Storage interfaces used by `DirectClient`. A `BffClient` holds no
 * tokens, so none of this applies to it.
 *
 * The client keeps three pieces of mutable state across calls:
 * - the current token bundle (access token, expiry, scope, id token),
 * - the refresh token, in its own store so it can persist somewhere the
 *   access token does not,
 * - a short-lived auth-request map (`state` → `{ codeVerifier, returnTo, … }`)
 *   used to correlate an authorize redirect with its callback.
 *
 * The implementations here are in-memory and live only for the process / tab
 * lifetime. `DirectClient` uses them by default, except that in a browser
 * document its auth-request storage defaults to `sessionStorage`. A browser
 * app that must stay signed in across reloads passes
 * `IndexedDBRefreshTokenStorage` for the refresh token and keeps the access
 * token in memory.
 *
 * @module
 */

/** The set of fields the client persists as one logical unit. */
export interface TokenBundle {
  /** The current access token. */
  accessToken: string;
  /** When the access token expires (epoch ms). */
  accessTokenExpiresAt?: number;
  /** The scope granted to this token, space-delimited. */
  scope?: string;
  /** Token type — always "Bearer" in this client. */
  tokenType: "Bearer";
  /** Optional OIDC ID token string (not verified by the client). */
  idToken?: string;
}

/** Persists the current token bundle (access token, expiry, scope, id_token). */
export interface TokenStorage {
  /** Returns the stored bundle, or `null` when none has been persisted. */
  get(): Promise<TokenBundle | null> | TokenBundle | null;
  /** Replaces the stored bundle with {@linkcode value}. */
  set(value: TokenBundle): Promise<void> | void;
  /** Discards the stored bundle. */
  clear(): Promise<void> | void;
}

/**
 * Persists the refresh token independently from the access token, so it can
 * outlive a reload (IndexedDB, a Web Worker, a server-side session) while the
 * short-lived access token stays wherever {@link TokenStorage} keeps it.
 */
export interface RefreshTokenStorage {
  /** Returns the stored refresh token, or `null` when none has been persisted. */
  get(): Promise<string | null> | string | null;
  /** Replaces the stored refresh token with {@linkcode value}. */
  set(value: string): Promise<void> | void;
  /** Discards the stored refresh token. */
  clear(): Promise<void> | void;
}

/** Correlates an authorize redirect with its callback. */
export interface AuthRequestRecord {
  /** PKCE code verifier paired with the `code_challenge` sent to authorize. */
  codeVerifier: string;
  /** Application URL to navigate to after the callback completes. */
  returnTo?: string;
  /** Scope requested for this authorization, space-delimited. */
  scope?: string;
  /** When the request was created (epoch ms), used for TTL expiry. */
  createdAt: number;
}

/**
 * Short-lived map from the authorization request `state` parameter to the
 * PKCE verifier / `returnTo` / scope it was built with. Must survive the
 * authorize-redirect round-trip but must not outlive the tab, and must
 * never contain access or refresh tokens.
 */
export interface AuthRequestStorage {
  /**
   * Returns the record for {@linkcode state}, or `null` if absent. An
   * implementation may also return `null` for, and prune, a record it deems
   * expired; `DirectClient` separately rejects one older than its
   * `authRequestTtlMs`.
   */
  get(
    state: string,
  ): Promise<AuthRequestRecord | null> | AuthRequestRecord | null;
  /** Stores {@linkcode value} under {@linkcode state} before the authorize redirect. */
  set(
    state: string,
    value: AuthRequestRecord,
  ): Promise<void> | void;
  /**
   * Returns the record for {@linkcode state} and removes it in one atomic
   * step, or `null` if absent. `DirectClient` claims the record this way
   * before it calls the token endpoint, so of two callbacks racing on one
   * `state` only one reaches it. Optional for compatibility: without it the
   * client falls back to `get` then `delete`, which still consumes the record
   * before the token call but lets concurrent callers that both read it
   * before either deletes it redeem it twice. Implement it with the backing
   * store's own atomic primitive (`GETDEL`, `DELETE … RETURNING`) whenever
   * the store is shared between processes or requests.
   */
  take?(
    state: string,
  ): Promise<AuthRequestRecord | null> | AuthRequestRecord | null;
  /** Removes one entry — a claimed or stale one. */
  delete(state: string): Promise<void> | void;
  /** Removes every entry. Called when the client clears its session. */
  clear(): Promise<void> | void;
}

/** Default in-memory {@link TokenStorage}. Data is lost when the process exits. */
export class MemoryTokenStorage implements TokenStorage {
  #bundle: TokenBundle | null = null;
  /** Returns the in-memory bundle, or `null` if none has been set. */
  get(): TokenBundle | null {
    return this.#bundle;
  }
  /** Replaces the in-memory bundle with {@linkcode value}. */
  set(value: TokenBundle): void {
    this.#bundle = value;
  }
  /** Discards the in-memory bundle. */
  clear(): void {
    this.#bundle = null;
  }
}

/**
 * Default in-memory {@link RefreshTokenStorage}. Data is lost when the
 * process exits.
 */
export class MemoryRefreshTokenStorage implements RefreshTokenStorage {
  #token: string | null = null;
  /** Returns the in-memory refresh token, or `null` if none has been set. */
  get(): string | null {
    return this.#token;
  }
  /** Replaces the in-memory refresh token with {@linkcode value}. */
  set(value: string): void {
    this.#token = value;
  }
  /** Discards the in-memory refresh token. */
  clear(): void {
    this.#token = null;
  }
}

/** Options for {@link MemoryAuthRequestStorage}. */
export interface MemoryAuthRequestStorageOptions {
  /**
   * Age past which a record is pruned the next time any record is written,
   * in ms. Defaults to 10 minutes; `Infinity` never prunes.
   */
  ttlMs?: number;
}

/**
 * In-memory {@link AuthRequestStorage}, `DirectClient`'s default outside a
 * browser document. Data is lost when the process exits. Every write prunes
 * records older than {@link MemoryAuthRequestStorageOptions.ttlMs}, so logins
 * that never return to the callback do not accumulate in a long-running
 * server.
 */
export class MemoryAuthRequestStorage implements AuthRequestStorage {
  #records = new Map<string, AuthRequestRecord>();
  readonly #ttlMs: number;

  /** Configures the pruning TTL, 10 minutes by default. */
  constructor(options: MemoryAuthRequestStorageOptions = {}) {
    this.#ttlMs = options.ttlMs ?? 10 * 60 * 1000;
  }

  /** Returns the record for {@linkcode state}, or `null` if none is stored. */
  get(state: string): AuthRequestRecord | null {
    return this.#records.get(state) ?? null;
  }
  /** Returns and removes the record for {@linkcode state} in one step. */
  take(state: string): AuthRequestRecord | null {
    const record = this.#records.get(state) ?? null;
    this.#records.delete(state);
    return record;
  }
  /**
   * Stores {@linkcode value} under {@linkcode state}, first pruning records
   * past the TTL. Pruning walks records oldest-write-first and stops at the
   * first one inside the TTL, so it assumes each `createdAt` is the time of
   * its write, as `DirectClient.login` sets it.
   */
  set(state: string, value: AuthRequestRecord): void {
    this.#pruneExpired();
    this.#records.delete(state);
    this.#records.set(state, value);
  }
  /** Removes the record for {@linkcode state}. */
  delete(state: string): void {
    this.#records.delete(state);
  }
  /** Removes every stored record. */
  clear(): void {
    this.#records.clear();
  }

  #pruneExpired(): void {
    if (this.#ttlMs === Infinity) return;
    const cutoff = Date.now() - this.#ttlMs;
    for (const [state, record] of this.#records) {
      if (record.createdAt >= cutoff) return;
      this.#records.delete(state);
    }
  }
}
