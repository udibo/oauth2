/**
 * Storage interfaces used by `DirectClient`. A `BffClient` holds no
 * tokens, so none of this applies to it.
 *
 * The client keeps three pieces of mutable state across calls:
 * - the current token bundle (access + refresh + expiry + id token),
 * - the refresh token specifically (may be split into a harder-to-exfiltrate
 *   store than the access token — e.g. IndexedDB or a Web Worker),
 * - a short-lived auth-request map (`state` → `{ codeVerifier, returnTo, … }`)
 *   used to correlate an authorize redirect with its callback.
 *
 * The defaults here are all in-memory and live only for the process / tab
 * lifetime. Browser applications that need persistence across reloads should
 * plug in the appropriate implementation — most commonly:
 * - `MemoryTokenStorage` for access tokens (always),
 * - an `IndexedDB`-backed `RefreshTokenStorage` for refresh tokens (so they
 *   are not readable via `document.cookie` or `localStorage`),
 * - `sessionStorage`-backed `AuthRequestStorage` for the redirect state map.
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
 * Persists the refresh token independently from the access token. Kept
 * separate so applications can harden refresh-token storage (IndexedDB,
 * Web Worker, or a server-side session cookie) without changing where
 * short-lived access tokens live.
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
   * Returns the record for {@linkcode state}, or `null` if absent or expired.
   * Implementations may prune the entry when returning `null` for an expired one.
   */
  get(
    state: string,
  ): Promise<AuthRequestRecord | null> | AuthRequestRecord | null;
  /** Stores {@linkcode value} under {@linkcode state} before the authorize redirect. */
  set(
    state: string,
    value: AuthRequestRecord,
  ): Promise<void> | void;
  /** Removes one entry (called after successful callback consumption). */
  delete(state: string): Promise<void> | void;
  /** Removes every entry. Called on logout. */
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

/**
 * Default in-memory {@link AuthRequestStorage}. Data is lost when the
 * process exits — fine for server-side / CLI usage. Browser apps should
 * plug in a `sessionStorage`-backed implementation so the record survives
 * the authorize-redirect round-trip.
 */
export class MemoryAuthRequestStorage implements AuthRequestStorage {
  #records = new Map<string, AuthRequestRecord>();
  /** Returns the record for {@linkcode state}, or `null` if none is stored. */
  get(state: string): AuthRequestRecord | null {
    return this.#records.get(state) ?? null;
  }
  /** Stores {@linkcode value} under {@linkcode state}. */
  set(state: string, value: AuthRequestRecord): void {
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
}
