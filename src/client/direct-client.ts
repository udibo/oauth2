/**
 * OAuth2 client that talks to the authorization server directly and holds the
 * resulting tokens (RFC 6749 + RFC 7636 PKCE + RFC 7009 revocation +
 * RFC 7662 introspection + RFC 8414 metadata + RFC 8628 device authorization).
 *
 * Works against any RFC-compliant authorization server. Use it for SPAs
 * without a Backend-for-Frontend, CLIs, mobile shells, and server-side apps —
 * anywhere this process is the one that keeps the access and refresh tokens.
 * When a BFF holds them instead, use `BffClient`.
 *
 * @module
 */

import { delay } from "@std/async/delay";

import {
  AccessDeniedError,
  InvalidGrantError,
  isOAuth2Error,
  OAuth2Error as OAuth2ErrorClass,
  ServerError,
} from "../errors.ts";
import type {
  AuthorizationServerMetadata,
  DeviceAuthorizationResponse,
} from "../models/responses.ts";
import type { IntrospectionResponse, TokenResponse } from "../models/token.ts";
import {
  challengeMethods,
  generateCodeVerifier,
  generateState,
} from "../utils/pkce.ts";
import { encodeBasicAuth } from "../utils/basic-auth.ts";
import { base64urlDecode } from "../utils/crypto.ts";
import { sanitizeProviderText } from "../utils/text.ts";

import {
  assertField,
  assertTokenResponse,
  type Endpoint,
  errorFromResponse,
  receiveJson,
  sendGuarded,
} from "./_http.ts";

import {
  type BaseLoginOptions,
  type BaseOptions,
  type LogoutOptions,
  type LogoutRedirect,
  mergedHeaders,
  OAuth2ClientBase,
  type SessionState,
  SIGNED_OUT,
  type UserInfoClaims,
} from "./base.ts";
import { SessionStorageAuthRequestStorage } from "./browser-storage.ts";
import {
  DEFAULT_DISCOVERY_TTL_MS,
  type DiscoveryCache,
} from "./discovery-cache.ts";
import {
  type AuthRequestStorage,
  MemoryAuthRequestStorage,
  MemoryRefreshTokenStorage,
  MemoryTokenStorage,
  type RefreshTokenStorage,
  type TokenBundle,
  type TokenStorage,
} from "./storage.ts";

/** Endpoints resolved via discovery or provided explicitly by the caller. */
export interface AuthorizationServerEndpoints {
  /** URL of the authorization endpoint (required for the auth-code flow). */
  authorization?: string;
  /**
   * URL of the token endpoint. Required by every grant; methods that need it
   * throw a clear error if it is missing both here and from the server's
   * discovery metadata.
   */
  token?: string;
  /** URL of the revocation endpoint (RFC 7009). */
  revocation?: string;
  /** URL of the introspection endpoint (RFC 7662). */
  introspection?: string;
  /** URL of the device authorization endpoint (RFC 8628). */
  deviceAuthorization?: string;
  /** URL of the OIDC userinfo endpoint. */
  userInfo?: string;
  /** URL of the OIDC end-session endpoint (for logout redirect). */
  endSession?: string;
}

/** Options accepted by {@link DirectClient}. */
export interface DirectClientOptions extends BaseOptions {
  /** OAuth2 client identifier. */
  clientId: string;
  /**
   * The client secret, sent via HTTP Basic auth on token-endpoint calls.
   *
   * Supplying one makes this a **confidential** client, which unlocks
   * {@link DirectClient.getClientCredentialsToken} and
   * {@link DirectClient.introspect}. **Omit the property** for a **public**
   * client (a browser or a native app, where a secret cannot be kept) — those
   * require refresh-token rotation with reuse detection on the server side.
   *
   * `clientSecret: undefined` reads as omitted, so a wrapper can forward an
   * optional secret. An **empty string** is a construction error rather than a
   * request for a public client — nobody spells "public" `""`, so it is a
   * variable that resolved to blank. Note that `clientSecret: getEnv("X")`
   * with `X` unset therefore yields a *public* client; require it at the
   * source if the deployment must be confidential.
   */
  clientSecret?: string;
  /** Registered redirect URI; required for the auth-code flow. */
  redirectUri?: string;
  /** Default scope string to request when none is passed explicitly. */
  scope?: string;
  /**
   * Issuer URL. If provided, endpoints are fetched from
   * `${issuer}/.well-known/oauth-authorization-server` on first use.
   * Mutually exclusive with an explicit `endpoints` record below.
   */
  issuer?: string;
  /** Explicit endpoint URLs, bypassing discovery. */
  endpoints?: AuthorizationServerEndpoints;
  /**
   * Cache the discovery result is read from and written to, shared with any
   * other client given the same instance. Without one, metadata is cached on
   * this client only — a server that builds a client per request then
   * re-fetches discovery on every request. `MemoryDiscoveryCache` is the
   * ready-made implementation.
   */
  discoveryCache?: DiscoveryCache;
  /** Access-token storage. Defaults to {@link MemoryTokenStorage}. */
  tokenStorage?: TokenStorage;
  /** Refresh-token storage. Defaults to {@link MemoryRefreshTokenStorage}. */
  refreshTokenStorage?: RefreshTokenStorage;
  /**
   * Auth-request storage.
   *
   * Defaults to {@link SessionStorageAuthRequestStorage} in a browser document
   * and {@link MemoryAuthRequestStorage} everywhere else. The browser default
   * is what makes the authorize redirect work at all: an in-memory record does
   * not survive the navigation away and back, so the callback rejects every
   * `state` as unknown. Servers keep the in-memory default so a per-request
   * client does not write pending logins into one process-wide store.
   *
   * Override it when the record must live somewhere else — a per-request
   * cookie store on a server, or a store scoped to something other than the
   * tab.
   */
  authRequestStorage?: AuthRequestStorage;
  /**
   * Max age of a pending auth-request (`state`) record before
   * {@link DirectClient.exchangeAuthorizationCode} rejects it as stale, in ms.
   * Bounds the callback replay window and unbounded growth of the in-memory
   * store. Defaults to 10 minutes; set `Infinity` to disable the check.
   */
  authRequestTtlMs?: number;
}

/** Options accepted by {@link DirectClient.login}. */
export interface LoginOptions extends BaseLoginOptions {
  /** Override the default scope string. */
  scope?: string;
  /** OIDC `prompt` parameter. */
  prompt?: string;
  /** Extra query parameters to append to the authorize URL. */
  extraParams?: Record<string, string>;
  /**
   * Override the origin (scheme + host) of the authorize endpoint and the
   * `redirect_uri` for THIS call, keeping their configured paths. Lets one
   * build-once client serve multiple deployment origins (preview URLs,
   * multi-tenant subdomains) — e.g. the Hono BFF passes the trusted request
   * origin so sign-in works on whichever host the request arrived at. The
   * callback returns to the same origin, so the matching `exchange` call is
   * given the same origin.
   */
  origin?: string;
  /**
   * Store the pending authorization request here instead of in the client's
   * configured `authRequestStorage`, for THIS call. Lets a server bind the
   * record to the request it belongs to — a per-request cookie store, or a
   * per-tenant table — rather than sharing one process-wide store. The
   * matching `exchangeAuthorizationCode` call MUST be given a storage that
   * can read the record back.
   */
  authRequestStorage?: AuthRequestStorage;
  /**
   * Override the `redirect_uri` for THIS call (used verbatim, not retargeted
   * by `origin`). Lets a Backend-for-Frontend derive `redirect_uri` from its
   * mounted callback path instead of restating it in the client config. The
   * matching `exchangeAuthorizationCode` call MUST be given the same value
   * (RFC 6749 §4.1.3 — the token-exchange `redirect_uri` must match
   * authorize).
   */
  redirectUri?: string;
}

/** Result of {@link DirectClient.login}. */
export interface AuthorizationRedirect {
  /** Fully-built authorize URL for the caller to navigate to. */
  url: string;
  /** Opaque `state` value the callback will echo back. */
  state: string;
}

/** Result of {@link DirectClient.handleAuthorizationCallback}. */
export interface AuthorizationCallbackResult {
  /** Token bundle saved on the client. */
  tokens: TokenBundle;
  /** `returnTo` that was recorded when `login` ran. */
  returnTo?: string;
}

/** Options accepted by {@link DirectClient.startDeviceAuthorization}. */
export interface DeviceAuthorizationOptions {
  /** Override the default scope string requested for the device grant. */
  scope?: string;
}

/** Options accepted by {@link DirectClient.pollDeviceToken}. */
export interface PollDeviceTokenOptions {
  /** Minimum seconds between polls. Defaults to the RFC 8628 fallback of 5. */
  interval?: number;
  /** Unix ms at which polling should give up. */
  expiresAt?: number;
  /** Abort signal to cancel polling. */
  signal?: AbortSignal;
}

/** Generic token introspection response. */
export type IntrospectionResult = IntrospectionResponse;

/** Options accepted by the low-level exchange primitives. */
export interface ExchangeOptions {
  /** Retarget the configured `redirect_uri` at this origin. */
  origin?: string;
  /** Use this `redirect_uri` verbatim. */
  redirectUri?: string;
  /** Read the pending auth-request record from here. */
  authRequestStorage?: AuthRequestStorage;
}

/** Result of the low-level exchange primitives. */
export interface ExchangeResult {
  /** The token bundle, not persisted to this client's storage. */
  tokens: TokenBundle;
  /** The rotated refresh token, when the server issued one. */
  refreshToken?: string;
  /** `returnTo` recorded at authorize time, for the code exchange. */
  returnTo?: string;
  /** The raw token-endpoint response. */
  raw: TokenResponse;
}

const REFRESH_SKEW_MS = 30_000;

/**
 * OAuth2 client that drives the standard grants against an authorization
 * server and keeps the tokens in its own storage.
 *
 * Public vs confidential is decided by whether `clientSecret` was supplied:
 * with a secret the client authenticates via HTTP Basic (RFC 6749 §2.3.1) and
 * may use `client_credentials` and introspection; without one it sends
 * `client_id` in the body and is limited to the grants a public client may
 * run.
 *
 * **Advanced — multi-session servers.**
 * {@link exchangeAuthorizationCode} and {@link exchangeRefreshToken} are
 * lower-level variants that bypass this client's token storage and event bus.
 * They exist so server-side adapters (e.g. the Hono BFF) can drive many
 * concurrent sessions through a single shared client without their tokens
 * clobbering each other. SPA / mobile / CLI consumers should never reach for
 * them — call {@link handleAuthorizationCallback} and {@link refresh}
 * instead.
 *
 * @example SPA with PKCE against a discovered issuer
 * ```ts
 * import {
 *   DirectClient,
 *   IndexedDBRefreshTokenStorage,
 * } from "@udibo/oauth2/client";
 *
 * const client = new DirectClient({
 *   clientId: "spa",
 *   issuer: "https://auth.example.com",
 *   redirectUri: "https://app.example.com/callback",
 *   scope: "openid profile",
 *   refreshTokenStorage: new IndexedDBRefreshTokenStorage({ clientId: "spa" }),
 * });
 *
 * const { url } = await client.login({ returnTo: "/dashboard" });
 * location.assign(url);
 * ```
 *
 * @example Confidential client issuing a machine token
 * ```ts
 * import { DirectClient } from "@udibo/oauth2/client";
 *
 * const client = new DirectClient({
 *   clientId: "worker",
 *   clientSecret: Deno.env.get("CLIENT_SECRET")!,
 *   endpoints: { token: "https://auth.example.com/token" },
 * });
 *
 * const tokens = await client.getClientCredentialsToken({ scope: "jobs:run" });
 * ```
 */
export class DirectClient extends OAuth2ClientBase {
  readonly #clientId: string;
  readonly #clientSecret?: string;
  readonly #redirectUri?: string;
  readonly #scope?: string;
  readonly #issuer?: string;
  readonly #discoveryCache?: DiscoveryCache;
  readonly #tokenStorage: TokenStorage;
  readonly #refreshTokenStorage: RefreshTokenStorage;
  readonly #authRequestStorage: AuthRequestStorage;
  readonly #authRequestTtlMs: number;

  #endpoints: AuthorizationServerEndpoints;
  #metadata?: AuthorizationServerMetadata;
  #metadataExpiresAt = 0;
  #discoveryPromise?: Promise<AuthorizationServerMetadata>;
  #refreshPromise?: Promise<string>;
  #refreshSnapshot?: { version?: number };
  #sessionVersion = 0;
  #sessionWrites: Promise<void> = Promise.resolve();
  #callbackPromises = new Map<string, Promise<AuthorizationCallbackResult>>();

  /**
   * Builds a client for one OAuth2 client registration.
   *
   * @param options Must carry `clientId`, plus either `issuer` (endpoints come
   * from discovery) or `endpoints` (discovery is skipped). Supply
   * `clientSecret` for a confidential client; **omit the property entirely**
   * for a public one.
   * @throws {TypeError} when both `endpoints` and `issuer` are supplied (they
   * are mutually exclusive), or when `clientSecret` is an empty string.
   * @throws {Error} when a secret is supplied in a document context, where it
   * would ship to every visitor in the bundle.
   */
  constructor(options: DirectClientOptions) {
    super(options);
    if (options.endpoints && options.issuer) {
      throw new TypeError("pass either `endpoints` or `issuer`, not both");
    }
    assertUsableSecret(options.clientSecret);
    this.#clientId = options.clientId;
    this.#clientSecret = options.clientSecret;
    this.#redirectUri = options.redirectUri;
    this.#scope = options.scope;
    this.#issuer = options.issuer;
    this.#discoveryCache = options.discoveryCache;
    this.#endpoints = { ...options.endpoints };
    this.#tokenStorage = options.tokenStorage ?? new MemoryTokenStorage();
    this.#refreshTokenStorage = options.refreshTokenStorage ??
      new MemoryRefreshTokenStorage();
    this.#authRequestStorage = options.authRequestStorage ??
      defaultAuthRequestStorage();
    this.#authRequestTtlMs = options.authRequestTtlMs ?? 10 * 60 * 1000;
  }

  /** True when the client was given a secret and authenticates via Basic. */
  get isConfidential(): boolean {
    return this.#clientSecret !== undefined;
  }

  /**
   * Fetches authorization-server metadata and caches it on the instance.
   *
   * Tries `.well-known/oauth-authorization-server` (RFC 8414) first, then
   * falls back to `.well-known/openid-configuration` (OIDC Discovery) — the
   * two use the same field names, and real IdPs serve one or the other, so
   * this works against any compliant server. **Lazy + cached**: it only runs
   * on the first endpoint use of an `issuer`-configured client (never at
   * construction), so there is no startup cost and no per-request fetch.
   * Concurrent calls share one in-flight request; a failure clears the cache
   * so a later call can retry.
   *
   * **Re-resolution contract.** The document this client holds is never
   * permanent: every endpoint use re-resolves once the copy in hand is past
   * its expiry, so a long-lived client picks up a rotated `jwks_uri` or a
   * moved endpoint without a restart. Without a `discoveryCache` the copy
   * expires {@link DEFAULT_DISCOVERY_TTL_MS} after it was fetched. With one,
   * the cache owns freshness: the copy expires when the cache says its entry
   * does (the `expiresAt` it reports), so the client reads the cache once
   * per entry lifetime rather than once per endpoint lookup — a Redis- or
   * file-backed cache costs one round trip per TTL window, not one per call.
   * Either way expiry only schedules the *next* resolve; nothing re-fetches on
   * a timer, and a client that is idle past its expiry makes no requests.
   *
   * A server that builds a client per request should supply a
   * `discoveryCache`, or it re-fetches discovery on every request.
   *
   * @returns The server's metadata document.
   * @throws {Error} when the client was configured with explicit `endpoints`
   * rather than an `issuer` — there is nothing to discover.
   * @throws {ServerError} when both well-known paths fail.
   *
   * @example
   * ```ts
   * import { DirectClient } from "@udibo/oauth2/client";
   *
   * const client = new DirectClient({
   *   clientId: "cli",
   *   issuer: "https://auth.example.com",
   * });
   * const meta = await client.discover();
   * ```
   */
  discover(): Promise<AuthorizationServerMetadata> {
    if (this.#hasFreshMetadata()) return Promise.resolve(this.#metadata!);
    if (this.#discoveryPromise) return this.#discoveryPromise;

    const issuer = this.#issuer;
    if (!issuer) {
      throw new Error(
        "discovery requires `issuer` in options; pass explicit `endpoints` " +
          "to skip discovery.",
      );
    }

    const cache = this.#discoveryCache;
    const promise = (async () => {
      if (cache) {
        const entry = await cache.resolve(
          issuer,
          () => this.#fetchMetadata(issuer),
        );
        return this.#adoptMetadata(entry.metadata, entry.expiresAt);
      }
      const meta = await this.#fetchMetadata(issuer);
      return this.#adoptMetadata(
        meta,
        Date.now() + DEFAULT_DISCOVERY_TTL_MS,
      );
    })();
    this.#discoveryPromise = promise;
    const clear = () => {
      if (this.#discoveryPromise === promise) {
        this.#discoveryPromise = undefined;
      }
    };
    promise.then(clear, clear);
    return promise;
  }

  #adoptMetadata(
    metadata: AuthorizationServerMetadata,
    expiresAt: number,
  ): AuthorizationServerMetadata {
    this.#metadata = metadata;
    this.#metadataExpiresAt = expiresAt;
    this.#endpoints = {
      ...this.#endpoints,
      ...metadataToEndpoints(metadata),
    };
    return metadata;
  }

  #hasFreshMetadata(): boolean {
    return this.#metadata !== undefined && Date.now() < this.#metadataExpiresAt;
  }

  async #fetchMetadata(issuer: string): Promise<AuthorizationServerMetadata> {
    const issuerBase = issuer.endsWith("/") ? issuer : `${issuer}/`;
    const wellKnownPaths = [
      ".well-known/oauth-authorization-server",
      ".well-known/openid-configuration",
    ];
    let lastError: unknown;
    for (const path of wellKnownPaths) {
      const url = new URL(path, issuerBase).toString();
      try {
        const res = await sendGuarded(
          (input, init) => this.fetchImpl(input, init),
          url,
          { headers: { Accept: "application/json" } },
          "discovery endpoint",
          { redirect: "follow" },
        );
        const meta = await receiveJson(res, "discovery endpoint");
        assertIssuer(meta, issuer);
        return meta as unknown as AuthorizationServerMetadata;
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError ?? new ServerError("discovery failed");
  }

  /** Last-seen authorization server metadata, if discovery has run. */
  get metadata(): AuthorizationServerMetadata | undefined {
    return this.#metadata;
  }

  /**
   * The configured authorization endpoint URL, if known **synchronously** —
   * set explicitly via `endpoints.authorization`, or learned from a previous
   * {@link discover}. `undefined` for an issuer-only client that has not
   * discovered yet.
   *
   * Exposed so a Backend-for-Frontend can recognize an in-flight authorize URL
   * (e.g. to decide whether to *resume* it or *start* a fresh login) without
   * re-running discovery. See `HonoBff.loginContinuation`.
   */
  get authorizationEndpoint(): string | undefined {
    return this.#endpoints.authorization;
  }

  /**
   * The configured OIDC end-session endpoint URL, if known **synchronously** —
   * set explicitly via `endpoints.endSession`, or learned from a previous
   * {@link discover}. `undefined` when the server advertises none.
   *
   * Exposed so a Backend-for-Frontend can drive RP-Initiated Logout (redirect
   * to the OP's end-session endpoint) without re-running discovery. See
   * `HonoBffOptions.rpInitiatedLogout`.
   */
  get endSessionEndpoint(): string | undefined {
    return this.#endpoints.endSession;
  }

  /**
   * This client's `client_id`.
   *
   * Exposed for the requests that identify the client without authenticating
   * it — RP-Initiated Logout's `client_id`, which is how the OP knows whose
   * registered `post_logout_redirect_uris` to check when no `id_token_hint` is
   * available. It is a public identifier, never a credential.
   */
  get clientId(): string {
    return this.#clientId;
  }

  async #endpoint<K extends keyof AuthorizationServerEndpoints>(
    key: K,
  ): Promise<AuthorizationServerEndpoints[K]> {
    if (this.#issuer && !this.#hasFreshMetadata()) await this.discover();
    return this.#endpoints[key];
  }

  async #requireEndpoint<K extends keyof AuthorizationServerEndpoints>(
    key: K,
  ): Promise<string> {
    const value = await this.#endpoint(key);
    if (typeof value !== "string") {
      throw new Error(`${String(key)} endpoint is not configured`);
    }
    return value;
  }

  #resolveRedirectUri(options: {
    origin?: string;
    redirectUri?: string;
  }): string | undefined {
    if (options.redirectUri) return options.redirectUri;
    if (this.#redirectUri && options.origin) {
      return withOrigin(this.#redirectUri, options.origin);
    }
    return this.#redirectUri;
  }

  /**
   * Builds the PKCE-protected authorize URL and persists the verifier under
   * the returned `state`. Navigate the browser to `url`; the callback route
   * then calls {@link handleAuthorizationCallback}. Non-browser callers can
   * use the URL for out-of-band flows.
   *
   * @param options `returnTo` is stored with the pending request and handed
   * back by the callback. The remaining fields let a server retarget the
   * authorize URL, override `redirect_uri`, or bind the pending request to a
   * per-request store.
   * @returns The authorize URL and the `state` the callback will echo back.
   * @throws {Error} when no authorization endpoint is configured or
   * discoverable.
   *
   * @example
   * ```ts
   * import { DirectClient } from "@udibo/oauth2/client";
   *
   * const client = new DirectClient({
   *   clientId: "spa",
   *   endpoints: { authorization: "https://auth.example.com/authorize" },
   *   redirectUri: "https://app.example.com/callback",
   * });
   * const { url, state } = await client.login({ returnTo: "/dashboard" });
   * ```
   */
  async login(
    options: LoginOptions = {},
  ): Promise<AuthorizationRedirect> {
    const baseAuthEndpoint = await this.#requireEndpoint("authorization");
    const authEndpoint = options.origin
      ? withOrigin(baseAuthEndpoint, options.origin)
      : baseAuthEndpoint;
    const redirectUri = this.#resolveRedirectUri(options);

    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await challengeMethods.S256(codeVerifier);
    const scope = options.scope ?? this.#scope;

    const authRequestStorage = options.authRequestStorage ??
      this.#authRequestStorage;
    await authRequestStorage.set(state, {
      codeVerifier,
      returnTo: options.returnTo,
      scope,
      createdAt: Date.now(),
    });

    const url = new URL(authEndpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.#clientId);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    if (redirectUri) url.searchParams.set("redirect_uri", redirectUri);
    if (scope) url.searchParams.set("scope", scope);
    if (options.prompt) url.searchParams.set("prompt", options.prompt);
    for (const [key, value] of Object.entries(options.extraParams ?? {})) {
      url.searchParams.set(key, value);
    }
    return { url: url.toString(), state };
  }

  /**
   * Completes the auth-code flow: reads `code` + `state` from the callback
   * URL, exchanges the code at the token endpoint, persists the token bundle,
   * and emits `authenticated`.
   *
   * Idempotent on duplicate calls with the same `code` — React strict-mode
   * double-mounts would otherwise double-redeem a single-use code and fail the
   * second call, so the first in-flight promise is returned again.
   *
   * @param input The callback URL, its query string, or the parsed params.
   * @returns The persisted tokens and the `returnTo` recorded at login.
   * @throws {OAuth2Error} when the callback carries `?error=…`, or the token
   * exchange fails.
   * @throws {TypeError} when `code` or `state` is missing.
   * @throws {InvalidGrantError} when `state` is unknown or expired.
   *
   * @example
   * ```ts
   * import { DirectClient } from "@udibo/oauth2/client";
   *
   * declare const client: DirectClient;
   * const { returnTo } = await client.handleAuthorizationCallback(
   *   location.href,
   * );
   * location.replace(returnTo ?? "/");
   * ```
   */
  handleAuthorizationCallback(
    input: URL | URLSearchParams | string,
  ): Promise<AuthorizationCallbackResult> {
    const params = toSearchParams(input);

    const error = params.get("error");
    if (error) {
      const description = params.get("error_description") ?? undefined;
      const errorUri = params.get("error_uri") ?? undefined;
      const instance = new OAuth2ErrorClass(
        description ?? "authorization error",
        {
          extensions: {
            error,
            error_description: description,
            error_uri: errorUri,
          },
        },
      );
      this.emit({ type: "error", error: instance });
      return Promise.reject(instance);
    }

    const code = params.get("code");
    const state = params.get("state");
    if (!code) return Promise.reject(new TypeError("callback missing `code`"));
    if (!state) {
      return Promise.reject(new TypeError("callback missing `state`"));
    }

    const existing = this.#callbackPromises.get(code);
    if (existing) return existing;

    const promise = this.#exchangeCode(code, state);
    this.#callbackPromises.set(code, promise);
    const cleanup = () =>
      queueMicrotask(() => this.#callbackPromises.delete(code));
    promise.then(cleanup, cleanup);
    return promise;
  }

  async #exchangeCode(
    code: string,
    state: string,
  ): Promise<AuthorizationCallbackResult> {
    const version = ++this.#sessionVersion;
    const result = await this.exchangeAuthorizationCode(code, state);
    const tokens = await this.#saveTokens(result.raw, version);
    this.emit({ type: "authenticated", tokens });
    return { tokens, returnTo: result.returnTo };
  }

  /**
   * **Advanced (BFF / multi-session servers).** SPA, mobile, and CLI consumers
   * should call {@link handleAuthorizationCallback} instead — that variant
   * persists the token bundle to this client's storage and emits the
   * `authenticated` event the React adapter listens for.
   *
   * Exchanges an authorization code for tokens **without persisting them**.
   * Used by server-side adapters that manage their own per-session storage
   * (e.g. the Hono BFF, which keeps tokens in a `SessionStore` keyed by an
   * HttpOnly cookie). Calling this from a single-session client splits the
   * token state across this client's storage and the caller's external store,
   * so refresh, revocation, and logout all stop working as expected.
   *
   * The verifier and `returnTo` are looked up under `state`; on success the
   * record is consumed. Emits nothing — the caller owns session semantics.
   *
   * @param code The authorization code from the callback.
   * @param state The `state` the callback echoed back.
   * @param options Per-call `redirect_uri` and auth-request storage overrides,
   * which must match what {@link login} was given.
   * @returns The tokens, the rotated refresh token, and the recorded
   * `returnTo`, plus the raw response.
   * @throws {InvalidGrantError} when `state` is unknown or older than
   * `authRequestTtlMs`.
   */
  async exchangeAuthorizationCode(
    code: string,
    state: string,
    options: ExchangeOptions = {},
  ): Promise<ExchangeResult> {
    const authRequestStorage = options.authRequestStorage ??
      this.#authRequestStorage;
    const record = await authRequestStorage.get(state);
    if (!record) throw new InvalidGrantError("unknown state parameter");
    if (
      this.#authRequestTtlMs !== Infinity &&
      Date.now() - record.createdAt > this.#authRequestTtlMs
    ) {
      await authRequestStorage.delete(state);
      throw new InvalidGrantError("authorization request expired");
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: record.codeVerifier,
    });
    const redirectUri = this.#resolveRedirectUri(options);
    if (redirectUri) body.set("redirect_uri", redirectUri);

    const raw = await this.#postToken(body);
    await authRequestStorage.delete(state);
    return {
      tokens: responseToBundle(raw),
      refreshToken: raw.refresh_token,
      returnTo: record.returnTo,
      raw,
    };
  }

  /**
   * **Advanced (BFF / multi-session servers).** SPA, mobile, and CLI consumers
   * should call {@link refresh} instead — that variant persists the rotated
   * bundle, dedupes concurrent calls, and emits `token_refreshed`.
   *
   * Exchanges a refresh token for a fresh bundle **without persisting** it.
   * Used by server-side adapters that manage their own per-session storage
   * (the Hono BFF's `attachToken` middleware calls this when refreshing on
   * expiry). Mixing this with this client's own token storage in a
   * single-session deployment leaves the two out of sync.
   *
   * Does not share the single-flight promise with {@link refresh} and emits
   * nothing — the caller owns concurrency control across its sessions.
   *
   * @param refreshToken The refresh token to redeem.
   * @returns The new tokens, the rotated refresh token, and the raw response.
   * @throws {OAuth2Error} when the token endpoint rejects the grant.
   */
  async exchangeRefreshToken(refreshToken: string): Promise<ExchangeResult> {
    const raw = await this.#postToken(
      new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      }),
    );
    return {
      tokens: responseToBundle(raw),
      refreshToken: raw.refresh_token,
      raw,
    };
  }

  /**
   * Issues a token via the `client_credentials` grant, persists it, and emits
   * `authenticated`. For machine-to-machine calls where there is no user.
   *
   * @param options `scope` overrides the client's default scope string.
   * @returns The persisted token bundle.
   * @throws {Error} when the client has no `clientSecret` — RFC 6749 §4.4
   * restricts this grant to confidential clients.
   * @throws {OAuth2Error} when the token endpoint rejects the grant.
   *
   * @example
   * ```ts
   * import { DirectClient } from "@udibo/oauth2/client";
   *
   * declare const client: DirectClient;
   * const { accessToken } = await client.getClientCredentialsToken({
   *   scope: "jobs:run",
   * });
   * ```
   */
  async getClientCredentialsToken(
    options: { scope?: string } = {},
  ): Promise<TokenBundle> {
    if (!this.isConfidential) {
      throw new Error(
        "client_credentials requires a confidential client; construct the " +
          "DirectClient with a `clientSecret`.",
      );
    }
    const body = new URLSearchParams({ grant_type: "client_credentials" });
    const scope = options.scope ?? this.#scope;
    if (scope) body.set("scope", scope);
    const version = ++this.#sessionVersion;
    const tokens = await this.#saveTokens(await this.#postToken(body), version);
    this.emit({ type: "authenticated", tokens });
    return tokens;
  }

  /**
   * Refreshes the access token using the stored refresh token, persists the
   * result, and emits `token_refreshed`. Single-flight: concurrent callers
   * share one in-flight promise.
   *
   * If the refresh fails with `invalid_grant` (the token was revoked or, under
   * rotation, already consumed), all local token state is cleared and
   * `logged_out` is emitted so the framework adapter can redirect to login.
   *
   * Single-flight has one consequence worth knowing: a call that **joins** a
   * refresh already started by {@link renewSession} inherits that call's quiet
   * policy, so it will not emit `error` on a transport failure even though it
   * still rejects. The rejection, not the event, is the contract for a caller
   * that asked directly.
   *
   * A refresh-token storage that fails to read refuses the refresh: the
   * rejection carries the storage's own error, `error` is emitted, and the
   * stored session is left alone — a broken store is not evidence the grant
   * died.
   *
   * @returns The new access token.
   * @throws {InvalidGrantError} when no refresh token is stored, or the stored
   * one is dead.
   * @throws {Error} whatever the configured `RefreshTokenStorage` threw when
   * the read itself failed.
   */
  refresh(): Promise<string> {
    return this.#sharedRefresh(true);
  }

  #sharedRefresh(reportTransient: boolean): Promise<string> {
    if (
      this.#refreshPromise &&
      (this.#refreshSnapshot?.version === undefined ||
        this.#refreshSnapshot.version === this.#sessionVersion)
    ) return this.#refreshPromise;
    const snapshot: { version?: number } = {};
    const promise = this.#doRefresh(reportTransient, snapshot);
    this.#refreshPromise = promise;
    this.#refreshSnapshot = snapshot;
    const clear = () => {
      if (this.#refreshPromise === promise) this.#refreshPromise = undefined;
    };
    promise.then(clear, clear);
    return promise;
  }

  async #doRefresh(
    reportTransient: boolean,
    snapshot: { version?: number },
  ): Promise<string> {
    const { version, refreshToken } = await this.#mutateSession(async () => {
      const version = snapshot.version = this.#sessionVersion;
      return {
        version,
        refreshToken: await this.#readRefreshToken(reportTransient),
      };
    });
    if (version !== this.#sessionVersion) {
      throw new InvalidGrantError("session changed during refresh");
    }
    if (!refreshToken) {
      throw new InvalidGrantError("no refresh token available");
    }
    try {
      const response = await this.#postToken(
        new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }),
      );
      const tokens = await this.#saveTokens(response, version, true);
      this.emit({ type: "token_refreshed", tokens });
      return tokens.accessToken;
    } catch (error) {
      if (version !== this.#sessionVersion) {
        throw new InvalidGrantError("session changed during refresh");
      }
      if (isOAuth2ErrorCode(error, "invalid_grant")) {
        await this.#clearSession();
        this.emit({ type: "logged_out", reason: "invalid_grant" });
      } else if (reportTransient) {
        this.emit({ type: "error", error });
      }
      throw error;
    }
  }

  async #readRefreshToken(reportTransient: boolean): Promise<string | null> {
    try {
      return await this.#refreshTokenStorage.get();
    } catch (error) {
      if (reportTransient) this.emit({ type: "error", error });
      throw error;
    }
  }

  /**
   * Initiates the device authorization flow (RFC 8628 §3.1) for an input-
   * constrained device. Show the returned `user_code` and
   * `verification_uri`, then hand `device_code` to {@link pollDeviceToken}.
   *
   * @param options `scope` overrides the client's default scope string.
   * @returns The server's device authorization response.
   * @throws {Error} when no device authorization endpoint is configured or
   * discoverable.
   * @throws {OAuth2Error} when the server rejects the request.
   *
   * @example
   * ```ts
   * import { DirectClient } from "@udibo/oauth2/client";
   *
   * declare const client: DirectClient;
   * const grant = await client.startDeviceAuthorization();
   * console.log(`go to ${grant.verification_uri}, enter ${grant.user_code}`);
   * const tokens = await client.pollDeviceToken(grant.device_code, {
   *   interval: grant.interval,
   *   expiresAt: Date.now() + grant.expires_in * 1000,
   * });
   * ```
   */
  async startDeviceAuthorization(
    options: DeviceAuthorizationOptions = {},
  ): Promise<DeviceAuthorizationResponse> {
    const endpoint = await this.#requireEndpoint("deviceAuthorization");
    const body = new URLSearchParams({ client_id: this.#clientId });
    const scope = options.scope ?? this.#scope;
    if (scope) body.set("scope", scope);
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };
    this.#applyClientAuth(headers, body);
    const grant = await this.#postForm(
      endpoint,
      headers,
      body,
      "device authorization endpoint",
    );
    assertField(grant, "device_code", "device authorization endpoint");
    return grant as unknown as DeviceAuthorizationResponse;
  }

  /**
   * Polls the token endpoint for a device-code exchange (RFC 8628 §3.4),
   * persists the tokens, and emits `authenticated`. Handles
   * `authorization_pending` (keep polling) and `slow_down` (add 5s to the
   * interval) automatically.
   *
   * @param deviceCode The `device_code` from
   * {@link startDeviceAuthorization}.
   * @param options Pass `interval` and `expiresAt` from the device
   * authorization response so polling respects the server's advertised
   * minimum interval and deadline, and `signal` to cancel.
   * @returns The persisted token bundle.
   * @throws {AccessDeniedError} when `signal` aborts, or the user declines.
   * @throws {InvalidGrantError} when the device code expires before approval.
   * @throws {OAuth2Error} on any other terminal error from the server.
   */
  async pollDeviceToken(
    deviceCode: string,
    options: PollDeviceTokenOptions = {},
  ): Promise<TokenBundle> {
    const version = ++this.#sessionVersion;
    let interval = Math.max(1, options.interval ?? 5);
    const deadline = options.expiresAt ?? Infinity;

    for (;;) {
      if (options.signal?.aborted) {
        throw new AccessDeniedError("polling aborted");
      }
      if (Date.now() >= deadline) {
        throw new InvalidGrantError("device code expired before authorization");
      }

      try {
        const response = await this.#postToken(
          new URLSearchParams({
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: deviceCode,
            client_id: this.#clientId,
          }),
        );
        const tokens = await this.#saveTokens(response, version);
        this.emit({ type: "authenticated", tokens });
        return tokens;
      } catch (error) {
        if (isOAuth2ErrorCode(error, "authorization_pending")) {
          await pollDelay(interval * 1000, options.signal);
          continue;
        }
        if (isOAuth2ErrorCode(error, "slow_down")) {
          interval += 5;
          await pollDelay(interval * 1000, options.signal);
          continue;
        }
        throw error;
      }
    }
  }

  /**
   * Calls the introspection endpoint (RFC 7662) to ask the server whether a
   * token is still active and what it carries.
   *
   * @param token The token to introspect.
   * @param options `tokenTypeHint` tells the server which kind to look up
   * first.
   * @returns The introspection response; check `active`.
   * @throws {Error} when the client has no `clientSecret` — RFC 7662 requires
   * an authenticated caller.
   * @throws {OAuth2Error} when the endpoint rejects the request.
   */
  async introspect(
    token: string,
    options: { tokenTypeHint?: "access_token" | "refresh_token" } = {},
  ): Promise<IntrospectionResult> {
    if (!this.isConfidential) {
      throw new Error(
        "introspection requires a confidential client per RFC 7662; " +
          "construct the DirectClient with a `clientSecret`.",
      );
    }
    const endpoint = await this.#requireEndpoint("introspection");
    const body = new URLSearchParams({ token });
    if (options.tokenTypeHint) {
      body.set("token_type_hint", options.tokenTypeHint);
    }
    const result = await this.#postForm(
      endpoint,
      {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: this.#basicAuth(),
      },
      body,
      "introspection endpoint",
    );
    return result as unknown as IntrospectionResult;
  }

  /**
   * Calls the revocation endpoint (RFC 7009) to kill a token server-side.
   * Does not touch this client's storage — {@link logout} does both.
   *
   * @param token The token to revoke.
   * @param options `tokenTypeHint` tells the server which kind to look up
   * first.
   * @throws {Error} when no revocation endpoint is configured or discoverable.
   * @throws {OAuth2Error} when the endpoint rejects the request.
   */
  async revoke(
    token: string,
    options: { tokenTypeHint?: "access_token" | "refresh_token" } = {},
  ): Promise<void> {
    const endpoint = await this.#requireEndpoint("revocation");
    const body = new URLSearchParams({ token });
    if (options.tokenTypeHint) {
      body.set("token_type_hint", options.tokenTypeHint);
    }
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };
    this.#applyClientAuth(headers, body);
    const res = await sendGuarded(
      (input, init) => this.fetchImpl(input, init),
      endpoint,
      { method: "POST", headers, body },
      "revocation endpoint",
    );
    if (!res.ok) throw await errorFromResponse(res, "revocation endpoint");
    await res.body?.cancel();
  }

  /**
   * Fetches the OIDC userinfo endpoint with the current access token,
   * refreshing it first if it is close to expiry.
   *
   * @returns The claims the server returns.
   * @throws {Error} when no userinfo endpoint is configured or discoverable.
   * @throws {AccessDeniedError} when no token is stored and none can be
   * refreshed.
   */
  async getUserInfo(): Promise<UserInfoClaims> {
    return await this.#fetchUserInfo(false);
  }

  async #fetchUserInfo(quiet: boolean): Promise<UserInfoClaims> {
    const endpoint = await this.#requireEndpoint("userInfo");
    const accessToken = await this.#accessTokenFor(quiet);
    const res = await sendGuarded(
      (input, init) => this.fetchImpl(input, init),
      endpoint,
      {
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
      },
      "userinfo endpoint",
    );
    return await receiveJson(res, "userinfo endpoint");
  }

  /**
   * Base64url-decodes an OIDC `id_token` payload and returns the claims.
   *
   * **Does not verify the signature** — the token arrives from the token
   * endpoint over TLS, so verification would only defend against a compromised
   * TLS chain and is not a normal client concern. If you need verification
   * (e.g. the token was obtained out-of-band), use a dedicated JWT library
   * with your server's JWKS.
   *
   * @param idToken A compact-serialized JWS.
   * @returns The decoded payload claims.
   * @throws {TypeError | RangeError | SyntaxError} on a token that isn't a
   * decodable JWS with a JSON payload. Callers that surface an authorization
   * server's response to a user should catch, since a broken or hostile
   * server controls this input.
   */
  decodeIdToken(idToken: string): UserInfoClaims {
    const parts = idToken.split(".");
    if (parts.length < 2) throw new TypeError("malformed id_token");
    const json = new TextDecoder().decode(base64urlDecode(parts[1]));
    return JSON.parse(json) as UserInfoClaims;
  }

  /**
   * Fetches with `Authorization: Bearer <access token>` attached, retrying
   * once after a silent {@link refresh} if the response is a `401` carrying
   * `WWW-Authenticate: … error="invalid_token"`.
   *
   * A `401` without that challenge is returned as-is — it means "not allowed",
   * not "token stale", and re-minting would not help.
   *
   * @param input Request target, as for `fetch`. A `Request` keeps the headers
   * and body it was built with; it is cloned up front so the retry has an
   * unread body.
   * @param init Request options. A caller-set `Authorization` header wins, and
   * `init.headers` override same-named headers on a `Request` input.
   * @returns The response; the original `401` when no new token could be
   * minted. A transport failure on the retry itself rejects rather than
   * masquerading as the original `401`.
   *
   * @example
   * ```ts
   * import { DirectClient } from "@udibo/oauth2/client";
   *
   * declare const client: DirectClient;
   * const res = await client.fetch("https://api.example.com/items");
   * ```
   */
  async fetch(
    input: RequestInfo | URL,
    init: RequestInit = {},
  ): Promise<Response> {
    const stored = await this.#tokenStorage.get();
    const retryInput = input instanceof Request ? input.clone() : input;
    const first = await this.#fetchWithBearer(input, init, stored?.accessToken);
    if (first.status !== 401) return first;

    const wwwAuth = first.headers.get("WWW-Authenticate") ?? "";
    if (!/error\s*=\s*"invalid_token"/i.test(wwwAuth)) return first;

    let accessToken: string;
    try {
      accessToken = await this.refresh();
    } catch {
      return first;
    }
    return await this.#fetchWithBearer(retryInput, init, accessToken);
  }

  async #fetchWithBearer(
    input: RequestInfo | URL,
    init: RequestInit,
    accessToken?: string,
  ): Promise<Response> {
    const headers = mergedHeaders(input, init);
    if (accessToken && !headers.has("Authorization")) {
      headers.set("Authorization", `Bearer ${accessToken}`);
    }
    return await this.fetchImpl(input, { ...init, headers });
  }

  /**
   * Revokes the stored refresh token (best effort), clears all local token
   * state, emits `logged_out`, and returns the OIDC end-session URL when the
   * server advertises one.
   *
   * Best effort covers the read too: a refresh-token store that cannot be read
   * skips the revocation rather than failing the sign-out, because a client
   * that stays signed in locally because its store broke is the worse outcome.
   *
   * @param options `returnTo` becomes `post_logout_redirect_uri` on the
   * end-session URL.
   * @returns `{ url }` when the browser should visit the OP's end-session
   * endpoint to drop the upstream SSO session, `{}` when sign-out completed
   * locally.
   *
   * @example
   * ```ts
   * import { DirectClient } from "@udibo/oauth2/client";
   *
   * declare const client: DirectClient;
   * const { url } = await client.logout({ returnTo: "https://app.test/" });
   * if (url) location.assign(url);
   * ```
   */
  async logout(options: LogoutOptions = {}): Promise<LogoutRedirect> {
    const version = ++this.#sessionVersion;
    const refreshToken = await this.#readRefreshToken(false).catch(() => null);
    const idToken = (await this.#tokenStorage.get())?.idToken;
    if (version !== this.#sessionVersion) return {};
    await this.#clearSession();
    this.emit({ type: "logged_out", reason: "user" });
    if (refreshToken) {
      try {
        await this.revoke(refreshToken, { tokenTypeHint: "refresh_token" });
      } catch {
        // Non-fatal; the local session clears regardless.
      }
    }
    let endSession: string | undefined;
    try {
      endSession = await this.#endpoint("endSession");
    } catch {
      return {};
    }
    if (!endSession) return {};
    const url = new URL(endSession);
    if (idToken) url.searchParams.set("id_token_hint", idToken);
    if (options.returnTo) {
      url.searchParams.set("post_logout_redirect_uri", options.returnTo);
    }
    return { url: url.toString() };
  }

  /**
   * The signed-in user's claims: the decoded `id_token` when one was issued,
   * otherwise the userinfo endpoint when one is configured, otherwise `null`.
   *
   * @returns The claims, or `null` when no token is stored or neither source
   * is available.
   */
  async getUser(): Promise<UserInfoClaims | null> {
    return await this.#resolveUser(false);
  }

  async #resolveUser(quiet: boolean): Promise<UserInfoClaims | null> {
    const tokens = await this.#tokenStorage.get();
    if (!tokens) return null;
    if (tokens.idToken) return this.decodeIdToken(tokens.idToken);
    if (this.#endpoints.userInfo) return await this.#fetchUserInfo(quiet);
    return null;
  }

  /**
   * The session as this client sees it, derived from stored tokens — no
   * network call unless the claims come from a userinfo endpoint.
   *
   * `isAuthenticated` requires a usable access token: a stored bundle whose
   * `accessToken` is non-empty and not past its expiry. A holder of a valid
   * token therefore still reads as signed in when the server issues neither an
   * `id_token` nor a userinfo endpoint, while an expired one reads as signed
   * out rather than leaving the UI authenticated over a dead token. An expired
   * bundle that a stored refresh token could still revive also reads as signed
   * in, with `sessionExpiresIn: 0` — call {@link renewSession} to revive it.
   *
   * `logoutUrl` is always `null`: sign-out runs through {@link logout}, which
   * revokes and clears locally rather than sending the browser somewhere.
   *
   * Never rejects — a failure to resolve claims reports a signed-out session
   * and emits `error`, per {@link OAuth2ClientBase.getSession}.
   *
   * @returns The current {@link SessionState}.
   */
  async getSession(): Promise<SessionState> {
    return await this.#session(false);
  }

  async #session(quiet: boolean): Promise<SessionState> {
    try {
      const tokens = await this.#tokenStorage.get();
      if (!tokens?.accessToken) return SIGNED_OUT;
      const expiresIn = tokens.accessTokenExpiresAt
        ? Math.round((tokens.accessTokenExpiresAt - Date.now()) / 1000)
        : null;
      if (expiresIn !== null && expiresIn <= 0) {
        const revivable = await this.#refreshTokenStorage.get();
        if (!revivable) return SIGNED_OUT;
      }
      return {
        isAuthenticated: true,
        user: await this.#resolveUser(quiet),
        sessionExpiresIn: expiresIn === null ? null : Math.max(0, expiresIn),
        logoutUrl: null,
      };
    } catch (error) {
      if (!quiet) this.emit({ type: "error", error });
      return SIGNED_OUT;
    }
  }

  /**
   * Refreshes the access token, then reports the resulting session.
   *
   * Never rejects: a dead grant has already cleared the session and emitted
   * `logged_out`, so the reported state is signed out, while a transient
   * network failure leaves the stored tokens — and the reported state — as
   * they were. Unlike {@link refresh}, nothing on this path emits `error`:
   * it runs on a background timer, and a blip the client will simply retry
   * must not paint a user-visible error over a session that is still perfectly
   * good. A dead grant still emits `logged_out`, because the UI does have to
   * react to that.
   *
   * "Transient" here means only "not `invalid_grant`", so a durable failure —
   * a rotated client secret answering `invalid_client`, or a token endpoint
   * returning `500` indefinitely — is retried silently for as long as the
   * timer runs. The session ends when the access token finally expires and a
   * request 401s, not when renewal starts failing. Subscribe to
   * `token_refreshed` if you need to notice renewals that stopped landing.
   *
   * **A client with no refresh token cannot renew.** That includes the
   * `client_credentials` case, where re-running the grant would be possible in
   * principle: doing it automatically is refused because a confidential client
   * that had signed a *user* in would silently swap that user's session for a
   * machine identity. Re-run {@link getClientCredentialsToken} yourself.
   *
   * @returns The {@link SessionState} after the refresh attempt.
   */
  async renewSession(): Promise<SessionState> {
    await this.#sharedRefresh(false).catch(() => {});
    return await this.#session(true);
  }

  /**
   * Returns a usable access token, refreshing first when the stored one is
   * within 30 seconds of expiry.
   *
   * Reach for this when you must attach `Authorization: Bearer <token>` to a
   * request {@link fetch} can't carry (a custom transport, a third-party SDK).
   * For ordinary HTTP calls prefer {@link fetch}, which attaches the token and
   * handles the 401/refresh dance for you.
   *
   * @returns A non-expired access token.
   * @throws {InvalidGrantError} when nothing is stored and no refresh token is
   * available.
   */
  async getAccessToken(): Promise<string> {
    return await this.#accessTokenFor(false);
  }

  async #accessTokenFor(quiet: boolean): Promise<string> {
    const tokens = await this.#tokenStorage.get();
    if (
      tokens &&
      (!tokens.accessTokenExpiresAt ||
        tokens.accessTokenExpiresAt - REFRESH_SKEW_MS > Date.now())
    ) {
      return tokens.accessToken;
    }
    return await this.#sharedRefresh(!quiet);
  }

  #basicAuth(): string {
    return encodeBasicAuth(this.#clientId, this.#clientSecret!);
  }

  /**
   * Applies exactly one client authentication method (RFC 6749 §2.3.1):
   * HTTP Basic for a confidential client — dropping any body `client_id` so
   * credentials aren't sent twice — or a body `client_id` for a public one.
   */
  #applyClientAuth(
    headers: Record<string, string>,
    body: URLSearchParams,
  ): void {
    if (this.isConfidential) {
      headers.Authorization = this.#basicAuth();
      body.delete("client_id");
    } else if (!body.has("client_id")) {
      body.set("client_id", this.#clientId);
    }
  }

  async #postToken(body: URLSearchParams): Promise<TokenResponse> {
    const endpoint = await this.#requireEndpoint("token");
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };
    this.#applyClientAuth(headers, body);
    const response = await this.#postForm(
      endpoint,
      headers,
      body,
      "token endpoint",
    );
    assertTokenResponse(response, "token endpoint");
    return response as unknown as TokenResponse;
  }

  /**
   * POSTs a form to a credentialed endpoint and returns its JSON object.
   * Refuses a redirect rather than replaying the credentials in `body`.
   */
  async #postForm(
    endpoint: string,
    headers: Record<string, string>,
    body: URLSearchParams,
    what: Endpoint,
  ): Promise<Record<string, unknown>> {
    const res = await sendGuarded(
      (input, init) => this.fetchImpl(input, init),
      endpoint,
      {
        method: "POST",
        headers: { Accept: "application/json", ...headers },
        body,
      },
      what,
    );
    return await receiveJson(res, what);
  }

  #saveTokens(
    response: TokenResponse,
    version: number,
    preserveRefreshToken = false,
  ): Promise<TokenBundle> {
    return this.#mutateSession(async () => {
      if (version !== this.#sessionVersion) {
        throw new InvalidGrantError("session changed during token exchange");
      }
      const bundle = responseToBundle(response);
      await this.#tokenStorage.set(bundle);
      if (response.refresh_token) {
        await this.#refreshTokenStorage.set(response.refresh_token);
      } else if (!preserveRefreshToken) {
        await this.#refreshTokenStorage.clear();
      }
      if (version !== this.#sessionVersion) {
        throw new InvalidGrantError("session changed during token exchange");
      }
      if (!preserveRefreshToken) {
        this.#sessionVersion++;
      }
      return bundle;
    });
  }

  #mutateSession<T>(mutate: () => Promise<T>): Promise<T> {
    const operation = this.#sessionWrites.then(mutate);
    this.#sessionWrites = operation.then(() => undefined, () => undefined);
    return operation;
  }

  #clearSession(): Promise<void> {
    this.#sessionVersion++;
    return this.#mutateSession(async () => {
      await this.#tokenStorage.clear();
      await this.#refreshTokenStorage.clear();
      await this.#authRequestStorage.clear();
    });
  }
}

/**
 * Returns `urlStr` with its origin (scheme + host) replaced by `origin`'s,
 * preserving the path/query. Resolving against the new origin replaces
 * scheme/host/port cleanly; setting `.host` alone would keep a stale port.
 */
function withOrigin(urlStr: string, origin: string): string {
  const url = new URL(urlStr);
  return new URL(`${url.pathname}${url.search}${url.hash}`, origin).toString();
}

function responseToBundle(response: TokenResponse): TokenBundle {
  return {
    accessToken: response.access_token,
    tokenType: "Bearer",
    accessTokenExpiresAt: response.expires_in
      ? Date.now() + response.expires_in * 1000
      : undefined,
    scope: response.scope,
    idToken: (response as TokenResponse & { id_token?: string }).id_token,
  };
}

function metadataToEndpoints(
  meta: AuthorizationServerMetadata,
): Partial<AuthorizationServerEndpoints> {
  const out: Partial<AuthorizationServerEndpoints> = {};
  if (meta.authorization_endpoint) {
    out.authorization = meta.authorization_endpoint;
  }
  if (meta.token_endpoint) out.token = meta.token_endpoint;
  if (meta.revocation_endpoint) out.revocation = meta.revocation_endpoint;
  if (meta.introspection_endpoint) {
    out.introspection = meta.introspection_endpoint;
  }
  if (meta.device_authorization_endpoint) {
    out.deviceAuthorization = meta.device_authorization_endpoint;
  }
  if (meta.userinfo_endpoint) out.userInfo = meta.userinfo_endpoint;
  if (meta.end_session_endpoint) out.endSession = meta.end_session_endpoint;
  return out;
}

function toSearchParams(
  input: URL | URLSearchParams | string,
): URLSearchParams {
  if (input instanceof URLSearchParams) return input;
  if (input instanceof URL) return input.searchParams;
  try {
    return new URL(input).searchParams;
  } catch {
    return new URLSearchParams(input.startsWith("?") ? input.slice(1) : input);
  }
}

function defaultAuthRequestStorage(): AuthRequestStorage {
  const inBrowserDocument = typeof document !== "undefined" &&
    typeof sessionStorage !== "undefined";
  return inBrowserDocument
    ? new SessionStorageAuthRequestStorage()
    : new MemoryAuthRequestStorage();
}

function assertUsableSecret(secret: string | undefined): void {
  if (secret === undefined) return;
  if (secret === "") {
    throw new TypeError(
      "`clientSecret` is an empty string — a confidential client cannot " +
        "authenticate with a blank secret. Omit the property for a public " +
        "client, or fix the value (a variable that resolved to blank is the " +
        "usual cause).",
    );
  }
  if (typeof document !== "undefined") {
    throw new Error(
      "refusing to construct a confidential DirectClient in a document " +
        "context: a `clientSecret` here ships to every visitor. Use a public " +
        "client (omit `clientSecret`; PKCE protects the code), or move the " +
        "exchange behind a BffClient.",
    );
  }
}

/**
 * RFC 8414 §3.3 / OIDC Discovery §4.3: the `issuer` a metadata document
 * reports must be the issuer it was fetched from. Without this a document
 * served (or redirected to) from elsewhere could name another provider's
 * endpoints, which is the mix-up attack the requirement exists to stop.
 */
function assertIssuer(meta: Record<string, unknown>, issuer: string): void {
  const reported = meta.issuer;
  if (typeof reported !== "string" || reported.length === 0) {
    throw new ServerError(
      "the discovery document reported no `issuer` (RFC 8414 §3.3)",
    );
  }
  if (trimSlash(reported) !== trimSlash(issuer)) {
    throw new ServerError(
      `the discovery document reported issuer ` +
        `"${sanitizeProviderText(reported)}" but was fetched ` +
        `from "${issuer}" (RFC 8414 §3.3); refusing metadata that names ` +
        `another provider's endpoints`,
    );
  }
}

function trimSlash(url: string): string {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}

function isOAuth2ErrorCode(error: unknown, code: string): boolean {
  return isOAuth2Error(error) && error.extensions.error === code;
}

/**
 * Sleeps `ms`, or rejects with {@link AccessDeniedError} if `signal` aborts —
 * so cancelling a device-flow poll mid-wait surfaces as `access_denied`, the
 * same as the loop-top abort guard in {@link DirectClient.pollDeviceToken}.
 * The timer/abort plumbing is `@std/async/delay`; only the OAuth2 error
 * mapping is ours (`delay` rejects solely on abort).
 */
function pollDelay(ms: number, signal?: AbortSignal): Promise<void> {
  return delay(ms, { signal }).catch(() => {
    throw new AccessDeniedError("aborted");
  });
}
