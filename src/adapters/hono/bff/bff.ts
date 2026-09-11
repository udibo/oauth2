/**
 * Backend-for-Frontend (BFF) adapter for Hono.
 *
 * Wraps a {@link DirectClient} configured with a client secret
 * and exposes the session endpoints a browser SPA talks to:
 *
 * - `POST /auth/login` — redirects the browser to the authorize endpoint,
 *   persisting a per-request state/verifier record and binding its `state` to
 *   this browser with a short-lived cookie.
 * - `GET  /auth/callback` — requires the browser to present that binding
 *   cookie, exchanges the code, opens a session (or, in
 *   `sessionMode: "shared"`, attaches the tokens to the app's existing
 *   session), and redirects to the app's `return_to` path.
 * - `GET|POST /auth/logout` — destroys the session and (best-effort) revokes
 *   the refresh token upstream. Registered for both methods because the
 *   shipped React client navigates the browser here (a GET).
 * - `GET  /auth/session` — returns `{ isAuthenticated, user }` from the
 *   session. **Never** exposes tokens to the browser.
 * - `POST /auth/backchannel` — OIDC Back-Channel Logout receiver, mounted only
 *   when `backchannelLogout` is configured. A server-to-server call from the OP
 *   that ends the matching server-side session(s).
 *
 * A companion {@link HonoBff.attachToken} middleware reads the session
 * cookie, looks up / refreshes the access token, and sets
 * `Authorization: Bearer <token>` on the inbound request so a co-located
 * resource-server adapter can validate it normally — all in-process, no
 * outbound HTTP.
 *
 * The credentialed surface is **CSRF-protected by default**: a request that
 * carries the session cookie must also carry a custom `x-csrf` header (the
 * shipped `BffClient` and React adapter send it automatically), and the
 * `GET /auth/logout` navigation — which cannot carry one, and is what the
 * shipped client uses — is guarded by a same-origin check that fails closed.
 * `POST /auth/logout` is the stronger path to adopt. See
 * {@link HonoBffCsrfOptions}; pass `csrf: false` to disable.
 *
 * Sign-in itself is bound to the browser that started it, and that binding is
 * **not** configurable: `/auth/login` records the `state` it minted in a
 * short-lived `HttpOnly` `SameSite=Lax` cookie, and `/auth/callback` refuses
 * any authorization response whose `state` that cookie does not vouch for. A
 * pending authorization is therefore never completable from a browser other
 * than the one that began it, whatever
 * {@link HonoBffOptions.authRequestStorage} it is kept in — without it an
 * attacker could start a sign-in and hand the victim the callback URL to log
 * the victim into the attacker's account.
 *
 * @module
 */

import { Hono } from "hono";
import type { Context, Handler, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { ContentfulStatusCode, StatusCode } from "hono/utils/http-status";

import type {
  DirectClient,
  TokenBundle,
  UserInfoClaims,
} from "../../../client/mod.ts";
import {
  InvalidRequestError,
  InvalidTokenError,
  isOAuth2Error,
  type OAuth2Error,
  TemporarilyUnavailableError,
} from "../../../errors.ts";
import type { ClientInterface } from "../../../models/client.ts";
import type { AbstractScope, BasicScope } from "../../../models/scope.ts";
import { timingSafeMatchIndex } from "../../../utils/_timing-safe.ts";
import { sha256Hash } from "../../../server/utils/hash.ts";
import type { HonoAuthorizationServer } from "../authorization-server.ts";
import type { HonoResourceServer } from "../resource-server.ts";
import { OAUTH2_CONTEXT_KEY } from "../_common.ts";
import {
  loginContinuation as computeLoginContinuation,
  safeReturnTo,
} from "../../../utils/url.ts";
import type { AuthRequestStorageFactory } from "./auth-request-store.ts";
import {
  resolveCookieName,
  resolvePrefixConstrainedAttributes,
} from "./cookie-prefix.ts";
import {
  DEFAULT_SESSION_MAX_AGE_MS,
  MemorySessionStore,
  type SessionData,
  type SessionStore,
  sessionStoreMaxAgeMs,
  supportsBackchannelLogout,
} from "./session-store.ts";
import {
  buildDownstreamHeaders,
  buildUpstreamHeaders,
  type HonoBffProxyOptions,
  isInvalidTokenChallenge,
  resolveForwardHeaders,
  resolveProxyUrl,
} from "./proxy.ts";

/**
 * A resource server the BFF can compose with `attachToken()` to expose a
 * single `bff.protect()` middleware.
 *
 * Accepted in two shapes so both deployment topologies stay symmetric:
 *
 * - **Own-issuer** (the Udibo case): pass a {@link HonoAuthorizationServer}.
 *   `protect()` validates against the same in-process token service the
 *   issuer uses — no introspection round-trip.
 * - **Third-party-issuer**: pass a {@link HonoResourceServer} configured
 *   with `IntrospectionTokenReader`. `protect()` validates via RFC 7662
 *   against the upstream.
 */
export type HonoBffResourceServer<
  // deno-lint-ignore no-explicit-any
  Client extends ClientInterface = any,
  // deno-lint-ignore no-explicit-any
  User = any,
  S extends AbstractScope = BasicScope,
> =
  | HonoResourceServer<Client, User, S>
  | HonoAuthorizationServer<Client, User, S>;

/**
 * Cookie settings for the BFF session cookie. Defaults follow the IETF
 * "OAuth 2.0 for Browser-Based Apps" BCP §6.1.3.2: `Secure`, `HttpOnly`,
 * `SameSite=Strict`, `Path=/`, no `Domain`, and the `__Host-` name prefix.
 *
 * The **default** name is prefix-aware: it carries `__Host-` only when every
 * attribute that prefix requires holds, and falls back to the bare name
 * otherwise. An **explicit** {@link name} whose prefix contradicts the other
 * attributes throws from the {@link HonoBff} constructor instead of emitting a
 * cookie every browser silently drops.
 */
export interface HonoBffCookieOptions {
  /**
   * Cookie name. Defaults to `"__Host-oauth2_session"` (the BCP `__Host-`
   * prefix) when the other options satisfy that prefix — {@link secure} on,
   * {@link path} `"/"`, and no {@link domain} — and to `"oauth2_session"`
   * otherwise, because a browser rejects a `__Host-` cookie that breaks any of
   * them.
   *
   * Setting this explicitly to a `__Host-` or `__Secure-` prefixed name throws
   * from the {@link HonoBff} constructor when the other options contradict the
   * prefix. Prefixes are matched case-insensitively, as browsers match them.
   */
  name?: string;
  /**
   * Cookie path. Defaults to `"/"`. Any other value drops the default
   * `__Host-` prefix, which requires `Path=/`.
   */
  path?: string;
  /**
   * Marks the cookie Secure. Defaults to `true`. Turning it off drops the
   * default `__Host-` prefix, which requires `Secure`.
   */
  secure?: boolean;
  /** Marks the cookie HttpOnly. Defaults to `true`. */
  httpOnly?: boolean;
  /**
   * SameSite attribute. Defaults to `"Strict"` (per the BCP). Use `"Lax"` if
   * you run `sessionMode: "shared"` with a cross-origin IDP, so the cookie
   * survives the cross-site callback return.
   *
   * `"None"` requires {@linkcode HonoBffCookieOptions.secure}; the constructor
   * throws on the combination rather than emitting a cookie every modern
   * browser silently drops.
   */
  sameSite?: "Lax" | "Strict" | "None";
  /**
   * Optional cookie domain. The BCP recommends omitting it (host-bound).
   * Setting it drops the default `__Host-` prefix, which forbids `Domain`.
   */
  domain?: string;
  /**
   * `Max-Age` in seconds, for the **cookie only**. Defaults to
   * {@linkcode HonoBffOptions.sessionMaxAgeMs}, so the browser keeps the
   * cookie exactly as long as the session behind it is honored.
   *
   * Set it to lengthen the cookie past the session (harmless: the session ends
   * first and the stale cookie is cleared). Setting it **shorter** than the
   * session lifetime throws from the {@link HonoBff} constructor — that is the
   * pairing where the browser drops the cookie while the session stays active
   * and listed.
   *
   * Pass `"session"` for a true session cookie (no `Max-Age`, gone when the
   * browser closes). The server-side bound still applies, so the two agree:
   * an ephemeral cookie shortens the window, it never unbounds the session.
   */
  maxAge?: number | "session";
}

/**
 * CSRF defense for the BFF's credentialed surface.
 *
 * The BFF's session cookie is an ambient credential the browser attaches
 * automatically, so a cross-site page can trigger credentialed requests
 * (classic CSRF). The defense (as used by Duende.BFF's `X-CSRF` and Curity's
 * `token-handler-version` headers) requires a **custom request header** on the
 * fetch-driven surface: a custom header makes the request "non-simple", forcing
 * a CORS preflight that an untrusted origin cannot satisfy, so the browser never
 * attaches the cookie. The shipped `BffClient` (and therefore the React
 * adapter) sends this header automatically.
 *
 * Enforced only when the session cookie is actually present (an anonymous
 * request has nothing to abuse). Applies to `GET /auth/session`, the
 * `POST /auth/logout` path, and {@link HonoBff.protect} / {@link HonoBff.attachToken}'s
 * cookie path.
 *
 * `POST /auth/logout` is the **preferred** sign-out path because it is covered
 * by that header check. The `GET /auth/logout` navigation cannot carry a custom
 * header, so it is guarded instead by a same-origin check that reads
 * `Sec-Fetch-Site` (accepting only `same-origin` and `none`) and falls back to
 * comparing `Origin`, else `Referer`, for clients that send no fetch metadata.
 * `same-site` is rejected along with `cross-site`, so a `GET` logout link
 * followed from a sibling subdomain does not pass. That check **fails closed**:
 * a request carrying none of the three signals is rejected. Two residuals come
 * with it. A `GET` logout link followed from a no-referrer page on a browser too
 * old to send `Sec-Fetch-Site` stops working. And because
 * `Sec-Fetch-Site: none` survives redirects by design (W3C Fetch Metadata §4.1),
 * a navigation with no browser initiator — the address bar, a bookmark, or a
 * link opened from a native app such as an email client — that redirects into
 * the `GET` route still passes.
 *
 * **Both residuals apply to the shipped client today**, which signs out by
 * navigating the browser to `GET /auth/logout` (`BffClient.logout()` returns
 * the URL and the React adapter assigns it to `location`). `POST` is the path
 * to **adopt**, not one you already get: wire your sign-out control to post to
 * this route with the `x-csrf` header if a forgeable `GET` sign-out matters to
 * you.
 *
 * Pass `csrf: false` to disable (e.g. an example whose page uses hand-written
 * `fetch` for readability, or an app that has not yet migrated its call sites).
 */
export interface HonoBffCsrfOptions {
  /**
   * Header name required on credentialed fetch requests. Defaults to `"x-csrf"`.
   * Matched case-insensitively.
   */
  headerName?: string;
  /**
   * If set, the header must equal this value. Otherwise any non-empty value is
   * accepted — presence is what forces the CORS preflight. Defaults to presence.
   */
  headerValue?: string;
}

/** Paths for the session endpoints mounted by {@link HonoBff.routes}. */
export interface HonoBffPaths {
  /**
   * The base the caller mounts {@link HonoBff.routes} under — stripped from
   * the paths below so each handler registers at the right sub-path. Defaults
   * to `/auth`, matching the default paths and the documented
   * `app.route("/auth", bff.routes())`.
   *
   * Set it whenever you move the surface: with
   * `basePath: "/session", login: "/session/login"` the router registers
   * `/login`, so `app.route("/session", bff.routes())` serves
   * `/session/login`. Pass `""` to mount the paths verbatim at the app root.
   *
   * A trailing slash is ignored. Unless it is `""`, **every path that gets
   * mounted must sit strictly under it** (`${basePath}/…`) — the constructor
   * throws otherwise, because `routes()` strips the base to mount each handler
   * while {@link HonoBff.loginContinuation} and the session probe's `logoutUrl`
   * hand out the unstripped paths, so a stray path would be served at one URL
   * and advertised at another. {@link HonoBffPaths.backchannel} is exempt
   * unless {@link HonoBffOptions.backchannelLogout} is configured, since
   * `routes()` mounts it only then.
   */
  basePath?: string;
  /** Where the browser is sent to begin sign-in. Defaults to `/auth/login`. */
  login?: string;
  /** Redirect target the IDP returns to after authorization. Defaults to `/auth/callback`. */
  callback?: string;
  /** Ends the session and clears the cookie. Defaults to `/auth/logout`. */
  logout?: string;
  /** Probed by the SPA for `{ isAuthenticated, user }`. Defaults to `/auth/session`. */
  session?: string;
  /** OIDC Back-Channel Logout receiver. Defaults to `/auth/backchannel`. */
  backchannel?: string;
}

/**
 * The subject / OP-session-id a validated OIDC `logout_token` says to log out.
 * Returned by {@link HonoBffBackchannelOptions.verifyLogoutToken}.
 */
export interface BackchannelLogoutSubject {
  /** The `sub` claim — log out all of the subject's sessions when no `sid`. */
  sub?: string;
  /** The `sid` claim — log out only the session with this OP session id. */
  sid?: string;
}

/**
 * OIDC Back-Channel Logout configuration. When set, {@link HonoBff.routes}
 * mounts a `POST /auth/backchannel` receiver.
 *
 * **Signature verification is yours.** The package stays dependency-free, so you
 * supply `verifyLogoutToken`: verify the JWT's signature (against the OP's JWKS,
 * e.g. with `jose`, or in-process for a co-located IDP) **and** its claims
 * (`iss`, `aud`, `iat`, `exp`, the required `events` member
 * `http://schemas.openid.net/event/backchannel-logout`, `sub`/`sid` presence,
 * `nonce` absence, and `jti` replay), then return the `{ sub, sid }` to log out.
 * Throw or return `null` to reject (the receiver responds `400`).
 *
 * Requires a {@link SessionStore} that implements `destroyByLogout`
 * (the in-memory and DB-backed stateful stores do; the stateless encrypted
 * cookie store cannot — construction throws if the store can't support it).
 */
export interface HonoBffBackchannelOptions {
  /**
   * Verifies a raw `logout_token` JWT (signature and claims) and returns the
   * `{ sub, sid }` to log out. Throw or return `null` to reject the request.
   */
  verifyLogoutToken: (
    logoutToken: string,
  ) =>
    | Promise<BackchannelLogoutSubject | null>
    | BackchannelLogoutSubject
    | null;
}

/**
 * Why `/auth/callback` could not complete a sign-in. Passed to
 * {@link HonoBffOptions.onCallbackError} so the app can render or redirect to a
 * friendly page instead of the default JSON.
 */
export interface BffCallbackError {
  /**
   * OAuth2-style error code: the IDP's `error` (e.g. `access_denied`),
   * `invalid_request` (missing `code`/`state`, or a `state` this browser never
   * started — see {@link HonoBffOptions.loginStateTtlMs}), or `invalid_grant`
   * (the code exchange failed — expired/replayed code, unknown `state`).
   */
  error: string;
  /** Human-readable description; never contains secrets. */
  error_description: string;
  /** The thrown cause for the `invalid_grant` (exchange) case; otherwise `undefined`. */
  cause?: unknown;
}

/** Options accepted by the {@link HonoBff} constructor. */
export interface HonoBffOptions {
  /**
   * OAuth2 client for the authorization server, constructed with a
   * `clientSecret`. The BFF drives the flows through its
   * `exchangeAuthorizationCode` / `exchangeRefreshToken` primitives; tokens
   * are stored in {@link HonoBffOptions.sessionStore} — **not** in the
   * client's token storage.
   */
  client: DirectClient;
  /**
   * Where session data lives. Defaults to {@link MemorySessionStore},
   * which is fine for dev and tests but must be replaced for production.
   */
  sessionStore?: SessionStore;
  /**
   * How long a BFF session is meant to live, in milliseconds. Defaults to 14
   * days ({@link DEFAULT_SESSION_MAX_AGE_MS}). Milliseconds match the store's
   * `maxAgeMs` and `loginStateTtlMs`; `cookie.maxAge` stays in seconds because
   * that is the unit of the HTTP `Max-Age` attribute it sets.
   *
   * This is the **one** place the lifetime is stated. It sets the session
   * cookie's `Max-Age` (see {@linkcode HonoBffCookieOptions.maxAge}) and, in
   * the default `sessionMode: "own"`, it is enforced on every read: a session
   * older than this is destroyed and its cookie cleared, so the cookie and the
   * record behind it can never disagree about whether the user is signed in.
   * Measured from `createdAt`, so it caps the session absolutely rather than
   * rolling forward with each token refresh. A store that does not persist
   * `createdAt` therefore opts its sessions out of this cap entirely — they
   * never age out. `runSessionStoreContractTests` pins that round-trip, so run
   * it against any store you write.
   *
   * Applies in the default `sessionMode: "own"` only. In
   * `sessionMode: "shared"` the app owns the session record and its cookie's
   * lifetime — often per session (remember-me vs ephemeral) — so this value is
   * ignored there: the BFF writes only an explicit {@linkcode
   * HonoBffCookieOptions.maxAge}, or an ephemeral cookie the app re-stamps.
   *
   * A store that advertises its own bound (see `BoundedSessionStore`, which
   * {@linkcode EncryptedCookieSessionStore} implements) is cross-checked at
   * construction: if the cookie would die before that store stops honoring the
   * session, the constructor throws instead of shipping the mismatch.
   */
  sessionMaxAgeMs?: number;
  /**
   * Where the pending authorization request (`state` → PKCE verifier,
   * return-to) lives, resolved per request. Defaults to the client's
   * configured `authRequestStorage`, which is in-memory unless the client was
   * given something else — fine for a single long-lived process, wrong for any
   * platform that can serve `/auth/login` and `/auth/callback` from different
   * isolates. Pass an {@link EncryptedCookieAuthRequestStorage} to carry the
   * record in an encrypted cookie instead, or implement
   * {@link AuthRequestStorageFactory} over storage of your own.
   *
   * Whatever this resolves to, the pending request is **also** bound to the
   * browser that started it by the login-state cookie, which no option turns
   * off. See {@link loginStateTtlMs}.
   */
  authRequestStorage?: AuthRequestStorageFactory;
  /**
   * How long, in ms, the browser keeps the login-state cookie `/auth/login`
   * sets and `/auth/callback` requires — the `Max-Age` on that cookie, and so
   * the window a started sign-in can still be completed in. Defaults to 10
   * minutes, matching `DirectClient`'s `authRequestTtlMs` default; raise both
   * together, since whichever expires first ends the pending sign-in.
   *
   * The cookie holds only SHA-256 hashes of the `state` values (the three most
   * recent, so parallel sign-ins in several tabs all stay completable), is
   * `HttpOnly`, `SameSite=Lax` — the strictest value that survives the
   * identity provider's redirect back — and inherits {@link cookie}'s
   * `secure` / `path` / `domain` so plain-HTTP local development works.
   */
  loginStateTtlMs?: number;
  /**
   * Who owns the BFF's session record. Defaults to `"own"`.
   *
   * - `"own"` (default): the BFF creates and owns its session at
   *   `/auth/callback` — it always mints a fresh id (`sessionStore.create`)
   *   and ignores any inbound cookie. Use when the app has no session here
   *   until the OAuth flow completes: standalone BFFs, or apps whose login
   *   lives on a separate / external IDP.
   * - `"shared"`: the app already created the session at its own login step,
   *   and the BFF **attaches** tokens to that existing session at
   *   `/auth/callback` (via `sessionStore.update`) instead of creating its
   *   own. Set {@link HonoBffCookieOptions.name} to the app's session-cookie
   *   name and back `sessionStore` with the app's session record. Use for a
   *   colocated first-party SPA that is also its own IDP, so the user has
   *   **one** session (login + tokens on one record), not two. If no session
   *   cookie is present at the callback the BFF falls back to creating one.
   *   `/auth/logout` destroys the whole shared session (a full sign-out).
   *   The app's cookie stays the app's: the BFF emits `Set-Cookie` only when
   *   the store hands back a **different** value (a stateless store does on
   *   every write), never to re-stamp an unchanged one — re-stamping would
   *   replace the attributes the app chose, turning a remember-me cookie
   *   with a `Max-Age` into a session cookie the browser drops on exit.
   *
   * Note on session fixation: this is the standard "renew the session id on
   * authentication" control. In `"own"` mode the BFF performs the renewal
   * (fresh id at the callback). In `"shared"` mode that responsibility sits
   * with your login step — use a login that mints a fresh session id on
   * success (the typical behavior, e.g. a session service that generates a
   * new id per login) so a pre-planted cookie can't survive authentication.
   */
  sessionMode?: "own" | "shared";
  /** Cookie attribute tweaks. */
  cookie?: HonoBffCookieOptions;
  /**
   * CSRF defense for the credentialed surface. Enabled by default with a
   * `"x-csrf"` header requirement; pass `false` to disable, or an object to
   * customize the header. See {@link HonoBffCsrfOptions}.
   */
  csrf?: HonoBffCsrfOptions | false;
  /**
   * OIDC RP-Initiated Logout. When `true` **and** the configured client knows
   * an end-session endpoint (`endpoints.endSession`, or via discovery),
   * `/auth/logout` — after destroying the local session — additionally
   * redirects the browser to the OP's `end_session_endpoint` with
   * `id_token_hint` (the session's id_token, if any) and a
   * `post_logout_redirect_uri` built from the resolved origin + the
   * open-redirect-guarded `return_to`. This ends the upstream IDP SSO session,
   * not just the local BFF session.
   *
   * Defaults to `false` (local logout only): not every IDP supports it, and it
   * adds a redirect hop. When enabled but no end-session endpoint is known,
   * logout falls back to the plain local redirect and warns once via
   * `console.warn` — a client built from an explicit `endpoints` object with no
   * `endSession` and no `issuer` can never learn one by discovery, so the
   * feature would otherwise no-op silently.
   */
  rpInitiatedLogout?: boolean;
  /**
   * OIDC Back-Channel Logout. When set, `routes()` mounts a
   * `POST /auth/backchannel` receiver that ends the matching server-side
   * session(s) when the OP notifies it. See {@link HonoBffBackchannelOptions}.
   */
  backchannelLogout?: HonoBffBackchannelOptions;
  /** Endpoint paths (within whatever base the caller mounts this under). */
  paths?: HonoBffPaths;
  /**
   * Scope string requested at `/auth/login`, and the scope the login flow
   * records for the authorization request it started.
   *
   * Server-chosen: a browser cannot change it by putting `scope` on the login
   * URL. An application that wants the browser to choose lists `scope` in
   * {@link forwardedParams}, and a forwarded value then **replaces** this one
   * rather than narrowing it.
   */
  scope?: string;
  /**
   * Extra parameters added to every authorize request `/auth/login` builds —
   * `login_hint`, `ui_locales`, `acr_values`, or whatever else the
   * authorization server accepts, such as a parameter naming the organization
   * a sign-in should land in.
   *
   * Server-chosen: these values are fixed when the BFF is constructed, so they
   * carry the same trust as {@link scope} and nothing a browser sends can
   * change them. When the browser is the one that should choose a parameter's
   * value, name it in {@link forwardedParams} instead.
   *
   * `prompt` is an ordinary name here — pin `{ prompt: "login" }` to make
   * every sign-in re-authenticate. `scope` is refused, because {@link scope}
   * already carries it and is the value the login flow records as the scope
   * it requested; setting both would leave which one applies ambiguous.
   *
   * A name the login flow reserves is refused at construction rather than
   * quietly dropped — {@link forwardedParams} carries the list and the reason.
   *
   * @example Pin every sign-in to one organization
   * ```ts
   * declare const client: DirectClient;
   *
   * const bff = new HonoBff({ client, extraParams: { organization: "acme" } });
   * ```
   */
  extraParams?: Record<string, string>;
  /**
   * Names of extra authorize parameters `/auth/login` may take off its own
   * query string. Empty by default, so a parameter that is not listed here is
   * not forwarded no matter who puts it on the login URL — `scope` and
   * `prompt` included. `routes()` serves login at `GET` and `POST` alike, and
   * both read the query string only, never a request body.
   *
   * Browser-chosen, and so untrusted: whatever a browser puts in
   * `/auth/login?<name>=…` reaches the authorization server verbatim, and the
   * BFF checks nothing but the name. The test to apply is not "does the
   * authorization server validate this parameter" but **"would I accept every
   * value it could carry"** — the two are different properties, and a
   * parameter can pass the first and fail the second. `acr_values` and
   * `max_age` are the cautionary pair: a server validates both and then
   * *honors* them, so a browser naming a weaker authentication context or a
   * longer re-authentication window gets a downgrade the server cooperates
   * with. For a value this deployment decides, use {@link extraParams}, which
   * no browser can reach.
   *
   * A parameter already baked into the configured authorization endpoint's
   * own query string is overridable this way too, and silently: the client
   * keeps that query string and then sets each extra parameter over it. The
   * reserved list below cannot know a name a deployment baked into its
   * endpoint URL, so check that URL before listing anything here.
   *
   * Reserved on this option and on {@link extraParams} alike, and refused when
   * the BFF is constructed — matched case-insensitively, since an
   * authorization server that folds parameter-name case would otherwise make
   * `Client_Id` a way around the list:
   *
   * - `response_type`, `client_id`, `redirect_uri`, `state`,
   *   `code_challenge`, `code_challenge_method` — the client mints or derives
   *   each one for the single sign-in in progress, and a supplied value
   *   replaces it, which variously redirects the authorization code, breaks
   *   the PKCE binding the token exchange depends on, or unpicks the `state`
   *   the login-state cookie commits to.
   * - `response_mode` — moves the authorization response out of the callback
   *   URL's query string, the only place `/auth/callback` reads it from.
   * - `nonce` — this client neither sends nor verifies one, so a supplied
   *   value would look like replay protection that nothing checks.
   * - `request`, `request_uri` — a request object supersedes the parameters
   *   beside it at an authorization server implementing RFC 9101, which puts
   *   every name above back within reach.
   *
   * Naming the same parameter both here and in {@link extraParams} is refused
   * as well: one pins the value every sign-in carries and the other lets the
   * browser choose it, so which one applies would be ambiguous.
   *
   * `scope` and `prompt` are ordinary names on this option, and the two worth
   * the most thought before listing. Listing `scope` lets whoever writes the
   * login link choose the breadth of the grant the session is minted with:
   * the value replaces {@link scope} rather than narrowing it, bounded only
   * by what the authorization server will grant this client. Listing `prompt`
   * hands over the authentication ceremony instead of the grant — it is what
   * a SPA needs to start a silent renew with `/auth/login?prompt=none`, and
   * the same entry lets a link suppress a re-authentication the application
   * meant to force. Where the deployment should decide either one, use
   * {@link scope} or a pinned {@link extraParams} entry, which no browser can
   * reach.
   *
   * @example Let a sign-in link choose the organization
   * ```ts
   * declare const client: DirectClient;
   *
   * const bff = new HonoBff({ client, forwardedParams: ["organization"] });
   * ```
   *
   * A link to `/auth/login?organization=acme&return_to=/dashboard` then
   * reaches the authorization server as `…&organization=acme`.
   */
  forwardedParams?: readonly string[];
  /** Default `return_to` applied when the browser doesn't pass one. */
  defaultReturnTo?: string;
  /**
   * Optional hook run after the authorization code is exchanged. Lets
   * apps enrich the session with database-backed user info before the
   * session cookie is set.
   */
  resolveUser?: (
    tokens: TokenBundle,
    idTokenClaims: UserInfoClaims | null,
  ) => Promise<UserInfoClaims | null> | UserInfoClaims | null;
  /**
   * Optional hook invoked when `/auth/callback` cannot complete the sign-in
   * (see {@link BffCallbackError} for the cases). The browser reaches the
   * callback via a full-page navigation, so the default JSON `400` is not
   * user-friendly — return a redirect to a sign-in/error page instead, e.g.
   * `c.redirect(`/sign-in?error=${err.error}`)`. When omitted, the BFF responds
   * with a `400` JSON body `{ error, error_description }`.
   */
  onCallbackError?: (
    c: Context,
    error: BffCallbackError,
  ) => Response | Promise<Response>;
  /**
   * Clock skew (seconds) applied when deciding whether the access token
   * is close enough to expiry that {@link HonoBff.attachToken} should
   * refresh proactively. Defaults to 30s.
   */
  refreshSkewSeconds?: number;
  /**
   * Optional resource server. When provided, {@link HonoBff.protect}
   * becomes available — a single middleware that composes
   * {@link HonoBff.attachToken} with `resourceServer.protect(scope)`.
   *
   * Pass a {@link HonoAuthorizationServer} for own-issuer co-located
   * deployments (validation happens against the in-process token service)
   * or a {@link HonoResourceServer} for third-party-issuer deployments
   * (validation goes through `IntrospectionTokenReader`).
   */
  resourceServer?: HonoBffResourceServer;
  /**
   * Resolves the per-request origin (scheme + host) used to build the
   * browser-facing authorize URL and `redirect_uri`. Lets ONE build-once BFF
   * serve every deployment host (preview URLs, multi-tenant subdomains): the
   * configured client's authorize/redirect paths are retargeted at this
   * origin per request. Return only allowlisted/trusted origins (never a raw
   * forged `Host`). When omitted, the client's configured origin is used.
   */
  resolveOrigin?: (c: Context) => string;
  /**
   * Derive the OAuth2 `redirect_uri` from the mounted callback path instead of
   * requiring it in the client config. When `true`, every login/callback uses
   * `redirect_uri = <origin><callback path>` (origin from {@link resolveOrigin},
   * else the request's). The same value is sent at authorize and at the token
   * exchange (RFC 6749 §4.1.3), re-derived from the request each time. Pairs
   * with an `issuer`-configured client (discovery) for a BFF you configure by
   * issuer alone — no restated endpoints or redirect URI. Defaults to `false`
   * (use the client's configured `redirectUri`).
   */
  deriveRedirectUri?: boolean;
}

/** A session read from the store, paired with the cookie value it lives under. */
interface SessionEntry {
  cookieValue: string;
  data: SessionData;
}

/**
 * What resolving the session cookie produced. `unavailable` is kept apart from
 * `anonymous` so a refresh the authorization server never answered reports a
 * transient failure instead of signing the user out.
 */
type SessionResolution =
  | { status: "active"; entry: SessionEntry }
  | { status: "anonymous" }
  | { status: "unavailable" };

/**
 * What a refresh attempt did to the session.
 *
 * `revoked` and `unavailable` are deliberately distinct: the authorization
 * server saying the grant is dead is the only reason to end a user's session.
 * A network blip, a 5xx, or a 429 must not, or one bad minute at the IdP signs
 * out every user at once.
 */
type RefreshOutcome =
  | { status: "refreshed"; entry: SessionEntry }
  | { status: "revoked" }
  | { status: "unavailable" };

/**
 * Whether the authorization server definitively rejected the grant, as opposed
 * to failing to answer. Only these end the session.
 */
function isRevokedGrant(error: unknown): boolean {
  if (!isOAuth2Error(error)) return false;
  const code = error.extensions.error;
  return code === "invalid_grant" || code === "invalid_token";
}

/** Fully-resolved paths with defaults applied. */
interface ResolvedPaths {
  basePath: string;
  login: string;
  callback: string;
  logout: string;
  session: string;
  backchannel: string;
}

const BFF_PATH_KEYS = [
  "login",
  "callback",
  "logout",
  "session",
  "backchannel",
] as const;

function resolvePaths(
  paths: HonoBffPaths = {},
  options: { backchannelMounted: boolean },
): ResolvedPaths {
  const basePath = (paths.basePath ?? "/auth").replace(/\/+$/, "");
  const resolved: ResolvedPaths = {
    basePath,
    login: paths.login ?? "/auth/login",
    callback: paths.callback ?? "/auth/callback",
    logout: paths.logout ?? "/auth/logout",
    session: paths.session ?? "/auth/session",
    backchannel: paths.backchannel ?? "/auth/backchannel",
  };
  if (basePath === "") return resolved;
  const stray = BFF_PATH_KEYS
    .filter((key) => key !== "backchannel" || options.backchannelMounted)
    .filter((key) => !resolved[key].startsWith(`${basePath}/`))
    .map((key) => `${key} ("${resolved[key]}")`);
  if (stray.length > 0) {
    throw new Error(
      `HonoBff paths must sit under paths.basePath "${basePath}", but ` +
        `${stray.join(", ")} ${stray.length === 1 ? "does" : "do"} not. ` +
        `routes() strips the base to mount each handler while ` +
        `loginContinuation() and the session probe's logoutUrl hand out the ` +
        `unstripped paths, so a stray path is served at one URL and ` +
        `advertised at another. Move it under "${basePath}/", or set ` +
        `paths.basePath to "" to mount every path verbatim.`,
    );
  }
  return resolved;
}

function sessionCookieName(opts: HonoBffCookieOptions | undefined): string {
  return resolveCookieName({
    name: opts?.name,
    base: "oauth2_session",
    attributes: resolvePrefixConstrainedAttributes(opts),
    consequence: "the session would silently never persist",
  });
}

/** Resolved CSRF config, or `null` when disabled. */
interface ResolvedCsrf {
  headerName: string;
  headerValue?: string;
}

function resolveCsrf(
  opt: HonoBffCsrfOptions | false | undefined,
): ResolvedCsrf | null {
  if (opt === false) return null;
  return {
    headerName: (opt?.headerName ?? "x-csrf").toLowerCase(),
    headerValue: opt?.headerValue,
  };
}

const RESERVED_AUTHORIZE_PARAMS = [
  "response_type",
  "client_id",
  "redirect_uri",
  "state",
  "code_challenge",
  "code_challenge_method",
  "response_mode",
  "nonce",
  "request",
  "request_uri",
];

const RESERVED_AUTHORIZE_PARAM_SET = new Set(RESERVED_AUTHORIZE_PARAMS);

/** The extra authorize parameters one BFF may send, split by who chooses them. */
interface ResolvedExtraAuthorizeParams {
  fixed: Record<string, string>;
  forwarded: readonly string[];
}

function assertUsableAuthorizeParamName(name: string, option: string): void {
  if (name === "" || name !== name.trim()) {
    throw new Error(
      `${option} may not use ${JSON.stringify(name)} as an ` +
        "authorize-parameter name: a name must be non-empty and free of " +
        "surrounding whitespace. A blank name addresses nothing at the " +
        "authorization server, and a padded one is not the parameter it " +
        `looks like — " state" is sent as "+state", so it would slip past ` +
        "the reserved list below while reading as a name on that list. " +
        "Splitting a list out of an environment variable without trimming " +
        "is the usual source.",
    );
  }
  if (!RESERVED_AUTHORIZE_PARAM_SET.has(name.toLowerCase())) return;
  throw new Error(
    `${option} may not name the authorize parameter "${name}". The login ` +
      `flow reserves ${RESERVED_AUTHORIZE_PARAMS.join(", ")}, and must be ` +
      "the only source of their values: one supplied from outside it would " +
      "variously redirect the authorization code, break the PKCE binding " +
      "the token exchange depends on, unpick the state the login-state " +
      "cookie commits to, move the authorization response off the callback " +
      "URL, pass off replay protection nothing verifies, or supersede the " +
      "parameters beside it. None of them has a supported override.",
  );
}

function resolveExtraAuthorizeParams(
  options: HonoBffOptions,
): ResolvedExtraAuthorizeParams {
  const fixed = Object.freeze({ ...options.extraParams });
  const forwarded = Object.freeze([...(options.forwardedParams ?? [])]);
  const pinnedByFoldedName = new Map<string, string>();
  for (const name of Object.keys(fixed)) {
    assertUsableAuthorizeParamName(name, "extraParams");
    if (name.toLowerCase() === "scope" && options.scope !== undefined) {
      throw new Error(
        `extraParams may not set ${JSON.stringify(name)} while ` +
          "HonoBffOptions.scope is set: both fix the scope every authorize " +
          "request carries, so which one a sign-in should send would be " +
          "ambiguous. The two are compared case-insensitively, since an " +
          "authorization server that folds parameter-name case would read " +
          "them as one parameter. Keep HonoBffOptions.scope, which is also " +
          "the value the login flow records as the scope it requested.",
      );
    }
    pinnedByFoldedName.set(name.toLowerCase(), name);
  }
  for (const name of forwarded) {
    assertUsableAuthorizeParamName(name, "forwardedParams");
    const pinned = pinnedByFoldedName.get(name.toLowerCase());
    if (pinned !== undefined) {
      throw new Error(
        `forwardedParams may not list "${name}" while extraParams sets ` +
          `"${pinned}": one pins the value every authorize request carries ` +
          "and the other lets the browser choose it, so which value a " +
          "sign-in should send would be ambiguous. The two are compared " +
          "case-insensitively, since an authorization server that folds " +
          "parameter-name case would read them as one parameter. Keep the " +
          "fixed value in extraParams, or list the name in forwardedParams " +
          "alone.",
      );
    }
  }
  return { fixed, forwarded };
}

/**
 * What one login request sends beyond the protocol parameters, with the two
 * the login call takes as their own options split out from the rest.
 */
interface RequestAuthorizeParams {
  scope?: string;
  prompt?: string;
  extraParams?: Record<string, string>;
}

function authorizeParamsForRequest(
  resolved: ResolvedExtraAuthorizeParams,
  requestParams: URLSearchParams,
): RequestAuthorizeParams {
  const entries = Object.entries(resolved.fixed);
  for (const name of resolved.forwarded) {
    const value = requestParams.get(name);
    if (value !== null) entries.push([name, value]);
  }
  const resolvedParams: RequestAuthorizeParams = {};
  const extraParams: Record<string, string> = {};
  for (const [name, value] of entries) {
    const folded = name.toLowerCase();
    if (folded === "scope") resolvedParams.scope = value;
    else if (folded === "prompt") resolvedParams.prompt = value;
    else extraParams[name] = value;
  }
  if (Object.keys(extraParams).length > 0) {
    resolvedParams.extraParams = extraParams;
  }
  return resolvedParams;
}

function cookieOpts(
  opts: HonoBffCookieOptions | undefined,
  maxAgeSeconds: number | undefined,
) {
  const { secure, path, domain } = resolvePrefixConstrainedAttributes(opts);
  return {
    path,
    secure,
    httpOnly: opts?.httpOnly ?? true,
    sameSite: (opts?.sameSite ?? "Strict") as "Lax" | "Strict" | "None",
    domain,
    ...(maxAgeSeconds === undefined ? {} : { maxAge: maxAgeSeconds }),
  };
}

const MAX_COOKIE_MAX_AGE_SECONDS = 400 * 24 * 60 * 60;
const MAX_SESSION_MAX_AGE_MS = MAX_COOKIE_MAX_AGE_SECONDS * 1000;

function positiveSeconds(value: number, field: string): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(
      `${field} must be a positive number of seconds, got ${value}.`,
    );
  }
  if (value > MAX_COOKIE_MAX_AGE_SECONDS) {
    throw new Error(
      `${field} must not exceed 400 days (${MAX_COOKIE_MAX_AGE_SECONDS} ` +
        `seconds), got ${value}. Browsers cap cookie lifetimes there, so a ` +
        "larger value would fail when the cookie is written, not here.",
    );
  }
  return value;
}

function positiveMs(value: number, field: string): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(
      `${field} must be a positive number of milliseconds, got ${value}.`,
    );
  }
  if (value > MAX_SESSION_MAX_AGE_MS) {
    throw new Error(
      `${field} must not exceed 400 days (${MAX_SESSION_MAX_AGE_MS} ` +
        `milliseconds), got ${value}. Browsers cap cookie lifetimes there, so ` +
        "a larger value would fail when the cookie is written, not here.",
    );
  }
  return value;
}

const LOGIN_STATE_BASE_NAME = "oauth2_login_state";
const DEFAULT_LOGIN_STATE_TTL_MS = 10 * 60 * 1000;
const MAX_PENDING_LOGIN_STATES = 3;
const LOGIN_STATE_SEPARATOR = ".";

function loginStateCookieName(opts: HonoBffCookieOptions | undefined): string {
  return resolveCookieName({
    name: undefined,
    base: LOGIN_STATE_BASE_NAME,
    attributes: resolvePrefixConstrainedAttributes(opts),
    consequence: "every sign-in would fail at the callback",
  });
}

function loginStateCookieOpts(
  opts: HonoBffCookieOptions | undefined,
  maxAgeSeconds?: number,
) {
  const { secure, path, domain } = resolvePrefixConstrainedAttributes(opts);
  return {
    path,
    secure,
    httpOnly: true,
    sameSite: "Lax" as const,
    ...(domain ? { domain } : {}),
    ...(maxAgeSeconds === undefined ? {} : { maxAge: maxAgeSeconds }),
  };
}

/**
 * Backend-for-Frontend adapter for Hono. Construct once per app, mount
 * `routes()` under `/auth`, and use `attachToken()` as middleware on
 * protected API routes. Apps that own their login surface (a custom sign-in
 * form, create-account, forgot-password) call `loginContinuation()` to hand
 * back to the OAuth2 flow after authenticating a user.
 */
export class HonoBff {
  readonly #options: HonoBffOptions;
  readonly #client: DirectClient;
  readonly #store: SessionStore;
  readonly #paths: ResolvedPaths;
  readonly #cookieName: string;
  readonly #loginStateCookieName: string;
  readonly #loginStateTtlMs: number;
  readonly #sessionMaxAgeMs: number;
  readonly #cookieMaxAgeSeconds: number | undefined;
  #warnedLogoutIsLocalOnly = false;
  readonly #sessionMode: "own" | "shared";
  readonly #csrf: ResolvedCsrf | null;
  readonly #extraAuthorizeParams: ResolvedExtraAuthorizeParams;
  readonly #refreshes = new Map<string, Promise<RefreshOutcome>>();

  /**
   * Defaults are applied for the session store ({@linkcode MemorySessionStore}),
   * session mode (`"own"`), cookie name, and CSRF.
   *
   * @throws {Error} When {@linkcode HonoBffOptions.backchannelLogout} is
   * configured against a store that cannot enumerate sessions (e.g.
   * {@linkcode EncryptedCookieSessionStore}), when an explicit
   * {@linkcode HonoBffCookieOptions.name} carries a `__Host-`/`__Secure-`
   * prefix the other cookie options contradict, when
   * {@linkcode HonoBffCookieOptions.sameSite} is `"None"` without
   * {@linkcode HonoBffCookieOptions.secure}, when any
   * {@linkcode HonoBffPaths} entry falls outside a non-empty
   * {@linkcode HonoBffPaths.basePath}, when the session cookie would die
   * before the session behind it (see
   * {@linkcode HonoBffOptions.sessionMaxAgeMs}), or when
   * {@linkcode HonoBffOptions.extraParams} or
   * {@linkcode HonoBffOptions.forwardedParams} names a reserved authorize
   * parameter, gives one a name that is empty or not equal to its trimmed
   * form (`" state"` and `"organization "` are refused rather than trimmed),
   * names the same parameter in both, or pins `scope` in
   * {@linkcode HonoBffOptions.extraParams} while
   * {@linkcode HonoBffOptions.scope} is also set.
   */
  constructor(options: HonoBffOptions) {
    this.#options = options;
    this.#client = options.client;
    this.#store = options.sessionStore ?? new MemorySessionStore();
    this.#paths = resolvePaths(options.paths, {
      backchannelMounted: options.backchannelLogout !== undefined,
    });
    this.#cookieName = sessionCookieName(options.cookie);
    this.#loginStateCookieName = loginStateCookieName(options.cookie);
    this.#loginStateTtlMs = options.loginStateTtlMs ??
      DEFAULT_LOGIN_STATE_TTL_MS;
    this.#sessionMode = options.sessionMode ?? "own";
    this.#csrf = resolveCsrf(options.csrf);
    this.#extraAuthorizeParams = resolveExtraAuthorizeParams(options);

    const sessionMaxAgeMs = positiveMs(
      options.sessionMaxAgeMs ?? DEFAULT_SESSION_MAX_AGE_MS,
      "sessionMaxAgeMs",
    );
    this.#sessionMaxAgeMs = sessionMaxAgeMs;
    if (this.#sessionMode === "shared") {
      const maxAge = options.cookie?.maxAge;
      this.#cookieMaxAgeSeconds = maxAge === undefined || maxAge === "session"
        ? undefined
        : positiveSeconds(maxAge, "cookie.maxAge");
    } else {
      const configuredMaxAge = options.cookie?.maxAge ??
        Math.ceil(sessionMaxAgeMs / 1000);
      this.#cookieMaxAgeSeconds = configuredMaxAge === "session"
        ? undefined
        : positiveSeconds(configuredMaxAge, "cookie.maxAge");
      if (this.#cookieMaxAgeSeconds !== undefined) {
        const storeMaxAgeMs = sessionStoreMaxAgeMs(this.#store);
        const sessionSeconds = Math.ceil(
          Math.max(sessionMaxAgeMs, storeMaxAgeMs ?? 0) / 1000,
        );
        if (this.#cookieMaxAgeSeconds < sessionSeconds) {
          const cookieSource = options.cookie?.maxAge !== undefined
            ? `cookie.maxAge (${this.#cookieMaxAgeSeconds}s)`
            : `the session cookie's Max-Age (${this.#cookieMaxAgeSeconds}s, ` +
              "taken from sessionMaxAgeMs)";
          const storeDrivesIt = (storeMaxAgeMs ?? 0) > sessionMaxAgeMs;
          const remedy = storeDrivesIt
            ? `Set sessionMaxAgeMs to ${sessionSeconds * 1000} so it matches ` +
              "the session store's maxAgeMs, or lower that maxAgeMs to match " +
              "the lifetime you want."
            : "Raise cookie.maxAge, lower sessionMaxAgeMs (and the " +
              'store\'s maxAgeMs) to match, or pass cookie.maxAge: "session" ' +
              "for a deliberately ephemeral cookie.";
          throw new Error(
            `${cookieSource} is shorter than the session lifetime ` +
              `(${sessionSeconds}s): the browser drops the cookie while the ` +
              "session stays active and listed, so the user is signed out " +
              `with no way to reach the session they still have. ${remedy}`,
          );
        }
      }
    }

    if (options.backchannelLogout && !supportsBackchannelLogout(this.#store)) {
      throw new Error(
        "backchannelLogout requires a SessionStore that implements " +
          "destroyByLogout() (a stateful store). The stateless " +
          "EncryptedCookieSessionStore cannot enumerate sessions.",
      );
    }
  }

  /**
   * Cookie name used for the session cookie. Read-only; configured via
   * {@link HonoBffOptions.cookie}.
   */
  get cookieName(): string {
    return this.#cookieName;
  }

  /**
   * Name of the cookie `/auth/login` binds the pending sign-in's `state` to
   * and `/auth/callback` requires. Read-only; derived from
   * {@link HonoBffOptions.cookie}'s `secure` / `path` / `domain` (it carries
   * the `__Host-` prefix whenever they allow it). A test that drives the
   * login flow by hand must carry this cookie from the login response into
   * the callback request, exactly as a browser would.
   */
  get loginStateCookieName(): string {
    return this.#loginStateCookieName;
  }

  /**
   * The CSRF header name required on credentialed requests, or `undefined`
   * when CSRF is disabled. Useful in tests that seed a session and then call a
   * protected route — they must send `{ [bff.csrfHeaderName!]: "1" }` alongside
   * the cookie. The shipped `BffClient` / React adapter send it
   * automatically in real apps.
   */
  get csrfHeaderName(): string | undefined {
    return this.#csrf?.headerName;
  }

  /**
   * The underlying session store. Exposed primarily for testing helpers
   * (e.g. seeding a session directly without driving the login flow);
   * production code should not reach in here.
   */
  get sessionStore(): SessionStore {
    return this.#store;
  }

  #hasSessionCookie(c: Context): boolean {
    return getCookie(c, this.#cookieName) !== undefined;
  }

  #cookieOptions() {
    return cookieOpts(this.#options.cookie, this.#cookieMaxAgeSeconds);
  }

  #isBeyondSessionMaxAge(data: SessionData): boolean {
    if (this.#sessionMode !== "own") return false;
    const { createdAt } = data;
    if (!Number.isFinite(createdAt) || createdAt <= 0) return false;
    return Date.now() - createdAt > this.#sessionMaxAgeMs;
  }

  async #readLiveSession(
    c: Context,
    cookieValue: string,
  ): Promise<SessionData | null> {
    const data = await this.#store.read(cookieValue);
    if (!data) return null;
    if (!this.#isBeyondSessionMaxAge(data)) return data;
    await this.#store.destroy(cookieValue);
    deleteCookie(c, this.#cookieName, this.#cookieOptions());
    return null;
  }

  #noStore(c: Context): void {
    c.header("Cache-Control", "no-store");
    c.header("Vary", "Cookie");
  }

  #loginStateHashes(c: Context): string[] {
    const value = getCookie(c, this.#loginStateCookieName);
    if (!value) return [];
    return value.split(LOGIN_STATE_SEPARATOR).filter((hash) => hash.length > 0);
  }

  #writeLoginStateHashes(c: Context, hashes: string[]): void {
    if (hashes.length === 0) {
      deleteCookie(
        c,
        this.#loginStateCookieName,
        loginStateCookieOpts(this.#options.cookie),
      );
      return;
    }
    setCookie(
      c,
      this.#loginStateCookieName,
      hashes.slice(-MAX_PENDING_LOGIN_STATES).join(LOGIN_STATE_SEPARATOR),
      loginStateCookieOpts(
        this.#options.cookie,
        Math.ceil(this.#loginStateTtlMs / 1000),
      ),
    );
  }

  #derivedRedirectUri(
    c: Context,
    origin: string | undefined,
  ): string | undefined {
    if (!this.#options.deriveRedirectUri) return undefined;
    const base = origin ?? new URL(c.req.url).origin;
    return new URL(this.#paths.callback, base).toString();
  }

  #csrfHeaderOk(c: Context): boolean {
    if (!this.#csrf) return true;
    const value = c.req.header(this.#csrf.headerName);
    if (this.#csrf.headerValue !== undefined) {
      return value === this.#csrf.headerValue;
    }
    return typeof value === "string" && value.length > 0;
  }

  #sameOriginOk(c: Context): boolean {
    const fetchSite = c.req.header("sec-fetch-site");
    if (fetchSite) return fetchSite === "same-origin" || fetchSite === "none";
    const target = new URL(c.req.url).origin;
    const check = (val: string | undefined): boolean | undefined => {
      if (!val) return undefined;
      try {
        return new URL(val).origin === target;
      } catch {
        return false;
      }
    };
    const fromOrigin = check(c.req.header("origin"));
    if (fromOrigin !== undefined) return fromOrigin;
    const fromReferer = check(c.req.header("referer"));
    if (fromReferer !== undefined) return fromReferer;
    return false;
  }

  #csrfReject(c: Context): Response {
    return c.json(
      {
        error: "csrf_validation_failed",
        error_description:
          "Missing or invalid CSRF header on a credentialed request.",
      },
      403,
    );
  }

  /**
   * Returns a Hono app with all session endpoints mounted, each registered
   * relative to {@link HonoBffPaths.basePath} (default `/auth`). Mount it under
   * that same base — `app.route("/auth", bff.routes())` — so the served URLs
   * are the configured {@link HonoBffPaths}. To mount at the app root instead,
   * set `paths.basePath` to `""`.
   */
  routes(): Hono {
    const app = new Hono();
    const p = this.#pathsRelative();
    app.get(p.login, this.loginHandler());
    app.post(p.login, this.loginHandler());
    app.get(p.callback, this.callbackHandler());
    app.get(p.logout, this.logoutHandler());
    app.post(p.logout, this.logoutHandler());
    app.get(p.session, this.sessionHandler());
    if (this.#options.backchannelLogout) {
      app.post(p.backchannel, this.backchannelHandler());
    }
    return app;
  }

  /**
   * Builds the URL that (re)starts sign-in toward `returnTo`, for an app that
   * owns its login surface (a custom sign-in form, create-account,
   * forgot-password) and needs to hand back to the OAuth2/BFF flow after it
   * authenticates the user.
   *
   * - When `returnTo` is an **in-flight authorize URL** — its path matches the
   *   client's authorization endpoint, i.e. the user was bounced to your login
   *   surface mid-authorize with the PKCE `state` already minted — it is
   *   returned unchanged so the flow **resumes** without a redundant
   *   `/auth/login` hop.
   * - Otherwise it returns `${login}?return_to=<returnTo>` so the BFF **starts**
   *   a fresh login (mints `state` at the login endpoint, attaches tokens to the
   *   session at the callback).
   *
   * `returnTo` is open-redirect-guarded (`safeReturnTo`), so the result is
   * always a safe same-origin path. This is the mechanism of the own-auth + BFF
   * topology; the credential form, validation, and copy stay in your app. It
   * replaces hand-rolled helpers that hardcode the authorize + login paths —
   * the BFF already knows both from its client config and `paths`.
   *
   * ```ts
   * // after your sign-in / create-account action authenticates the user:
   * return c.redirect(bff.loginContinuation(returnTo));
   * ```
   *
   * Note: the in-flight-authorize check needs the client's authorization
   * endpoint to be known synchronously (an explicit `endpoints.authorization`,
   * or after `client.discover()` has run). For an issuer-only client that has
   * not discovered yet, every `returnTo` is treated as "start a fresh login".
   */
  loginContinuation(returnTo: string | null | undefined): string {
    return computeLoginContinuation(returnTo, {
      authorizeEndpoint: this.#client.authorizationEndpoint,
      loginPath: this.#paths.login,
      defaultReturnTo: this.#options.defaultReturnTo,
    });
  }

  #pathsRelative(): ResolvedPaths {
    const { basePath } = this.#paths;
    const strip = (p: string) =>
      basePath && p.startsWith(`${basePath}/`) ? p.slice(basePath.length) : p;
    return {
      basePath,
      login: strip(this.#paths.login),
      callback: strip(this.#paths.callback),
      logout: strip(this.#paths.logout),
      session: strip(this.#paths.session),
      backchannel: strip(this.#paths.backchannel),
    };
  }

  /**
   * Login handler — builds the authorize URL, binds the `state` it minted to
   * this browser with the login-state cookie, and redirects the browser.
   *
   * The authorize request carries every {@link HonoBffOptions.extraParams}
   * entry, plus each {@link HonoBffOptions.forwardedParams} name this
   * request's query string supplies a value for. Nothing else off this
   * request's query string reaches the authorize URL: `scope` falls back to
   * {@link HonoBffOptions.scope} and `prompt` is sent only when one of those
   * two options supplies it.
   */
  loginHandler(): Handler {
    return async (c) => {
      this.#noStore(c);
      const returnTo = safeReturnTo(
        c.req.query("return_to"),
        this.#options.defaultReturnTo ?? "/",
      );
      const origin = this.#options.resolveOrigin?.(c);
      const requested = authorizeParamsForRequest(
        this.#extraAuthorizeParams,
        new URL(c.req.url).searchParams,
      );
      const { url, state } = await this.#client.login({
        returnTo,
        scope: requested.scope ?? this.#options.scope,
        origin,
        prompt: requested.prompt,
        extraParams: requested.extraParams,
        redirectUri: this.#derivedRedirectUri(c, origin),
        authRequestStorage: this.#options.authRequestStorage?.forRequest(c),
      });
      this.#writeLoginStateHashes(c, [
        ...this.#loginStateHashes(c),
        await sha256Hash(state),
      ]);
      return c.redirect(url);
    };
  }

  /**
   * Callback handler — requires the login-state cookie to vouch for the
   * returned `state`, then exchanges the code and opens a session.
   */
  callbackHandler(): Handler {
    return async (c) => {
      this.#noStore(c);
      const params = new URL(c.req.url).searchParams;

      const fail = (error: BffCallbackError) =>
        this.#options.onCallbackError
          ? this.#options.onCallbackError(c, error)
          : c.json(
            { error: error.error, error_description: error.error_description },
            400,
          );

      if (params.get("error")) {
        return await fail({
          error: params.get("error")!,
          error_description: params.get("error_description") ?? "",
        });
      }

      const code = params.get("code");
      const state = params.get("state");
      if (!code || !state) {
        return await fail({
          error: "invalid_request",
          error_description: "missing code/state",
        });
      }

      const pendingStates = this.#loginStateHashes(c);
      const matched = timingSafeMatchIndex(
        pendingStates,
        await sha256Hash(state),
      );
      if (matched === undefined) {
        return await fail({
          error: "invalid_request",
          error_description: "state was not started in this browser",
        });
      }
      this.#writeLoginStateHashes(
        c,
        pendingStates.filter((_, index) => index !== matched),
      );

      try {
        const origin = this.#options.resolveOrigin?.(c);
        const { tokens, refreshToken, returnTo, raw } = await this.#client
          .exchangeAuthorizationCode(code, state, {
            origin,
            redirectUri: this.#derivedRedirectUri(c, origin),
            authRequestStorage: this.#options.authRequestStorage?.forRequest(c),
          });

        let user: UserInfoClaims | null = null;
        let sid: string | undefined;
        const idToken = (raw as { id_token?: string }).id_token;
        if (idToken) {
          try {
            const claims = this.#client.decodeIdToken(idToken);
            user = claims;
            const claimSid = (claims as { sid?: unknown }).sid;
            if (typeof claimSid === "string") sid = claimSid;
          } catch {
            user = null;
          }
        }
        if (this.#options.resolveUser) {
          user = await this.#options.resolveUser(tokens, user);
        }

        const now = Date.now();
        const data: SessionData = {
          tokens,
          refreshToken,
          user,
          sid,
          createdAt: now,
          updatedAt: now,
        };
        const existing = this.#sessionMode === "shared"
          ? getCookie(c, this.#cookieName)
          : undefined;
        const cookieValue = existing
          ? await this.#store.update(existing, data)
          : await this.#store.create(data);
        if (cookieValue !== existing) {
          setCookie(
            c,
            this.#cookieName,
            cookieValue,
            this.#cookieOptions(),
          );
        }

        return c.redirect(
          safeReturnTo(returnTo, this.#options.defaultReturnTo ?? "/"),
        );
      } catch (cause) {
        return await fail({
          error: "invalid_grant",
          error_description: "code exchange failed",
          cause,
        });
      }
    };
  }

  /** Logout handler — revokes the refresh token and clears the session cookie. */
  logoutHandler(): Handler {
    return async (c) => {
      this.#noStore(c);
      const cookieValue = getCookie(c, this.#cookieName);
      if (cookieValue && this.#csrf) {
        const ok = c.req.method === "GET"
          ? this.#sameOriginOk(c)
          : this.#csrfHeaderOk(c);
        if (!ok) return this.#csrfReject(c);
      }
      let idToken: string | undefined;
      if (cookieValue) {
        const data = await this.#store.read(cookieValue);
        idToken = data?.tokens?.idToken;
        if (data?.refreshToken) {
          try {
            await this.#client.revoke(data.refreshToken, {
              tokenTypeHint: "refresh_token",
            });
          } catch {
            // best-effort
          }
        }
        await this.#store.destroy(cookieValue);
        deleteCookie(c, this.#cookieName, this.#cookieOptions());
      }

      const returnTo = safeReturnTo(
        c.req.query("return_to"),
        this.#options.defaultReturnTo ?? "/",
      );

      if (this.#options.rpInitiatedLogout) {
        const endSession = this.#client.endSessionEndpoint;
        if (endSession) {
          const origin = this.#options.resolveOrigin?.(c) ??
            new URL(c.req.url).origin;
          const url = new URL(endSession, origin);
          if (idToken) url.searchParams.set("id_token_hint", idToken);
          url.searchParams.set("client_id", this.#client.clientId);
          url.searchParams.set(
            "post_logout_redirect_uri",
            new URL(returnTo, origin).toString(),
          );
          return c.redirect(url.toString());
        }
        this.#warnLogoutIsLocalOnly();
      }

      return c.redirect(returnTo);
    };
  }

  #warnLogoutIsLocalOnly(): void {
    if (this.#warnedLogoutIsLocalOnly) return;
    this.#warnedLogoutIsLocalOnly = true;
    console.warn(
      "[@udibo/oauth2] rpInitiatedLogout is enabled but no end_session " +
        "endpoint is known, so logout only clears this app's session — the " +
        "identity provider's stays alive and the next sign-in will be " +
        "silent. Give the client an `issuer` so discovery can find the " +
        "endpoint, or add `endpoints.endSession` explicitly.",
    );
  }

  /** Session probe — returns `{ isAuthenticated, user }` without tokens. */
  sessionHandler(): Handler {
    return async (c) => {
      this.#noStore(c);
      const cookieValue = getCookie(c, this.#cookieName);
      if (!cookieValue) {
        return c.json({ isAuthenticated: false, user: null });
      }
      if (this.#csrf && !this.#csrfHeaderOk(c)) return this.#csrfReject(c);
      const data = await this.#readLiveSession(c, cookieValue);
      if (!data) {
        return c.json({ isAuthenticated: false, user: null });
      }
      const expiresAt = data.tokens.accessTokenExpiresAt;
      const sessionExpiresIn = expiresAt !== undefined
        ? Math.max(0, Math.round((expiresAt - Date.now()) / 1000))
        : null;
      return c.json({
        isAuthenticated: true,
        user: data.user ?? null,
        sessionExpiresIn,
        logoutUrl: this.#paths.logout,
      });
    };
  }

  /**
   * OIDC Back-Channel Logout receiver. A server-to-server `POST` from the OP
   * carrying a signed `logout_token`; the configured verifier validates it (and
   * returns the subject / OP session id), then the matching server-side
   * session(s) are destroyed. Responds `200` on success and `400` on a
   * missing/invalid token, with `Cache-Control: no-store`, per the spec.
   */
  backchannelHandler(): Handler {
    return async (c) => {
      c.header("Cache-Control", "no-store");
      const opts = this.#options.backchannelLogout;
      if (!opts) return c.json({ error: "not_supported" }, 400);

      let logoutToken: string | undefined;
      try {
        logoutToken = (await c.req.formData()).get("logout_token")?.toString();
      } catch {
        logoutToken = undefined;
      }
      if (!logoutToken) {
        return c.json(
          {
            error: "invalid_request",
            error_description: "missing logout_token",
          },
          400,
        );
      }

      let subject: BackchannelLogoutSubject | null;
      try {
        subject = await opts.verifyLogoutToken(logoutToken);
      } catch {
        subject = null;
      }
      if (
        !subject || (subject.sub === undefined && subject.sid === undefined)
      ) {
        return c.json(
          {
            error: "invalid_request",
            error_description: "invalid logout_token",
          },
          400,
        );
      }

      if (!supportsBackchannelLogout(this.#store)) {
        return c.json({ error: "not_supported" }, 400);
      }
      await this.#store.destroyByLogout({ sub: subject.sub, sid: subject.sid });
      return c.body(null, 200);
    };
  }

  async #resolveSessionEntry(c: Context): Promise<SessionResolution> {
    const cookieValue = getCookie(c, this.#cookieName);
    if (!cookieValue) return { status: "anonymous" };
    const data = await this.#readLiveSession(c, cookieValue);
    if (!data) return { status: "anonymous" };

    const skew = (this.#options.refreshSkewSeconds ?? 30) * 1000;
    const needsRefresh = data.tokens.accessTokenExpiresAt !== undefined
      ? data.tokens.accessTokenExpiresAt - skew < Date.now()
      : false;
    if (!needsRefresh || !data.refreshToken) {
      return { status: "active", entry: { cookieValue, data } };
    }

    const outcome = await this.#refreshSessionEntry(c, { cookieValue, data });
    if (outcome.status === "refreshed") {
      return { status: "active", entry: outcome.entry };
    }
    return outcome.status === "unavailable"
      ? { status: "unavailable" }
      : { status: "anonymous" };
  }

  #temporarilyUnavailable(c: Context): Response {
    return this.#errorResponse(
      c,
      new TemporarilyUnavailableError(
        502,
        "token refresh temporarily unavailable",
      ),
    );
  }

  async #refreshSessionEntry(
    c: Context,
    entry: SessionEntry,
  ): Promise<RefreshOutcome> {
    const outcome = await this.#sharedRefresh(entry);
    if (outcome.status === "refreshed") {
      if (outcome.entry.cookieValue !== entry.cookieValue) {
        setCookie(
          c,
          this.#cookieName,
          outcome.entry.cookieValue,
          this.#cookieOptions(),
        );
      }
    } else if (outcome.status === "revoked") {
      deleteCookie(c, this.#cookieName, this.#cookieOptions());
    }
    return outcome;
  }

  #sharedRefresh(entry: SessionEntry): Promise<RefreshOutcome> {
    const inFlight = this.#refreshes.get(entry.cookieValue);
    if (inFlight) return inFlight;
    const pending = this.#exchangeRefresh(entry).finally(() => {
      this.#refreshes.delete(entry.cookieValue);
    });
    this.#refreshes.set(entry.cookieValue, pending);
    return pending;
  }

  async #exchangeRefresh(entry: SessionEntry): Promise<RefreshOutcome> {
    const { cookieValue, data } = entry;
    if (!data.refreshToken) return { status: "unavailable" };
    try {
      const result = await this.#client.exchangeRefreshToken(data.refreshToken);
      const refreshed: SessionData = {
        tokens: result.tokens,
        refreshToken: result.refreshToken ?? data.refreshToken,
        user: data.user,
        sid: data.sid,
        createdAt: data.createdAt,
        updatedAt: Date.now(),
      };
      const newCookieValue = await this.#store.update(cookieValue, refreshed);
      return {
        status: "refreshed",
        entry: { cookieValue: newCookieValue, data: refreshed },
      };
    } catch (error) {
      if (!isRevokedGrant(error)) return { status: "unavailable" };
      const current = await this.#store.read(cookieValue);
      if (current && current.refreshToken !== data.refreshToken) {
        return { status: "refreshed", entry: { cookieValue, data: current } };
      }
      await this.#store.destroy(cookieValue);
      return { status: "revoked" };
    }
  }

  /**
   * Middleware that reads the session cookie, refreshes the access token
   * if it's near expiry, and sets `Authorization: Bearer <token>` on the
   * inbound request so downstream middleware can read it from the
   * standard header.
   *
   * Prefer {@link protect} for the common case — it authenticates against
   * the configured `resourceServer` directly without mutating the
   * request, so middleware ordering doesn't matter. Reach for
   * `attachToken` only when composing with downstream middleware that
   * expects a bearer token in the `Authorization` header (e.g. a custom
   * resource-server-like guard, or an in-process proxy).
   *
   * **Ordering caveat**: mount `attachToken` *before* any middleware
   * that reads the request body (CSRF parsers, validators, etc.).
   * `attachToken` replaces `c.req.raw` with a clone that carries the
   * Authorization header, which transfers the body stream from the
   * original Request to the clone. Downstream middleware that reads
   * through `c.req` is fine; middleware that captured a pre-clone
   * reference to `c.req.raw` will see a "used" body on it.
   *
   * Unauthenticated requests fall through without a header — the
   * downstream guard returns the proper 401 with `WWW-Authenticate`.
   */
  attachToken(): MiddlewareHandler {
    return async (c, next) => {
      if (this.#csrf && this.#hasSessionCookie(c)) {
        const inboundAuth = c.req.header("Authorization") ?? "";
        const hasBearer = /^bearer\s+\S/i.test(inboundAuth);
        if (!hasBearer && !this.#csrfHeaderOk(c)) return this.#csrfReject(c);
      }
      const resolution = await this.#resolveSessionEntry(c);
      if (resolution.status === "unavailable") {
        return this.#temporarilyUnavailable(c);
      }
      if (resolution.status !== "active") {
        await next();
        return;
      }
      const headers = new Headers(c.req.raw.headers);
      headers.set(
        "Authorization",
        `Bearer ${resolution.entry.data.tokens.accessToken}`,
      );
      c.req.raw = new Request(c.req.raw, { headers });
      await next();
    };
  }

  /**
   * Returns a Hono middleware that asserts an **already-authenticated**
   * request (guarded upstream by {@link protect}) carries `requiredScope`,
   * **without** re-validating the token — the per-route companion to
   * `protect` for mounts whose routes need different scopes (e.g. `read` vs
   * `write`). Delegates to the configured resource server's `requireScope`;
   * see {@link HonoResourceServer.requireScope}.
   *
   * @throws {Error} When the BFF was constructed without a `resourceServer` —
   * thrown when the middleware is built, not per request.
   *
   * @example
   * ```ts
   * app.use("/api/*", bff.protect()); // session cookie OR bearer
   * app.get("/api/items", bff.requireScope("read"), list);
   * app.post("/api/items", bff.requireScope("write"), create);
   * ```
   */
  requireScope(requiredScope: string): MiddlewareHandler {
    const resourceServer = this.#options.resourceServer;
    if (!resourceServer) {
      throw new Error(
        "HonoBff.requireScope() requires a `resourceServer` option (the same " +
          "one `protect` authenticates against).",
      );
    }
    return resourceServer.requireScope(requiredScope);
  }

  /**
   * Middleware that authenticates the request against the configured
   * `resourceServer`, accepting **either** auth style so one guard protects an
   * API used by both the BFF's own frontend and machine-to-machine clients:
   *
   * - **Browser frontend** — no `Authorization` header; the access token is
   *   resolved from the BFF session cookie (refreshed if near expiry) and
   *   validated. Available only when the BFF was constructed with a
   *   `resourceServer` option.
   * - **Machine-to-machine** — an inbound `Authorization: Bearer <token>` is
   *   validated directly (e.g. a `client_credentials` token), so direct API
   *   clients work without a session cookie.
   *
   * Unlike `attachToken + resourceServer.protect()`, this does **not**
   * mutate `c.req.raw` for the session path — the token is read from the
   * session and handed to `resourceServer.authenticate()` directly, so
   * middleware ordering doesn't matter and earlier middleware that already
   * touched the request body is unaffected.
   *
   * ```ts
   * app.use("/api/*", bff.protect("read")); // session cookie OR bearer token
   * ```
   *
   * Without `resourceServer` configured, throws an error with a hint to
   * either pass `resourceServer` or compose the middleware chain manually
   * (`app.use(bff.attachToken(), resourceServer.protect(scope))`).
   */
  protect(requiredScope?: string): MiddlewareHandler {
    const resourceServer = this.#options.resourceServer;
    if (!resourceServer) {
      throw new Error(
        "HonoBff.protect() requires a `resourceServer` option. Either pass " +
          "one to the constructor or compose middleware manually: " +
          "`app.use(bff.attachToken(), resourceServer.protect(scope))`.",
      );
    }
    return async (c, next) => {
      try {
        const inboundAuth = c.req.header("Authorization") ?? "";
        const hasBearer = /^bearer\s+\S/i.test(inboundAuth);

        if (
          !hasBearer && this.#csrf && this.#hasSessionCookie(c) &&
          !this.#csrfHeaderOk(c)
        ) {
          return this.#csrfReject(c);
        }

        let authRequest: Request;
        if (hasBearer) {
          authRequest = c.req.raw;
        } else {
          const resolution = await this.#resolveSessionEntry(c);
          if (resolution.status === "unavailable") {
            return this.#temporarilyUnavailable(c);
          }
          if (resolution.status === "active") {
            const headers = new Headers(c.req.raw.headers);
            headers.set(
              "Authorization",
              `Bearer ${resolution.entry.data.tokens.accessToken}`,
            );
            authRequest = new Request(c.req.raw.url, { headers });
          } else {
            authRequest = new Request(c.req.raw.url);
          }
        }
        const ctx = await resourceServer.authenticate(
          authRequest,
          requiredScope,
        );
        c.set(OAUTH2_CONTEXT_KEY, ctx);
        await next();
      } catch (error) {
        return resourceServer.handleAuthError(error);
      }
    };
  }

  #errorResponse(c: Context, error: OAuth2Error): Response {
    if (error.status === 401) {
      c.header(
        "WWW-Authenticate",
        `Bearer error="${error.extensions.error ?? "invalid_token"}"`,
      );
    }
    return c.json(
      {
        error: error.extensions.error,
        error_description: error.message,
      },
      error.status as ContentfulStatusCode,
    );
  }

  /**
   * Handler that forwards the request to a **separate** resource server with
   * the session's access token attached, and streams the response back — the
   * full-proxy BFF of the IETF "OAuth 2.0 for Browser-Based Apps" BCP §6.1.1.
   * Tokens stay server-side and the browser only ever talks to its own origin,
   * so there is no CORS to configure.
   *
   * Reach for this when the API lives in another service. When the resource
   * server is co-located in the same process, {@link protect} is faster and
   * simpler — it validates in-process with no outbound HTTP.
   *
   * Mount it as a catch-all and strip the mount prefix:
   *
   * @example
   * ```ts
   * app.all(
   *   "/api/*",
   *   bff.proxy("https://api.example.com/v1", { stripPrefix: "/api" }),
   * );
   * ```
   *
   * Semantics:
   *
   * - **Session only.** The access token comes from the session cookie
   *   (refreshed when within {@link HonoBffOptions.refreshSkewSeconds} of
   *   expiry, exactly as {@link protect} does). An inbound `Authorization`
   *   header is *not* honored and never forwarded — point machine-to-machine
   *   clients at the resource server directly. No session is `401`
   *   `invalid_token`.
   * - **CSRF.** The same custom-header check the rest of the credentialed BFF
   *   surface enforces, so mounting a proxy cannot reopen it. See
   *   {@link HonoBffCsrfOptions}.
   * - **Retry.** An upstream `401` carrying `error="invalid_token"` triggers
   *   one refresh-and-retry, when the session has a refresh token. A refresh
   *   the authorization server rejects clears the session and answers `401`; a
   *   refresh that merely fails to complete (network error, 5xx, 429) leaves
   *   the session intact and answers `502` `temporarily_unavailable`. Bodied
   *   requests are not retried (the body was streamed). Disable with
   *   `retryOn401: false`.
   * - **Headers.** Only {@link DEFAULT_PROXY_FORWARD_HEADERS} (or your
   *   `forwardHeaders`) travel upstream; the session cookie, inbound
   *   `Authorization`, and hop-by-hop headers never do. Coming back, upstream
   *   `Set-Cookie` and hop-by-hop headers are dropped and everything else —
   *   including problem-details error bodies and their status — is passed
   *   through verbatim.
   * - **Bodies stream** in both directions; nothing is buffered. Upstream
   *   redirects are returned to the browser rather than followed, so the token
   *   is never replayed to a `Location` the BFF did not vet.
   *
   * A `502` with `temporarily_unavailable` is returned when the upstream
   * cannot be reached, and a `400` `invalid_request` when a path segment has a
   * malformed percent-escape or hides a `..`.
   *
   * **Ordering caveat**: mount this before any middleware that reads the
   * request body — the proxy forwards `c.req.raw.body` as a stream, and a
   * middleware that already consumed it leaves nothing to forward.
   *
   * @param target Upstream base URL. Fixed here, never derived from the
   * request, so the proxy cannot be steered at another host. Query parameters
   * pinned on it are merged into every proxied request and win over an inbound
   * parameter of the same name.
   * @param options Prefix stripping, header allowlist, retry, and `fetch`
   * injection. See {@link HonoBffProxyOptions}.
   * @returns A Hono handler to mount on a catch-all route.
   */
  proxy(target: string | URL, options: HonoBffProxyOptions = {}): Handler {
    const base = new URL(target);
    const allowedHeaders = resolveForwardHeaders(
      options.forwardHeaders,
      this.#csrf?.headerName,
    );
    const fetchImpl = options.fetch ??
      ((input: URL, init: RequestInit) => fetch(input, init));
    const retryOn401 = options.retryOn401 ?? true;
    const mountPrefix = (options.stripPrefix ?? "").endsWith("/")
      ? options.stripPrefix!.slice(0, -1)
      : options.stripPrefix ?? "";

    return async (c) => {
      if (this.#csrf && this.#hasSessionCookie(c) && !this.#csrfHeaderOk(c)) {
        return this.#csrfReject(c);
      }

      let url: URL;
      try {
        url = resolveProxyUrl(base, c.req.url, options.stripPrefix);
      } catch {
        return this.#errorResponse(
          c,
          new InvalidRequestError("invalid proxy path"),
        );
      }

      const resolution = await this.#resolveSessionEntry(c);
      if (resolution.status === "unavailable") {
        return this.#temporarilyUnavailable(c);
      }
      if (resolution.status !== "active") {
        return this.#errorResponse(
          c,
          new InvalidTokenError("no active session"),
        );
      }
      const entry = resolution.entry;

      const body = c.req.raw.body;
      const send = (
        accessToken: string,
        requestBody: ReadableStream<Uint8Array> | null,
      ): Promise<Response> => {
        const init: RequestInit & { duplex?: "half" } = {
          method: c.req.method,
          headers: buildUpstreamHeaders(
            c.req.raw.headers,
            allowedHeaders,
            accessToken,
          ),
          body: requestBody,
          redirect: "manual",
        };
        if (requestBody) init.duplex = "half";
        return fetchImpl(url, init);
      };

      let response: Response;
      try {
        response = await send(entry.data.tokens.accessToken, body);
      } catch (cause) {
        return this.#errorResponse(
          c,
          new TemporarilyUnavailableError(502, "upstream request failed", {
            cause,
          }),
        );
      }

      const canRetry = retryOn401 && body === null &&
        entry.data.refreshToken !== undefined;
      if (canRetry && isInvalidTokenChallenge(response)) {
        await response.body?.cancel();
        const outcome = await this.#refreshSessionEntry(c, entry);
        if (outcome.status === "revoked") {
          return this.#errorResponse(
            c,
            new InvalidTokenError("session refresh failed"),
          );
        }
        if (outcome.status === "unavailable") {
          return this.#temporarilyUnavailable(c);
        }
        try {
          response = await send(outcome.entry.data.tokens.accessToken, null);
        } catch (cause) {
          return this.#errorResponse(
            c,
            new TemporarilyUnavailableError(502, "upstream request failed", {
              cause,
            }),
          );
        }
      }

      const downstream = response.body;
      const init = {
        status: response.status as StatusCode,
        headers: buildDownstreamHeaders(response, {
          upstreamUrl: url,
          base,
          mountPrefix,
        }),
      };
      return downstream === null ? c.body(null, init) : c.body(downstream, {
        ...init,
        status: response.status as ContentfulStatusCode,
      });
    };
  }
}
