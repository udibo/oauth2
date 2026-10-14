# Known Limitations

Behavior to account for when choosing and deploying an integration. The API
reference documents each option; this page collects cross-cutting limits and
application-owned responsibilities.

## Request logging

OAuth callbacks carry authorization codes and state in query parameters. Mount
`requestLogger()` from `@udibo/oauth2/hono/log` before authentication routes. It
replaces every query value with `[redacted]` in request and response lines. For
other loggers or telemetry, use `redactedRequestTarget(url)` before recording
the URL.

The pathname and parameter names remain visible, so do not put secrets there.
The middleware does not control reverse-proxy access logs, tracing exporters, or
logs your own handlers emit. Configure those separately to avoid recording
credentials, request bodies, or raw callback URLs.

## Request body limits

The package caps the bodies it reads before authenticating the caller. Each read
counts bytes as they arrive and stops at the cap, whatever the `Content-Length`
header claims, and a body with no `Content-Length` (chunked) is counted the same
way. The caps default to 64 KiB, far above the largest legitimate field, a JWT
of a few KiB, except the resource server's token search, which defaults to
16 KiB.

- **`AuthorizationServer`** caps the token, revocation, introspection, device
  authorization and end-session endpoints with `maxBodyBytes`. An oversized body
  gets `413` with `error: "invalid_request"`: RFC 6749 §5.2 names no error code
  for size, and `413` tells the client that retrying the same body cannot
  succeed.
- **`HonoBff`** caps the back-channel logout receiver with
  `backchannelLogout.maxBodyBytes`. An oversized body gets `400` with
  `error: "invalid_request"`, because OIDC Back-Channel Logout 1.0 §2.8 requires
  `400` for every failed logout request. `verifyLogoutToken` is not called. When
  a middleware mounted before the receiver has already read the body (for
  example with `c.req.parseBody()`), the receiver reads Hono's parsed copy and
  the cap does not apply, so that middleware needs its own limit.
- **`ResourceServer`** (and so `protect()`, `authenticate()` and an
  `AuthorizationServer`'s userinfo endpoint) looks for an RFC 6750 §2.2
  `access_token` in a form-encoded `POST` body when the request carries no
  bearer `Authorization` header. It reads at most `maxTokenBodyBytes` (16 KiB,
  Node's default limit on a request's whole header block) from a copy of the
  body. A larger body is not searched: the request counts as carrying no token,
  so `protect()` answers `401`, and the rest of the body is left unread for the
  route. Send the token in the `Authorization` header from any client whose form
  bodies are larger.
- **`honoIdentityRoutes`** caps the sign-up, sign-in, password-reset and
  email-verification bodies with `maxBodyBytes`. An oversized body gets `413`
  with `error: "invalid_request"` before the identity service is called. As with
  the back-channel receiver, a middleware that already read the body leaves the
  routes Hono's parsed copy, uncapped.

The caps bound what the package reads, not what your own routes read. A route
behind `protect()` that parses its body still needs a request-size limit, in
your framework (for example Hono's `bodyLimit` middleware) or your reverse
proxy. Mount that limit ahead of `protect()` so an anonymous oversized body is
refused before any authentication work.

The `udibo-oauth2 idp dev` server caps its sign-in, consent and admin bodies at
64 KiB and answers a larger one with `413`.

## Response size limits

The package also caps every response its runtime code reads from a server it
calls; the `@udibo/oauth2/testing` suites, which run only in your tests, do not.
As with request bodies, each read counts bytes as they arrive and cancels the
response at the cap. A `Content-Length` over the cap is refused before any of
the body is read, and a chunked response with no `Content-Length` is cut off at
the cap.

- **`JwksTokenReader`** caps the discovery document and the JWKS with
  `maxResponseBytes`, default 256 KiB. A larger response fails the key refresh
  with `ServerError`, as a malformed one does. A body that stops arriving before
  `fetchTimeoutMs` gives `TemporarilyUnavailableError`.
- **`IntrospectionTokenReader`** caps the introspection response with
  `maxResponseBytes`, default 64 KiB, and fails the same way.
- **`breachedPasswordValidator`** caps the range response with
  `maxResponseBytes`, default 1 MiB. A larger response counts as the range API
  being unavailable, so `failOpen` decides whether the password is allowed.
- **`DirectClient`, `BffClient` and `checkPermissions`** cap every
  authorization-server response at 64 KiB. **The external connectors** cap token, profile, UserInfo and Apple
  JWKS responses at 64 KiB, and an oversized error body is left out of the error
  message. These caps are fixed. An oversized OIDC UserInfo response is
  discarded like any other UserInfo failure, so the profile comes from the
  id_token claims alone.

A cap bounds how much a response can send, not how long it can take. **The
external connectors** also give each request they send a fixed 10-second
deadline: the token exchange, the profile and GitHub API reads, OIDC UserInfo,
and Apple's JWKS. The deadline covers the connection, the response headers and
the whole body, including an error body read for the message. A provider that
stops sending at any point fails the sign-in with `ExternalAuthError`
`provider_error` once it passes, and the connection is closed. An OIDC UserInfo
request that misses it is a UserInfo failure like any other, so the profile
comes from the id_token claims alone. The OIDC connector's discovery and token
requests go through `DirectClient`, which bounds each one at 10 seconds as well.
An injected `fetch` must pass the request's `signal` through, or none of these
deadlines reaches the transport.

## BFF storage across instances

`HonoBff` requires `sessionStore` and `authRequestStorage` and has no default
for either; constructing it without one throws a `TypeError` naming the option.
The memory stores, `MemorySessionStore` and `MemoryAuthRequestStorageFactory`,
must be chosen explicitly and serve one process only: behind a load balancer a
session created on one instance is unknown on the others, so the user appears
signed out, and a sign-in whose callback reaches another instance fails. See
[choosing the BFF's stores](guides/production-deployment.md#choosing-the-bffs-stores)
for which store fits which deployment.

## Rate limit and lockout storage across instances

`RateLimiter` and `AccountLockout` require a `store` and have no default;
constructing either without one throws a `TypeError` naming the option.
`MemoryRateLimitStore` and `MemoryLockoutStore` must be chosen explicitly and
serve one process only: behind a load balancer each instance keeps its own
counters, so a client gets the rate limit once per instance, an attacker gets
`maxAttempts` password guesses per instance, and a lock on one instance does not
stop sign-in on another. Pass a `RateLimitStore` and a `LockoutStore` over
Redis or a database every instance shares, with an atomic `increment`.

## DirectClient storage outside a browser

In a browser document `DirectClient` keeps pending sign-ins in
`SessionStorageAuthRequestStorage` and the refresh token in memory. Outside a
browser it has no default for either. `login` and `exchangeAuthorizationCode`
throw a `TypeError` unless the client or the call has an `authRequestStorage`,
and `handleAuthorizationCallback`, `startDeviceAuthorization` and
`pollDeviceToken` throw one unless the client has a `refreshTokenStorage`. Each
check runs before any request and before a pending sign-in is claimed. A
client that only runs client credentials needs neither; it never stores a
refresh token, and drops one a non-conforming server returns. Pass
`MemoryAuthRequestStorage` and `MemoryRefreshTokenStorage` explicitly for a
single process, tests and local development.

## Pending sign-in limits

Anyone can start a sign-in. `HonoBff`'s `/auth/login` stores the pending
request (`state`, PKCE verifier, return path) before it knows who the caller is,
so the package bounds what each start can cost:

- **`return_to` is capped at 2048 UTF-16 code units.** `safeReturnTo` treats a longer
  value as unsafe and returns the fallback, so `HonoBff` stores and redirects to
  `defaultReturnTo` instead. Change the cap with `HonoBffOptions.maxReturnToLength`
  (or `safeReturnTo`'s `maxLength` and `loginContinuation`'s
  `maxReturnToLength`); `Infinity` removes it.
- **`MemoryAuthRequestStorage` holds at most 1000 records.** This is what
  `MemoryAuthRequestStorageFactory` gives the BFF, and the client's fallback in
  a browser document without `sessionStorage`. It keeps pending sign-ins in one process, so a callback served by
  another instance fails with an unknown `state`; use it only for a single
  process, tests and local development. A write beyond the cap evicts the oldest-written record,
  so memory stays bounded however many starts arrive. Raise or lower it with
  `maxEntries`. The cap protects memory, not sign-in: a burst of anonymous starts
  evicts real users' pending sign-ins, and their callbacks then fail with an
  unknown `state`.
- **`EncryptedCookieAuthRequestStorage` keeps nothing on the server.** Each
  browser carries its own pending requests: at most `maxPending` (3), and fewer
  when keeping them all would push the sealed cookie past about 4 KB, which a
  browser drops silently. One browser's starts cannot evict another browser's.
  The size trim never drops the record being written, so a single record with a
  long non-ASCII `return_to` (up to three UTF-8 bytes per code unit) can still
  exceed 4 KB; that browser's cookie is dropped and the sign-in fails. Lower
  `maxReturnToLength` if your return paths are not ASCII.
  Use this store for any deployment with more than one instance, and for any
  deployment where sign-in can be reached anonymously from the internet.

A rate limit on the login route, in your framework or reverse proxy, still
limits how often one client can start a sign-in. The caps only bound the memory
each start can cost.

## Deliberate deviations (stricter than spec)

- **`state` is required at the authorize endpoint.** RFC 6749 §4.1.1 lists
  `state` as RECOMMENDED; this server rejects authorize requests without it
  (`invalid_request`). This is a deliberate CSRF-hardening choice. PKCE also
  defaults to required (`requirePKCE: true`, enforced at both the authorize and
  token endpoints), matching OAuth 2.1. Keep this default for new integrations.
- **Resource Owner Password grant ships but is discouraged.** It exists for
  migration paths; OAuth 2.1 drops it. Nothing in the adapters or examples wires
  it by default.
- **The password grant does not enforce MFA, and cannot.** A token request has
  no interactive step, so `PasswordGrant` issues tokens for whatever user
  `UserServiceInterface.getAuthenticated` returns — including a user enrolled in
  a second factor. Registering the grant is therefore an opt-out of MFA unless
  your `getAuthenticated` enforces the policy itself: return `undefined`, or
  throw an OAuth2 error (`InvalidGrantError` surfaces as `invalid_grant`), for
  any user who owes a second factor. `@udibo/oauth2/identity/mfa` exposes
  `MfaService`/`MfaStore` to ask that question.

## Defaults that are looser than the specs

Confidential clients authenticate alongside PKCE by default.
`requireClientAuthentication: false` remains an explicit legacy opt-out and
should not be enabled for new deployments.

- **Both Basic and body client credentials are accepted, and the header wins
  silently.** `extractClientCredentials` reads the `Authorization: Basic` header
  first and returns as soon as it parses; `client_id` / `client_secret` in the
  form body are consulted only when there is no usable header. RFC 6749 §2.3.1
  says a client MUST NOT use more than one authentication method and that a
  server receiving both SHOULD refuse the request; this server picks one
  instead. The consequence worth knowing is a logging one: a request carrying
  `Basic <credentials for A>` **and** `client_id=B` in the body authenticates as
  **A**, while an access log or audit hook that reads `client_id` off the body
  records **B**. Log the authenticated client the grant hands you, never the
  request body's `client_id`.

## Spec-level gaps

- **Introspection (RFC 7662) emits a subset of the optional fields:** `active`,
  `client_id`, `token_type`, `scope`, `exp`, `iss`, `sub`, `username`. `sub` and
  `username` appear only when the token has a user; a machine token (client
  credentials) has neither, and its `client_id` identifies the caller — so the
  presence of `sub` is how a resource server tells a user token from a machine
  one. The typed response also declares `iat` / `nbf` / `aud` / `jti`, but the
  server never populates them itself; only an `introspectionClaims` hook you
  configure can add them. Practical consequence: without such a hook, a resource
  server cannot enforce audience restriction via introspection `aud` — issue JWT
  access tokens (`createJwtAccessTokenGenerator`) and validate them with
  `JwksTokenReader`, which enforces `aud`, if you need in-token
  audience/issued-at claims.
- **Introspection authorization is application policy.** By default,
  `/introspect` allows any admitted client to inspect any live token, preserving
  the separate resource-server use of RFC 7662. Configure
  `AuthorizationServerOptions.canIntrospectToken` to decide which resolved
  tokens each authenticated client may inspect. The callback receives the
  client, token and actual token kind, independent of `token_type_hint`.
  Returning false yields only `{ active: false }`, without claims enrichment;
  throwing fails the request closed. Revocation always checks ownership.

  The disclosure surface of one successful call is `active`, `client_id`,
  `scope`, `exp`, `iss`, and — when the token has a resource owner — `sub` and
  `username`. That is enough to enumerate which user a captured token belongs to
  and what it may do. If your deployment has clients that should not learn that
  about each other, configure this policy or mount the endpoint behind a
  separate authorization boundary. A public client ID does not authenticate its
  holder, so matching a token's client ID alone does not protect public-client
  metadata. For confidential clients inspecting only their own tokens, require
  verified confidentiality as well as matching client IDs. A separately
  registered resource server needs an explicit policy for the tokens it may
  read; do not grant it every client's refresh-token metadata by accident.
- **A live refresh token introspects as `active: true`.** `/introspect` resolves
  both token kinds, so a refresh token reports `active: true` with `exp` taken
  from its own expiry, and carries **no** `token_type` (an access token carries
  `token_type: "Bearer"`). A caller that treats any `active: true` response as
  "this is a valid access token" will accept a refresh token presented as a
  bearer — check `token_type` when the distinction matters. The shipped
  `IntrospectionTokenReader` does exactly that: it accepts an active response
  only when `token_type` names a bearer token, so an authorization server that
  omits `token_type` from active responses cannot be read by it.

## Resource servers (`@udibo/oauth2/server/resource`)

- Offline JWT validation does not consult token revocation state. A revoked
  token can remain valid until its signed expiry. Use an appropriate short
  lifetime or online validation when prompt revocation is required. That signed
  expiry is the server's own when the token service forwards the grant's
  `expiresAt` argument to `createJwtAccessTokenGenerator`: it clamps `exp` to
  the expiry the grant stores, refresh-family cap included, so the revocation
  window is no longer than the stored access-token lifetime. A custom
  `generateAccessToken` wrapper that drops that argument falls back to the
  generator's `lifetimeSeconds` alone.

- **Clock skew is two options, and only one of them is on by default.**
  `JwksTokenReaderOptions.clockSkewSeconds` (default 30) governs the reader's
  own `exp` and `nbf` claim checks; the reader then hands `ResourceServer` a
  token whose `accessTokenExpiresAt` is the issuer's raw `exp`, and
  `ResourceServer.getToken` re-checks it with
  `ResourceServerOptions.clockSkewSeconds`, which defaults to **0**. Set both to
  tolerate drift end to end. The resource-server option is the only one that
  reaches an `IntrospectionTokenReader`, which has no notion of skew at all. The
  `nbf` half is reader-only — nothing re-checks `nbf` — so a slow-clock issuer
  is tolerated only by the reader.
- **`IntrospectionTokenReader` calls the authorization server on every
  request.** It takes `fetchTimeoutMs` (default 5000, matching
  `JwksTokenReader`), so an endpoint that accepts connections and then stops
  answering fails at the deadline rather than hanging — but there is still **no
  response caching**, so every authenticated request costs a round trip. The
  `fetch` injection seam remains the escape hatch for mTLS, retries, or a
  different bound; note that an injected `fetch` which ignores `AbortSignal`
  also ignores `fetchTimeoutMs`. Transport failures and timeouts both map to
  `temporarily_unavailable` rather than `invalid_token`, so they are correctly
  reported as "issuer is down", not "your token is bad".
- **`errorFormat` covers protected-resource refusals only.** With
  `errorFormat: "problem-details"`, `protect()`, `handleAuthError`,
  `createErrorResponse` and an authorization server's UserInfo endpoint answer
  RFC 9457 problem details as `application/problem+json`. RFC 6750 §3 defines
  the challenge but no error body. The problem body carries `error`, with the
  message in `detail` and not repeated as `error_description`; the
  `WWW-Authenticate` challenge carries both `error` and `error_description`.
  An authorization server's OAuth endpoints
  ignore the option and always answer in the RFC 6749 §5.2 format as
  `application/json`.

## Not implemented (adjacent specs)

Commonly requested capabilities that are simply not in scope yet — none are
partially implemented or emulated:

- Dynamic client registration (RFC 7591/7592)
- Pushed Authorization Requests (PAR, RFC 9126)
- JWT-secured authorization requests (JAR, RFC 9101) and JARM
- Sender-constrained tokens (DPoP, RFC 9449; mTLS, RFC 8705)
- Token exchange (RFC 8693)
- OIDC **logout-token emission** (back-channel logout on the provider side),
  OIDC Session Management, and front-channel logout. RP-Initiated Logout **is**
  implemented on the provider side — configure the `endSession` option and the
  server serves `/end_session` and advertises `end_session_endpoint`; without it
  the endpoint 404s and stays unadvertised. The BFF also _consumes_ both
  RP-initiated and back-channel logout as a relying party (`rpInitiatedLogout`,
  `backchannelLogout`)
- OIDC dynamic discovery of anything beyond the served metadata documents

## OIDC connector validation

Generic `oidcProvider` and Google validate ID-token claims while trusting the
direct TLS token exchange for integrity. They do not verify ID-token signatures.
Apple verifies its signature separately. Do not pass out-of-band ID tokens to
connectors designed for a direct authorization-code exchange. Generic OIDC
requires HTTPS endpoints except loopback development URLs and refuses provider
fetch redirects. A trusted provider configuration is part of that boundary.

## OIDC issuance scope

- **Signing is ES256 only** (Web Crypto, zero dependencies). There is no RS256
  option; verify your relying parties accept ES256.
- `id_token` claims are released per scope through the app-provided `userClaims`
  hook; there is no `claims` request-parameter support.
- Authentication-event claims (`auth_time`, `acr`, and `amr`) are opt-in through
  the configured claims hooks. The application supplies verified evidence, and
  its code/token stores must retain the captured snapshot across refreshes. The
  package does not infer assurance or methods, or enforce the raw `acr_values`,
  `max_age`, and `prompt` controls. Omit unknown evidence; legacy and userless
  tokens do not gain it automatically. See
  [Preserve the authentication event](guides/become-an-oauth-provider.md#preserve-the-authentication-event)
  for store, hook, and BFF integration.

## Identity flows (`@udibo/oauth2/identity`)

- Automatic password upgrades require atomic
  `IdentityUserStore.replaceCredential`. Stores without it skip upgrades. A
  failed comparison re-verifies the password against the credential now stored:
  a login that raced with a reset to a different password is rejected, one that
  raced with another correct login is not.
- OTP `consume` must atomically return whether this caller consumed the record.
  Concurrent issuance is separate: invalidate/create are not one transaction, so
  serialize requests when only one code may remain outstanding.
- Uniform response bodies do not by themselves make request timing uniform.
  Account lookup, persistence, and email delivery can still expose differences.
  Throttle requests and avoid synchronously waiting for network mail delivery.

- The built-in fixed-window rate limiter is deliberately feature-frozen; it is a
  floor, not a product. Two seams sit under it and they do different jobs:
  **`RateLimiterLike` replaces the limiter** — implement `check` / `reset` for a
  sliding window, a token bucket, IP reputation, or a limiter you already run —
  while **`RateLimitStore` only relocates the counters** the built-in fixed
  window keeps. A store cannot deliver a sliding window: the window arithmetic
  lives in `RateLimiter.check` and the store is told nothing but `windowMs`.
  `AccountLockoutLike` is the matching seam for lockout policy. Both are
  structural, so a plain object with the right methods is assignable.
- `MemoryRateLimitStore` sweeps lapsed buckets and is hard-capped at 10,000, so
  attacker-chosen keys cannot grow it without bound — but a bounded store must
  discard something, and at the cap it evicts. It evicts the **coldest** live
  buckets first (fewest hits, ties broken by soonest reset), never the oldest,
  so a unique-key flood discards the attacker's own single-hit junk rather than
  the counter that is throttling them. The residual is that an attacker willing
  to raise ~10,000 keys above a victim's hit count can still displace that
  victim's counter — roughly a 10x cost increase over a naive flood, not an
  impossibility. Bounding memory and resisting eviction are in genuine tension
  in a single process; this is a dev / single-process store, and production
  backs the limiter with Redis or a database where neither compromise is forced.
- `MemoryLockoutStore` is bounded the same way: it forgets an account's failures
  `ttlMs` (24 hours) after the last one, never while the account's lock is
  active, and holds at most `maxEntries` (10,000) records. At the cap it drops
  expired records first, then evicts unlocked records before locked ones, the
  fewest failures first. Lockout keys are account ids, so displacing an active
  lock takes failures against more than 10,000 other accounts that each end
  locked. The TTL also means a slow guesser who waits a day between failures
  never reaches the threshold in this store; a store over your database keeps
  the count until a successful sign-in clears it.
- `rateLimiter` covers every flow, keyed only by prefix, so a single threshold
  applies until you override the email-sending flows through `rateLimiters` —
  per-flow limiters are configuration, not a default.
- IP-based throttling is a route-layer concern by design — the service has no
  request context.
- The flows are single-app primitives: multi-tenancy, organizations, and SSO
  orchestration are intentionally out of scope for this library.
- **`resetPassword` voids outstanding passwordless credentials only as far as
  your stores let it.** It drops the subject's pending sign-in links
  (`TokenFlowStore.deleteBySubject(TokenPurpose.SignIn, userId)`) and the
  pending sign-in code (`OtpStore.invalidate(email, purpose)`) after the
  password changes. Both calls are best-effort: `deleteBySubject` is
  **optional** on `TokenFlowStore`, so a store that does not implement it leaves
  outstanding links redeemable until they expire, and a store that throws is
  logged rather than failing the reset — the password has already changed by
  that point. The OTP half also depends on the reset token carrying
  `data.email`, which `requestPasswordReset` sets; an app that mints reset
  tokens by calling `TokenFlowService.create` itself gets the link half only.
  Account-unlock and email-verification links are deliberately untouched —
  neither authenticates anyone.
- **`honoIdentityRoutes`' CSRF guard trusts the browser, and only the browser.**
  The factory mounts a same-origin guard on unsafe methods by default: a request
  whose `Sec-Fetch-Site` is anything but `same-origin`/`none` is refused with
  `403 { "error": "forbidden_origin" }`, and for browsers that omit that header
  it falls back to comparing the `Origin` header's **host** (not scheme — a
  TLS-terminating proxy leaves the request URL on `http:`). That is sound
  against a cross-site page, because page JavaScript cannot forge either header.
  It is not a synchronizer token: a caller that speaks HTTP directly sends
  neither header and is allowed through by design (that is not CSRF), and an
  intermediary that rewrites those headers defeats it. Safe methods are left to
  the router so preflights still work. Use `csrf: { allowedOrigins: [...] }` for
  a legitimate cross-origin form, or `csrf: false` when an outer middleware
  already terminates CSRF.

## Sessions (`@udibo/oauth2/hono/bff`)

- **`EncryptedCookieSessionStore` cannot genuinely revoke a session.**
  `destroy()` is a no-op — statelessness is the whole point — so sign-out clears
  the browser's cookie and nothing else, and a captured copy stays valid until
  it either expires or ages out. The same holds when a new sign-in in the same
  browser (an organization switch, a step-up) replaces the session: the browser
  receives the new cookie, but a copy of the earlier one still reads as signed
  in, and the BFF does not revoke its refresh token because an authorization
  server may extend that revocation to the new tokens (RFC 7009 §2.1). Revoke
  the refresh token at the authorization server, or use a database-backed
  `SessionStore` where revocation is real and immediate. Two options shrink the
  window without making `destroy` real:
  - **Secret rotation with a grace window.** `secret` accepts an ordered list:
    the first entry seals every new cookie and `read` tries each in turn, so
    rotating `SESSION_SECRET` is a `[new, old]` deploy that keeps existing
    sessions readable rather than a fleet-wide forced sign-out. Drop the old
    secret once the grace window elapses. This mirrors the multi-key JWKS grace
    window for signing keys. A single secret seals and reads with that one key.
  - **Bounded lifetime, on by default.** `maxAgeMs` stamps each cookie with a
    seal time and rejects any cookie older than the cap on `read`, bounding how
    long a captured cookie stays useful without any server-side state. It
    defaults to 14 days rather than being opt-in, and there is no unbounded
    setting — a bearer cookie `destroy()` cannot revoke has to expire on its
    own. Because `update` re-seals with a fresh stamp, the cap is an inactivity
    window; `HonoBff`'s `sessionMaxAgeMs` (also 14 days) is the absolute one,
    and the constructor throws if the two are configured to disagree. Genuine
    revocation still requires a DB-backed store.
- **Refreshing across instances needs a store with a refresh lock.** `HonoBff`
  shares one token refresh between concurrent requests for a session on the
  same instance. Across instances it relies on the session store: a store that
  implements `withRefreshLock` (`RefreshLockStore`) makes the instances refresh
  a session one at a time, and an instance that waited re-reads the session and
  uses the tokens its peer stored instead of spending the refresh token again.
  `MemorySessionStore` implements it for the BFFs that share one store object.
  A shared `SessionStore` without it leaves a race when parallel requests for
  one session reach different instances near access-token expiry, as when a
  single-page app fires several calls after sitting idle. Against an
  authorization server that rotates refresh tokens, both instances present the
  same refresh token. The loser's exchange fails and it destroys the session,
  or it arrives a moment later with a rotated-out token, reuse detection
  revokes the whole rotation family, and `onTokenReuse` reports a replay that
  was not an attack. Either way the user is signed out. Implement
  `withRefreshLock` on any store more than one instance shares, and check it
  with `runSessionStoreContractTests`.
- **With `EncryptedCookieSessionStore`, a request carrying the cookie from
  before a refresh can replay the old refresh token.** The session lives in
  the browser's cookie, so the server has nothing to lock or re-read. A
  refresh seals the rotated token into a new cookie that reaches the browser
  with that response, and a request the browser sent before then still carries
  the old one. `HonoBff`'s `rotatedCookieGrace`, on by default, covers the
  instance that ran the refresh: for 10 seconds it answers the old cookie with
  the new session and its cookie, for up to 1000 replaced cookies, and
  forgets a session on sign-out. A request with the old cookie that reaches
  another instance, or arrives after the grace, presents the rotated-out
  refresh token: reuse detection revokes the family, `onTokenReuse` fires, and
  both cookies stop working. An authorization server that does not rotate
  refresh tokens is unaffected. Where it rotates them, route each browser to
  one instance, or prefer a shared stateful store that implements
  `withRefreshLock`.
- **`rotatedCookieGrace` trades some of reuse detection's signal for
  fewer false sign-outs.** Within the grace, a stolen copy of the pre-refresh
  cookie replayed to the instance that ran the refresh receives the new
  session instead of tripping reuse detection. A cookie store cannot revoke a
  copied cookie anyway, but the grace hides the replay from `onTokenReuse` for
  that window. Shorten it with `rotatedCookieGrace: { ttlMs }`, or turn it off
  with `rotatedCookieGrace: false` and accept that stragglers sign the user
  out.
- **A token refresh in flight on a replaced session can clear the new cookie.**
  When a request on the earlier cookie starts a refresh just before a new
  sign-in in the same browser replaces that session, the refresh then fails as
  revoked and its response clears the session cookie, which by then names the
  new session. The browser is signed out and signs in again; the new session's
  record stays until it expires.
- Back-channel logout is unavailable on any store that cannot enumerate
  sessions, and `HonoBff` throws at construction rather than degrading silently.
- **Behind a TLS-terminating proxy, the request URL reports `http:`.** A Node
  server such as `@hono/node-server` sees the proxy's plain-HTTP hop. The BFF
  therefore takes the application's origin from configuration wherever that
  origin must match a registration. RP-Initiated Logout's
  `post_logout_redirect_uri` uses `resolveOrigin`, else the origin of the
  client's configured `redirectUri`. The `GET /auth/logout` same-origin
  fallback accepts that origin as well as the request's own. Only with
  `deriveRedirectUri`, or with no `redirectUri` configured, does the BFF use the
  request's origin. That is how sign-in builds its `redirect_uri` then, so a
  deployment like that behind a TLS proxy must set `resolveOrigin`.
- **`attachToken()` overwrites an inbound bearer; `protect()` lets it win.** The
  two guards are presented as alternatives, and they differ here:
  `attachToken()` resolves the session and `set`s
  `Authorization: Bearer <session
  token>` unconditionally, replacing whatever
  the caller sent, while `protect()` checks for an inbound bearer first and
  validates that one directly (so one guard serves both the BFF's own frontend
  and machine-to-machine clients). Both behaviors are deliberate and pinned by
  tests. Neither is attacker-forceable from a browser: the package writes no
  `Access-Control-*` header anywhere in `src/`, so a cross-origin page cannot
  set an `Authorization` header on a credentialed request, and the CSRF header
  check runs before either path. The practical rule is the one the difference
  implies — if a mount must serve machine-to-machine callers, use `protect()`;
  if a mount must **only** ever act as the signed-in browser user,
  `attachToken()` is the one that guarantees it.
- **`SessionData` and `ListableSessionService` are two layers, not a missing
  bridge**. `SessionData` (in `@udibo/oauth2/hono/bff`) is the BFF's _token
  custody_ record — the access token, refresh token, cached claims, `sid`.
  `ListableSessionService` (in `@udibo/oauth2/identity`) is the _app login
  session_ seam a "where you're signed in" screen renders and revokes against.
  They describe different things, so there is deliberately no automatic mapping
  between them.

  The reason this reads as a gap is that `SessionData` carries no id field — but
  it does not need one: every `SessionStore` method is keyed by `cookieValue`
  (`read`, `update`, `destroy` all take it, and `create` returns it), so an
  app-owned store already holds the id for each record and can project its own
  rows into `SessionSummary` directly. The correlating field is that internal
  record ID, which is safe to return as `SessionSummary.id`. Never expose
  `cookieValue` or its hash in a session summary: the cookie value authenticates
  requests. Keep a separate non-secret row identifier. When the app and the BFF
  should share one session record rather than keeping two, the documented bridge
  is `sessionMode: "shared"`, which attaches the tokens to the session your
  login already created.

## Runtime

- **The `udibo-oauth2` command is Node-only.** It uses `node:http`, `node:fs`
  and `process`, so it runs on Node 22 or later and nowhere else. It is a
  development tool (`oidc keygen`, `idp dev`); nothing on the library path
  imports it, so its floor never constrains the rest of the package. Outside
  the command, the library path is Web-standard apart from `node:crypto`
  (`timingSafeEqual`) in `/identity` and `/identity/migration`, and one feature
  check: the default `fetch` uses `Deno.createHttpClient` when it exists, as the
  next item describes. The testing helpers (`/testing`, `/testing/contract`,
  `/hono/bff/testing`, `/react/testing`) register suites through Vitest. The
  full matrix is in [the README](../README.md#runtime-support); the support
  boundary is in [the stability policy](stability.md#runtime-support).
- **On Deno, a request that misses the package's own deadline moves later
  requests off the pooled connection.** Deno's global `fetch` sends every
  request to an origin over one pooled HTTP/2 connection, and aborting a request
  at its deadline resets only that request: if the connection itself has stopped
  answering — a proxy still routing it to a backend that restarted, say — it
  stays pooled, and every later request to that origin would time out on it as
  well. So when one of the requests the package bounds with a deadline of its
  own is sent with the default `fetch` to an `https` origin and misses that
  deadline before its response has fully arrived, every later default-`fetch`
  request from that process to that origin opens a connection of its own and
  closes it once the response headers arrive. Those requests are:
  `JwksTokenReader`'s JWKS and discovery fetches and `IntrospectionTokenReader`
  (`fetchTimeoutMs`); `checkPermissions`; `DirectClient`'s discovery, token,
  revocation and userinfo calls and `BffClient`'s session probe;
  `breachedPasswordValidator`; and every request the external connectors send:
  the token exchange, the profile, UserInfo and GitHub API reads, Apple's JWKS,
  and the OIDC connector's discovery. Nothing else triggers the switch: not a
  request aborted for any other reason, not a deadline a caller sets on its own
  signal (`DirectClient.fetch(url, { signal })`), and not the calls that carry
  no package deadline — `DirectClient.fetch` and `BffClient.fetch`, and the BFF
  proxy. Those still take a connection of their own to an origin that has
  already switched, and their responses are the global `fetch`'s, unaltered.
  The switch trades connection reuse to that origin, for the life of the
  process, for not depending on a pooled connection that may be stalled. Plain
  `http` (which Deno sends over HTTP/1.1, where an abort already discards the
  connection) keeps the shared pool, and other runtimes use their global
  `fetch` unchanged. An injected `fetch` manages its own connections and gets
  none of this; one that pins an HTTP/2 client of its own should replace that
  client after a timeout.
