# Known Limitations

Behavior to account for when choosing and deploying an integration. The API
reference documents each option; this page collects cross-cutting limits and
application-owned responsibilities.

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

Confidential clients authenticate alongside PKCE by default as of 0.1.0.
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
  server never populates them today. Practical consequence: a resource server
  that enforces audience restriction via introspection `aud` cannot do so —
  issue JWT access tokens (`createJwtAccessTokenGenerator`) and validate them
  with `JwksTokenReader`, which enforces `aud`, if you need in-token
  audience/issued-at claims.
- **Introspection answers for any client's token, by design.** `/introspect`
  requires client authentication but does **not** check that the presented token
  was issued to the authenticated client — deliberately, because RFC 7662 is
  written for _resource servers_, which are by construction not the issuing
  client, so an ownership check would break the endpoint's primary use. (Token
  **revocation** does check ownership, per RFC 7009 §2.1.) That makes "who may
  introspect what" application policy, delegated entirely to whoever mounts the
  endpoint: every client you register with introspection access can read the
  metadata of every live token the server issued.

  The disclosure surface of one successful call is `active`, `client_id`,
  `scope`, `exp`, `iss`, and — when the token has a resource owner — `sub` and
  `username`. That is enough to enumerate which user a captured token belongs to
  and what it may do. If your deployment has clients that should not learn that
  about each other, gate the endpoint yourself: mount it on a network the
  untrusted clients cannot reach, or register introspection-capable credentials
  separately from ordinary client credentials.
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
  lifetime or online validation when prompt revocation is required.

- **Clock skew is two options, and only one of them is on by default.**
  `JwksTokenReaderOptions.clockSkewSeconds` (default 30) governs the reader's
  own `exp` and `nbf` claim checks; the reader then hands `ResourceServer` a
  token whose `accessTokenExpiresAt` is the issuer's raw `exp`, and
  `ResourceServer.getToken` re-checks it with
  `ResourceServerOptions.clockSkewSeconds`, which defaults to **0**. Set both to
  tolerate drift end to end. The resource-server option is the only one that
  reaches an `IntrospectionTokenReader`, which has no notion of skew at all. The
  `nbf` half is still reader-only — nothing re-checks `nbf` — so a slow-clock
  issuer is tolerated only by the reader.
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
  option; verify your relying parties accept ES256 .
- `id_token` claims are released per scope through the app-provided `userClaims`
  hook; there is no `claims` request-parameter support.
- `acr` / `amr` are not asserted.

## Identity flows (`@udibo/oauth2/identity`)

- Automatic password upgrades require atomic
  `IdentityUserStore.replaceCredential`. Stores without it skip upgrades; a
  failed comparison rejects the login that raced with a reset.
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
  attacker-chosen keys can no longer grow it without bound — but a bounded store
  must discard something, and at the cap it evicts. It evicts the **coldest**
  live buckets first (fewest hits, ties broken by soonest reset), never the
  oldest, so a unique-key flood discards the attacker's own single-hit junk
  rather than the counter that is throttling them. The residual is that an
  attacker willing to raise ~10,000 keys above a victim's hit count can still
  displace that victim's counter — roughly a 10x cost increase over a naive
  flood, not an impossibility. Bounding memory and resisting eviction are in
  genuine tension in a single process; this is a dev / single-process store, and
  production backs the limiter with Redis or a database where neither compromise
  is forced.
- `rateLimiter` covers every flow, keyed only by prefix, so a single threshold
  applies until you override the email-sending flows through `rateLimiters` —
  per-flow limiters are configuration, not a default.
- IP-based throttling is a route-layer concern by design — the service has no
  request context.
- The flows are single-app primitives: multi-tenancy, organizations, and SSO
  orchestration are intentionally out of scope for this library.
- **`resetPassword` voids outstanding passwordless credentials only as far as
  your stores let it.** It now drops the subject's pending sign-in links
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
  it either expires or ages out. Revoke the refresh token at the authorization
  server, or use a database-backed `SessionStore` where revocation is real and
  immediate. Two options shrink the window without making `destroy` real:
  - **Secret rotation with a grace window.** `secret` accepts an ordered list:
    the first entry seals every new cookie and `read` tries each in turn, so
    rotating `SESSION_SECRET` is a `[new, old]` deploy that keeps existing
    sessions readable rather than a fleet-wide forced sign-out. Drop the old
    secret once the grace window elapses. This mirrors the multi-key JWKS grace
    window for signing keys. A single secret still behaves as before.
  - **Bounded lifetime, on by default.** `maxAgeMs` stamps each cookie with a
    seal time and rejects any cookie older than the cap on `read`, bounding how
    long a captured cookie stays useful without any server-side state. It
    defaults to 14 days rather than being opt-in, and there is no unbounded
    setting — a bearer cookie `destroy()` cannot revoke has to expire on its
    own. Because `update` re-seals with a fresh stamp, the cap is an inactivity
    window; `HonoBff`'s `sessionMaxAgeMs` (also 14 days) is the absolute one,
    and the constructor throws if the two are configured to disagree. Genuine
    revocation still requires a DB-backed store.
- Back-channel logout is unavailable on any store that cannot enumerate
  sessions, and `HonoBff` throws at construction rather than degrading silently.
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

- **`./cli` is the only Deno-locked entrypoint.** It uses `Deno.serve`,
  `Deno.env`, `Deno.readTextFile` and `Deno.args`, so it runs on Deno and
  nowhere else. Every other subpath is Web-standard — no `node:` import and no
  runtime-specific global anywhere on the library path (the `Deno.env.get` you
  see in connector JSDoc is example prose, not code the package runs). The CLI
  is a development tool (`oidc keygen`, `idp dev`); nothing on the library path
  imports it, so its floor never constrains the rest of the package. The full
  matrix is in [the stability policy](stability.md#runtime-support).
