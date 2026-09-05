# `app-with-external-auth` example

A single-process Hono app — SPA + BFF + own resource server — delegating
authentication to an **external** identity provider over real HTTP. The
canonical "I'm using Udibo (or another IDP) for login" topology.

Use this shape when:

- Your users sign in via Udibo, Auth0, Cognito, Google, Okta, or any other RFC
  6749 / 6750 / 7662 IDP.
- You want full control over your SPA and your API, but you're not building the
  identity layer yourself.

This example is **structurally identical** to `app-with-own-auth/` — same Hono
mount layout, same SPA homepage, same `/api/*` shape, same scope handling, same
`HonoBff` and `HonoResourceServer` usage. Diff the two folders to see exactly
what changes between self-hosted and delegated auth.

## What this example includes

- **OAuth2 client** (`DirectClient` with a client secret) configured with real
  `fetch` against the IDP's endpoints. No `localAuthServerFetch` — token
  exchanges and refreshes go over the network like any other HTTP call.
- **BFF** (`HonoBff`) mounted at `/auth/*` exposing `/auth/login`,
  `/auth/callback`, `/auth/logout`, `/auth/session`. `/auth/login` redirects the
  browser to the IDP's `/oauth2/authorize`; `/auth/callback` exchanges the
  returned code server-side.
- **Resource server** (`HonoResourceServer`) with `IntrospectionTokenReader`
  validating bearer tokens via RFC 7662 introspection against the IDP.
- **Protected routes** with scope gating: `/api/me`, `/api/write`, `/api/admin`.
- **BFF CSRF protection left on** (the default). The homepage's hand-written
  `fetch` calls send the `x-csrf` header themselves; a real SPA gets it from the
  React adapter or `BffClient`'s wrapped `fetch`. This matters most for the
  proxied mount below — a wildcard proxy is exactly what you don't want to
  expose without it.
- **A proxied route to a separate API** at `/remote-api/*`, mounted with
  `bff.proxy()`. The `/api/*` routes above are validated in this process; this
  one is forwarded to the `api-service/` example on port 8002 with the session's
  access token attached and the response streamed back. Both topologies, one
  app, so the difference is a diff.
- **Interactive SPA homepage** at `/` with sign-in, sign-out, and endpoint-call
  buttons. No login form or consent UI here — those live on the IDP.
- **Tests** that stub `tokenReader.getToken` and seed BFF sessions via
  `createTestSession` from `@udibo/oauth2/hono/bff/testing`. The introspection
  wire format is covered by the framework's own tests; the example tests focus
  on routing, scope gates, and error responses.

## The migration path is the diff

The two `app-*` examples differ in exactly two configuration points:

1. **`DirectClient.fetch`** — `localAuthServerFetch(authServer)` (own auth) vs.
   real `fetch` (external IDP).
2. **Resource server's token service** — the shared in-process `tokenService`
   (own auth) vs. an `IntrospectionTokenReader` configured with the IDP's
   `introspectionEndpoint`, `clientId`, `clientSecret` (external IDP).

Plus the structural cleanup that follows: external-auth apps don't host
`/oauth2/*`, `/login`, `/logout`, `/consent`, or `/device` — those endpoints
belong to the IDP. Diff `app-with-own-auth/` and this folder to see the
migration as a real patch.

## Running it

By default this example points at `app-with-own-auth/` on port 8001 as its IDP.
Start both:

```bash
# Terminal 1 — the IDP
deno task serve:app-with-own-auth

# Terminal 2 — this app
deno task serve:app-with-external-auth

# Terminal 3 (optional) — the separate API behind /remote-api/*
deno task serve:api-service
```

Then open <http://localhost:8003/>. Without terminal 3 the page works normally;
only the `/remote-api/private` button returns `502`.

Configuring this app for local development, preview deployments, and production
— including what to do about preview URLs that change every deploy — is covered
in
[Local, preview, and production for a relying party](../../../docs/guides/deploy-across-environments.md).

## What to change to make this production-ready

- **Move `IDP_BASE_URL`, `APP_BASE_URL`, `IDP_CLIENT_ID`, `IDP_CLIENT_SECRET`,
  `API_SERVICE_URL` out of `oauth2/server.ts` into env config.** These are the
  production swap points. In production:
  - `IDP_BASE_URL` points at Udibo (or whichever IDP you're using).
  - `APP_BASE_URL` is your deployed app URL.
  - `IDP_CLIENT_ID` / `IDP_CLIENT_SECRET` come from registering this app as a
    client in the IDP's admin UI.
- **Register your `redirect_uri` with the IDP**. The default is
  `${APP_BASE_URL}/auth/callback`. The IDP rejects any redirect URI not in its
  registered list.
- **Replace `MemorySessionStore`** with a persistent store: the included
  `EncryptedCookieSessionStore` (stateless, in `@udibo/oauth2/hono/bff`), or
  your own server-side `SessionStore` implementation (Redis, Postgres, …)
  verified with `runSessionStoreContractTests`.
- **Replace the client's in-memory auth-request storage** if requests can land
  on more than one instance. The pending `state` → PKCE verifier record defaults
  to `MemoryAuthRequestStorage`, so `/auth/login` and `/auth/callback` served by
  different isolates fail with `unknown state parameter` — the characteristic
  intermittent sign-in failure on serverless platforms. Pass
  `authRequestStorage: new EncryptedCookieAuthRequestStorage({ secret })` to the
  BFF to carry it in an encrypted cookie, or implement `AuthRequestStorage` over
  your database and pass it as `{ forRequest: (c) => yourStorage(c) }`.
- **Remove the `secure: false` cookie override** on the BFF — it defaults to
  `secure: true`; the example sets `false` only so it works over local HTTP.
- **Cache introspection responses** until the token's `exp` — the default
  `IntrospectionTokenReader` calls the IDP on every request. Caching is left out
  for clarity but is essential in production.
- **Replace the `resolveUser` introspection call with a userinfo (OIDC) call**
  if your IDP supports it. Introspection is intended for resource servers;
  userinfo is intended for user identity. Both work, but userinfo gives you
  richer claims (email, name, picture, custom attributes) and is the
  OIDC-canonical path.
- **Wire your own user record** alongside the IDP's `sub`. The example's
  `resolveUser` returns only `{ sub, username }`. Real apps typically look up an
  internal user record keyed on `sub` so they can attach app-specific data
  (role, tenant, preferences) without round-tripping to the IDP every time.
- **Add rate limiting and logging** on `/api/*`.
- **Wire OpenTelemetry / your tracing system** through the BFF middleware so you
  can correlate sessions to API calls and onwards.
- **Handle IDP logout (OIDC `end_session_endpoint`)**. The example's "Sign out"
  button clears the local BFF session but doesn't sign the user out of the IDP.
  A real app should also call the IDP's logout endpoint so the next sign-in
  shows the IDP's login form instead of silently re-authenticating.
