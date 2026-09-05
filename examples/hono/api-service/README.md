# `api-service` example

A standalone backend service whose API routes are gated by OAuth2 bearer tokens
issued by an **external** identity provider.

Use this shape when you have a backend (microservice, M2M API, worker-fronting
endpoint) that needs to accept tokens but has no frontend of its own.

## What this example includes

- `HonoResourceServer` with `IntrospectionTokenReader` validating bearer tokens
  against the external IDP's `/oauth2/introspect` endpoint (RFC 7662).
- API routes demonstrating different scope requirements:
  - `GET /api/public` — no token required
  - `GET /api/private` — any valid token
  - `GET /api/write` — token must carry `write` scope
  - `GET /api/admin` — token must carry `admin` scope
- An interactive `GET /` walkthrough page that drives every OAuth2 grant type
  against the companion `app-with-own-auth/` example and tests the resulting
  token against `/api/*`.
- A dev-only `/dev/callback` redirect target and `/dev/token` proxy so the
  homepage can exercise the auth-code flow without exposing the client secret in
  the browser. Real api-services don't host these. The auth-code flow uses PKCE
  (required by default under OAuth 2.1, even for confidential clients): the
  homepage mints a verifier, stashes it in an HttpOnly cookie, and puts only the
  S256 challenge in the authorize URL; `/dev/callback` reads the verifier back
  to complete the token exchange.
- Tests that stub `tokenReader.getToken` directly (no introspection wire format
  faked in test code — the framework owns that).

## Running it

By default this example points at `app-with-own-auth/` on port 8001 as its IDP.
Start both:

```bash
# Terminal 1 — the IDP
deno task serve:app-with-own-auth

# Terminal 2 — this service
deno task serve:api-service
```

Then open <http://localhost:8002/>.

## What to change to make this production-ready

The example deliberately skips operational concerns to keep the OAuth2 wiring
readable. When you copy this to a real project:

- **Move `AUTH_SERVER_URL`, `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URI` out of
  `oauth2/server.ts` into env config.** Hardcoded credentials ship with the demo
  because the example must stand up without setup.
- **Register this service as a client with the external IDP** (e.g. Udibo,
  Auth0, Cognito). The `CLIENT_ID` / `CLIENT_SECRET` here authenticate the
  _introspection request_ — the IDP gates who can introspect tokens.
- **Drop the `/dev/*` mount.** Token acquisition is a client-app concern; this
  service shouldn't host it.
- **Persist anything you cache on the introspection response.** The example
  calls introspection on every request; production deployments typically cache
  active tokens in memory (or Redis) until expiry to avoid hitting the IDP on
  every call.
- **Add rate limiting and logging** on `/api/*` — both standard hardening,
  neither shown here.
- **Wire OpenTelemetry / your tracing system** through the resource server's
  `getContext(c)` so you can correlate API calls back to the client and user
  that made them.
- **If you need user data beyond `sub` and `username`**, enrich it in
  `getUser(data)` by joining against your own user table on `data.sub` (the
  IDP's stable user identifier), or by calling the IDP's `/userinfo` endpoint
  (OIDC). A machine token (client credentials) carries no `sub`, so `data.sub`
  is present only when there is a real user to join against.

The introspection wire format itself is covered by
`@udibo/oauth2/server/resource`'s `IntrospectionTokenReader` — you do not write
that code yourself, just the `getClient` / `getUser` projection mappers in
`oauth2/server.ts`.
