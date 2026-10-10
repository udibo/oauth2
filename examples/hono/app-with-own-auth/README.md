# `app-with-own-auth` example

A single-process Hono app that runs an OAuth2 authorization server, a BFF, and a
resource server together. The canonical "I want to own my identity layer"
topology — your app is also the IDP.

Use this shape when:

- You want full control over the login flow, consent screen, and user data, with
  no third-party IDP in the loop.
- You're shipping a SaaS where your users sign in to your platform (not to
  Google / Auth0 / Udibo).
- You want to issue your own tokens for third-party clients (M2M partners,
  mobile apps, etc.) as well as power your own SPA.

If instead you want to use Udibo (or another IDP) for authentication, see
`app-with-external-auth/`. It's this same SPA + BFF + resource-server shape with
the embedded authorization server and its `/login`, `/consent`, and `/device`
routes removed — compare the two folders' `oauth2/server.ts` and `main.ts` to
see exactly what delegated auth drops.

## What this example includes

- **Authorization server** (`HonoAuthorizationServer`) mounted at `/oauth2/*`
  with the standard endpoints: `/authorize`, `/token`, `/revoke`, `/introspect`,
  `/device_authorization`, plus `/.well-known/oauth-authorization-server`
  metadata.
- **Supported grants**: authorization code (with PKCE), refresh token, client
  credentials, and device authorization (RFC 8628).
- **Real login UI** at `/login` backed by the `MemoryUserService` (seeded with
  two demo users: `admin` and `user`, both `password`).
- **Sign-up UI** at `/create-account` that creates a user, auto-signs-in, and
  hands back to the OAuth2 flow — _resuming_ an in-flight authorize URL or
  _starting_ a fresh `/auth/login` when reached as a normal entry point. This is
  the handoff `routes/login.ts` (only ever reached mid-authorize) never has to
  do, and it's why the example ships it: an own-auth app almost always owns
  sign-up too. (The BFF lifts that decision into the library itself as
  `bff.loginContinuation()`.)
- **Password reset** at `/forgot-password` + `/reset-password` — the library's
  `IdentityService` flow end to end: an enumeration-safe request form mints a
  single-use, expiring token (hashed at rest via `MemoryTokenFlowStore`), the
  consume form validates without burning the token, and a completed reset
  revokes the user's other IDP sessions. No email transport in the example — the
  reset link is logged to the server console; a real app swaps the two delivery
  hooks in `oauth2/identity.ts` for its mailer.
- **Email verification** at `/verify-email` — sign-up with an email mints a
  verification link (also console-logged) whose consumption marks the user
  verified, with distinct expired vs. invalid outcomes.
- **Real consent UI** at `/consent` that records the user's decision in a
  server-side one-time record (keyed by a short-lived cookie, bound to the
  user/client/scope) before redirecting back to `/oauth2/authorize` — the
  decision never rides the authorize URL, which the client builds and could
  forge. The consent handler narrows the granted scope to the user's `maxScope`
  field — so an `admin`-only endpoint rejects tokens issued for the regular
  `user`.
- **Device-verification UI** at `/device` for the RFC 8628 device flow.
- **BFF** (`HonoBff`) mounted at `/auth/*` wrapping a `DirectClient` with a
  client secret against the in-process auth server via `localAuthServerFetch` —
  no socket roundtrip for token exchanges. Its `resolveUser` hook populates
  `session.user` after the code exchange by looking the user up through the
  shared in-process `tokenService` — this auth server is OAuth2-only (no
  `id_token`), so the BFF can't decode claims from a JWT; a BFF talking to a
  separate OIDC provider would call `/userinfo` (or introspection) here instead.
- **Resource server** (`HonoResourceServer`) sharing the auth server's
  in-process `tokenService` so bearer-token validation skips introspection
  entirely.
- **Interactive SPA homepage** at `/` with sign-in, sign-out, and endpoint-call
  buttons that show how scope governs access.

## Running it

This example is a pnpm workspace member that depends on the package through
`@udibo/oauth2: workspace:*`, which resolves to the package's built `dist/`.
From the repository root, install and build once, then start it:

```bash
pnpm install
pnpm build
pnpm --filter example-app-with-own-auth start
```

Then open <http://localhost:8001/>. Use
`pnpm --filter example-app-with-own-auth dev` to restart on file changes
(`node --watch`). The `api-service` and `app-with-external-auth` examples use
this app as their identity provider.

Configuration is read from the environment by `config.ts`, which validates it
at startup and lists every invalid variable at once. Every variable is optional.

| Variable              | Default                 | Meaning                                                              |
| --------------------- | ----------------------- | -------------------------------------------------------------------- |
| `PORT`                | `8001`                  | Port to listen on (`0` picks a free one)                             |
| `PUBLIC_URL`          | `http://localhost:PORT` | Origin of this app; it is the OAuth2 issuer and base of emailed links |
| `API_SERVICE_ORIGIN`  | `http://localhost:8002` | Origin of `api-service`, whose `/dev/callback` redirect is registered  |
| `EXTERNAL_APP_ORIGIN` | `http://localhost:8003` | Origin of `app-with-external-auth`, whose `/auth/callback` is registered |

Run the tests with `pnpm --filter example-app-with-own-auth test`. The main
suite drives the whole sign-in, consent, device, reset and verify flows
in-process through `app.request()`; `serve.test.ts` starts the real Node server
on a free port.

## What to change to make this production-ready

- **Replace `MemoryUserService`, `MemoryClientService`, `MemoryTokenService`,
  `MemoryAuthorizationCodeService`, and `MemoryDeviceAuthorizationService`**
  with DB-backed implementations of the corresponding interfaces. The contract
  test runners in `@udibo/oauth2/testing/contract` will verify your
  implementations conform.
- **Replace `MemorySessionStore`** with a persistent store. The only persistent
  store that ships is `EncryptedCookieSessionStore` (stateless, AES-GCM cookie,
  in `@udibo/oauth2/hono/bff`). For a server-side store (Redis, Postgres, …),
  implement the exported `SessionStore` interface —
  `runSessionStoreContractTests` verifies your implementation conforms.
- **Remove the `secure: false` cookie overrides** — the BFF cookie defaults to
  `secure: true`, and the `idp_session` cookie in `sessions.ts` also hardcodes
  `secure: false`. The example sets `false` only so it works over local HTTP;
  production should always be HTTPS. (The in-memory `sessions` Map in
  `sessions.ts` is also a demo store — replace it alongside
  `MemorySessionStore`.)
- **Set `PUBLIC_URL` (the issuer) to your deployed HTTPS origin** and register
  your real clients' redirect URIs in place of the companion-example origins in
  `oauth2/server.ts`. The localhost defaults ship with the demo because the
  example must stand up without setup.
- **Persist consent decisions per `(userId, clientId, scope)`** so users aren't
  re-prompted on every login. The example always shows the consent screen for
  visibility.
- **Calibrate the password work factor** if you stick with the built-in PBKDF2
  helper — `new PasswordIdentityService({ iterations })`, defaulting to 600,000
  — or swap it for argon2id / scrypt through the `PasswordHasherLike` seam.
  Persist the credential's `params` field either way: it records the algorithm
  and work factor, which is what lets the factor be raised later and applied one
  login at a time instead of by a forced reset.
- **Bind `markEmailVerified` to the address the link was minted for.** This
  example's store ignores the second argument, so a link requested for one
  address would verify whichever address the account holds when it is clicked. A
  real store predicates the update on the id **and** the email.
- **Add CSRF protection on `/login`, `/create-account`, and `/consent`** — the
  example omits it for readability. Use Hono's CSRF middleware or a similar
  pattern. The BFF itself ships CSRF protection on by default (a required
  `x-csrf` header on credentialed requests); this example passes `csrf: false`
  only because the homepage uses hand-written `fetch` calls. Real SPAs use the
  React adapter (or the `BffClient`'s wrapped `fetch`), which sends the header
  automatically — so drop the override and keep the secure default.
- **Add rate limiting** on `/login`, `/create-account`, `/forgot-password`,
  `/oauth2/token`, and any other endpoint that gates authentication or token
  issuance.
- **Wire real email transport** — the reset and verification flows are complete
  (token lifecycle, enumeration safety, session revocation), but delivery is
  console-only: replace the two hooks in `oauth2/identity.ts` with your mailer.
  Enqueue the send instead of awaiting your mail provider in-request: the
  forgot-password response body is enumeration-safe, but an awaited send would
  make response _timing_ reveal which emails have accounts. Add MFA, lockout,
  and captcha as needed.
- **Wire OpenTelemetry / your tracing system** through the auth server's request
  handlers and the BFF's middleware so you can correlate sign-ins to sessions to
  API calls.
- **Rotate signing keys** if/when you swap opaque tokens for JWT access tokens.
  The current `MemoryTokenService` issues opaque tokens validated through the
  token service — JWT support is a future addition.

## Trusted-first-party SPA shortcut

The example's consent handler shows the consent page even for its own SPA so the
per-user scope-narrowing behaviour stays visible. If all your clients are
first-party you can skip consent two ways:

- **Omit `handleConsent` entirely.** With no handler the framework treats the
  request as consented and grants the accepted scope without a prompt — the
  simplest path when you don't need to narrow scope at the consent step.
- **Auto-approve inside `handleConsent`** when you still want to cap scope per
  user. Replace the `if (decision === null)` branch in `main.ts`'s
  `handleConsent` with:

  ```ts ignore
  return Promise.resolve({
    approved: true,
    scope: BasicScope.intersection(requestedScope.toString(), u.maxScope),
  });
  ```

Third-party clients (apps your users authorize to access their data on your
behalf) should always go through the full consent screen.

## Variation: standalone IDP without an app frontend

If you're running an IDP that serves _other_ applications and doesn't have its
own SPA, omit the `HonoBff` and the `/api/*` mount:

- Drop the `HonoBff` construction in `oauth2/server.ts`.
- Drop the `bff` export.
- Drop `app.route("/auth", bff.routes())` and `app.route("/api", api)` in
  `main.ts`.
- Optionally drop `routes/api.ts`, `routes/home.ts`, and the SPA-side homepage
  UI.

What remains is a pure RFC 6749 issuer that other apps point their
`IntrospectionTokenReader` at. See `api-service/` for the consuming side.
