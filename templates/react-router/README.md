# React Router app with auth preconfigured

Your app: a [React Router](https://reactrouter.com/) **framework mode** app with
server-side rendering, served by a [Hono](https://hono.dev/) server on Node
through [`react-router-hono-server`](https://github.com/rphlmr/react-router-hono-server),
built with Vite, Tailwind CSS 4 and the React Compiler. A complete
authentication layer from [`@udibo/oauth2`](https://github.com/udibo/oauth2) is
already wired up:

- **Sign-up, sign-in, sign-out, and a protected page** work out of the box.
- **The browser never holds a token.** The server runs the OAuth2
  Backend-For-Frontend (BFF) pattern: tokens live in a server-side session
  behind an HttpOnly cookie, and the app reads auth state through the
  `@udibo/oauth2/react` adapter (`OAuth2Provider`, `useOAuth2`).
- **Pages render signed in on the first paint.** The server reads the BFF
  session for each request (`bff.readSession`), passes it to React Router
  through the load context, and the root route seeds `OAuth2Provider` with it,
  so there is no signed-out flash and no session probe on load.
- **You own the identity layer.** An embedded OAuth2 authorization server issues
  the tokens, and the app's own `/login` and `/signup` pages are the credential
  surface (via the library's `IdentityService`). No third-party IdP in the loop.
- **The auth pages use the package's own components.** Sign-in, sign-up, and
  both password-reset pages render `@udibo/oauth2/react/components`
  (`SignInForm`, `SignUpForm`, `RequestPasswordResetForm`, `ResetPasswordForm`),
  so you inherit their accessibility — programmatic labels, `aria-invalid` /
  `aria-describedby`, focus moved to the first errored field, a re-announced
  error summary — instead of hand-rolling it. They ship unstyled with per-slot
  `className` hooks; theme them, or pass a function as `children` to keep the
  wiring and own the markup.

## Scaffold

Copy this directory, or:

```bash
npx degit udibo/oauth2/templates/react-router my-app
```

> This command activates once the repository is public. Until then, copy this
> directory instead.

### Point `@udibo/oauth2` at a published version

Inside this repository `package.json` depends on the package through
`"@udibo/oauth2": "workspace:*"`, which resolves to the repository's own build.
Everything else in `package.json` is a plain version range, so a copy outside
the workspace needs one edit: replace that line with a version range.

```json
"@udibo/oauth2": "^0.15.0"
```

Until the package is on npm, the JSR registry serves it under an npm name; add
`@jsr:registry=https://npm.jsr.io` to an `.npmrc` and use
`"@udibo/oauth2": "npm:@jsr/udibo__oauth2@^0.14.1"`.

Tests use MSW 3, which Vitest 5 does not list among its accepted peer ranges.
If your package manager warns about it, allow it (pnpm:
`peerDependencyRules.allowedVersions` for `@vitest/mocker>msw` set to `3`) or
pin `msw` to a 2.x release.

## First run

Requires Node 24.2 or later.

```bash
pnpm install
pnpm dev      # http://localhost:8000, with hot reloading
```

Open <http://localhost:8000/>, click **Dashboard**, and sign in as the seeded
demo user (`demo@example.com` / `password`) — or create an account and watch the
server console for the email-verification link.

For production:

```bash
pnpm build
pnpm start    # node build/server/index.js
```

Other scripts:

```bash
pnpm test        # server tests (no build or network) and component tests (jsdom + MSW)
pnpm typecheck   # react-router typegen, then tsc
```

In development, editing a server file reloads the server module, which resets
the in-memory stores (accounts and sessions) — sign in again after a server
change.

## Project tour

```
server/
  index.ts               # the server entry: mounts the auth layer, hands the rest to React Router
  auth.ts                # /oauth2, /auth, /identity, /api as one Hono app (tested with app.request)
  api.ts                 # your protected API (/api/*), guarded by bff.protect()
  config.ts              # zod-validated environment (see below)
  sessions.ts            # the issuer's login session (in-memory demo store)
  load-context.ts        # builds the router context: BFF session + demo-account flag
  oauth2/
    server.ts            # authorization server + BFF + resource server, one process
    identity.ts          # sign-up/sign-in/reset/verify flows + console "mailer"
app/
  root.tsx               # html shell, <OAuth2Provider> seeded from the load context
  context.ts             # the typed router context the server provides
  routes.ts              # layout, home, login, signup, dashboard, verify-email,
                         #   forgot-password, reset-password
  routes/                # one module per page, each with a colocated *.test.tsx
  lib/identity.ts        # posts the login/signup forms to /identity/*
  oauth2/browser-client.ts  # browser-safe BffClient for the React adapter
test/                    # shared test setup, MSW server, route-stub renderer
```

### How a sign-in flows

1. A signed-out request for `/dashboard` hits the route's `loader`, which
   redirects (a document redirect, so the browser leaves React Router) to the
   BFF's `/auth/login?return_to=/dashboard` before any HTML is sent.
2. The BFF redirects to the authorization server's `/oauth2/authorize`; with no
   issuer session, that bounces to the `/login` page carrying the in-flight
   authorize URL as `return_to`.
3. The login form posts to `/identity/signin`. On success the server opens the
   issuer session and redirects into `bff.loginContinuation(returnTo)`, which
   resumes the authorize URL.
4. The authorize endpoint issues a code to the BFF's `/auth/callback`, which
   exchanges it in-process and stores the tokens in the server-side session —
   the browser gets only the HttpOnly `oauth2_session` cookie and lands back on
   `/dashboard`.

Signing out via the header button hits `/auth/logout`, which revokes the refresh
token and clears both sessions.

The loader is what protects the page. A rendering guard such as
`<RequireAuth>` is for client-rendered apps; here the check runs on the server,
and `/api/*` is guarded separately by `bff.protect()`.

## Seed & configuration

**Seeded account** (in-memory, recreated on every restart; **skipped when
`APP_ENV=production`** so no known credential ships to a live deploy):

| Email              | Password   | Notes                            |
| ------------------ | ---------- | -------------------------------- |
| `demo@example.com` | `password` | Email already marked as verified |

**Email delivery is the server console.** Sign-up prints the verification link
(`/verify-email?token=…`) to the terminal running the server, and **Forgot your
password?** on the sign-in page prints a reset link (`/reset-password?token=…`)
the same way — both links land on real pages that consume the token. Swap the
two hooks in `server/oauth2/identity.ts` for your mailer.

**Environment variables** (all optional; see `.env.example`, loaded with
`--env-file-if-exists` when a `.env` exists). `server/config.ts` validates them
once at startup and lists every invalid variable at once:

| Variable               | Default                 | Purpose                                                                                                               |
| ---------------------- | ----------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `ORIGIN`               | `http://localhost:8000` | Public origin the app is served from. Issuer, redirect URIs, and emailed links derive from it; https ⇒ Secure cookies |
| `PORT`                 | `8000`                  | Port `pnpm start` listens on. `pnpm dev` uses the port in `vite.config.ts`                                            |
| `APP_ENV`              | `development`           | `production` skips seeding the demo user. Independent of `NODE_ENV`                                                   |
| `OAUTH2_CLIENT_SECRET` | `dev-only-secret`       | Secret for the app's OAuth2 client. **Required** when `APP_ENV=production` (no fallback)                              |

Everything is hermetic: in-memory stores, no database, no external services.

## Going to production

The demo shortcuts to replace before shipping:

- Swap the `Memory*Service` stores (`server/oauth2/server.ts`) and the in-memory
  session `Map` (`server/sessions.ts`) for persistent implementations —
  `@udibo/oauth2/testing/contract` has conformance tests for yours.
- **The BFF session store.** `HonoBff` defaults to `MemorySessionStore`,
  separate from the issuer's login `Map` in `sessions.ts`. Configure its
  `sessionStore` in `server/oauth2/server.ts` for restarts and multiple
  instances. Choose a shared stateful store, or `EncryptedCookieSessionStore`
  when its
  [revocation and cookie limits](https://github.com/udibo/oauth2/blob/main/docs/guides/production-deployment.md#cookies-and-sessions)
  suit your app.
- **Pending browser login.** The server's `DirectClient` defaults to
  `MemoryAuthRequestStorage` for pending `state` and PKCE verifier records.
  Configure the BFF's `authRequestStorage` factory or the client's storage so
  login and callback can use the same record across restarts and instances. See
  [environment configuration](https://github.com/udibo/oauth2/blob/main/docs/guides/deploy-across-environments.md)
  for shared storage and encrypted pending-login cookie options.
- Set `OAUTH2_CLIENT_SECRET` — the app refuses to start in production without
  it, since the development fallback is public in the template source.
- Wire a real mailer into `server/oauth2/identity.ts`, and add rate limiting on
  the identity endpoints (`IdentityService` accepts a `rateLimiter`).
- Serve over HTTPS (cookies become `Secure` automatically via `ORIGIN`).
- Decide how long a sign-in lasts. `sessionMaxAgeMs` in
  `server/oauth2/server.ts` is the single place that says so: it stamps the
  session cookie's `Max-Age` and bounds the session server-side. The template
  states the package default of 14 days explicitly so the knob is visible; raise
  it for a longer "stay signed in", and if you pass your own session store with
  its own maximum age, keep the two in agreement — the BFF refuses a
  configuration whose cookie would expire before the session does.
- Pages that depend on the session send `Cache-Control: private, no-store`
  (the root route's `headers` export). Keep that on any page you render from the
  session.
