# @udibo/oauth2

[![npm version](https://img.shields.io/npm/v/@udibo/oauth2)](https://www.npmjs.com/package/@udibo/oauth2) [![JSR version](https://jsr.io/badges/@udibo/oauth2)](https://jsr.io/@udibo/oauth2) [![JSR score](https://jsr.io/badges/@udibo/oauth2/score)](https://jsr.io/@udibo/oauth2/score) [![CI](https://github.com/udibo/oauth2/actions/workflows/ci-cd.yml/badge.svg?branch=main)](https://github.com/udibo/oauth2/actions/workflows/ci-cd.yml?query=branch%3Amain) [![License: MIT](https://img.shields.io/npm/l/@udibo/oauth2)](LICENSE) [![npm downloads](https://img.shields.io/npm/dw/@udibo/oauth2)](https://www.npmjs.com/package/@udibo/oauth2) [![Node.js version](https://img.shields.io/node/v/@udibo/oauth2)](https://www.npmjs.com/package/@udibo/oauth2)

OAuth2 and OpenID Connect tools for TypeScript applications: clients,
authorization and resource servers, Hono middleware, React bindings, and
optional login flows over your own database. It runs standalone in your own app:
host an authorization server, protect an API, or sign users in through an
OAuth2 or OpenID Connect issuer.

The package also connects your app to Udibo's managed identity service, which
requires a Udibo account; see [udibo.com](https://www.udibo.com/) for how to get
one. The self-hosted examples run locally without a hosted account.

## Choose your path

| Your application needs                      | Start here                                                                                                                |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Udibo to handle sign-in                     | [Use Udibo's identity service](docs/guides/use-udibo.md) — requires a Udibo account                                       |
| Its own login and authorization server      | [Run the quickstart](docs/quickstart.md), then [host authorization for your app](docs/guides/become-an-oauth-provider.md) |
| An API that accepts access tokens           | [Protect an API](docs/guides/protect-an-api.md)                                                                           |
| A React application with server-held tokens | [React Router starter](templates/react-router/README.md)                                                                  |

[Documentation index](docs/index.md) ·
[API reference](https://jsr.io/@udibo/oauth2/doc) · [Examples](#examples) ·
[Agent documentation](#for-coding-agents)

## Install

The package supports Node.js 22 and later and ships ESM with type declarations.
It is published to npm, and to [JSR](https://jsr.io/@udibo/oauth2) as
TypeScript source:

```sh
npm install @udibo/oauth2   # or: pnpm add @udibo/oauth2
npx jsr add @udibo/oauth2   # or, with Deno: deno add jsr:@udibo/oauth2
```

`hono`, `react`, and `react-dom` are optional peer dependencies. Install the
ones for the entrypoints you import: `hono` for the `/hono/*` adapters, `react`
and `react-dom` for `/react` and `/react/components`. `vitest` is an optional
peer dependency of the testing helpers. Import the part you use; there is no
root barrel or default export.

## Protect an API

This Hono API accepts JWT access tokens from your issuer and requires the
`profile` scope. The [API protection guide](docs/guides/protect-an-api.md)
covers token introspection and scope checks.

```ts
import { Hono } from "hono";
import { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import { JwksTokenReader } from "@udibo/oauth2/server/resource";

const tokenService = new JwksTokenReader({
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  getClient: (claims) => ({ id: String(claims.client_id) }),
  getUser: (claims) => (claims.sub ? { id: claims.sub } : undefined),
});
const api = new HonoResourceServer({
  resolve: () => ({ services: { tokenService } }),
});

const app = new Hono();
app.get("/api/me", api.protect("profile"), (c) =>
  c.json(api.getContext(c).user),
);
```

## Standards

The package implements these specifications, with the limits noted:

- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) OAuth 2.0: authorization
  code, client credentials, refresh token, and password grants; no implicit grant.
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) bearer tokens in the
  `Authorization` header or a form body, with `WWW-Authenticate` challenges.
- [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) PKCE, `S256` unless you
  register other methods.
- [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) revocation,
  [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) introspection,
  [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) server metadata, and
  [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) device authorization.
- [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) `iss` in authorization
  responses. `DirectClient` and the BFF check it when the client is configured
  with an `issuer`, and so do the external sign-in connectors.
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access tokens, opt-in;
  access tokens are opaque by default.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html):
  the authorization code flow, ES256 ID tokens, `nonce`, UserInfo, and the
  `prompt`, `max_age` and `acr_values` controls, with `auth_time` and `acr` in
  the ID token. Your login callback performs any re-authentication they need,
  and there is no `claims` request parameter.
- OpenID Connect [Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
  and [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html),
  as a receiver in the BFF only. You supply the `logout_token` verifier, and the
  server sends no logout tokens.

## How the pieces fit

For a browser app, use a backend-for-frontend (BFF), so tokens stay on the
server. `BffClient` connects the browser to it, and the React adapter uses that
same client:

1. The browser starts sign-in at your BFF, which redirects it to the issuer's
   authorization endpoint.
2. The user signs in, and the issuer redirects back with a code and `state`.
3. The BFF exchanges the code, with PKCE and client authentication, for tokens.
4. The BFF keeps the tokens and sets an HttpOnly session cookie.
5. Later requests carry the cookie; the BFF calls your API with the access
   token and returns the data.

The [BFF guide](docs/guides/use-udibo.md#how-sign-in-flows) has this flow as a
sequence diagram.

`DirectClient` is for a process that holds tokens: your backend, a CLI, a native
app, or a public browser client. Supply a client secret only on the server.
`HonoAuthorizationServer` issues tokens when your app hosts its own
authorization server. The framework-independent core accepts standard `Request`
and `Response` objects; Hono adapters add routing and middleware.

For app-owned login, `verifyCaptcha` checks a bot-challenge token from a
`CaptchaProvider` you supply before your route calls `IdentityService`; see the
[CAPTCHA route example](docs/guides/add-login.md#captcha-at-the-route-boundary).

## Examples

From a checkout of this repository, with Node.js 24.2 or later and pnpm:

```sh
pnpm install
pnpm build
pnpm --filter example-app-with-own-auth start
```

Open <http://localhost:8001/> and sign in as `user` / `password`. The
[quickstart](docs/quickstart.md) explains what to try and which files to read.
All demo credentials, in-memory stores, and local HTTP settings are for
development.

| Example                                                                   | Demonstrates                                                    |
| ------------------------------------------------------------------------- | --------------------------------------------------------------- |
| [Hono with own auth](examples/hono/app-with-own-auth/README.md)           | App login, OAuth2 server, BFF, and protected API in one process |
| [Hono with external auth](examples/hono/app-with-external-auth/README.md) | Delegated sign-in, token introspection, and a BFF proxy         |
| [Standalone API](examples/hono/api-service/README.md)                     | Bearer-token validation without a frontend                      |

## Package entrypoints

All paths below start with `@udibo/oauth2`. Each entrypoint has typed API docs
and examples in the [reference](https://jsr.io/@udibo/oauth2/doc).

| Subpath                      | Purpose                                                                                         |
| ---------------------------- | ----------------------------------------------------------------------------------------------- |
| `/client`                    | `BffClient`, `DirectClient`, token storage, discovery caching                                   |
| `/server`                    | Shared models, errors, scope types, and service contracts                                       |
| `/server/authorization`      | Authorization server, grants, token/code services, signing keys                                 |
| `/server/resource`           | Resource server, introspection and JWKS token readers                                           |
| `/server/public-suffix`      | Public Suffix List checks for optional wildcard redirect registration                           |
| `/hono/authorization-server` | Hono authorization endpoints                                                                    |
| `/hono/resource-server`      | Bearer authentication and scope middleware                                                      |
| `/hono/bff`                  | BFF routes, server-held tokens, session and pending-login stores                                |
| `/identity`                  | App-owned signup, login, password reset, email verification, passwordless, and protection hooks |
| `/identity/mfa`              | TOTP, recovery codes, and MFA storage contract                                                  |
| `/identity/external`         | Social and external OIDC sign-in for your own login pages                                       |
| `/identity/migration`        | Verify imported password hashes and upgrade them at login                                       |
| `/hono/identity`             | Hono routes for `IdentityService`                                                               |
| `/hono/log`                  | Request logger and URL helper that redact every query value                                     |
| `/react`                     | Context, hooks, authentication guards, and callback handling                                    |
| `/react/components`          | Optional forms for login, signup, password reset, and MFA                                       |
| `/crypto`                    | Random tokens, hashing, encoding, authenticated encryption                                      |
| `/url`                       | Safe return paths and login continuation                                                        |
| `/testing`                   | In-memory fixtures and authorization-server test helpers                                        |
| `/testing/contract`          | Tests for app-owned service and storage implementations                                         |
| `/hono/bff/testing`          | BFF session fixtures and session-store contract tests                                           |
| `/react/testing`             | Mock clients and providers for component tests                                                  |

## Runtime support

The library uses Web APIs and runs on Node.js 22 and later. CI runs the
complete suite on Node 22, 24, and 26 on Linux, and on Node 26 on Windows and
macOS. It also packs the npm tarball, installs it into an empty project, type
checks a consumer of every entrypoint, and imports each one on Node.

| Surface                                                                | Node 22+              | Browser                                     | Deno, Bun     |
| ---------------------------------------------------------------------- | --------------------- | ------------------------------------------- | ------------- |
| `/client`, `/react`, `/react/components`                               | Tested, including SSR | Intended for client code; no secrets        | Not verified  |
| `/server/*`, `/identity/*`, `/hono/*`, `/crypto`, `/url`               | Tested                | Server functionality belongs on the backend | Not verified  |
| `/testing`, `/testing/contract`, `/hono/bff/testing`, `/react/testing` | Tested; need Vitest   | Not supported                               | Not verified  |
| `udibo-oauth2` command (`bin`)                                         | Tested                | Not supported                               | Not supported |

The `udibo-oauth2` development command prints OIDC signing keys (`oidc keygen`)
and runs a [local identity provider](docs/guides/run-a-local-identity-provider.md)
(`idp dev`). Nothing on the library path imports it.

See [stability](docs/stability.md#runtime-support) for the support boundary.

## Before deploying

Use the [application deployment guide](docs/guides/production-deployment.md) and
[deployment checklist](docs/guides/hardening-checklist.md). Keep PKCE, state,
confidential-client authentication, and CSRF checks enabled. Replace development
stores with persistent implementations where needed, and run the exported
contract tests against those implementations.

Read [known limitations](docs/known-limitations.md) for token-revocation,
cookie-session, OIDC, and optional-protection behavior. Identity feature
examples apply to apps hosting their own login; Udibo clients use the hosted
sign-in flow.

## Upgrading

The package is pre-1.0, so a minor release may contain breaking changes. Each
release lists them under **⚠ BREAKING CHANGES** in [CHANGELOG.md](CHANGELOG.md).
The [stability policy](docs/stability.md) says what counts as public API and
what a patch release preserves.

## For coding agents

Start with [llms.txt](llms.txt) for the task-to-guide map and integration rules.
Use [llms-full.txt](llms-full.txt) when a single documentation download is
useful. It is generated from the same guides developers read. Prefer the
exported types and [extension reference](docs/trigger-points.md) when
implementing a custom store or callback.

## Contributing and security

Run `pnpm check` and `pnpm test` before proposing changes. See
[CONTRIBUTING.md](CONTRIBUTING.md) for development conventions,
[SECURITY.md](SECURITY.md) for private vulnerability reports, and
[CHANGELOG.md](CHANGELOG.md) for release history.
