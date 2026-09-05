# Run a Local Identity Provider

`idp dev` runs a real OAuth2/OIDC authorization server on a port of your
machine, seeded from a JSON file. Point any application at it — in any language
— and sign in without an internet round trip, a shared development tenant, or a
rate limit.

```sh
deno run --allow-net --allow-read --allow-env jsr:@udibo/oauth2/cli idp dev
```

The protocol behavior is the same `AuthorizationServer` a production deployment
runs: the same grants, the same PKCE enforcement, the same discovery document.
What makes it a development tool is where state lives (a `Map`, dropped when the
process exits) and the `/__admin/` endpoints, which mint tokens for any seeded
user without their password.

> **Development and CI only.** Anyone who can reach this server _and_ holds its
> admin token can mint a token for any seeded user. Never point a production
> application at it.

## What is enforced, and what is only documented

Three things the server enforces rather than leaving to your discipline:

- **The admin endpoints require a token.** `idp dev` prints one at startup (set
  it yourself with `--admin-token` or `IDP_ADMIN_TOKEN`), and every `/__admin/`
  request must carry it in the `x-admin-token` header. Because that is a custom
  header, a browser has to send a CORS preflight first, which this server never
  answers — so a page you happen to visit while developing cannot drive the
  admin API. Admin POSTs must also be `content-type: application/json`, which
  rules out the "simple" request shapes a cross-origin form can send, and any
  request arriving with an `Origin` header is refused outright.
- **A non-loopback bind needs an explicit opt-in.** The default is `127.0.0.1`.
  Binding anything else — `0.0.0.0` in a container, a LAN address — fails unless
  you pass `--unsafe-remote-access`, and when you do, the banner says so and a
  warning goes to stderr.
- **The issuer is fixed at startup**, never read from a request's `Host` header,
  so a forged `Host` cannot change what your tokens claim.

Everything else is documentation, not enforcement: seeded passwords are
plaintext in a config file, nothing is rate limited, and handing out tokens is
the admin API's whole purpose. Treat the admin token as a gate that stops
accidents, not as a boundary you would put on the internet.

## What you get out of the box

With no config file, the server starts on port 9000 with one user and two
clients, and prints all of it:

```
Listening on http://127.0.0.1:9000
Reachable from: this machine only (loopback)
Issuer: http://127.0.0.1:9000 (derived from the bind address; pin it with --issuer)
Discovery: http://127.0.0.1:9000/.well-known/openid-configuration
Admin token: 4f1c…  (send as the x-admin-token header)

Users:
  alice@example.com  password: password  sub: user-alice

Clients:
  dev-client  secret: dev-secret
    grants: authorization_code, refresh_token, client_credentials
    redirect URIs: http://localhost:3000/callback, ...
  dev-public-client  public client
```

Endpoints are mounted at the root, so discovery sits exactly where an OIDC
client library looks for it:

| Path                                      | What it is                      |
| ----------------------------------------- | ------------------------------- |
| `/.well-known/openid-configuration`       | OIDC discovery                  |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata               |
| `/authorize`, `/token`                    | The authorization code flow     |
| `/userinfo`, `/jwks`                      | OIDC issuance                   |
| `/revoke`, `/introspect`                  | RFC 7009 / RFC 7662             |
| `/login`, `/logout`, `/consent`           | The browser-facing pages        |
| `/__admin/*`                              | The test control surface        |
| `/`                                       | A status page listing all of it |

Most client libraries need nothing but the issuer. If yours wants explicit
endpoints, read them from the discovery document rather than hardcoding them.

### The issuer is fixed at startup

The issuer is resolved once, when the server starts: `"issuer"` from the config
(or `--issuer`) if you set one, otherwise the bind address — so the default is
`http://127.0.0.1:9000`. It is deliberately **not** derived from each request's
`Host` header, which a client controls and can forge.

The practical consequence: if your app reaches the server under a different name
than it bound — `localhost` rather than `127.0.0.1`, or a container service
hostname like `idp` — the tokens' `iss` will not match the URL your app used,
and a strict OIDC client will reject them. Pass `--issuer` with the URL your app
actually uses:

```sh
deno run --allow-net --allow-read --allow-env jsr:@udibo/oauth2/cli idp dev \
  --hostname 0.0.0.0 --unsafe-remote-access --issuer http://idp:9000
```

## Configuration

Everything is declared in one JSON file — using this tool means running a
program, not writing one.

```sh
deno run --allow-net --allow-read --allow-env jsr:@udibo/oauth2/cli idp dev \
  --config idp.json
```

```json
{
  "port": 9000,
  "hostname": "127.0.0.1",
  "consent": "auto",
  "scopesSupported": ["openid", "profile", "email", "orders:read"],
  "accessTokenLifetime": 3600,
  "grants": {
    "authorization_code": true,
    "client_credentials": true,
    "refresh_token": true,
    "password": false
  },
  "users": [
    {
      "id": "user-alice",
      "username": "alice@example.com",
      "password": "password",
      "claims": {
        "name": "Alice Example",
        "email": "alice@example.com",
        "email_verified": true
      }
    }
  ],
  "clients": [
    {
      "id": "web-app",
      "secret": "dev-secret",
      "redirectUris": ["http://localhost:3000/callback"],
      "grants": ["authorization_code", "refresh_token"]
    }
  ]
}
```

| Field                    | Default                               | Notes                                                                                                                                                            |
| ------------------------ | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`                 | the bind address                      | Pin it to the URL your app uses to reach the server.                                                                                                             |
| `hostname` / `port`      | `127.0.0.1` / `9000`                  | `0` asks the OS for a free port.                                                                                                                                 |
| `consent`                | `"auto"`                              | `"prompt"` shows a consent screen instead of granting silently.                                                                                                  |
| `scopesSupported`        | `openid profile email offline_access` | Advertised in discovery.                                                                                                                                         |
| `accessTokenLifetime`    | `3600`                                | Seconds. Drop it to a few seconds to test expiry handling.                                                                                                       |
| `grants`                 | all but `password`                    | Server-wide switches; each client also lists its own grants.                                                                                                     |
| `signingKey`             | generated per process                 | An ES256 private JWK. See below.                                                                                                                                 |
| `users[].id`             | the username                          | Becomes the `sub` claim.                                                                                                                                         |
| `users[].claims`         | `{}`                                  | Merged into the id_token and UserInfo response.                                                                                                                  |
| `clients[].secret`       | none                                  | Omit for a public (PKCE-only) client.                                                                                                                            |
| `clients[].redirectUris` | none                                  | Matched **exactly** (no wildcard seam here) — list every URI. A loopback IP literal (`http://127.0.0.1`, `http://[::1]`) matches on any port, per RFC 8252 §7.3. |
| `clients[].grants`       | `authorization_code refresh_token`    | A grant the client does not list is rejected.                                                                                                                    |
| `clients[].ownerUserId`  | none                                  | Puts a user on the client's `client_credentials` token. Omit it for a machine token with no user, whose subject is the client itself.                            |

Unknown fields are rejected rather than ignored, so a typo fails at startup
instead of silently doing nothing. Flags (`--port`, `--hostname`, `--issuer`)
override the file.

The device authorization grant is not served — it needs a verification UI that
this tool does not ship. Everything else in the package's grant set is
available.

## Stable signing keys

By default the server generates a key per process, so tokens signed before a
restart fail verification after it. That is fine for a run-to-completion test
suite and wrong for anything that caches JWKS or holds a token across a restart.

Generate a key once and hand it to the server:

```sh
deno run jsr:@udibo/oauth2/cli oidc keygen
```

Pass it as `OIDC_SIGNING_KEY`, or paste the JWK into the config file's
`signingKey` field. `OIDC_SIGNING_KEY` wins when both are set, so CI can
override a committed config without editing it:

```sh
OIDC_SIGNING_KEY='{"kty":"EC",...}' deno run --allow-net --allow-read \
  --allow-env jsr:@udibo/oauth2/cli idp dev --config idp.json
```

The server never writes key material to disk. When no key is supplied it says so
on stderr — if you see that warning in CI, the key is not reaching the process.

## Signing in

`GET /authorize` behaves the way a hosted provider does: with no session it
returns a sign-in page, and after sign-in it redirects back to your
`redirect_uri` with a code.

The page has a `username` and `password` field, plus a one-click button per
seeded user (`name="as"`), which signs that user in without a password —
convenient by hand, and the fastest path in a browser test that is not about
credentials. Elements carry stable ids: `#sign-in-form`, `#username`,
`#password`, `#sign-in`, `#sign-in-error`.

With `"consent": "prompt"`, an approval screen (`#consent-form`, `#approve`,
`#deny`) appears before the code is issued. Denial redirects back with
`error=access_denied`, which is the branch most applications never test.

`GET /logout` drops the session. It honours `post_logout_redirect_uri` only when
the value exactly matches a redirect URI one of the configured clients
registered — an unregistered target is answered with a 400 rather than a
redirect, so the endpoint cannot be used as an open redirect.

## The test control surface

Four endpoints under `/__admin/` exist so end-to-end tests can skip the parts
they are not testing. Every one of them requires the `x-admin-token` header
carrying the token printed at startup, and every POST must be
`content-type: application/json`. Choose the token up front with `--admin-token`
or `IDP_ADMIN_TOKEN` so your tests can hold it before the server starts.

**Reset between scenarios.** Drops every session, authorization code, and token,
and re-seeds from the config:

```sh
curl -X POST http://localhost:9000/__admin/reset \
  -H "x-admin-token: $IDP_ADMIN_TOKEN" -H 'content-type: application/json'
```

**Sign a user in without the form.** Returns a session cookie; a browser context
that stores it goes straight through `/authorize`:

```sh
curl -X POST http://localhost:9000/__admin/session \
  -H "x-admin-token: $IDP_ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"username":"alice@example.com"}'
```

**Mint tokens without a browser.** Runs the real authorization-code exchange
internally and returns the ordinary token response — `access_token`,
`refresh_token`, and `id_token` signed by the published key:

```sh
curl -X POST http://localhost:9000/__admin/tokens \
  -H "x-admin-token: $IDP_ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"clientId":"web-app","username":"alice@example.com","scope":"openid email"}'
```

Accepts `userId` instead of `username`, and `redirectUri` when the client has
more than one. Omit `scope` to get every supported scope.

**Inspect what is seeded.** `GET /__admin/state` (also token-gated) returns the
users, clients, and live session count — useful when a test fails and you want
to know whether a reset actually happened.

## In CI

No container is required: the CLI is one command, and GitHub Actions can run it
in the background.

```yaml
- uses: denoland/setup-deno@v2
  with:
    deno-version: v2.x

- name: Start the identity provider
  env:
    OIDC_SIGNING_KEY: ${{ secrets.CI_OIDC_SIGNING_KEY }}
    IDP_ADMIN_TOKEN: ${{ github.run_id }}-idp-admin
  run: |
    deno run --allow-net --allow-read --allow-env \
      jsr:@udibo/oauth2/cli idp dev --config idp.ci.json \
      --issuer http://localhost:9000 &
    timeout 30 bash -c \
      'until curl -sf http://localhost:9000/.well-known/openid-configuration \
        >/dev/null; do sleep 0.5; done'

- run: npm test
  env:
    OIDC_ISSUER: http://localhost:9000
    IDP_ADMIN_TOKEN: ${{ github.run_id }}-idp-admin
```

Setting `IDP_ADMIN_TOKEN` yourself is what lets the test step reach the admin
API — otherwise the token is random per run and only printed on stdout. The
signing key does not have to be a secret (nothing it signs is trusted outside
CI), but pinning it is what makes a cached JWKS survive a job that restarts the
server.

If your pipeline prefers service containers, wrap the CLI in an image:

```dockerfile
FROM denoland/deno:alpine
COPY idp.ci.json /idp.json
EXPOSE 9000
CMD ["run", "--allow-net", "--allow-read", "--allow-env", \
     "jsr:@udibo/oauth2/cli", "idp", "dev", \
     "--config", "/idp.json", "--hostname", "0.0.0.0", \
     "--unsafe-remote-access", "--issuer", "http://idp:9000"]
```

A container has to bind `0.0.0.0` for its port to be reachable, which is exactly
the case `--unsafe-remote-access` exists to make deliberate: the admin API is
now reachable by anything on that network, so keep it to a CI job's private
network and set `IDP_ADMIN_TOKEN`. Pin `--issuer` to the hostname your tests use
to reach the service.

## With Playwright

Start the server once for the run, and reset between tests:

```ts ignore
// playwright.config.ts
export default defineConfig({
  webServer: {
    command:
      "deno run --allow-net --allow-read --allow-env jsr:@udibo/oauth2/cli idp dev --config idp.json",
    env: { IDP_ADMIN_TOKEN: process.env.IDP_ADMIN_TOKEN! },
    url: "http://localhost:9000/.well-known/openid-configuration",
    reuseExistingServer: !process.env.CI,
  },
});
```

```ts ignore
const IDP = "http://localhost:9000";
const admin = { "x-admin-token": process.env.IDP_ADMIN_TOKEN! };

test.beforeEach(async ({ request }) => {
  await request.post(`${IDP}/__admin/reset`, { headers: admin, data: {} });
});

test("signs in through the identity provider", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: "Sign in" }).click();
  await page.fill("#username", "alice@example.com");
  await page.fill("#password", "password");
  await page.click("#sign-in");
  await expect(page.getByText("alice@example.com")).toBeVisible();
});

test("shows the dashboard for a signed-in user", async ({ page, context }) => {
  await context.request.post(`${IDP}/__admin/session`, {
    headers: admin,
    data: { username: "alice@example.com" },
  });
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Orders" })).toBeVisible();
});
```

The second test never touches the sign-in page: the admin session cookie is
stored in the browser context, so the redirect through `/authorize` completes
without a stop. Tests about sign-in drive the form; tests about everything else
skip it.

## How this differs from production

|               | `idp dev`                      | A production authorization server              |
| ------------- | ------------------------------ | ---------------------------------------------- |
| Storage       | In memory, dropped on exit     | Your database, behind `@udibo/oauth2/server`   |
| Users         | Seeded from a JSON file        | Your identity flows (`@udibo/oauth2/identity`) |
| Passwords     | Plaintext in a config file     | Hashed, with lockout and rate limiting         |
| Token minting | Anyone holding the admin token | Only the protocol                              |
| Tenants       | None                           | Whatever your application models               |

It is also not a self-host path for Udibo's hosted identity service, which adds
tenants, persistence, and an administrative dashboard. `idp dev` is a
development and test dependency, deliberately.

To build the real thing, see
[Become an OAuth provider](become-an-oauth-provider.md). To wire an application
to any provider — this one included — see
[Add login to an existing app](add-login.md) and
[Local, preview, and production for a relying party](deploy-across-environments.md).

## Checklist

- [ ] The server is bound to loopback, or `--unsafe-remote-access` was a
      deliberate choice on a network only the test job can reach.
- [ ] `IDP_ADMIN_TOKEN` is set wherever a test needs the admin API, and is not
      shared outside that job.
- [ ] `--issuer` matches the URL your application uses to reach the server.
- [ ] Every redirect URI your app sends is listed on the client, exactly —
      including any `post_logout_redirect_uri`.
- [ ] `OIDC_SIGNING_KEY` is set wherever a token or a cached JWKS has to outlive
      a restart.
- [ ] The application reads its endpoints from discovery, not from constants.
- [ ] Tests reset state between scenarios instead of depending on order.
- [ ] Nothing in production configuration points at this server.
