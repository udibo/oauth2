# Quickstart: run auth for your application

Two ways to see sign-in working, neither needing a Udibo account, an external
database, or an email service:

- **[Start from npm](#start-from-npm-no-account)** installs the published
  package, runs a local development identity provider, and signs a user in to a
  small Hono app you write. It takes a few minutes and uses nothing from this
  repository.
- **[Run the full example](#run-the-full-example-from-a-clone)** clones this
  repository and runs a larger workspace example with its own login pages, an
  authorization server, a BFF, and a protected API.

If you want Udibo to host sign-in, use
[the managed-service guide](guides/use-udibo.md). It requires a Udibo account;
see [udibo.com](https://www.udibo.com/) for how to get one.

## Start from npm, no account

You need Node.js 22.18 or later, which runs the TypeScript app file directly,
and npm. The local identity provider is for development and CI only: its users,
sessions, and tokens live in memory and vanish when it exits, its config file
holds plaintext passwords, and it has no persistence. It is not a way to
self-host a production identity service. To host authorization in production,
see [host authorization for your app](guides/become-an-oauth-provider.md).

### Install

Pin exact versions so the steps below behave as written. These are the versions
this guide was last run against:

```sh
mkdir local-signin && cd local-signin
npm init -y
npm pkg set type=module
npm install --save-exact @udibo/oauth2@0.52.0 hono@4.13.17 @hono/node-server@2.1.6
```

### Configure the provider

Save this as `idp.json`. It seeds one client and one user, and pins the
provider's issuer and port so the app can be configured once:

```json
{
  "port": 9000,
  "issuer": "http://127.0.0.1:9000",
  "clients": [
    {
      "id": "demo-app",
      "secret": "demo-secret",
      "redirectUris": ["http://127.0.0.1:3100/auth/callback"]
    }
  ],
  "users": [
    {
      "username": "alice@example.com",
      "password": "password",
      "claims": { "name": "Alice Example", "email": "alice@example.com" }
    }
  ]
}
```

### Write the app

Save this as `app.ts`. The `issuer`, `clientId`, `clientSecret`, and
`redirectUri` in `DirectClient` are the values `idp.json` declares, and
`DirectClient` discovers the provider's endpoints from the issuer.

```ts
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { html } from "hono/html";
import { DirectClient } from "@udibo/oauth2/client";
import {
  HonoBff,
  MemoryAuthRequestStorageFactory,
  MemorySessionStore,
} from "@udibo/oauth2/hono/bff";

const client = new DirectClient({
  issuer: "http://127.0.0.1:9000",
  clientId: "demo-app",
  clientSecret: "demo-secret",
  redirectUri: "http://127.0.0.1:3100/auth/callback",
});

const bff = new HonoBff({
  client,
  scope: "openid profile email",
  cookie: { secure: false },
  sessionStore: new MemorySessionStore(),
  authRequestStorage: new MemoryAuthRequestStorageFactory(),
});

const app = new Hono();
app.route("/auth", bff.routes());

app.get("/", (c) =>
  c.html(html`<a href="/auth/login?return_to=/dashboard">Sign in</a>`),
);

app.get("/dashboard", async (c) => {
  c.header("Cache-Control", "private, no-store");
  const session = await bff.readSession(c);
  if (!session.isAuthenticated) {
    return c.redirect("/auth/login?return_to=/dashboard");
  }
  return c.html(html`
    <h1>Hello, ${session.user?.name}</h1>
    <a href="/auth/logout?return_to=/">Sign out</a>
  `);
});

serve({ fetch: app.fetch, hostname: "127.0.0.1", port: 3100 });
```

`bff.routes()` mounts `/auth/login`, `/auth/callback`, `/auth/logout`, and
`/auth/session`. The dashboard is a server-rendered page behind the session
cookie, so it asks the BFF who is signed in with `bff.readSession(c)` and checks
`isAuthenticated`. The memory stores and `secure: false` cookies suit plain-HTTP
local development only.

### Run it

Start the provider in one terminal and the app in another:

```sh
npx udibo-oauth2 idp dev --config idp.json
node app.ts
```

Open <http://127.0.0.1:3100/>, select **Sign in**, and enter
`alice@example.com` / `password` on the provider's page. You land on
`/dashboard` showing "Hello, Alice Example". Opening `/dashboard` with no
session sends you through the same sign-in. Stop each process with Ctrl+C.

Selecting **Sign out** ends the app's session. The provider keeps its own
browser session, so the next sign-in completes without asking for a password
again. To see the sign-in page again, also open <http://127.0.0.1:9000/logout>.

### Use `127.0.0.1` everywhere

Open the app at `127.0.0.1`, not `localhost`. A redirect URI is compared exactly
against the client's registered list, except that a loopback IP literal such as
`http://127.0.0.1` matches on any port (RFC 8252 §7.3), and `localhost` is a
different host from `127.0.0.1`. The provider's issuer, the registered redirect
URI, the app's `redirectUri`, and the address in your browser then all name the
same host. Browsing the app at `localhost` while the redirect URI says
`127.0.0.1` ends in a 400 at `/auth/callback`, because the browser stored the
pending sign-in on one host and returns on the other. The provider's own
[issuer and port pairing](guides/run-a-local-identity-provider.md#pair-an-app-with-the-provider)
explains each value.

### Moving to a hosted OpenID Connect issuer

The app code stays the same; the configuration changes:

| Setting       | Local provider                  | Hosted issuer                                                  |
| ------------- | ------------------------------- | -------------------------------------------------------------- |
| Issuer        | `http://127.0.0.1:9000`         | The issuer URL your provider publishes, copied exactly         |
| Client ID     | `demo-app`                      | The client ID of your registration                             |
| Client secret | `demo-secret`                   | The registration's secret, kept in your secret store           |
| Callback URL  | `http://127.0.0.1:3100/auth/callback` | Your deployed app's `/auth/callback`, registered with the issuer |
| Scopes        | `openid profile email`          | Only scopes your registration allows                           |

Before production, also replace what the local path leaves in memory or
disabled: swap `MemorySessionStore` for a persistent `SessionStore` shared by
every instance, swap `MemoryAuthRequestStorageFactory` for
`EncryptedCookieAuthRequestStorage`, and remove `cookie: { secure: false }` from
the BFF options so the HTTPS defaults apply. The
[environments guide](guides/deploy-across-environments.md) keeps these values
together per environment, and the
[deployment guide](guides/production-deployment.md) and
[checklist](guides/hardening-checklist.md) cover the rest.

## Run the full example from a clone

Install Node.js 24.2 or later, [pnpm](https://pnpm.io/installation), and Git,
then check out the public package repository. The example is a workspace member
that uses the package's built output, so build once before starting it:

```sh
git clone https://github.com/udibo/oauth2.git
cd oauth2
pnpm install
pnpm build
pnpm --filter example-app-with-own-auth start
```

Open <http://localhost:8001/>. Use `user` / `password` for the regular demo
user, or `admin` / `password` to exercise the admin scope. These credentials and
all in-memory data belong only to this local demo.

## Follow a sign-in

1. Select **Sign in**. The browser visits the BFF's login route, which starts an
   authorization-code flow with state and PKCE.
2. Enter a demo user's credentials at the app's login page.
3. Review the consent page. The example limits the requested scopes to the
   user's allowed scopes.
4. The callback exchanges the code on the server and creates an HttpOnly session
   cookie. Access and refresh tokens stay in the BFF.
5. Call the API from the homepage. Requests without a session are rejected; the
   regular user cannot call the admin-scoped endpoint.
6. Sign out and confirm the protected request is rejected again.

The example also has signup, password reset, and email-verification pages.
Delivery hooks print links to the terminal in place of sending mail. Restarting
the process resets users, sessions, codes, and tokens.

## Read the implementation

Start with the [example README](../examples/hono/app-with-own-auth/README.md),
then follow these files:

| File                                                                        | What to learn                                            |
| --------------------------------------------------------------------------- | -------------------------------------------------------- |
| [oauth2/server.ts](../examples/hono/app-with-own-auth/oauth2/server.ts)     | Clients, grants, token storage, and BFF configuration    |
| [main.ts](../examples/hono/app-with-own-auth/main.ts)                       | Endpoint mounting, session lookup, and consent decisions |
| [oauth2/identity.ts](../examples/hono/app-with-own-auth/oauth2/identity.ts) | Login, reset, verification, and delivery hooks           |
| [sessions.ts](../examples/hono/app-with-own-auth/sessions.ts)               | The example's application session                        |
| [main.test.ts](../examples/hono/app-with-own-auth/main.test.ts)             | Successful flows and refused requests                    |

Run its tests from the repository root:

```sh
pnpm --filter example-app-with-own-auth test
```

## Start your own application

For an existing Hono app, use
[host authorization for your app](guides/become-an-oauth-provider.md) and
[add login](guides/add-login.md). They explain which interfaces your database
must implement and how to connect your existing session and login pages.

For a new React app, start with the
[React Router template](../templates/react-router/README.md). For an API without
a browser frontend, use [protect an API](guides/protect-an-api.md).

Before deployment, replace the demo stores, credentials, console delivery, and
local HTTP settings. Follow the
[deployment guide](guides/production-deployment.md) and
[checklist](guides/hardening-checklist.md); the demo is not a production
configuration.
