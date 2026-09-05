# Quickstart: run auth for your application

Run the Hono example to see login, an OAuth2 authorization server, a BFF, and a
protected API working together. Everything runs locally; no Udibo account,
external database, or email service is required.

If you want Udibo to host sign-in, use
[the managed-service guide](guides/use-udibo.md). Udibo is currently in private
beta with a [waitlist](https://udibo.com).

## Run the example

Install Deno 2 and Git, then check out the public package repository:

```sh
git clone https://github.com/udibo/oauth2.git
cd oauth2
deno ci
deno task serve:app-with-own-auth
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
deno task test:app-with-own-auth
```

## Start your own application

For an existing Hono app, use
[host authorization for your app](guides/become-an-oauth-provider.md) and
[add login](guides/add-login.md). They explain which interfaces your database
must implement and how to connect your existing session and login pages.

For a new React app, start with the [Juniper](../templates/juniper/README.md) or
[React Router](../templates/react-router/README.md) template. For an API without
a browser frontend, use [protect an API](guides/protect-an-api.md).

Before deployment, replace the demo stores, credentials, console delivery, and
local HTTP settings. Follow the
[deployment guide](guides/production-deployment.md) and
[checklist](guides/hardening-checklist.md); the demo is not a production
configuration.
