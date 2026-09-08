# Use Udibo's identity service

Udibo handles sign-in and issues tokens for your application. Your backend
completes the OAuth2 callback, maintains an application session, and protects
application data.

**Udibo is in private beta.** [Join the waitlist](https://udibo.com). The
configuration below is for developers who already have beta access. Public
registration and its setup instructions will be documented when access opens. To
develop without an account, use the
[local identity provider](run-a-local-identity-provider.md) or the
[external-auth example](../../examples/hono/app-with-external-auth/README.md).

## What you need

Obtain these values for your application through your beta setup:

| Value                               | Use                                                                                 |
| ----------------------------------- | ----------------------------------------------------------------------------------- |
| Issuer URL                          | The identity service's issuer, copied exactly; it may differ from your app's origin |
| Client ID and secret                | A confidential client registration for your backend                                 |
| Callback URL                        | An exact registered URL, such as `https://app.example.com/auth/callback`            |
| Allowed scopes                      | Identity claims and API permissions your application may request                    |
| Introspection or JWKS configuration | Token validation for your API; use the mode configured for the application          |

Use separate registrations and secrets for development and production. Keep
client credentials on the backend. The issuer and client ID are identifiers; a
client secret is a credential.

## Put the BFF on your app's origin

Mount the BFF at `/auth`. The browser talks to your own backend using its
session cookie. It never needs your client secret or refresh token.

The following is integration wiring. `sessions` is a persistent `SessionStore`
you implement for your app; `resourceServer` validates access tokens using the
[API protection guide](protect-an-api.md). Both are declared here so the example
makes its application-owned dependencies explicit.

```ts
import { Hono } from "hono";
import { DirectClient } from "@udibo/oauth2/client";
import {
  EncryptedCookieAuthRequestStorage,
  HonoBff,
  type SessionStore,
} from "@udibo/oauth2/hono/bff";
import type { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import { requestLogger } from "@udibo/oauth2/hono/log";
import type { ClientInterface } from "@udibo/oauth2/server";

declare const sessions: SessionStore;
declare const resourceServer: HonoResourceServer<ClientInterface, unknown>;

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

const client = new DirectClient({
  issuer: required("AUTH_ISSUER"),
  clientId: required("AUTH_CLIENT_ID"),
  clientSecret: required("AUTH_CLIENT_SECRET"),
  redirectUri: required("AUTH_CALLBACK_URL"),
});

const bff = new HonoBff({
  client,
  sessionStore: sessions,
  authRequestStorage: new EncryptedCookieAuthRequestStorage({
    secret: required("AUTH_REQUEST_SECRET"),
  }),
  resourceServer,
  scope: required("AUTH_SCOPES"),
  defaultReturnTo: "/",
});

const app = new Hono();
app.use(requestLogger());
app.route("/auth", bff.routes());
app.use("/api/*", bff.protect());
app.get("/api/message", (c) => c.json({ message: "Authenticated" }));

export default app;
```

`AUTH_REQUEST_SECRET` is an app-generated high-entropy secret shared by every
instance of this application. It protects the pending state and PKCE verifier
across the redirect. Store it in your deployment's secret manager. The example
keeps the BFF's HTTPS cookie and CSRF defaults enabled.

`requestLogger()` redacts every query value on both log lines, including
callback `code` and `state`. Configure reverse proxies and tracing separately;
this middleware cannot redact logs emitted by other systems.

Use `bff.protect("read")` for a scope required throughout an API mount, or layer
`resourceServer.requireScope(...)` on individual routes after authentication.
Authentication alone does not check whether a user owns a specific record; that
authorization check belongs in your application.

For a separate API process, use `bff.proxy(fixedApiUrl, options)` and validate
tokens in that API. See
[the proxy example](protect-an-api.md#when-the-api-is-a-separate-service).

## Connect the browser

```ts
import { BffClient } from "@udibo/oauth2/client";

const auth = new BffClient();
const session = await auth.getSession();
if (!session.isAuthenticated) {
  const { url } = await auth.login({ returnTo: "/" });
  location.assign(url);
}

const response = await auth.fetch("/api/message");
```

`BffClient` sends the BFF's CSRF header. A custom fetch client must send the
same header on credentialed requests. Do not disable CSRF to make a browser
request work.

React apps can use `OAuth2Provider`, `useOAuth2`, and `RequireAuth` from
`@udibo/oauth2/react`; the
[external-auth Juniper example](../../examples/juniper/app-with-external-auth/README.md)
shows that wiring. A client-side guard controls rendering; your API still
requires server-side authorization.

The BFF's local logout ends the application session and attempts upstream token
revocation. Ending the identity provider's SSO session is a separate operation;
configure and verify that behavior for your application if you need it.

## Test the integration

Before pointing it at production:

- Complete sign-in and sign-out in a real browser with the registered callback.
- Verify unauthenticated requests receive `401` and insufficient scopes receive
  `403`.
- Expire an access token and check that a refresh preserves the session.
- Revoke the session and check that an in-flight refresh cannot restore it.
- Run `runSessionStoreContractTests` from `@udibo/oauth2/hono/bff/testing`
  against your store. Stateful updates must reject expired, missing, or revoked
  sessions.
- Confirm callbacks work when login and callback requests reach different
  application instances.

## Troubleshooting

| Symptom                               | Check                                                                                       |
| ------------------------------------- | ------------------------------------------------------------------------------------------- |
| Callback rejected before sign-in      | Exact callback registration: scheme, host, port, path, and query                            |
| `invalid_client`                      | Backend client ID/secret and whether this is the correct registration                       |
| Unknown state or missing login cookie | Shared pending-login storage, cookie attributes, and whether callback uses the same browser |
| Credentialed BFF request gets `403`   | CSRF header and same-origin request configuration                                           |
| Refresh gives `invalid_grant`         | Expiry or revocation; start a new login instead of retrying the credential indefinitely     |
| API rejects a token                   | Issuer, intended audience, token format, and required scopes                                |

See [environment configuration](deploy-across-environments.md) and
[application deployment](production-deployment.md) for the remaining app-side
setup. Hosted-service administration and account provisioning are documented
separately from this package.
