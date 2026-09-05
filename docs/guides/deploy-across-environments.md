# Configure local, preview, and production environments

This guide applies when your app delegates sign-in to Udibo or another
OAuth2/OIDC server. Use the same integration code with different configuration
for each environment. Udibo is in [private beta](use-udibo.md).

## Keep these values together

| Setting                      | Example                                 | Where it belongs                                        |
| ---------------------------- | --------------------------------------- | ------------------------------------------------------- |
| Issuer                       | `https://auth.example.com`              | Backend configuration; copy the issuer exactly          |
| App origin                   | `https://app.example.com`               | Configured public origin, not arbitrary request headers |
| Callback                     | `https://app.example.com/auth/callback` | Client registration and `DirectClient.redirectUri`      |
| Client ID and secret         | Registration-specific values            | Backend secret/configuration store                      |
| Requested scopes             | `openid profile read`                   | Scopes allowed by that registration                     |
| Pending-login encryption key | A generated secret                      | Shared by instances in this environment                 |
| Session store                | Your application's persistent store     | Shared by instances serving this application            |

Keep production credentials and data separate from development and previews. The
issuer's actual registration policy determines which callback URLs and scopes it
accepts; the package does not define a hosted-service management API.

## Local development

Use a separate development registration, or the
[local identity provider](run-a-local-identity-provider.md). Register the
precise callback your browser will use, including the port.

For a local HTTP app only, set the BFF's session cookie and its pending-login
cookie factory to `secure: false`. Restore HTTPS defaults for deployed apps.
`localhost` and `127.0.0.1` are different hosts; use one consistently in the app
origin, registered callback, and browser address bar.

```ts
import {
  EncryptedCookieAuthRequestStorage,
  HonoBff,
} from "@udibo/oauth2/hono/bff";
import type { DirectClient } from "@udibo/oauth2/client";

declare const client: DirectClient;
declare const localDevelopmentSecret: string;

const bff = new HonoBff({
  client,
  cookie: { secure: false },
  authRequestStorage: new EncryptedCookieAuthRequestStorage({
    secret: localDevelopmentSecret,
    cookie: { secure: false },
  }),
});
```

This snippet uses the default in-memory session store and is local-only. It
deliberately leaves state, PKCE, and CSRF protection enabled.

## Production

Use a stable HTTPS app origin and an exact registered HTTPS callback. Configure
the public origin explicitly when your reverse proxy uses internal HTTP to reach
the application. Trust forwarded host/scheme headers only when your deployment
validates them at a known proxy boundary.

Use persistent sessions and pending-login storage that survives process restarts
and works across replicas. An encrypted pending-login cookie is one option;
`MemoryAuthRequestStorage` requires the same process for login and callback. See
[application deployment](production-deployment.md#cookies-and-sessions).

## Preview deployments

Choose one policy for previews:

1. **Skip real sign-in.** Use isolated fixtures for UI tests; do not expose
   production data or accept test sessions on production routes.
2. **Use a stable preview origin.** Register one HTTPS callback and route the
   preview environment through it.
3. **Register each preview callback explicitly.** Automate this only through
   your identity provider's documented administration interface. Keep those
   credentials out of untrusted pull-request jobs and remove expired previews.

A preview URL changing on every deployment does not relax callback matching. Do
not accept a callback origin from a query parameter or request header.

For an app hosting its own authorization server, wildcard redirects are an
optional advanced registration feature. They require `isPublicSuffix` and a
narrow application-owned hostname pattern; they are unnecessary for the normal
exact-callback setup. See
[redirect policy](production-deployment.md#redirect-uri-policy-in-production).

## Verify each environment

- Sign in using the registered callback in the same browser that started login.
- Confirm cookies are present on both the callback and later application calls.
- Repeat with login and callback reaching different application instances.
- Verify production does not accept a development credential or callback.
- Test logout, expired sessions, and a rejected refresh token.
- Check that logs contain error codes and request IDs, without tokens, cookies,
  authorization codes, client secrets, or pending-login records.
