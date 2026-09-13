# Deploy your application

Use this guide for the application you are deploying. If Udibo hosts sign-in,
you operate the client, BFF, sessions, and API. If your app hosts its own
authorization server, you also operate its credential, code, token, and
signing-key storage. The package provides protocol handling; your deployment
supplies persistent storage, secrets, delivery, and application policy.

## Choose the integration boundary

| Responsibility                                          | App using Udibo     | App hosting authorization                  |
| ------------------------------------------------------- | ------------------- | ------------------------------------------ |
| Callback and application sessions                       | Your app            | Your app                                   |
| API token validation and record-level access            | Your app            | Your app                                   |
| Login, password reset, MFA, and email delivery          | Hosted sign-in flow | Your app's configured identity flows       |
| Registered clients, authorization codes, token issuance | Identity service    | Your authorization server                  |
| Token signing keys                                      | Identity service    | Your authorization server, if issuing JWTs |

Udibo's hosted-service setup is described in [use Udibo](use-udibo.md). The rest
of this guide documents package integration, not hosted-service administration.

## The multi-instance rule

State needed by two requests must be available to either request's process. A
local example can keep it in memory; a deployment with replicas, serverless
isolates, or restarts needs shared persistence or an appropriate encrypted
cookie.

| State                        | Public contract                                    | Requirement                                                                                  |
| ---------------------------- | -------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| BFF session                  | `SessionStore`                                     | Enforce expiry and revocation; stateful `update` must never recreate a missing session       |
| Pending browser login        | `AuthRequestStorage` / `AuthRequestStorageFactory` | Preserve state and PKCE verifier across redirects; bind completion to the initiating browser |
| Authorization codes          | `AuthorizationCodeServiceInterface`                | Atomic single-use consumption, expiry, client and redirect binding                           |
| Tokens                       | `TokenServiceInterface`                            | Protect stored token material; atomic revocation/rotation claims                             |
| App credentials              | `IdentityUserStore`                                | Persist the complete credential, including `params`; unique identifiers                      |
| Reset and verification links | `TokenFlowStore`                                   | Expiring, single-use records; implement invalidation capabilities your app needs             |
| Email codes                  | `OtpStore`                                         | Atomic attempt increments and boolean `consume`; protect low-entropy code hashes             |
| MFA                          | `MfaStore`                                         | Protect TOTP secrets; atomically consume recovery codes                                      |
| Rate limits and lockout      | `RateLimitStore` / `LockoutStore`                  | Shared counters and expiry across instances                                                  |

Run the appropriate contract suite from `@udibo/oauth2/testing/contract` or
`@udibo/oauth2/hono/bff/testing` against your actual adapter. Test concurrent
callers against the database implementation, not just an in-memory substitute.

## Configuration inventory

Keep public app origin, issuer, registered callback URLs, client credentials,
requested scopes, session lifetimes, and storage configuration in deployment
configuration. Validate required values at startup. Do not silently fall back to
demo secrets or localhost URLs in production.

For an app-owned issuer, construct `resolve` with the configured services and
issuer. Do not derive the issuer or emailed links from an unvalidated `Host`
header.

## Secrets

Store client secrets, cookie encryption keys, signing keys, and mail credentials
in your deployment's secret store. Use different values for each environment.
Keep token responses, cookies, authorization codes, PKCE verifiers, reset links,
and TOTP/recovery secrets out of logs and exception telemetry.

Persist signing and encryption keys across deployments. Generating replacements
at startup breaks existing sessions or token verification on every restart.

## Signing keys and rotation

This section applies only when your app issues OIDC or JWT tokens. Generate a
signing key with `deno run jsr:@udibo/oauth2/cli oidc keygen`, then store its
output as a secret. The package's issuer signs with ES256; verify that your
consumers accept that algorithm.

Use `RotatingSigningKeyProvider` to publish the previous public key while
signing new tokens with a new key:

```ts
import {
  importSigningKeyJwk,
  RotatingSigningKeyProvider,
} from "@udibo/oauth2/server/authorization";

declare const currentJwk: JsonWebKey;
declare const previousJwk: JsonWebKey;

const signingKeys = new RotatingSigningKeyProvider({
  current: await importSigningKeyJwk(currentJwk),
  previous: [await importSigningKeyJwk(previousJwk)],
});
```

For routine rotation, keep the previous public key available through the longest
outstanding token lifetime and relevant consumer cache windows. Compromise
response may require retiring a key sooner and forcing reauthentication. Offline
JWT validation cannot provide immediate per-token revocation.

## Stores you provision

Choose the stores required by your enabled flows. A client using Udibo does not
need local password or authorization-code tables. An app hosting password login
needs credential storage and session revocation; email codes additionally need
an `OtpStore`, while reset links and magic links use `TokenFlowStore`.

Automatic password rehash or import upgrades require
`IdentityUserStore.replaceCredential`. It must atomically compare all old
credential fields before writing the replacement. A failed comparison writes
nothing and the password is re-verified against the credential now stored;
omitting the capability skips automatic upgrades. Explicit password resets still
use `setCredential`.

For rotating refresh tokens, `revokeRotated` (or the fallback `revoke`) must
return `true` only to the caller that consumed the old credential. Keep replay
tombstones and family revocation state if you enable reuse detection. The
library's calls are separate storage operations; your adapter must account for
competing writes and failures. Revoking a family must also prevent a racing save
from restoring it.

Sequential OTP resends invalidate prior codes. Concurrent requests use separate
invalidate/create calls, so that alone does not guarantee one outstanding code.
Serialize issuance for each `(email, purpose)` across instances when your
application requires that policy. Atomic `consume` separately ensures a given
code succeeds once.

## Cookies and sessions

The BFF defaults to Secure, HttpOnly, host-bound cookies and enables CSRF
checks. Keep those settings on HTTPS deployments. The pending authorization
cookie needs to survive the authorization server's redirect back to your app;
use the provided pending-login cookie factory or a correctly scoped app-owned
store.

Prefer a stateful `SessionStore` when your app needs immediate revocation,
session listings, or backchannel logout. `EncryptedCookieSessionStore` is an
alternative with a different contract: a copied cookie remains usable until
expiry, even after logout clears the original browser's cookie. It also has
browser cookie-size limits. See
[session limitations](../known-limitations.md#sessions-udibooauth2honobff).

Keep the session lifetime consistent between the store and
`HonoBff.sessionMaxAgeMs`. A stateful store's update must reject revoked,
expired, or missing records; a refresh finishing after logout must not insert a
session again.

If you expose a session list, return a separate, non-secret record ID as
`SessionSummary.id`. The BFF's `cookieValue` is a credential and must never
appear in listings, URLs, analytics, or browser-readable session summaries.

## TLS and the reverse proxy

Serve deployed callbacks, token endpoints, and APIs over HTTPS. Configure your
proxy to preserve the external origin in a trusted way and forward the request
headers required by your CSRF policy. Do not trust arbitrary client-supplied
forwarded headers.

Generic OIDC connectors rely on direct TLS token exchange for ID-token
integrity. They validate claims but do not verify signatures. Configure trusted
issuers, retain endpoint HTTPS checks, and never use these connectors to accept
ID tokens obtained through unrelated channels. Apple uses separate signature
verification.

## CSRF, CORS, and security headers

Keep the BFF and browser on the same origin where possible. `BffClient` sends
the required CSRF header. Handwritten requests must follow the same contract. A
React route guard changes rendering; it does not authorize an API request.

`honoIdentityRoutes` includes a same-origin guard on unsafe requests. Custom
login, social-linking, MFA, session-revocation, and password-change routes must
apply their own authentication and CSRF policy. Bind sensitive actions to the
current authenticated user rather than trusting a submitted user ID.

Configure security headers for your app's content and hosting environment. Do
not log or place reset tokens in third-party analytics URLs. Use a restrictive
referrer policy on pages that receive credentials in URLs.

## Redirect-URI policy in production

Register exact HTTPS callbacks for web applications. Keep local development
registrations separate. Native loopback IP redirects have protocol-specific port
matching; do not treat that exception as a general wildcard.

If your own server accepts wildcard registrations, supply `isPublicSuffix` from
`@udibo/oauth2/server/public-suffix` and constrain patterns to a hostname
namespace your application controls. Shared hosting domains are not an ownership
boundary. Exact callbacks avoid this additional policy surface.

## Rate limiting, lockout, and password policy

`IdentityService` always applies password policy, but rate limiting, account
lockout, and CAPTCHA are opt-in integrations. Construct the protections you
need; `protectionMode: "log-only"` records decisions without enforcing them.
Default deployed configuration should enforce.

Apply IP/request throttling at the route layer as well as identifier-based
limits within identity flows. Rate-limit mail requests and code verification. A
six-digit code has only a million possibilities: storing its hash does not make
a leaked code database resistant to offline guessing.

For password reset, implement `TokenFlowStore.deleteBySubject` to invalidate
outstanding sign-in links. Reset also attempts OTP invalidation when the reset
token contains the email. These cleanup operations are best-effort; decide how
your app responds to failures and monitor them. See
[known limitations](../known-limitations.md#identity-flows-udibooauth2identity).

## Backups and restore

Back up persistent credentials and MFA records with appropriate access controls.
Keep encryption keys separately protected and rehearse restoration. A restore
can reintroduce sessions or tokens that were revoked after the backup; include
reauthentication or explicit revocation in the recovery procedure.

Apply retention to expired codes, tokens, sessions, and audit events. Retain
rotation tombstones long enough for your chosen replay-detection policy.

## Observability, audit, and health checks

Record request IDs, flow outcomes, authenticated client IDs, and stable error
codes. Avoid logging raw request bodies on credential endpoints. Treat audit
callbacks as observation: a callback whose errors are isolated is not an
enforcement gate. Use the [extension reference](../trigger-points.md) to check
when a callback runs and how failures propagate.

Monitor failed callbacks, refresh rejection, storage errors, email-delivery
failures, and token-validation timeouts. Test recovery from an unavailable
issuer or database without relabeling those failures as bad credentials.

## Before you go live

Complete the [deployment checklist](hardening-checklist.md) against your chosen
integration. Test in the actual proxy, cookie, and storage environment; a local
example passing does not validate production configuration.
