# Host authorization for your application

Use this guide when your own app needs to authenticate its users and issue
OAuth2 tokens for its frontend, API, CLI, or other registered application
clients. You provide your users, login pages, and persistent stores; the package
handles authorization requests, PKCE, token exchange, refresh, and revocation.

If you want Udibo to host sign-in, use [the managed-service guide](use-udibo.md)
instead. This guide covers an application's authorization server, not an
identity platform or hosted-service control plane.

Start with the [quickstart](../quickstart.md). The runnable reference is
[Hono with own auth](../../examples/hono/app-with-own-auth/README.md). The
snippets below show how to replace its development configuration with your
application's services. `declare const` marks an implementation your app
supplies.

## The seams: your entities, your storage

The framework owns the protocol; you own the data. Every server and grant is
generic over your `Client` and `User` types, and all storage flows through
service interfaces you implement against your own database.

Your client entity extends `ClientInterface` from `@udibo/oauth2/server` — the
minimum the framework inspects:

```ts
interface ClientInterface {
  id: string;
  grants?: string[];
  redirectUris?: string[];
}
```

`grants` lists the grant types the client may use (a grant-type request outside
this list is rejected), and `redirectUris` is the allowlist for the
authorization-code flow: entries are matched exactly, unless an entry is a
wildcard pattern (`https://myapp-*.myorg.deno.net/cb`), which needs the
`isPublicSuffix` seam wired or it stays inert. Add whatever else your app needs
— name, secret hash, owner — the framework never sees those fields.

Three services back the server:

- **`ClientServiceInterface<Client, User>`** — `get(id)`,
  `getAuthenticated(id, secret?)`, and `getUser(client)` (the subject of a
  client-credentials token). Returning `undefined` is the conformant default:
  RFC 6749 §4.4 has no resource owner, so the grant issues a token with no user
  and the client itself is the subject (RFC 9068 §2.2). Return a user only when
  that user is a principal of its own — a per-application service account.
  Returning the human who owns the application hands the machine that person's
  identity, which is the _Client Impersonating Resource Owner_ attack of RFC
  9700 §4.15.
- **`TokenServiceInterface<Client, User, Scope>`** — token generation, storage,
  and revocation. Extend `AbstractTokenService` (from
  `@udibo/oauth2/server/authorization`) and implement the five storage methods
  (`getToken`, `getRefreshToken`, `save`, `revoke`, `revokeCode`); generation,
  expiry math, and scope acceptance come with overridable defaults. Two optional
  methods, `getRevokedRefreshToken` and `revokeFamily`, enable refresh-token
  reuse detection (covered below).
- **`AuthorizationCodeServiceInterface<Client, User, Scope>`** — single-use code
  storage for the authorization-code grant; extend
  `AbstractAuthorizationCodeService`.

In-memory implementations of all of these ship in `@udibo/oauth2/testing`
(`MemoryClientService`, `MemoryTokenService`, `MemoryAuthorizationCodeService`,
`MemoryUserService`) — use them to get running today, then swap in DB-backed
implementations and prove them with the contract test runners in
`@udibo/oauth2/testing/contract`.

## Construct the server

`HonoAuthorizationServer` (from `@udibo/oauth2/hono/authorization-server`) takes
the same options as the core `AuthorizationServer` and adds the Hono mounting
helpers. Configuration flows through one seam: `resolve(request)` returns the
services the server's own endpoints need plus the issuer and endpoint URLs. For
an application server, return the configured issuer and persistent services.
Each grant resolves its own services the same way. Keep issuer selection in
trusted application configuration.

```ts
import { HonoAuthorizationServer } from "@udibo/oauth2/hono/authorization-server";
import {
  AuthorizationCodeGrant,
  type AuthorizationCodeServiceInterface,
  type ClientServiceInterface,
  RefreshTokenGrant,
  type TokenServiceInterface,
} from "@udibo/oauth2/server/authorization";
import type { ClientInterface } from "@udibo/oauth2/server";

interface AppClient extends ClientInterface {
  id: string;
}

interface AppUser {
  id: string;
}

declare const clientService: ClientServiceInterface<AppClient, AppUser>;
declare const tokenService: TokenServiceInterface<AppClient, AppUser>;
declare const authorizationCodeService: AuthorizationCodeServiceInterface<
  AppClient,
  AppUser
>;

const issuer = "https://auth.example.com";
const services = { clientService, tokenService };

const authServer = new HonoAuthorizationServer<AppClient, AppUser>({
  resolve: () => ({
    services,
    issuer,
    authorizationEndpoint: `${issuer}/oauth2/authorize`,
    tokenEndpoint: `${issuer}/oauth2/token`,
    revocationEndpoint: `${issuer}/oauth2/revoke`,
    introspectionEndpoint: `${issuer}/oauth2/introspect`,
  }),
  grants: {
    authorization_code: new AuthorizationCodeGrant<AppClient, AppUser>({
      resolve: () => ({
        clientService,
        tokenService,
        authorizationCodeService,
      }),
      allowRefreshToken: true,
    }),
    refresh_token: new RefreshTokenGrant<AppClient, AppUser>({
      resolve: () => ({ clientService, tokenService }),
    }),
  },
  scopesSupported: ["openid", "profile", "email", "read", "write"],
});
```

Any endpoint you omit defaults to `${issuer}${path}` (e.g. `${issuer}/token`),
so a server whose endpoints sit at the issuer root needs only `issuer`. The
explicit URLs above exist because this guide mounts everything under `/oauth2`.

## Mount the endpoints

`routes()` returns a Hono app with every standard endpoint at its conventional
path: `POST /token`, `GET /authorize`, `POST /revoke`, `POST /introspect`,
`POST /device_authorization`, `GET /.well-known/oauth-authorization-server`,
`GET /.well-known/openid-configuration`, `GET /jwks`, and `/userinfo` (GET and
POST). The last three go live when OIDC issuance is configured.

The one thing `routes()` cannot decide for you is who the user is. The authorize
endpoint asks your `authenticateUser` callback, which receives the Hono
`Context` and returns one of three things: `{ user }` when a session exists, a
`Response` (typically a redirect to your login page) to short-circuit the flow,
or `null` for an explicit denial:

```ts
import { Hono } from "hono";
import type { Context } from "hono";
import type { HonoAuthorizationServer } from "@udibo/oauth2/hono/authorization-server";
import type { UserServiceInterface } from "@udibo/oauth2/server/authorization";
import type { ClientInterface } from "@udibo/oauth2/server";

interface AppClient extends ClientInterface {
  id: string;
}

interface AppUser {
  id: string;
}

declare const authServer: HonoAuthorizationServer<AppClient, AppUser>;
declare const userService: UserServiceInterface<AppUser>;
declare function readSessionUserId(c: Context): string | undefined;

const app = new Hono();

app.route(
  "/oauth2",
  authServer.routes({
    authenticateUser: async (c) => {
      const userId = readSessionUserId(c);
      if (!userId) {
        const url = new URL(c.req.url);
        const returnTo = encodeURIComponent(`${url.pathname}${url.search}`);
        return c.redirect(`/login?return_to=${returnTo}`);
      }
      const user = await userService.get(userId);
      if (!user) {
        return c.redirect("/login");
      }
      return { user };
    },
  }),
);
```

The login redirect carries the full authorize URL as `return_to`, so after your
login form authenticates the user it sends the browser back to
`/oauth2/authorize` with the original query intact and the flow resumes. Reserve
`null` for "the user said no" — it redirects to the client's `redirect_uri` with
`error=access_denied`.

The well-known documents are registered relative to the mount, so the layout
above serves discovery at `/oauth2/.well-known/oauth-authorization-server`.
Mount `routes()` at the root, or mount the individual handler factories
(`tokenHandler()`, `authorizeHandler()`, `metadataHandler()`, …) at custom
paths, if you want discovery at the origin-root well-known location.

With this much mounted, the authorization-code + PKCE flow works end to end: a
client sends the user to `GET /oauth2/authorize` with `response_type=code`,
`client_id`, `redirect_uri`, `state`, `scope`, and a S256 `code_challenge`; your
login authenticates them; the browser returns to the client's `redirect_uri`
with a single-use `code`; and the client exchanges it at `POST /oauth2/token`
with its `code_verifier`.

## Security defaults

Two protections are on by default, deliberately stricter than RFC 6749:

- **`state` is required** at the authorize endpoint. Requests without it are
  rejected with `invalid_request` rather than degrading CSRF protection to
  optional.
- **PKCE is required** for the authorization-code grant, for all clients
  including confidential ones, matching OAuth 2.1. The only challenge method
  registered by default is `S256`. Set `requirePKCE: false` on the
  `AuthorizationCodeGrant` only if you must support a legacy confidential client
  that cannot send a challenge.
- **The challenge's format is enforced too.** For `S256` and `plain` — the two
  methods the IANA PKCE registry defines and whose output shape RFC 7636 §4.2
  fixes — `/authorize` rejects a `code_challenge` that is not 43–128 characters
  of `[A-Z] / [a-z] / [0-9] / - / . / _ / ~`, with `invalid_request`. The check
  runs after the method check, so an unsupported method still reports
  `unsupported code_challenge_method`. A method **you** register in
  `challengeMethods` is deliberately left alone: its challenge shape is yours to
  define. `validateCodeChallenge` is exported from
  `@udibo/oauth2/server/authorization` if you mint codes by calling the grant
  directly and want the same check.

`AuthorizationCodeGrant` takes four options worth setting deliberately:

| Option                        | Default    | What it does                                                                                                      |
| ----------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------- |
| `allowRefreshToken`           | `true`     | Whether a code exchange also issues a refresh token                                                               |
| `requirePKCE`                 | `true`     | Rejects an authorize request with no `code_challenge`, and a token request with no `code_verifier`                |
| `challengeMethods`            | `{ S256 }` | The PKCE methods this grant accepts. What you register here is what `code_challenge_methods_supported` advertises |
| `requireClientAuthentication` | `true`     | Whether a client presenting a `code_verifier` must **also** present its `client_secret`                           |

**Confidential clients authenticate alongside PKCE by default.** A valid
`code_verifier` does not replace the registered client secret. Public clients
have no secret and continue to use PKCE. The explicit
`requireClientAuthentication: false` option is only for legacy integrations.

Authorization-code replay is also handled: exchanging a code twice revokes every
token the first exchange issued (RFC 6819 §4.4.1.1), via your token service's
`revokeCode`. See [Known Limitations](../known-limitations.md) for the full list
of deliberate deviations.

## Consent: optional by design

`handleConsent` is optional. **With no handler, the framework treats the request
as consented** and grants the accepted scope — the right behavior for a server
whose clients are all first-party. Configure a handler only when untrusted
third-party clients need a prompt (or a denial):

```ts
import type { Context, Hono } from "hono";
import type {
  HonoAuthenticateUserFn,
  HonoAuthorizationServer,
} from "@udibo/oauth2/hono/authorization-server";
import type { AbstractScope, ClientInterface } from "@udibo/oauth2/server";

interface AppClient extends ClientInterface {
  id: string;
}

interface AppUser {
  id: string;
}

declare const app: Hono;
declare const authServer: HonoAuthorizationServer<AppClient, AppUser>;
declare const authenticateUser: HonoAuthenticateUserFn<AppUser>;
declare function takePendingConsent(
  c: Context,
  user: unknown,
  client: AppClient,
  requestedScope: AbstractScope | undefined,
): Promise<"deny" | "approve" | undefined>;
declare function renderConsentPage(
  c: Context,
  client: AppClient,
  requestedScope: AbstractScope | undefined,
): Response;

app.route(
  "/oauth2",
  authServer.routes({
    authenticateUser,
    handleConsent: async (c, client, requestedScope, user) => {
      const decision = await takePendingConsent(
        c,
        user,
        client,
        requestedScope,
      );
      if (decision === undefined) {
        return renderConsentPage(c, client, requestedScope);
      }
      if (decision === "deny") {
        return { approved: false };
      }
      return { approved: true };
    },
  }),
);
```

The handler returns `{ approved: true, scope? }` (optionally narrowing the grant
per RFC 6749 §3.3), `{ approved: false }` (redirects to the client with
`error=access_denied`), or a `Response` rendering your consent page. The page
flow is two visits to `/oauth2/authorize`: on the first, the handler finds no
recorded decision and returns the consent page; the page POSTs to your own
`/consent` route, which records the decision server-side — one-time, bound to
the user, client, and scope — and redirects back; on the second visit the
handler consumes that record. Never carry the decision in the authorize URL's
query parameters: the client builds that URL, so any client could append an
approval and skip the prompt. The full pattern lives in
[`examples/hono/app-with-own-auth/routes/consent.ts`](https://github.com/udibo/oauth2/blob/main/examples/hono/app-with-own-auth/routes/consent.ts).

Users who should not be able to grant everything they're asked for are handled
here too: intersect the requested scope with what the user may grant and return
it as the narrowed `scope`.

## Refresh-token rotation and reuse detection

The `RefreshTokenGrant` rotates on every refresh: it revokes the presented token
and saves its replacement, carrying the original `familyId` **and**
`familyCreatedAt` forward so an entire rotation chain shares one family and one
anchor.

Your token service has to round-trip both fields — persist them on `save` and
return them from `getRefreshToken` / `getRevokedRefreshToken`. Dropping
`familyId` disables reuse detection; dropping `familyCreatedAt` disables the
absolute family cap below, and neither failure announces itself: rotation keeps
working and the tests you would write against a single refresh still pass.

## Capping a rotation family's absolute lifetime

Rotation renews the refresh token's lifetime every exchange, so a client that
refreshes often enough holds a credential forever. Implement the optional
`refreshTokenFamilyExpiresAt(client, user, familyCreatedAt, scope?)` to put an
absolute ceiling on the family. That gives you the sliding-window-with-maximum
shape: each exchange renews the refresh token, but the whole chain still dies at
a fixed point measured from when the family started.

```ts ignore
class AppTokenService extends AbstractTokenService<AppClient, AppUser> {
  override refreshTokenFamilyExpiresAt(
    client: AppClient,
    _user: AppUser,
    familyCreatedAt: Date,
  ): Promise<Date | undefined> {
    return Promise.resolve(
      client.refreshTokenMaxLifetime == null ? undefined : new Date(
        familyCreatedAt.getTime() + client.refreshTokenMaxLifetime * 1000,
      ),
    );
  }
}
```

Every rotation's access and refresh expiries are clamped to the date you return,
and once it has passed the exchange answers `invalid_grant`, so the client must
obtain a fresh authorization. `AbstractTokenService` implements the method from
its own `refreshTokenMaxLifetime` option (service-wide, and rejected at
construction if it is shorter than `refreshTokenLifetime`); override it, as
above, to cap per client. **The method is the whole cap** — leave it off, or
return `undefined`, and families are never capped. A record with no
`familyCreatedAt` (one stored before you added the cap) rotates once uncapped
and is anchored from then on.

Reuse detection activates when your token service implements the two optional
methods: keep revoked refresh-token records findable via
`getRevokedRefreshToken`, and implement `revokeFamily(familyId)` to kill every
token in a chain. When a rotated-out token is replayed — stolen, or a client
raced itself — the grant revokes the whole family so neither party keeps a live
session, then invokes your `onTokenReuse` hook so the event lands in your audit
log:

```ts
import {
  type ClientServiceInterface,
  RefreshTokenGrant,
  type TokenServiceInterface,
} from "@udibo/oauth2/server/authorization";
import type { ClientInterface } from "@udibo/oauth2/server";

interface AppClient extends ClientInterface {
  id: string;
}

interface AppUser {
  id: string;
}

declare const clientService: ClientServiceInterface<AppClient, AppUser>;
declare const tokenService: TokenServiceInterface<AppClient, AppUser>;
declare const auditLog: {
  record(entry: Record<string, unknown>): Promise<void>;
};

const refreshGrant = new RefreshTokenGrant<AppClient, AppUser>({
  resolve: () => ({ clientService, tokenService }),
  onTokenReuse: async (event) => {
    await auditLog.record({
      type: "refresh_token_reuse_detected",
      familyId: event.familyId,
      clientId: event.client.id,
      userId: event.user?.id,
      familyRevoked: event.familyRevoked,
    });
  },
});
```

If the token service omits those two methods, reuse detection is silently
disabled and a replayed token simply fails with `invalid_grant` — rotation still
happens, but a theft can't be distinguished from a typo. `MemoryTokenService`
implements both, so the detection path is exercisable in tests.

## Revocation and introspection

Both endpoints require client authentication, both take `token` and an optional
`token_type_hint`, and on both the hint **orders the lookup rather than
restricting it**: a token labelled `access_token` that turns out to be a refresh
token is still found, and vice versa. A mislabelled token is therefore still
revoked, and still introspected.

**`POST /revoke` only revokes tokens issued to the authenticated client.** The
server resolves the presented token, compares its `client.id` against the client
that authenticated, and revokes only on a match — RFC 7009 §2.1. It answers
`200` regardless: for a match, for another client's token, for an unknown token,
and for one already revoked. That uniformity is deliberate (§2.2) — the endpoint
must not become an oracle for whether a token exists or who owns it — which also
means **a caller cannot tell a successful revocation from a refused one.**
Revocation uses the resolved token kind, not the hint.

This puts a real requirement on your token service: `getRefreshToken` must
return live refresh tokens. A service whose `getRefreshToken` returns
`undefined` for tokens that exist will silently no-op every refresh-token
revocation and report `active: false` for every live refresh token, with a `200`
either way and nothing in the logs.

**Configure `canIntrospectToken` to authorize introspection.** The callback on
`AuthorizationServerOptions` receives the authenticated client, the resolved
token and its actual kind (`access_token` or `refresh_token`). Return false to
answer only `{ active: false }`; claims enrichment runs only after
authorization. An error fails the request closed. Without this policy, the
endpoint preserves its separate resource-server behavior: every admitted client
can inspect any live token. Choose the policy when mounting the endpoint, and
remember that a public client ID does not authenticate its holder. See
[Known Limitations](../known-limitations.md#spec-level-gaps).

Introspection answers for **refresh** tokens too: a live one reports
`active: true` with `exp` from its own expiry and carries **no** `token_type`,
while an access token carries `token_type: "Bearer"`. A caller that must
distinguish them checks `token_type`; one that treats any `active: true` as a
valid access token will accept a refresh token presented as a bearer.

## Discovery metadata

`GET /.well-known/oauth-authorization-server` serves the RFC 8414 document built
from your resolved context: `issuer` (required — metadata requests fail without
it), the endpoint URLs, `grant_types_supported` (the keys of your `grants` map),
`scopes_supported`, `code_challenge_methods_supported`, and the token-endpoint
auth methods (`client_secret_basic`, `client_secret_post`, `none`).
`code_challenge_methods_supported` is **derived** from the registered
authorization-code grant's own `challengeMethods` — only own, callable entries
count — so registering an extra method advertises it and dropping `S256`
un-advertises it, and the field is omitted entirely when no authorization-code
grant is registered. It reports what the server will actually accept rather than
a fixed string.

`token_endpoint_auth_methods_supported` always carries `none` — the RFC 7591
method for a client with no secret — because the token endpoint accepts it
unconditionally: a request that presents only `client_id` reaches your
`clientService.getAuthenticated` with no secret (an authorization-code exchange
carrying a `code_verifier` looks the client up with `clientService.get` instead,
unless `requireClientAuthentication` is set), and resolving a public client
there is part of that interface's contract. There is no option that switches it
off, and `requireClientAuthentication` on the authorization-code grant does not
(it constrains confidential clients that send a `code_verifier` in place of
their secret). Whether a given client may authenticate with `none` is still
decided per client, by whether it has a secret; discovery describes the
endpoint, not which clients you registered. Clients that discover — including
this package's `DirectClient` via `discover()` — configure themselves from it,
so keep the advertised endpoints matching where you actually mounted the routes.

## Turning on OIDC issuance

Everything above is plain OAuth2: clients get access tokens but learn nothing
portable about the user. OpenID Connect adds the `id_token` — a signed JWT
asserting who authenticated — plus the JWKS and UserInfo endpoints. The whole
surface switches on with one option: `signingKeys`.

### Generate and persist a signing key

Keys are ES256 (see [Known Limitations](../known-limitations.md) — there is no
RS256 option; every mainstream client library accepts ES256). Generate a key
**once**, export the private JWK, and store it as a secret; every instance of a
multi-instance deploy must load the same key, because an ephemeral per-instance
key would fail verification across instances — see
[the multi-instance rule](production-deployment.md#the-multi-instance-rule) for
the other state this applies to.

The package's CLI generates one. Run it once and put the printed JWK in your
secret manager as `OIDC_SIGNING_KEY`:

```sh
deno run jsr:@udibo/oauth2/cli oidc keygen
```

The JWK goes to stdout as a single line ready to paste into a secret store; the
notes about handling it go to stderr, so piping stdout straight into your secret
store — `… oidc keygen | gh secret set OIDC_SIGNING_KEY`, or your provider's
equivalent — carries the key and nothing else. Nothing is written to disk, and
the command needs **no Deno permissions** — run it without `-A`; a key generator
asking for permissions is a reason to stop and look.

The exported JWK contains the private key material — guard it like any
credential. At boot, load it:

```ts
import {
  importSigningKeyJwk,
  StaticSigningKeyProvider,
} from "@udibo/oauth2/server/authorization";

const signingKey = await importSigningKeyJwk(
  JSON.parse(Deno.env.get("OIDC_SIGNING_KEY")!),
);
const signingKeys = new StaticSigningKeyProvider(signingKey);
```

`StaticSigningKeyProvider` covers the single-key case. For rotation, implement
the two-method `SigningKeyProvider` interface yourself: `getSigningKey()`
returns the key new tokens sign with, and `getPublicJwks()` returns every public
key a verifier may still need (current plus not-yet-expired old keys). What that
costs if you don't, and what the package does not yet ship, is spelled out in
[Signing keys and rotation](production-deployment.md#signing-keys-and-rotation).

### Configure claims

Add `signingKeys` — plus the two claim hooks — to the server options:

```ts
import { HonoAuthorizationServer } from "@udibo/oauth2/hono/authorization-server";
import type {
  AuthorizationServerGrants,
  AuthorizationServerServices,
  SigningKeyProvider,
} from "@udibo/oauth2/server/authorization";
import type { BasicScope, ClientInterface } from "@udibo/oauth2/server";

interface AppClient extends ClientInterface {
  id: string;
}

interface AppUser {
  id: string;
  username?: string;
  name?: string;
  email?: string;
  emailVerified?: boolean;
}

declare const resolve: () => {
  services: AuthorizationServerServices<AppClient, AppUser, BasicScope>;
  issuer: string;
};
declare const grants: AuthorizationServerGrants<AppClient, AppUser, BasicScope>;
declare const signingKeys: SigningKeyProvider;

const authServer = new HonoAuthorizationServer<AppClient, AppUser>({
  resolve,
  grants,
  scopesSupported: ["openid", "profile", "email", "read", "write"],
  signingKeys,
  subjectOf: (user) => user.id,
  userClaims: (user, scope) => {
    const claims: Record<string, unknown> = {};
    if (scope?.has("profile")) {
      claims.preferred_username = user.username;
      claims.name = user.name;
    }
    if (scope?.has("email") && user.email) {
      claims.email = user.email;
      claims.email_verified = user.emailVerified ?? false;
    }
    return claims;
  },
});
```

`subjectOf` maps a user to the `sub` claim (it defaults to the user's `id`
property, so you can omit it when that's right). `userClaims` releases the
optional claims, and the scope parameter is how you honor the standard `profile`
and `email` scopes — release each claim only when its governing scope was
granted. The protocol claims always win: `sub`, `iss`, `aud`, `iat`, `exp`, and
`nonce` are stamped over anything `userClaims` returns.

### What switches on

With `signingKeys` configured:

- **The token endpoint mints an `id_token`** alongside the access token for
  user-bound grants whose scope includes `openid`. If the client sent a `nonce`
  on the authorize request, it is bound to the code and echoed into the
  `id_token` for the client to verify — replay protection the relying party
  enforces.
- **`GET /jwks`** serves your public keys, and **`GET`/`POST /userinfo`**
  answers bearer-token requests (the token must carry the `openid` scope and a
  user) with `sub` plus your `userClaims`.
- **`GET /.well-known/openid-configuration`** serves the discovery document with
  the OIDC members (`jwks_uri`, `userinfo_endpoint`,
  `id_token_signing_alg_values_supported: ["ES256"]`). Without `signingKeys`,
  this endpoint — and JWKS and UserInfo — return 404, so relying parties fail
  fast instead of reading a document missing its required members.

Add `jwksEndpoint` and `userinfoEndpoint` to your `resolve` context if the
issuer-derived defaults (`${issuer}/jwks`, `${issuer}/userinfo`) don't match
where you mounted the routes.

The same `signingKeys` can also back **JWT access tokens**: wire
`createJwtAccessTokenGenerator({ signingKeys, issuer, audience })` in as your
token service's `generateAccessToken`, and resource servers can validate offline
against your JWKS endpoint — see
[Protect an API](./protect-an-api.md#strategy-2-local-jwt-validation-against-the-jwks-endpoint).
The token store still persists the JWT string, so revocation and introspection
keep working exactly as with opaque tokens.

The generator's `userClaims` option is the same seam the server's `userClaims`
option gives the id_token, so one claims computation (roles, permissions, an
organization) can feed both. It runs only when a resource owner is behind the
token — a client-credentials token never carries user claims — and the protocol
claims (`iss`, `sub`, `aud`, `client_id`, `iat`, `exp`, `jti`, `scope`) always
win over anything it returns.

## Where to go next

- [Protect an API](./protect-an-api.md) — the consumer side of the tokens you
  now issue. The same `HonoAuthorizationServer` instance also exposes
  `protect()` / `requireScope()`, so one process can issue tokens and guard its
  own API routes.
- [Deploy and Operate in Production](production-deployment.md) — configuration
  inventory, the stores you provision and their retention, TLS and proxy
  assumptions, security headers, and the
  [hardening checklist](hardening-checklist.md).
- [Known Limitations](../known-limitations.md) — ES256-only signing, the
  introspection field subset, no dynamic client registration, no provider-side
  OIDC logout (`end_session_endpoint`), and the other honest walls.
- The [README](../../README.md) covers error-format configuration
  (`errorFormat: "problem-details"`), the `resolve` hook for
  application-specific and proxy deployments, and testing with
  `createMemoryAuthorizationServer`.
