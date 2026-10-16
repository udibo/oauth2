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
  postLogoutRedirectUris?: string[];
}
```

`grants` lists the grant types the client may use (a grant-type request outside
this list is rejected), and `redirectUris` is the allowlist for the
authorization-code flow: entries are matched exactly, unless an entry is a
wildcard pattern (`https://myapp-*.myorg.deno.net/cb`), which needs the
`isPublicSuffix` seam wired or it stays inert. `postLogoutRedirectUris` is the
exact-match allowlist for RP-initiated logout redirects. Add whatever else your
app needs — name, secret hash, owner — the framework never sees those fields.

Three services back the server:

- **`ClientServiceInterface<Client, User>`** — `get(id)`,
  `getAuthenticated(id, secret?)`, and `getUser(client)` (the subject of a
  client-credentials token). For `getUser`, returning `undefined` is the
  conformant default: RFC 6749 §4.4 has no resource owner, so the grant issues a
  token with no user and the client itself is the subject (RFC 9068 §2.2).
  Return a user only when that user is a principal of its own — a
  per-application service account. Returning the human who owns the application
  hands the machine that person's identity, which is the _Client Impersonating
  Resource Owner_ attack of RFC 9700 §4.15. `getAuthenticated` resolves a
  confidential client only with its correct secret, and a public client only
  when the request presents none — a public client that sends a secret it was
  never issued resolves `undefined`, which the server answers with
  `invalid_client`. `runClientServiceContractTests` from
  `@udibo/oauth2/testing/contract` pins all three rules.
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
`MemoryUserService`) — use them to get running, then swap in DB-backed
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

For machine-to-machine callers, add
`client_credentials: new ClientCredentialsGrant({ resolve: () => ({ clientService, tokenService }) })`.
RFC 6749 §4.4 limits that grant to confidential clients, so it refuses any
request that presents no client secret with `401 invalid_client` — a public
client, or a confidential client that left its secret out. Register each machine
client with a secret and have it send that secret with HTTP Basic or as
`client_secret` in the body, not both.

Any endpoint you omit defaults to `${issuer}${path}` (e.g. `${issuer}/token`),
so a server whose endpoints sit at the issuer root needs only `issuer`. The
explicit URLs above exist because this guide mounts everything under `/oauth2`.

## Mount the endpoints

`routes()` returns a Hono app with every standard endpoint at its conventional
path: `POST /token`, `GET /authorize`, `POST /revoke`, `POST /introspect`,
`POST /device_authorization`, `GET /.well-known/oauth-authorization-server`,
`GET /.well-known/openid-configuration`, `GET /jwks`, `/userinfo` (GET and
POST), and `/end_session` (GET and POST). OIDC discovery, JWKS, and UserInfo go
live when OIDC issuance is configured; `/end_session` goes live when the
`endSession` option is configured.

For RP-initiated logout, compare a verified `subject` with the active session
before ending it. If they name different people, return
`{ refused: true, fallback: "/sign-in" }` from `endSession`. The server then
ignores the relying party's redirect and any session-clearing headers, sending
the browser to your fallback instead. Without a fallback it answers 204.

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

These protections are on by default, deliberately stricter than RFC 6749:

- **`state` is required** at the authorize endpoint. Requests without it are
  rejected with `invalid_request` rather than degrading CSRF protection to
  optional.
- **A request authenticates its client by exactly one method.** The token,
  revocation, introspection and device authorization endpoints refuse a request
  that combines HTTP Basic with a body `client_secret` or `client_assertion`, or
  a body `client_secret` with a `client_assertion`, with `400 invalid_request`
  (RFC 6749 §2.3: a client MUST NOT use more than one authentication method in
  each request). A body `client_id` next to Basic credentials is allowed only
  when it names the same client. An `Authorization` header that uses the Basic
  scheme is the method the client chose, so a malformed one is answered with
  `401 invalid_client` even when the body names a client.
- **PKCE is required** for the authorization-code grant, for all clients
  including confidential ones, matching OAuth 2.1. The only challenge method
  registered by default is `S256`. Set `requirePKCE: false` on the
  `AuthorizationCodeGrant` only if you must support a legacy confidential client
  that cannot send a challenge.
- **An omitted `code_challenge_method` means `S256`.** RFC 7636 §4.3 defaults
  it to `plain`; this server deliberately follows OAuth 2.1 and the OAuth
  security BCP instead. A challenge sent without a method is verified as the
  SHA-256 of the verifier, so a client that sends its verifier as the challenge
  and omits the method fails the token exchange with `invalid_grant`.
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
- **Request bodies are capped at 64 KiB.** The token, revocation, introspection,
  device authorization and end-session endpoints read their form body before the
  caller is authenticated, so each read stops once it passes `maxBodyBytes` (an
  `AuthorizationServer` option, default `65536`). Bytes are counted as they
  arrive, so a chunked body or an understated `Content-Length` does not get past
  the cap. An oversized body is refused with `413` and `invalid_request` before
  `resolve` runs. The largest legitimate field is a JWT of a few KiB, so raise
  the cap only if your clients send larger bodies.

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

A request with `prompt=consent` reaches the handler even when the scope is
already authorized, and the handler's fifth argument carries `prompt` so it can
ask again instead of reusing a stored decision. A server with no handler cannot
ask, so it answers `prompt=consent` with `consent_required`. Under `prompt=none`
the server never shows the page a handler returns; it redirects with
`consent_required` instead. See
[Honor `prompt`, `max_age` and `acr_values`](#honor-prompt-max_age-and-acr_values).

## Error responses

The OAuth endpoints answer every error in the RFC 6749 §5.2 format:
`{ error, error_description, error_uri }` as `application/json`, with
`error_description` and `error_uri` present when the error has them. That
covers token, revocation, introspection, device authorization, end-session,
metadata, OIDC metadata and JWKS, and the authorize endpoint when it cannot
redirect. Revocation and introspection (RFC 7009, RFC 7662) and device
authorization (RFC 8628) take their error format from RFC 6749 §5.2. The
client-authenticated endpoints also send `Cache-Control: no-store` and
`Pragma: no-cache`, and a `WWW-Authenticate: Basic` challenge on a `401` when
the client authenticated with an `Authorization` header.

`errorFormat` does not change these responses. It governs only refusals from
the server's protected resources: `protect()`, `handleAuthError` and the
UserInfo endpoint. With `errorFormat: "problem-details"`, those answer RFC 9457
problem details as `application/problem+json`, as a resource server does.

## Form parameter cardinality

The token, revocation, introspection and device-authorization handlers reject
repeated recognized singleton form parameters with `400 invalid_request`, even
when the values are identical. The check runs before `resolve`, client
authentication, grant execution or token lookup. The refusal is in the RFC 6749
format with `Cache-Control: no-store` and `Pragma: no-cache`, whatever
`errorFormat` is set to.

| Endpoint / grant             | Singleton form parameters               |
| ---------------------------- | --------------------------------------- |
| All four endpoints           | `client_id`, `client_secret`            |
| Token, all grants            | `grant_type`                            |
| Token, `authorization_code`  | `code`, `redirect_uri`, `code_verifier` |
| Token, `refresh_token`       | `refresh_token`, `scope`                |
| Token, `client_credentials`  | `scope`                                 |
| Token, `password`            | `username`, `password`, `scope`         |
| Token, device-code grant     | `device_code`                           |
| Revocation and introspection | `token`, `token_type_hint`              |
| Device authorization         | `scope`                                 |

The token handler selects the grant-specific fields from the single raw
`grant_type`. It leaves another grant's fields and unknown extensions alone.
Repeated `resource` and `audience` values are preserved, as are custom-grant
extension fields; your custom grant owns their validation. This check does not
validate authorization-query, callback or end-session parameters.

[RFC 6749 §3.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2) and
[RFC 8628 §3.1](https://www.rfc-editor.org/rfc/rfc8628.html#section-3.1)
prohibit repeated request parameters at their respective endpoints. Revocation
uses the
[RFC 7009 §2.2.1](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.2.1)
error format. For introspection, refusing repeated scalar `token` and
`token_type_hint` fields is the package's parsing policy;
[RFC 7662 §2.1](https://www.rfc-editor.org/rfc/rfc7662.html#section-2.1) does
not state a general prohibition on repeated extension parameters. The multivalue
resource/audience conventions in
[RFC 8707 §2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2) and
[RFC 8693 §2.1](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1) remain
available to extensions.

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

### Atomic rotation

Implement the optional `rotate(current, next)` so a refresh claims the presented
token and saves its successor as one step. It resolves the saved successor, or
`undefined` with nothing saved when `current` was already claimed or revoked, or
its family has been revoked; the grant answers `undefined` with `invalid_grant`.
Stamp the rotated-out record with `rotatedAt` exactly as `revokeRotated` does,
or `replayGraceSeconds` and the revocation endpoint's family revocation stop
applying. `MemoryTokenService` implements it.

Without `rotate`, the grant claims the token with `revokeRotated` (or `revoke`)
and saves the successor in a second call. A refresh that presents the same token
between those calls, such as a client's own concurrent request, finds it
revoked with no live successor. Reuse detection takes that for theft: it revokes
the family and fires `onTokenReuse`. A store that keeps a revoked family
revoked then stores the successor already revoked, so the client that refreshed
is signed out; a store that does not leaves that successor live in a family the
server revoked. With `rotate`, a concurrent refresh either claims the token
first or loses the claim and gets a plain `invalid_grant`.

When your `rotate` awaits I/O between its claim and its insert, as a database
transaction does, `revokeFamily` must still be linearizable with it: once
`revokeFamily` resolves, the family has no live member and no later `rotate` of
a member succeeds, and a `rotate` that committed before it began has its
successor revoked. Taking one lock per family, first in both methods, meets
this: a revocation that would otherwise run while a rotation is between its
claim and its insert waits, then sees and revokes the successor. Prove it with
`runTokenRotationContractTests` (see
[testing](testing.md#persistent-storage-contracts)).

### Replay grace for clients that race themselves

Reuse detection cannot tell a thief from a client that raced itself. A
backend-for-frontend whose instances do not coordinate refreshes, or a browser
request that still carries a session cookie from before a refresh, can present
a refresh token its own concurrent request just rotated. That revokes the
family and signs the user out. `replayGraceSeconds` on `RefreshTokenGrant`,
off by default, gives that straggler a plain `invalid_grant` instead:

```ts
import {
  type ClientServiceInterface,
  RefreshTokenGrant,
  type TokenReuseEvent,
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
declare function onTokenReuse(
  event: TokenReuseEvent<AppClient, AppUser>,
): Promise<void>;

const refreshGrant = new RefreshTokenGrant<AppClient, AppUser>({
  resolve: () => ({ clientService, tokenService }),
  replayGraceSeconds: 10,
  onTokenReuse,
});
```

The grace applies only when all of these hold: the replayed token was rotated
out by the grant (not revoked any other way), it was rotated within the last
`replayGraceSeconds`, and its family still has a live refresh token. Then the
family keeps that token and `onTokenReuse` does not fire. Any other replay
revokes the family and raises the event as before.

The cost is real: a stolen refresh token replayed within the window after the
legitimate client rotated it goes unflagged. It cuts the other way too: when a
thief rotates a stolen live token first, the legitimate client's replay within
the window is refused without revoking the family, so the thief keeps the
session, the user is the one signed out, and `onTokenReuse` does not fire.
Keep the window to seconds, and
prefer fixing the race at the client, for example with `HonoBff`'s
`RefreshLockStore` on a shared session store.

The grace needs two things from your token service. `revokeRotated` stamps the
revoked record with `rotatedAt`, which `getRevokedRefreshToken` returns, and
`hasLiveRefreshToken(familyId)` reports whether the family still has a live
token. `MemoryTokenService` implements both. With a service that lacks either,
the grace never applies. `runTokenServiceContractTests` checks both when a
service implements them.

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

**Revoking a refresh token that rotation already replaced revokes its whole
family.** A sign-out can present a token the client's own refresh rotated a
moment earlier: a backend-for-frontend's logout request still carries the
session from before a refresh that is in flight. That token is no longer live,
so revoking it alone would leave the successor working. When the presented
token is not live, the endpoint asks `getRevokedRefreshToken` for it. If the
record carries `rotatedAt` and a `familyId`, and was issued to the
authenticated client, the endpoint calls `revokeFamily`, and the successor and
its access tokens die with it. RFC 7009 §2.1 allows a server to revoke related
tokens this way, and the answer is the same `200` either way.

Three cases revoke nothing more. A token revoked other than by rotation has no
`rotatedAt`, so presenting it again does not cascade. A rotated-out token issued
to another client leaves that client's family alone. A token service without
`getRevokedRefreshToken` and `revokeFamily`, or one whose `revokeRotated` does
not stamp `rotatedAt`, keeps the earlier behavior: the endpoint answers `200`
and the successor stays live until it expires. `replayGraceSeconds` excuses a
straggling refresh only, never a revocation, and this path does not call
`onTokenReuse`, since a sign-out is not a replay. `/revoke` on a rotated-out
token ends the family without firing `onTokenReuse`, so any audit trail for it
comes from your store's `revokeFamily`. `runTokenServiceContractTests`
checks that a service implementing `revokeRotated` returns the family and client
from a rotated-out token.

Return the tombstone from `getRevokedRefreshToken` unconditionally. Apply a
replay grace through `replayGraceSeconds`, never by hiding recently rotated
tombstones in the store: a hidden tombstone also hides the family from a
sign-out that races the refresh.

Without `rotate`, the refresh grant saves the successor after it claims the
presented token, as two storage calls. A revocation that lands between them
finds no live successor to revoke. To close that gap, `revokeFamily` must record
the revoked family and `save` must store any later member of it already revoked.
`MemoryTokenService` does; a custom store needs the same, and reuse detection
relies on it too. A store that implements
[`rotate`](#atomic-rotation) has no such gap, provided `revokeFamily` is
linearizable with it.

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

With an authorization-code grant registered, the document also carries
`prompt_values_supported`: `none`, `login` and `consent` unless you set
`promptValuesSupported`. The OIDC discovery document adds
`acr_values_supported` when you set `acrValuesSupported`.

`token_endpoint_auth_methods_supported` always carries `none` — the RFC 7591
method for a client with no secret — because the token endpoint accepts it
unconditionally: a request that presents only `client_id` reaches your
`clientService.getAuthenticated` with no secret (an authorization-code exchange
carrying a `code_verifier` looks the client up with `clientService.get` instead,
when `requireClientAuthentication` is explicitly `false`), and resolving a
public client there is part of that interface's contract. There is no option
that switches it off, and `requireClientAuthentication` on the
authorization-code grant does not (it constrains confidential clients that send
a `code_verifier` in place of their secret). Whether a given client may
authenticate with `none` is still decided per client, by whether it has a
secret; discovery describes the endpoint, not which clients you registered. A
public client that presents a non-empty `client_secret` anyway is refused with
`invalid_client` rather than authenticated as public — it was issued no secret,
so the request is misconfigured — and the contract suite pins that answer. The
one grant that refuses `none` is `client_credentials`: RFC 6749 §4.4 limits it
to confidential clients, so a request for it that presents no secret is refused
with `invalid_client`. Clients that discover — including this package's
`DirectClient` via `discover()` — configure themselves from it, so keep the
advertised endpoints matching where you actually mounted the routes.

## Turning on OIDC issuance

Everything above is plain OAuth2: clients get access tokens but learn nothing
portable about the user. OpenID Connect adds the `id_token` — a signed JWT
asserting who authenticated — plus the JWKS and UserInfo endpoints. The whole
surface switches on with one option: `signingKeys`.

### Generate and persist a signing key

Keys are ES256 (see [Known Limitations](../known-limitations.md) — there is no
RS256 option; confirm your relying parties accept ES256). Generate a key
**once**, export the private JWK, and store it as a secret; every instance of a
multi-instance deploy must load the same key, because an ephemeral per-instance
key would fail verification across instances — see
[the multi-instance rule](production-deployment.md#the-multi-instance-rule) for
the other state this applies to.

The package's CLI generates one. Run it once and put the printed JWK in your
secret manager as `OIDC_SIGNING_KEY`:

```sh
npx udibo-oauth2 oidc keygen
```

The JWK goes to stdout as a single line ready to paste into a secret store; the
notes about handling it go to stderr, so piping stdout straight into your secret
store — `… oidc keygen | gh secret set OIDC_SIGNING_KEY`, or your provider's
equivalent — carries the key and nothing else. Nothing is written to disk and
the command makes no network requests.

The exported JWK contains the private key material — guard it like any
credential. At boot, load it:

```ts
import {
  importSigningKeyJwk,
  StaticSigningKeyProvider,
} from "@udibo/oauth2/server/authorization";

const signingKey = await importSigningKeyJwk(
  JSON.parse(process.env.OIDC_SIGNING_KEY!),
);
const signingKeys = new StaticSigningKeyProvider(signingKey);
```

`StaticSigningKeyProvider` covers the single-key case. For rotation, use
`RotatingSigningKeyProvider`, which signs with the current key and publishes
previous public keys, or implement the two-method `SigningKeyProvider` interface
yourself: `getSigningKey()` returns the key new tokens sign with, and
`getPublicJwks()` returns every public key a verifier may still need (current
plus not-yet-expired old keys). See
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
keep working exactly as with opaque tokens. The JWT's `exp` is the earlier of
the generator's `lifetimeSeconds` and the expiry the grant stores for the token
(the token service's `accessTokenExpiresAt`, clamped to any refresh-family cap),
so an offline verifier stops accepting the token when the server does.

The generator's `userClaims` option is the same seam the server's `userClaims`
option gives the id_token, so one claims computation (roles, permissions, an
organization) can feed both. It runs only when a resource owner is behind the
token — a client-credentials token never carries user claims — and the protocol
claims (`iss`, `sub`, `aud`, `client_id`, `iat`, `exp`, `jti`, `scope`) always
win over anything it returns.

### Preserve the authentication event

Return `authenticationContext` from your `authenticateUser` callback when your
application has verified evidence for `auth_time` (Unix seconds), `acr`, or
`amr`. Omit any claim you cannot establish. Session creation, a refresh, or a
federated callback alone does not prove when or how the user authenticated.

The authorization code captures a snapshot. Its tokens and every refresh
generation retain that event even if the user later signs in with stronger
authentication. Your code store must persist and restore
`AuthorizationCode.authenticationContext`; your token store must do the same for
`Token.authenticationContext`, including refresh records. Leave legacy records
without context rather than backfilling timestamps.

Claims are opt-in through the existing hooks. Use the credential's context in
each response, rather than looking up the current session:

```ts
import type { AuthenticationContext } from "@udibo/oauth2/server";

const claims = (event?: AuthenticationContext): Record<string, unknown> => ({
  ...event,
});

const oidcClaims = (
  _user: unknown,
  _scope: unknown,
  event?: AuthenticationContext,
): Record<string, unknown> => claims(event);

const accessTokenClaims = (
  _user: unknown,
  _scope: unknown,
  _client: unknown,
  event?: AuthenticationContext,
): Record<string, unknown> => claims(event);

const introspectionClaims = (
  token: { authenticationContext?: AuthenticationContext },
): Record<string, unknown> => claims(token.authenticationContext);
```

Set `AuthorizationServer.userClaims` to `oidcClaims` for ID tokens and UserInfo,
`createJwtAccessTokenGenerator.userClaims` to `accessTokenClaims` for JWT access
tokens, and `AuthorizationServer.introspectionClaims` to `introspectionClaims`.
Custom `generateAccessToken` wrappers must forward the fourth
(`authenticationContext`) argument to the JWT generator. Tokens without a
resource owner receive no event context.

The ID token's `auth_time` and `acr` come from the credential's recorded
context, whatever `userClaims` returns: each is present exactly when the context
has it, so a claims hook cannot report a stronger or more recent sign-in than
the one the code captured.

For a BFF requesting assurance or freshness, pin `acr_values` and `max_age` in
`extraParams`. They are forbidden in `forwardedParams`, case-insensitively,
because browser-chosen values could weaken the server's requirements. With
`max_age` pinned, `/auth/callback` also checks the ID token's `auth_time`, as
OpenID Connect Core §3.1.3.7 asks of a relying party. It refuses a token whose
`auth_time` is missing, more than 60 seconds in the future, or older than
`max_age` plus 60 seconds, which allows for clock skew between the BFF and the
server. `max_age=0` means `prompt=login`, so it needs `auth_time` but no
particular age. A token response without an ID token is not checked, unless
`forwardedParams` names `scope`; then the browser could leave out `openid` to
skip the check, so a missing ID token is refused as well. A refusal reaches
`onCallbackError` as `login_required`.

### Honor `prompt`, `max_age` and `acr_values`

The authorize endpoint validates the OpenID Connect authentication controls once
the redirect URI is verified, and hands them to `authenticateUser` as a second
argument, an `AuthenticationRequest` of `{ prompt, maxAge?, acrValues }`. A
repeated parameter, a `prompt` value the server does not support, `none`
combined with another value, or a `max_age` that is not a non-negative integer
is refused with `invalid_request`. A parameter sent without a value counts as
omitted.

The server enforces what it can check, so a client is never handed a code that
contradicts what it asked for:

| Control          | What the server does                                                                                                                                       |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `prompt=none`    | A `Response` from `authenticateUser` becomes a `login_required` redirect, and one from `handleConsent` becomes `consent_required`. No page reaches the browser. |
| `prompt=login`   | Issues a code only when `authenticateUser` returns `reauthenticated: true`, and otherwise redirects with `login_required`.                                 |
| `max_age`        | Requires `authenticationContext.auth_time`, no more than a minute in the future. Issues a code only when it is at most `max_age` seconds old, even after a re-authentication. |
| `max_age=0`      | Treated as `prompt=login`, as OIDC Core specifies.                                                                                                         |
| `prompt=consent` | Calls `handleConsent` even for an authorized scope. With no handler, it answers `consent_required`.                                                        |
| `acr_values`     | Passes the preferences through. The ID token's `acr` is the one `authenticationContext` reports.                                                           |

The server cannot show a login page itself, so `authenticateUser` does the
re-authentication. Check the session against the request with
`satisfiesAuthenticationRequest`, the same check the server applies, and send
the user to sign in when it fails. Report `reauthenticated: true` only when the
user signed in again for this authorization request. A session that merely
exists, or one that signed in for a different request, does not count. One way
to know is to have your login route record, on the session it creates, the
authorize URL it returns to, and compare it on the way back. Bound the match in
time as well: the recorded URL stays on the session, so a client that sends the
same authorize URL again would otherwise count as re-authenticated for as long
as the session lives. The `app-with-own-auth` example and the `react-router`
template both work this way.

```ts
import type { Context } from "hono";
import type { HonoAuthenticateUserFn } from "@udibo/oauth2/hono/authorization-server";
import { satisfiesAuthenticationRequest } from "@udibo/oauth2/server";

interface AppUser {
  id: string;
}

interface AppSession {
  user: AppUser;
  authTime: number;
  acr?: string;
  signedInFor?: string;
}

declare function readSession(c: Context): Promise<AppSession | undefined>;

const authenticateUser: HonoAuthenticateUserFn<AppUser> = async (
  c,
  authentication,
) => {
  const { pathname, search } = new URL(c.req.url);
  const returnTo = `${pathname}${search}`;
  const login = c.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`);
  const session = await readSession(c);
  if (!session) return login;
  const result = {
    user: session.user,
    authenticationContext: { auth_time: session.authTime, acr: session.acr },
    reauthenticated:
      session.signedInFor === returnTo &&
      Math.floor(Date.now() / 1000) - session.authTime <= 600,
  };
  if (
    authentication &&
    !satisfiesAuthenticationRequest(authentication, result)
  ) {
    return login;
  }
  return result;
};
```

Under `prompt=none` the same code needs no special case: the server turns the
login redirect into `login_required`. Throw `InteractionRequiredError` or
`AccountSelectionRequiredError` from either callback when some other screen
would be needed, and the server redirects with that code.

Use `acrValues` to choose how to sign the user in, for example offering a
second factor when one is requested. `acr_values` is a preference, so the server
never refuses a sign-in for missing it. Report the `acr` the sign-in achieved,
never the requested one. Set `acrValuesSupported` to advertise the values you
can achieve.

The server enforces `none`, `login` and `consent`. To accept `select_account`,
`create` or another value, list it in `promptValuesSupported` along with the
enforced values you keep. The server passes it through to `authenticateUser`
but cannot check that you honored it. Any value not listed is refused with
`invalid_request`.

## Where to go next

- [Protect an API](./protect-an-api.md) — the consumer side of the tokens you
  now issue. The same `HonoAuthorizationServer` instance also exposes
  `protect()` / `requireScope()`, so one process can issue tokens and guard its
  own API routes.
- [Deploy your application](production-deployment.md) — configuration inventory,
  the stores you provision and their retention, TLS and proxy assumptions,
  security headers, and the [hardening checklist](hardening-checklist.md).
- [Known Limitations](../known-limitations.md) — ES256-only signing, the
  introspection field subset, no dynamic client registration, no provider-side
  logout-token emission, and the other honest walls.
- [Protect an API](./protect-an-api.md#what-failures-look-like-on-the-wire)
  covers the error format of protected-resource refusals
  (`errorFormat: "problem-details"`), and
  [testing](testing.md) covers `createMemoryAuthorizationServer`.
