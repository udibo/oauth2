# Protect an API with Bearer Tokens

This guide takes you from an unprotected Hono app to an API that validates
OAuth2 bearer tokens (RFC 6750), gates routes by scope, and answers failures
with spec-correct `WWW-Authenticate` challenges. You will set up a resource
server with the Hono adapter, pick between the two token-validation strategies
the package supports, and call the protected API from a client that holds a
token.

The runnable version of everything here is
[`examples/hono/api-service/`](https://github.com/udibo/oauth2/tree/main/examples/hono/api-service)
— a backend service that validates tokens against an external identity provider.

## The pieces

`ResourceServer` (from `@udibo/oauth2/server/resource`) is framework-agnostic:
it validates bearer tokens on web `Request` objects and knows nothing about
routing. For a Hono app you use its subclass `HonoResourceServer` (from
`@udibo/oauth2/hono/resource-server`), which adds the `protect()` and
`requireScope()` middleware and the `getContext()` accessor.

The resource server itself never talks to a database or an identity provider. It
delegates token lookup to a `tokenService` — any object implementing
`TokenReaderInterface` from `@udibo/oauth2/server`:

```ts
import type {
  AbstractScope,
  BasicScope,
  ClientInterface,
  Token,
} from "@udibo/oauth2/server";

interface TokenReaderInterface<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> {
  getToken(
    accessToken: string,
  ): Promise<Token<Client, User, Scope> | undefined>;
}
```

Return the token record (with its `client`, optional `user`, `scope`, and
`accessTokenExpiresAt`) for a live token, or `undefined` for an unknown one.
Choosing how `getToken` answers is choosing your validation strategy.

## Strategy 1: Introspection against the authorization server

The built-in `IntrospectionTokenReader` validates tokens by calling the
authorization server's RFC 7662 introspection endpoint. This is the standard
choice when your API is a separate service from the identity provider: every
request costs one HTTP call to the introspection endpoint, and revocation takes
effect immediately because the authorization server is the source of truth.

RFC 7662 only fixes a minimal response shape, so the reader takes two mappers —
`getClient` and `getUser` — that project the introspection response into your
app's own `Client` / `User` types. Both may be async if you want to enrich from
your database.

```ts
import { IntrospectionTokenReader } from "@udibo/oauth2/server/resource";

interface Client {
  id: string;
}

interface User {
  id: string;
  username?: string;
}

const tokenReader = new IntrospectionTokenReader<Client, User>({
  introspectionEndpoint: "https://auth.example.com/oauth2/introspect",
  clientId: "my-api",
  clientSecret: Deno.env.get("INTROSPECTION_CLIENT_SECRET")!,
  getClient: (data) => ({ id: data.client_id ?? "" }),
  getUser: (data) =>
    data.sub ? { id: data.sub, username: data.username } : undefined,
});
```

A machine token — one issued by the client-credentials grant, which has no
resource owner — carries no `sub`; its `client_id` identifies the caller. So
`data.sub` is present only when a person is behind the token, and a machine
caller resolves to no user (RFC 9700 §4.15.1).

The reader distinguishes failure modes so your API doesn't misreport them: an
inactive token resolves to `undefined` (the caller gets `invalid_token`), an
unreachable or 5xx introspection endpoint throws `TemporarilyUnavailableError`
(503 — the identity provider is down, the caller's token isn't necessarily bad),
and a 4xx throws `ServerError` (your introspection credentials are
misconfigured).

**Audience caveat:** the introspection response this package's authorization
server emits omits `aud`, `iat`, `nbf`, and `jti`, so a resource server cannot
enforce audience restriction through introspection. If you need in-token
audience claims, use JWT access tokens (strategy 2). See
[Known Limitations](../known-limitations.md).

**The call is bounded; it is not cached.** This reader takes `fetchTimeoutMs`
(default 5000), the same option, default, and semantics as `JwksTokenReader`, so
an issuer that accepts connections and then stops answering fails at the
deadline instead of stalling. It still caches nothing — it calls the
authorization server on every authenticated request. The `fetch` option remains
the seam for mTLS, retries, or a different bound; note that an injected `fetch`
which ignores `AbortSignal` also ignores `fetchTimeoutMs`:

```ts ignore
const tokenReader = new IntrospectionTokenReader<Client, User>({
  // …
  fetch: (input, init) =>
    fetch(input, { ...init, signal: AbortSignal.timeout(2_000) }),
});
```

An aborted call surfaces as `TemporarilyUnavailableError` (503), which is the
honest answer — the issuer is down, the caller's token is not necessarily bad.

**This package's introspection endpoint answers for refresh tokens too**, with
`active: true` and no `token_type` (an access token carries
`token_type: "Bearer"`). The shipped reader does not currently check
`token_type`, so if your resource server introspects against an issuer that
reports refresh tokens as active, a refresh token presented as
`Authorization: Bearer …` validates. That widens what a leaked refresh token is
good for and bypasses rotation and reuse detection; verify `token_type` in your
`getClient` mapper (throw or return a client your authorization checks reject)
if refresh tokens circulate anywhere near your API surface.

## Strategy 2: Local JWT validation against the JWKS endpoint

When the authorization server issues **signed JWT access tokens** (RFC 9068
`at+jwt`, enabled server-side via `createJwtAccessTokenGenerator` — see
[Become an OAuth Provider](./become-an-oauth-provider.md)), your API can
validate tokens offline: fetch the public keys from the server's JWKS endpoint
once, then verify signatures locally with no per-request network call.

`JwksTokenReader` is the shipped implementation. It takes the same `getClient` /
`getUser` mappers as the introspection reader — the claims replace the
introspection response — so swapping strategies is a constructor change and
nothing else:

```ts
import { JwksTokenReader } from "@udibo/oauth2/server/resource";

interface Client {
  id: string;
}

interface User {
  id: string;
  username?: string;
}

const tokenReader = new JwksTokenReader<Client, User>({
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  getClient: (claims) => ({ id: String(claims.client_id) }),
  getUser: (claims) => (claims.sub ? { id: claims.sub } : undefined),
});
```

`issuer` and `audience` are required: RFC 9068 §4 obliges a resource server to
reject tokens minted for another issuer or another audience, and with local
validation there is no authorization server in the request path to do it for
you. `audience` is your API's identifier — pass an array to accept several.
Prefer an identifier that names the API (`https://api.example.com`) over a
client id: `createJwtAccessTokenGenerator` defaults `aud` to the client id when
you leave its `audience` unset, and while listing client ids works, it is the
same value an `id_token` carries in `aud` — see the `id_token` warning below
before combining that with a relaxed `types`.

`jwksUri` is optional: omit it and the reader discovers the key set from
`issuer`, trying `/.well-known/oauth-authorization-server` and then
`/.well-known/openid-configuration` inserted ahead of the issuer's path
component (RFC 8414 §3.1), then the OIDC Core form with
`/.well-known/openid-configuration` appended. Issuers without a path component —
the common case — only cost one extra request. Pass `jwksUri` explicitly to skip
discovery.

A token is accepted only when all of these hold:

- its `typ` header is `at+jwt`,
- it carries a client-id claim — `client_id`, which RFC 9068 §2.2 makes
  REQUIRED. Point `clientIdClaim` at the vendor claim for issuers that deviate
  (Okta's `cid`, Azure AD v1's `appid`); there is no way to drop the
  requirement,
- it carries no `id_token`-only claim (`nonce`, `at_hash`, `c_hash`, `s_hash`)
  and no `crit` header (RFC 7515 §4.1.11 — this reader implements no JWS
  extensions, so it must reject any token that requires one). `auth_time`, `acr`
  and `amr` are fine: RFC 9068 §2.2.1 permits them on an access token,
- its `alg` is an asymmetric algorithm you accept **and** the one the matched
  key publishes. Defaults to every algorithm Web Crypto covers (`ES256`/`384`/
  `512`, `RS256`/`384`/`512`, `PS256`/`384`/`512`); pin it with `algorithms`
  when you know what your issuer signs with. `none` and `HS*` are never
  accepted, and symmetric keys in a JWKS are ignored, so an algorithm-confusion
  token cannot verify,
- its signature verifies against a published key,
- `iss` and `aud` match the configuration, `exp` is in the future and `nbf` (if
  present) is in the past, both within the reader's `clockSkewSeconds` (default
  30).

`ResourceServer` then re-checks `exp` itself, with its **own**
`ResourceServerOptions.clockSkewSeconds` — which defaults to `0`. Set both to
tolerate drift end to end; the resource-server option is also the only one that
reaches an `IntrospectionTokenReader`, which has no notion of skew.

Anything else resolves to `undefined` — the same `invalid_token` response as an
unknown opaque token, with no detail leaked about which check failed.

**Don't let an `id_token` in.** The three checks above — `typ`, the required
client-id claim, and the `id_token`-claim rejection — exist because an
`id_token` is signed by the same issuer with the same keys, and accepting one as
an access token hands your API a token the browser was allowed to see. `typ` is
the strongest of the three, so prefer configuring your issuer to stamp `at+jwt`
over relaxing `types`. If your issuer only stamps a plain `JWT` and you must set
`types: ["at+jwt", "jwt"]`, then also give this API an `audience` that is
**not** one of your client ids — an `id_token`'s `aud` _is_ a client id, so an
audience of `"my-client"` plus a relaxed `types` would leave the client-id claim
as the only thing standing between the two token kinds. Most IdPs let you
register a distinct API identifier for exactly this reason.

**Key rotation.** Keys are cached on the reader instance for `cacheMaxAgeMs`
(default 10 minutes). A token that no cached key verifies triggers one refetch,
and concurrent requests share it — including tokens with no `kid`, so a
single-key issuer that publishes its JWK without one still rotates promptly. The
exception is a token whose `kid` matched a cached key and still failed to
verify: that's a forgery, not a rotation, and it provokes no fetch at all.
Refetches are throttled to one per `minFetchIntervalMs` (default 30 seconds) so
a flood of junk tokens can't turn your API into a DoS amplifier against the JWKS
endpoint; the cost is that a rotation is picked up at most one interval late.

A refresh that fails is absorbed — the cached keys keep serving — and once keys
are cached the refresh happens **in the background**: requests are answered from
the cache rather than blocked behind the issuer. Requests are bounded by
`fetchTimeoutMs` (default 5 seconds), so a blackholed JWKS host fails fast
instead of hanging every request that joins the shared fetch.

**Errors.** An unreachable or 5xx JWKS endpoint throws
`TemporarilyUnavailableError` when nothing is cached (a down issuer must not
read as a bad token); a 4xx, a non-JWKS body, or metadata without a `jwks_uri`
throws `ServerError`, because those are your misconfiguration rather than a
verdict on the caller's token.

**The trade-off versus introspection:** local validation cannot see revocation —
a revoked JWT stays valid until it expires. Keep access tokens short-lived, or
introspect on the endpoints where revocation latency matters.

A third option worth naming: if your API shares a database with the
authorization server, implement `TokenReaderInterface` directly against that
token table — no HTTP and no JWT parsing. The
[`app-with-own-auth`](https://github.com/udibo/oauth2/tree/main/examples/hono/app-with-own-auth)
example uses this in-process shape.

## A minimal protected API

With a token reader in hand, construct the Hono resource server and mount its
middleware. The `resolve` option supplies the services for each request; for a
application API it's a constant function returning the same reader every time.

```ts
import { Hono } from "hono";
import {
  HonoResourceServer,
  type HonoResourceServerVariables,
} from "@udibo/oauth2/hono/resource-server";
import type { TokenReaderInterface } from "@udibo/oauth2/server";

interface Client {
  id: string;
}

interface User {
  id: string;
  username?: string;
}

declare const tokenReader: TokenReaderInterface<Client, User>;

const resourceServer = new HonoResourceServer<Client, User>({
  resolve: () => ({ services: { tokenService: tokenReader } }),
  realm: "Example API",
});

const app = new Hono<{
  Variables: HonoResourceServerVariables<Client, User>;
}>();

app.get("/api/public", (c) => c.json({ message: "No token required." }));

app.use("/api/private", resourceServer.protect());
app.get("/api/private", (c) => {
  const { client, user, scope } = resourceServer.getContext(c);
  return c.json({
    client: client.id,
    user: user?.id,
    scope: scope?.toString(),
  });
});

app.use("/api/write", resourceServer.protect("write"));
app.get("/api/write", (c) => c.json({ message: "Token carries write scope." }));

export default app;
```

`protect()` validates the bearer token from the `Authorization` header and, on
success, stores the authenticated context on the Hono context; `getContext(c)`
reads it back, typed via `HonoResourceServerVariables`. Passing a scope to
`protect("write")` additionally requires that scope.

## Layering scopes under one authenticated mount

When routes under a single mount need different scopes, authenticate once with a
bare `protect()` and layer `requireScope(scope)` per route. `requireScope`
asserts the scope against the context `protect` already populated — no second
token lookup — and emits the identical `insufficient_scope` response:

```ts
import type { Handler, Hono } from "hono";
import type { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import type { ClientInterface } from "@udibo/oauth2/server";

declare const app: Hono;
declare const resourceServer: HonoResourceServer<ClientInterface, unknown>;
declare const listItems: Handler;
declare const createItem: Handler;

app.use("/api/items/*", resourceServer.protect());
app.get("/api/items", resourceServer.requireScope("read"), listItems);
app.post("/api/items", resourceServer.requireScope("write"), createItem);
```

This layering fails safe: every route under the mount is authenticated
regardless, and a route missing its `requireScope` is merely under-scoped, never
wide open.

For handlers that want to authenticate inline instead of via middleware,
`resourceServer.authenticate(c, scope?)` throws typed errors on failure; pair it
with `resourceServer.handleAuthError(error)` to convert them to responses.

## Checking the person, not just the client: the Authorization object

Scope answers what the **client application** was delegated. When the issuer
also stamps user-authorization claims into its tokens — `roles`, `permissions`,
and the active organization's `org_id`/`org_slug`/`org_roles` — the
authenticated context carries them as one checkable object,
`context.authorization`, built the same way from either validation strategy (the
JWT's verified payload, or the introspection response's extension fields — the
authorization server's `introspectionClaims` option is what puts them there):

```ts
import type { Handler, Hono } from "hono";
import type { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import type { ClientInterface } from "@udibo/oauth2/server";

declare const app: Hono;
declare const resourceServer: HonoResourceServer<ClientInterface, unknown>;
declare const createPost: Handler;
declare const removePost: Handler;

app.use("/api/*", resourceServer.protect());

app.post(
  "/api/posts",
  resourceServer.require({ scope: "posts:write", permission: "posts:write" }),
  createPost,
);

app.delete(
  "/api/orgs/acme/posts/:id",
  resourceServer.require({ organization: "acme", orgRole: "admin" }),
  removePost,
);
```

`require(conditions)` layers under `protect()` exactly like `requireScope`: AND
semantics across keys, arrays mean all-of. A failed `scope` condition answers
the same `insufficient_scope` challenge `requireScope` sends; a failed
permission, role, or organization condition answers a plain 403 whose body
carries `insufficient_permissions` (RFC 6750 registers no challenge code for
it). Any-of checks are deliberately not expressible in the middleware — branch
on the object in a handler, where the semantics stay visible:

```ts
import type { Context } from "hono";
import type { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import type { ClientInterface } from "@udibo/oauth2/server";

declare const c: Context;
declare const resourceServer: HonoResourceServer<ClientInterface, unknown>;

const { authorization } = resourceServer.getContext(c);
authorization.can("posts:write"); // permission — the recommended check
authorization.hasRole("editor"); // tenant-wide role
authorization.hasOrgRole("admin"); // role in the active organization
authorization.inOrganization("acme"); // active-organization match (id or slug)
authorization.hasScope("posts:read"); // client delegation
```

Predicates never throw; they return booleans. A machine token (client
credentials — no resource owner) has empty roles and permissions and no
organization, so every non-scope condition refuses it. A token whose reader
supplied no claims (a plain DB-backed token store) behaves the same: only its
scope answers.

What the credential's own claims cannot answer stays behind a network call — an
organization the credential was not issued in, and any resource-level question,
because a grant on one of your resource instances never rides a credential.
Freshness is not on that list for every reader, because it is a property of the
surface rather than of the token. Strategy 1 gets claims computed for the
request in hand, so against an issuer whose hooks answer from live state they
are not a stale answer; strategy 2 holds what was computed when the token was
signed — the same lag as
[the revocation trade-off above](#strategy-2-local-jwt-validation-against-the-jwks-endpoint).

`checkPermissions` from `@udibo/oauth2/client` wraps a bearer-authenticated
check endpoint for these. **It answers only for the scope you name**, so it
replaces a claim only when it names the claim's scope: pass
`resource: { type: "organization", id: org_id }` to ask what a claim resolved
for that organization answered. Leave `resource` off — `permissions` is always
required, so a request without it is a 400 rather than a wider answer — and you
get the endpoint's default scope, which need not be the claim's; where that
default is narrower, a permission the subject holds through an organization
comes back `false`. That applies to either strategy, because an introspected
claim carries the same organization-granted half. One cost of echoing: an
`org_id` signed into a token can name an organization deleted since, which
answers 404 and reaches you as a thrown `ServerError`.

## What failures look like on the wire

The middleware produces RFC 6750-conformant responses; you don't build these
yourself:

- **No token sent** → `401` with
  `WWW-Authenticate: Bearer realm="Example
  API"`. Per RFC 6750 §3.1, a request
  with no credentials gets a bare challenge with no error code.
- **Invalid or expired token** → `401` with
  `WWW-Authenticate: Bearer
  realm="Example API", error="invalid_token", error_description="..."`.
  The `DirectClient`'s `fetch` wrapper keys its silent-refresh retry off exactly
  this challenge.
- **Valid token, missing scope** → `403` with
  `WWW-Authenticate: Bearer
  realm="Example API", error="insufficient_scope", scope="write"`,
  naming the scope the route required.

The challenge carries an `error` code only for the three codes RFC 6750 §3.1
registers — `invalid_request`, `invalid_token`, `insufficient_scope`. Any other
code, including the `access_denied` raised when a request presents no
credentials at all, yields a bare `Bearer realm="…"`, because §3.1 says a
challenge must not carry an unregistered code and must not carry one at all when
no credentials were presented. The consequence for your own guards: throw
`InsufficientScopeError` (403) when you mean "the token is fine, the scope is
not", and `InvalidTokenError` (401) when you mean "this token is no good". Throw
anything else and the client sees a bare challenge, which it will read as
"credentials missing" and answer by starting a fresh sign-in.

Response bodies default to the RFC 6749 JSON shape (`error`,
`error_description`, `error_uri`). Pass `errorFormat: "problem-details"` to the
constructor to emit RFC 9457 Problem Details (`application/problem+json`)
instead — the same fields, with `type`/`detail` carrying the URI and message.
Errors thrown from your own services (any `OAuth2Error` subclass, which are all
`HttpError` instances) are converted through the same path, and only an error's
`exposedMessage` reaches the wire, so internal diagnostic detail stays in your
logs.

```ts
import { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import type { TokenReaderInterface } from "@udibo/oauth2/server";

interface Client {
  id: string;
}

interface User {
  id: string;
  username?: string;
}

declare const tokenReader: TokenReaderInterface<Client, User>;

const resourceServer = new HonoResourceServer<Client, User>({
  resolve: () => ({ services: { tokenService: tokenReader } }),
  realm: "Example API",
  errorFormat: "problem-details",
});
```

## Calling the API with a token

**Direct clients** (a service or SPA holding its own tokens) use `DirectClient`
from `@udibo/oauth2/client`. After completing a grant, its `fetch` wrapper
attaches `Authorization: Bearer <token>` and, on a 401 whose challenge says
`invalid_token`, silently refreshes and retries once:

```ts
import { DirectClient } from "@udibo/oauth2/client";

const client = new DirectClient({
  clientId: "my-service",
  clientSecret: Deno.env.get("CLIENT_SECRET")!,
  endpoints: {
    authorization: "https://auth.example.com/oauth2/authorize",
    token: "https://auth.example.com/oauth2/token",
    revocation: "https://auth.example.com/oauth2/revoke",
  },
});

await client.getClientCredentialsToken({ scope: "read" });
const response = await client.fetch("https://api.example.com/api/private");
```

`fetch` takes the same arguments the global one does, including a `Request`:
that request's own headers **and** its body reach the server, `init.headers` win
on a name collision, and a caller-set `Authorization` header is left alone. A
`Request`-shaped POST is cloned before the first send, so its body is replayed
on the post-refresh retry rather than arriving empty. The same rules hold for
`BffClient.fetch`, which additionally adds the `x-csrf` header only when the
request does not already carry one. A retry that fails at the transport level
now rejects; only a failed _refresh_ falls back to reporting the original `401`.

`DirectClient` also re-resolves discovery metadata as it ages. Constructed with
an `issuer` and no `discoveryCache`, it re-discovers after
`DEFAULT_DISCOVERY_TTL_MS` (1 hour); given a `discoveryCache`, `resolve` reports
`{ metadata, expiresAt }` and the client holds the document until that
`expiresAt`, so the cache is read once per entry lifetime rather than once per
endpoint lookup. A remote `DiscoveryCache` implementation therefore needs no
memo of its own — it just reports the entry's own expiry, never later.

**Browser frontends** should not hold tokens at all — put a `HonoBff` (from
`@udibo/oauth2/hono/bff`) in front. The BFF keeps tokens server-side against a
session cookie, and `bff.protect(scope?)` guards an API route by accepting
**either** the session cookie (resolved to the stored access token, refreshed
near expiry, then validated against your resource server) **or** an inbound
bearer token, so browsers and machine-to-machine clients share one guard:

```ts
import type { Handler, Hono } from "hono";
import type { HonoBff } from "@udibo/oauth2/hono/bff";

declare const app: Hono;
declare const bff: HonoBff;
declare const listItems: Handler;
declare const createItem: Handler;

app.use("/api/*", bff.protect());
app.get("/api/items", bff.requireScope("read"), listItems);
app.post("/api/items", bff.requireScope("write"), createItem);
```

When you'd rather compose the chain yourself — for example, a downstream
middleware expects the bearer token in the `Authorization` header —
`bff.attachToken()` resolves the session and sets the header on the inbound
request, then your `resourceServer.protect()` validates it as usual:

```ts
import type { Hono } from "hono";
import type { HonoBff } from "@udibo/oauth2/hono/bff";
import type { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import type { ClientInterface } from "@udibo/oauth2/server";

declare const app: Hono;
declare const bff: HonoBff;
declare const resourceServer: HonoResourceServer<ClientInterface, unknown>;

app.use("/api/*", bff.attachToken(), resourceServer.protect());
```

Prefer `bff.protect()` unless you need the header: it doesn't mutate the
request, so middleware ordering doesn't matter.

**They differ on an inbound bearer, and the difference is deliberate.**
`protect()` checks for `Authorization: Bearer …` on the incoming request first
and validates _that_ token, so one guard serves both the BFF's own frontend
(session cookie, no header) and machine-to-machine callers. `attachToken()`
overwrites the header with the session's token whenever a session resolves, so a
mount behind it can only ever act as the signed-in browser user. Pick on that:
`protect()` for a mount that must accept `client_credentials` callers,
`attachToken()` for one that must not. Neither is attacker-forceable from a
browser — the package writes no `Access-Control-*` header anywhere, so a
cross-origin page cannot put an `Authorization` header on a credentialed
request, and the CSRF header check runs before either path.

Both BFF examples
([`app-with-own-auth`](https://github.com/udibo/oauth2/tree/main/examples/hono/app-with-own-auth),
[`app-with-external-auth`](https://github.com/udibo/oauth2/tree/main/examples/hono/app-with-external-auth))
run this pattern end to end.

### When the API is a separate service

`protect()` and `attachToken()` both assume the resource server is
**co-located** — validation happens in this process. When the API is a different
service, `bff.proxy()` forwards the call instead: it reads the session, attaches
the access token server-side, and streams the response back. This is the full
proxying BFF the IETF "OAuth 2.0 for Browser-Based Apps" BCP §6.1.1 recommends
for sensitive apps: the token never reaches the browser, and since the browser
only talks to its own origin, there is no CORS to configure.

```ts
import type { Hono } from "hono";
import type { HonoBff } from "@udibo/oauth2/hono/bff";

declare const app: Hono;
declare const bff: HonoBff;

app.all(
  "/api/*",
  bff.proxy("https://api.example.com/v1", { stripPrefix: "/api" }),
);
```

`GET /api/things?page=2` becomes `GET https://api.example.com/v1/things?page=2`
with `Authorization: Bearer <the session's token>`. What it does, and what it
deliberately does not do:

| Concern          | Behavior                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Target           | Fixed at mount time. Only the path and query come from the request, so the proxy can't be steered at another host. A query parameter pinned on the target (`https://api.example.com/v1?tenant=acme`) is merged into every call and wins over an inbound parameter of the same name.                                                                                                                                                                                                                                                                                                                                                        |
| Auth             | Session cookie only. An inbound `Authorization` is ignored **and** never forwarded — point machine-to-machine clients at the resource server directly.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Refresh          | Proactive near expiry (as `protect()`), plus one retry after an upstream `401` carrying `error="invalid_token"`. Concurrent requests share one exchange, so a rotating refresh token is never presented twice. The session ends only when the IdP says the grant is dead — a network blip, 5xx, or 429 answers `502` and leaves the session intact.                                                                                                                                                                                                                                                                                        |
| CSRF             | The same custom-header check as the rest of the credentialed BFF surface, so mounting a proxy can't reopen it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Request headers  | An allowlist (`DEFAULT_PROXY_FORWARD_HEADERS`, extendable via `forwardHeaders`). The session cookie, `Authorization`, `Host`, and hop-by-hop never cross.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Response headers | Everything except upstream `Set-Cookie` and hop-by-hop — both the fixed set and whatever the response's `Connection` field names. Content coding and length are dropped only when a body is streamed back (`fetch` already decoded it), so a `HEAD` keeps its `Content-Length`. `Location` / `Content-Location` pointing under the target are rewritten into the mount's namespace, so a `201` is followable and the upstream's hostname stays private. The response is marked `private`, `Vary: Cookie`, and `nosniff` — it is cookie-authenticated and served from your origin. Status and problem-details bodies pass through verbatim. |
| Bodies           | Streamed both ways — nothing is buffered. Bodied requests are not retried, since the body has already been sent.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Redirects        | Returned to the browser, never followed, so the token isn't replayed to an unvetted `Location`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Paths            | An encoded separator inside a segment (`/files/a%2Fb`) is forwarded as-is, since it's a legitimate resource id. A segment that decodes to a `..` — or whose percent-escape is malformed, like the overlong `%C0%AF` — is refused, because a lenient upstream decoder could reconstruct `../` from it.                                                                                                                                                                                                                                                                                                                                      |

The BFF generates only four responses of its own: `401` `invalid_token` (no
session, or the refresh failed), `403` `csrf_validation_failed`, `400`
`invalid_request` (a rejected path segment), and `502` `temporarily_unavailable`
(upstream unreachable).

Mount it before any middleware that reads the request body — the proxy forwards
`c.req.raw.body` as a stream, and a middleware that already consumed it leaves
nothing to forward.

One thing the proxy cannot do for you: an upstream that returns `text/html`
renders on **your** origin, same-origin with your session cookie. `nosniff`
stops content-type sniffing, but a genuine `Content-Type: text/html` is still
honored. Proxy APIs that return data, not documents — or add a
`Content-Security-Policy` on the mount.
[`app-with-external-auth`](https://github.com/udibo/oauth2/tree/main/examples/hono/app-with-external-auth)
runs both topologies side by side: in-process `/api/*` and proxied
`/remote-api/*`.

## Where to go next

- [Become an OAuth Provider](./become-an-oauth-provider.md) — stand up the
  authorization server these tokens come from.
- [Known Limitations](../known-limitations.md) — the honest list, including the
  introspection field subset and ES256-only signing.
- The package [README](testing.md) covers testing protected routes without a
  live identity provider.
