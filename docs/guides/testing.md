# Test your authentication integration

Test application decisions, persistent adapters, and browser flows separately.
The package's protocol tests do not prove your registered callbacks, database
transactions, reverse proxy, or app authorization rules are configured
correctly.

## Application routes

For an app that exports its token reader or client instance, stub the relevant
method with `vi.spyOn` from [Vitest](https://vitest.dev/) to exercise accepted tokens, rejected tokens,
and issuer failures. Avoid a global fetch stub that also intercepts unrelated
application traffic. For a protocol integration test, inject fetch through the
client/reader constructor or run the
[local identity provider](run-a-local-identity-provider.md).

| Helper                                                            | Purpose                                                               |
| ----------------------------------------------------------------- | --------------------------------------------------------------------- |
| `createMemoryAuthorizationServer` from `/testing`                 | Run the real protocol implementation with isolated in-memory services |
| `createFakeTenant` from `/testing`                                | Stand in for a Udibo Identity tenant, served on a real socket         |
| `createAuthenticatedTestSession` from `/hono/bff/testing`         | Register an access token and create a corresponding BFF session       |
| `createTestSession` from `/hono/bff/testing`                      | Seed a session for BFF session-endpoint tests                         |
| `createMockBffClient`, `MockOAuth2Provider` from `/react/testing` | Render React behavior with controlled auth state                      |

A protected BFF request needs both a session and an access token accepted by the
resource server. The following test assumes you have constructed an isolated app
and its token service:

```ts
import { expect, test } from "vitest";
import { BasicScope } from "@udibo/oauth2/server";
import { createAuthenticatedTestSession } from "@udibo/oauth2/hono/bff/testing";
import type { HonoBff } from "@udibo/oauth2/hono/bff";
import type { TokenServiceInterface } from "@udibo/oauth2/server/authorization";
import type { Hono } from "hono";

declare const app: Hono;
declare const bff: HonoBff;
declare const tokenService: TokenServiceInterface<
  { id: string },
  { id: string }
>;

test("an authenticated user can read the protected route", async () => {
  const cookie = await createAuthenticatedTestSession(bff, {
    tokenService,
    client: { id: "app" },
    user: { id: "user-1" },
    scope: new BasicScope("read"),
    claims: { sub: "user-1" },
  });
  const response = await app.request("/api/me", {
    headers: { cookie, [bff.csrfHeaderName!]: "1" },
  });
  expect(response.status).toBe(200);
  await response.body?.cancel();
});
```

Use the same token service that the app's resource server validates against. For
a custom persistent session store, seed through that store's test setup. Also
cover no session, insufficient scope, and a user trying to access another user's
record. Keep the CSRF guard enabled in tests that claim to exercise browser
credential handling.

## An app built on a Udibo Identity tenant

An app that signs in against a Udibo Identity tenant reads more than a token:
the `permissions` claim, the organization the person picked at sign-in, the
caller's `GET /api/memberships`, and the tenant's answers to `POST /api/check`.
`createFakeTenant` answers all of them with the shapes a tenant uses, so the
app's own routes can be tested without the identity service. Serve it on a
loopback port, point the app's issuer at that origin, and decide who signs in:

```ts
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { serve } from "@hono/node-server";
import { createFakeTenant } from "@udibo/oauth2/testing";

const server = serve({
  fetch: (request) => tenant.fetch(request),
  hostname: "127.0.0.1",
  port: 0,
});
if (!server.listening) await once(server, "listening");
const { port } = server.address() as AddressInfo;
const tenant = await createFakeTenant({ issuer: `http://127.0.0.1:${port}` });

await tenant.addClient({
  id: "my-app",
  secret: "test-secret",
  redirectUris: ["http://localhost:8000/auth/callback"],
});
await tenant.addUser({ id: "ada", username: "ada" });
tenant.addOrganization({ id: "org-acme", slug: "acme" });
tenant.addMember("org-acme", "ada", { permissions: ["projects:archive"] });
tenant.signInAs("ada", { organizationId: "org-acme" });

server.close();
```

The next authorization request authenticates as whoever `signInAs` named, with
no hosted page and no consent step; a credential keeps the organization it was
issued in across refreshes, and stops answering for it once `removeMember` ends
the membership. Register a resource type and add grants to exercise
resource-level answers, or register the client with `accessTokenFormat: "jwt"`
and an `audience` to test a resource server that validates locally against the
tenant's JWKS. `issueAccessToken` mints a token directly, for an API test that
does not need the browser flow. Introspection answers a confidential client, one
registered with a `secret`, only about the tokens issued to it; any other caller
gets `active: false`, as from a tenant.

The fake also answers the two APIs an app calls with the signed-in person's own
token:

- **The organization API** under `/api/organizations`. It creates an
  organization owned by its creator, lists the caller's organizations and
  members, and handles renames, deletes, invitations, offers and accepting them,
  and revoking a tier. Any member can read the organization and its members. An
  `owner` or `admin` manages it, and anyone below that gets the same `404` on
  those actions, whatever the reason. An `admin` asking to delete the
  organization, or to offer or revoke the `owner` tier, gets `403`. An
  invitation to the address of someone already in the tenant becomes a pending
  membership. Any other address gets an invitation, which only the verified
  holder of that address can accept. `defineOrganizationRole` adds a tenant-wide
  role beside the built-in tiers and returns its id. Invitations may offer it by
  slug, `member-roles` lists it with that id, and a manager grants it to an
  accepted member through `POST …/members/:userId/roles`, lists what a member
  holds with `GET …/members/:userId/roles`, and takes it away with
  `DELETE …/members/:userId/roles/:roleId`. The role's `permissions` then answer
  inside that organization only. When a manager revokes someone's last accepted
  role in an organization, the membership ends with everything it carried there:
  the application roles, the permissions `addMember` seeded, and the offers
  still open to them, pending memberships and invitations to their address
  alike. Rejoining grants only what the new offer names.
- **The account API** under `/api/account`: the person's own metadata bucket,
  their login sessions, and their linked accounts. Every authorization request
  is a sign-in that starts a new login session and sets a cookie on the tenant's
  origin naming it. A request that sends the cookie back, as the same browser
  does, continues that session while it is live and belongs to the person
  `signInAs` chose, so a person has as many devices as browsers. Name a new
  session's device with `signInAs(id, { userAgent, ipAddress })`, seed metadata
  with `userMetadata`, add linked accounts with `linkAccount`, and set
  `hasPassword: false` to test the refusal to disconnect someone's last way in.

It also answers the app's own machine credential, the way a tenant answers a bot
the app runs. Register a client with `grants: ["client_credentials"]`, a
`secret`, and a `scopes` allowlist. A tenant requires the allowlist of such an
application, and `addClient` refuses to go without it. Only a confidential
client may use that grant (RFC 6749 §4.4), so one registered without a secret is
refused `401 invalid_client`. The token endpoint issues a confidential one a
token that names no person, with no refresh token; its scope vocabulary is
`identity:organizations:read` and `identity:organizations:write`, narrowed by
that allowlist, and any other scope, an OIDC scope included, is refused
`invalid_scope`. An `organization_id` is accepted on the `refresh_token` grant
alone. That token is refused `403` wherever the tenant answers for a person, and
`401` at UserInfo. Register the client with
`machinePermissions: ["resource_grants.read"]`, as a tenant administrator would
assign it, and `GET /api/resource-grants?type=…&id=…` under its token lists who
holds a grant on that one resource, each row naming its holder and its role. A
grant's `role` is the slug it is listed under, with the name
`defineOrganizationRole` gave it; it defaults to a slug built from the grant's
permissions, and a built-in tier is listed as `builtInRole` with no `roleId`. A
person's token is refused `403` there, and a machine token without the
permission or the `identity:organizations:read` scope gets `404`.

A login session and the credentials issued from it are tied together only for a
first-party application, which is what `addClient` registers unless you pass
`type: "third-party"`. For a first-party application:

- Signing in again in the same browser revokes the credentials that session
  issued before.
- Revoking one of its tokens at the revocation endpoint, as a sign-out does,
  ends the session.
- Ending the session revokes its credentials.

A third-party application's credentials only name the session they came from as
the caller's current one. Revoking them leaves the session alone, and they
outlive it.

The same contract suite runs these answers against the fake and against the real
identity service, so both give the same shapes and refusals. The fake still does
not do everything a tenant does. It has no hosted pages and no management API.
Its organization API grants members only tenant-wide roles, and nobody in it
holds a built-in role as an application role, so revoking one is refused `403`.
It does not let an organization define its own roles. It lists resource grants
but does not place or revoke them over HTTP. It has no policy: no MFA, no
lockout, no rate limits and no session limits. Test those against a real tenant.

## Persistent storage contracts

Use the exported suites against an isolated database or equivalent real store.
They register `describe` and `it` blocks through [Vitest](https://vitest.dev/),
an optional peer dependency of the package, so call them from a Vitest test
file:

```ts
import { runOtpStoreContractTests } from "@udibo/oauth2/testing/contract";
import type { OtpStore } from "@udibo/oauth2/identity";

declare function freshOtpStore(): Promise<OtpStore>;

runOtpStoreContractTests({
  describeName: "Application OTP store",
  makeStore: freshOtpStore,
});
```

Each `makeStore` must provide fresh state. Follow the suite's options for the
other interfaces: tokens, authorization codes, device codes, MFA, rate limits,
lockout, token flows, token readers, and pending login requests
(`AuthRequestStorage`, whose optional `take` is raced by eight concurrent
callers). Register an `AuthRequestStorage` shared between users with
`clear: "scoped"` when its `clear()` removes only expired records: the suite
then requires `clear()` to leave every in-progress sign-in intact and to remove
an expired record, instead of removing everything. The BFF session suite lives
in `@udibo/oauth2/hono/bff/testing`.

The identity user suite covers `IdentityUserStore`, separately from the OAuth2
`UserServiceInterface`. Its fixture supplies your application's valid sign-up
profiles and deterministic lookup keys. Explicitly enable the optional
capabilities you use; a disabled capability is not checked:

```ts
import {
  type IdentityUserStoreContractFixture,
  type ListableSessionServiceContractFixture,
  runIdentityUserStoreContractTests,
  runListableSessionServiceContractTests,
  runRevocableSessionServiceContractTests,
} from "@udibo/oauth2/testing/contract";

interface AppUser {
  id: string;
}
declare function freshUsers(): Promise<
  IdentityUserStoreContractFixture<AppUser>
>;
declare function freshSessions(): Promise<
  ListableSessionServiceContractFixture
>;

runIdentityUserStoreContractTests({
  makeFixture: freshUsers,
  replaceCredential: true,
  emailVerification: true,
  legacyCredentials: true,
});
runRevocableSessionServiceContractTests({ makeFixture: freshSessions });
runListableSessionServiceContractTests({ makeFixture: freshSessions });
```

Supply `unknownUserId` as a valid absent id for your user store. Session
fixtures supply two distinct existing owners (`userId` and `otherUserId`) and
deterministic, valid non-secret ids through `sessionId(sequence)`. This lets
UUID-backed implementations use their real foreign-key owners and id format.
Each fixture is fresh for each test and may provide `dispose()` to close its
connections and delete its records. For credential replacement, supply
`removeCredential` to seed a user without a native credential. For email
verification, supply `setEmail` and `isEmailVerified`; for imported credentials,
supply `setLegacyCredential`. These setup helpers manipulate your own store, not
an in-memory substitute for the implementation being verified. The suite checks
all stored credential fields, a read after a lost compare-and-set, and
concurrent replacement winners. Email verification must not mark the current
address verified using a token issued for an earlier address.

The identity session suites exercise `RevocableSessionService` and the optional
`ListableSessionService`; they are separate from the BFF's `SessionStore` suite.
Translate `addSession`'s live, revoked, expired, and idle-timed-out states into
your application's storage and clock policy. `isLive` must observe whether your
application still accepts that session after revocation returns. Listing must
exclude ended and foreign sessions, sort by latest activity, and expose only the
documented display fields. Run both suites for a store with both capabilities.
These tests cover observed concurrency scenarios; they do not prove every
possible database interleaving or validate your application's normalization and
sign-up policy.

In addition to the shared contracts, test your adapter's transaction boundaries:

- Two consumers of one OTP/code/refresh token cannot both succeed.
- A refresh completing after logout cannot recreate a revoked session.
- A password upgrade cannot replace a credential changed by a reset.
- A competing token save cannot restore a revoked refresh-token family.
- Records from another application or user cannot satisfy an app-specific
  lookup.

A contract suite checks its scenarios, not every isolation failure your database
can exhibit. Close connections and dispose request bodies so test resource
sanitizers remain enabled.

## Browser verification

Use a real browser for callback cookies, CSRF, and redirect behavior. Start
login and finish it in the same browser; attempt a mismatched callback as a
refusal case. Test production cookie/proxy settings on HTTPS and repeat with
requests reaching different app instances. The
[external-auth example](../../examples/hono/app-with-external-auth/README.md)
and [local provider](run-a-local-identity-provider.md) support this without a
hosted account.

## Package contributor checks

To change this package itself, follow [CONTRIBUTING.md](../../CONTRIBUTING.md)
for its checks and test suites.
