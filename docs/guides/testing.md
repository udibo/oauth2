# Test your authentication integration

Test application decisions, persistent adapters, and browser flows separately.
The package's protocol tests do not prove your registered callbacks, database
transactions, reverse proxy, or app authorization rules are configured
correctly.

## Application routes

For an app that exports its token reader or client instance, stub the relevant
method with `@std/testing/mock` to exercise accepted tokens, rejected tokens,
and issuer failures. Avoid a global fetch stub that also intercepts unrelated
application traffic. For a protocol integration test, inject fetch through the
client/reader constructor or run the
[local identity provider](run-a-local-identity-provider.md).

| Helper                                                            | Purpose                                                               |
| ----------------------------------------------------------------- | --------------------------------------------------------------------- |
| `createMemoryAuthorizationServer` from `/testing`                 | Run the real protocol implementation with isolated in-memory services |
| `createAuthenticatedTestSession` from `/hono/bff/testing`         | Register an access token and create a corresponding BFF session       |
| `createTestSession` from `/hono/bff/testing`                      | Seed a session for BFF session-endpoint tests                         |
| `createMockBffClient`, `MockOAuth2Provider` from `/react/testing` | Render React behavior with controlled auth state                      |

A protected BFF request needs both a session and an access token accepted by the
resource server. The following test assumes you have constructed an isolated app
and its token service:

```ts
import { assertEquals } from "@std/assert";
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

Deno.test("an authenticated user can read the protected route", async () => {
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
  assertEquals(response.status, 200);
  await response.body?.cancel();
});
```

Use the same token service that the app's resource server validates against. For
a custom persistent session store, seed through that store's test setup. Also
cover no session, insufficient scope, and a user trying to access another user's
record. Keep the CSRF guard enabled in tests that claim to exercise browser
credential handling.

## Persistent storage contracts

Use the exported suites against an isolated database or equivalent real store:

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
lockout, token flows, and token readers. The BFF session suite lives in
`@udibo/oauth2/hono/bff/testing`.

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

From the repository root:

```sh
deno task check
deno task test:all
```

`check` validates types, lint, formatting, API docs, snippets, links, generated
agent docs, the JSR payload, and an external consumer. `test:all` runs the
package, script, example, and template suites. These tasks publish nothing.
