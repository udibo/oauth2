/**
 * Hermetic tests for the Juniper app-with-external-auth example.
 *
 * Everything runs in-process via `server.request(...)` — no sockets, no
 * live identity provider. Because this app validates tokens by
 * introspecting the external IDP, the tests stub `tokenReader.getToken`
 * (the scoped-override pattern the package recommends) and inject a BFF
 * session with {@link createTestSession}.
 *
 * @module
 */

import { assertEquals, assertStringIncludes } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { stub } from "@std/testing/mock";
import type { Token } from "@udibo/oauth2/server";
import { BasicScope } from "@udibo/oauth2/server";
import { createTestSession } from "@udibo/oauth2/hono/bff/testing";

import {
  bff,
  type ExternalClient,
  type ExternalUser,
  tokenReader,
} from "@/oauth2/server.ts";
import { server } from "./main.ts";

/** Tokens the stubbed introspection endpoint "recognizes". */
const TOKENS: Record<string, { user: ExternalUser; scope: string }> = {
  "admin-token": {
    user: { id: "user-admin", username: "admin" },
    scope: "read write admin",
  },
  "user-token": {
    user: { id: "user-1", username: "user" },
    scope: "read write",
  },
};

/** Stubs introspection to resolve the tokens above (and nothing else). */
function stubIntrospection(): Disposable {
  return stub(
    tokenReader,
    "getToken",
    (accessToken: string): Promise<Token<ExternalClient, ExternalUser>> => {
      const t = TOKENS[accessToken];
      if (!t) return Promise.resolve(undefined as never);
      return Promise.resolve({
        accessToken,
        accessTokenExpiresAt: new Date(Date.now() + 60 * 60 * 1000),
        client: { id: "spa" },
        user: t.user,
        scope: new BasicScope(t.scope),
      });
    },
  );
}

/** A BFF session header carrying the given (stub-recognized) access token. */
function sessionFor(accessToken: string): Promise<string> {
  return createTestSession(bff, {
    tokens: { accessToken, accessTokenExpiresAt: Date.now() + 60 * 60 * 1000 },
    user: { sub: TOKENS[accessToken].user.id },
  });
}

describe("app-with-external-auth (juniper)", () => {
  it("renders the React SPA shell at /", async () => {
    const res = await server.request("http://localhost/");
    assertEquals(res.status, 200);
    assertStringIncludes(res.headers.get("content-type") ?? "", "text/html");
    assertStringIncludes(await res.text(), "OAuth2 + Juniper");
  });

  it("reports an unauthenticated BFF session at /auth/session", async () => {
    const res = await server.request("http://localhost/auth/session");
    assertEquals(res.status, 200);
    assertEquals(await res.json(), { isAuthenticated: false, user: null });
  });

  it("rejects a protected API call without a session", async () => {
    const res = await server.request("http://localhost/api/me");
    assertEquals(res.status, 401);
    await res.body?.cancel();
  });

  it("an admin token (via introspection) can call every endpoint", async () => {
    using _ = stubIntrospection();
    const cookie = await sessionFor("admin-token");
    for (const path of ["/api/me", "/api/write", "/api/admin"]) {
      const res = await server.request(`http://localhost${path}`, {
        headers: { cookie, "x-csrf": "1" },
      });
      assertEquals(res.status, 200, `${path} should be 200 for admin`);
      await res.text();
    }
  });

  it("a user token is forbidden from the admin endpoint (403)", async () => {
    using _ = stubIntrospection();
    const cookie = await sessionFor("user-token");

    const write = await server.request("http://localhost/api/write", {
      headers: { cookie, "x-csrf": "1" },
    });
    assertEquals(write.status, 200);
    await write.text();

    const admin = await server.request("http://localhost/api/admin", {
      headers: { cookie, "x-csrf": "1" },
    });
    assertEquals(admin.status, 403);
    await admin.text();
  });

  it("clears the session on GET /auth/logout (the SPA navigates here)", async () => {
    const cookie = await sessionFor("admin-token");
    const res = await server.request("http://localhost/auth/logout", {
      headers: { cookie, "sec-fetch-site": "same-origin" },
    });
    assertEquals(res.status, 302);
    await res.body?.cancel();

    const probe = await server.request("http://localhost/auth/session", {
      headers: { cookie, "x-csrf": "1" },
    });
    assertEquals(await probe.json(), { isAuthenticated: false, user: null });
  });
});
