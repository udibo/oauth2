/**
 * Hermetic tests for the Juniper app-with-own-auth example.
 *
 * Everything runs in-process via `server.request(...)` — no sockets, no
 * Docker. Protected-endpoint tests skip the browser redirect flow by
 * minting a real token into the shared token service and injecting a BFF
 * session with {@link createTestSession}.
 *
 * @module
 */

import { assertEquals, assertStringIncludes } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { BasicScope } from "@udibo/oauth2/server";
import { createTestSession } from "@udibo/oauth2/hono/bff/testing";

import {
  ADMIN_USER,
  bff,
  DEMO_CLIENT,
  type DemoUser,
  STANDARD_USER,
  tokenService,
} from "@/oauth2/server.ts";
import { server } from "./main.ts";

/**
 * Mints a real access token (so the resource server can validate it),
 * then returns a `Cookie` header for a BFF session holding that token.
 */
async function sessionFor(user: DemoUser, scope: string): Promise<string> {
  const accessToken = `tok-${user.id}-${crypto.randomUUID()}`;
  const expiresAt = Date.now() + 60 * 60 * 1000;
  await tokenService.save({
    accessToken,
    accessTokenExpiresAt: new Date(expiresAt),
    client: DEMO_CLIENT,
    user,
    scope: new BasicScope(scope),
  });
  return await createTestSession(bff, {
    tokens: { accessToken, accessTokenExpiresAt: expiresAt },
    user: { sub: user.id, username: user.username, name: user.name },
  });
}

describe("app-with-own-auth (juniper)", () => {
  it("renders the React SPA shell at /", async () => {
    const res = await server.request("http://localhost/");
    assertEquals(res.status, 200);
    assertStringIncludes(res.headers.get("content-type") ?? "", "text/html");
    assertStringIncludes(await res.text(), "OAuth2 + Juniper");
  });

  it("serves the IDP login form at /login", async () => {
    const res = await server.request("http://localhost/login");
    assertEquals(res.status, 200);
    assertStringIncludes(await res.text(), "Sign in");
  });

  it("POST /login refuses an open-redirect return_to (same-origin only)", async () => {
    const res = await server.request("http://localhost/login", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "admin",
        password: "password",
        return_to: "https://evil.example/phish",
      }),
    });
    assertEquals(res.status, 302);
    assertEquals(res.headers.get("location"), "/");
    await res.body?.cancel();
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

  it("an admin session can call every scope-gated endpoint", async () => {
    const cookie = await sessionFor(ADMIN_USER, "read write admin");
    for (const path of ["/api/me", "/api/write", "/api/admin"]) {
      const res = await server.request(`http://localhost${path}`, {
        headers: { cookie, "x-csrf": "1" },
      });
      assertEquals(res.status, 200, `${path} should be 200 for admin`);
      await res.text();
    }
  });

  it("a user session is forbidden from the admin endpoint (403)", async () => {
    const cookie = await sessionFor(STANDARD_USER, "read write");

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
    const cookie = await sessionFor(ADMIN_USER, "read write admin");
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
