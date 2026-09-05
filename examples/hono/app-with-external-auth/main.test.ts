/**
 * Tests for the app-with-external-auth example.
 *
 * Unlike `app-with-own-auth/` (which can drive a real OAuth dance
 * end-to-end because it owns the IDP in-process), this example talks
 * to an external IDP over real HTTP. The tests therefore:
 *
 *   - Verify the BFF's local behaviour: homepage renders, session
 *     probe works, protected endpoints respond appropriately.
 *   - Stub `tokenReader.getToken` to inject canned bearer tokens
 *     and seed BFF sessions directly via `createTestSession`.
 *
 * The introspection wire format itself is covered by the framework's
 * own tests in `packages/oauth2/src/server/introspection-token-reader.test.ts`,
 * so we don't reproduce that here. This file focuses on the example's
 * own wiring (routes, scope gates, error responses).
 */

import { assertEquals, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { stub } from "@std/testing/mock";

import { BasicScope } from "@udibo/oauth2/server";
import { createTestSession } from "@udibo/oauth2/hono/bff/testing";

import app from "./main.ts";
import { bff, tokenReader } from "./oauth2/server.ts";

/**
 * The BFF's CSRF defense (on by default) requires this header on any
 * request that carries the session cookie. Real SPAs get it from
 * `BffClient` / the React adapter; tests read the name off the BFF.
 */
const CSRF = { [bff.csrfHeaderName!]: "1" };

/**
 * Tokens the stubbed `tokenReader.getToken` recognises. Anything not
 * in this map resolves to `undefined`, mirroring the real
 * introspection response for an inactive token.
 */
const activeTokens: Record<string, {
  client: string;
  user: string;
  scope?: string;
}> = {
  "user-token": {
    client: "spa",
    user: "user-1",
    scope: "read write",
  },
  "admin-token": {
    client: "spa",
    user: "user-admin",
    scope: "read write admin",
  },
};

function stubTokenReader() {
  return stub(tokenReader, "getToken", (token: string) => {
    const claims = activeTokens[token];
    if (!claims) return Promise.resolve(undefined);
    return Promise.resolve({
      accessToken: token,
      client: { id: claims.client },
      user: { id: claims.user, username: claims.user },
      scope: claims.scope ? new BasicScope(claims.scope) : undefined,
    });
  });
}

describe("app-with-external-auth example", () => {
  it("GET / returns the SPA index page", async () => {
    const res = await app.request("/");
    assertStrictEquals(res.status, 200);
    const body = await res.text();
    assertEquals(body.includes("App with external auth"), true);
    assertEquals(body.includes(`action="/auth/login"`), true);
    assertEquals(body.includes(">Sign in<"), true);
  });

  it("GET / mentions the IDP-pairing dev tip", async () => {
    const res = await app.request("/");
    const body = await res.text();
    assertEquals(body.includes("app-with-own-auth"), true);
    assertEquals(body.includes("port 8001"), true);
  });

  it("GET /auth/session returns isAuthenticated=false without a cookie", async () => {
    const res = await app.request("/auth/session");
    assertStrictEquals(res.status, 200);
    assertEquals(await res.json(), { isAuthenticated: false, user: null });
  });

  it("POST /auth/login redirects to the external IDP's /oauth2/authorize", async () => {
    const res = await app.request("/auth/login?return_to=/welcome", {
      method: "POST",
    });
    assertStrictEquals(res.status, 302);
    const location = res.headers.get("Location")!;
    assertEquals(
      location.startsWith("http://localhost:8001/oauth2/authorize"),
      true,
    );
  });

  it("GET /api/me returns 401 without a session cookie", async () => {
    const res = await app.request("/api/me");
    assertStrictEquals(res.status, 401);
  });

  it("GET /api/me returns 200 with a valid session (introspection stubbed)", async () => {
    using _stub = stubTokenReader();
    const cookie = await createTestSession(bff, {
      tokens: { accessToken: "user-token" },
      user: { sub: "user-1", username: "user" },
    });
    const res = await app.request("/api/me", {
      headers: { cookie, ...CSRF },
    });
    assertStrictEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.sub, "user-1");
    assertEquals(body.client, "spa");
  });

  it("GET /api/admin returns 403 for a token without admin scope", async () => {
    using _stub = stubTokenReader();
    const cookie = await createTestSession(bff, {
      tokens: { accessToken: "user-token" },
      user: { sub: "user-1", username: "user" },
    });
    const res = await app.request("/api/admin", {
      headers: { cookie, ...CSRF },
    });
    assertStrictEquals(res.status, 403);
    assertEquals(
      res.headers.get("WWW-Authenticate")?.includes("insufficient_scope"),
      true,
    );
  });

  it("GET /api/admin returns 200 for an admin token", async () => {
    using _stub = stubTokenReader();
    const cookie = await createTestSession(bff, {
      tokens: { accessToken: "admin-token" },
      user: { sub: "user-admin", username: "admin" },
    });
    const res = await app.request("/api/admin", {
      headers: { cookie, ...CSRF },
    });
    assertStrictEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.sub, "user-admin");
    assertEquals(body.scope?.includes("admin"), true);
  });

  it("GET /api/write returns 200 for a token with write scope", async () => {
    using _stub = stubTokenReader();
    const cookie = await createTestSession(bff, {
      tokens: { accessToken: "user-token" },
      user: { sub: "user-1", username: "user" },
    });
    const res = await app.request("/api/write", {
      headers: { cookie, ...CSRF },
    });
    assertStrictEquals(res.status, 200);
  });

  it("GET /remote-api/* returns 401 without a session, never calling the API service", async () => {
    const res = await app.request("/remote-api/private");
    assertStrictEquals(res.status, 401);
    assertEquals(
      res.headers.get("WWW-Authenticate")?.includes("invalid_token"),
      true,
    );
    assertEquals((await res.json()).error, "invalid_token");
  });

  it("GET /remote-api/* rejects a credentialed request without the CSRF header", async () => {
    const cookie = await createTestSession(bff, {
      tokens: { accessToken: "user-token" },
      user: { sub: "user-1", username: "user" },
    });
    const res = await app.request("/remote-api/private", {
      headers: { cookie },
    });
    assertStrictEquals(res.status, 403);
    assertEquals((await res.json()).error, "csrf_validation_failed");
  });

  it("/api/me returns 401 when the IDP says the token is inactive", async () => {
    using _stub = stubTokenReader();
    const cookie = await createTestSession(bff, {
      tokens: { accessToken: "unknown-token" },
      user: { sub: "anyone", username: "anyone" },
    });
    const res = await app.request("/api/me", {
      headers: { cookie, ...CSRF },
    });
    assertStrictEquals(res.status, 401);
  });
});
