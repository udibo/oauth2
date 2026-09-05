import { assertEquals, assertStrictEquals } from "@std/assert";
import { afterEach, beforeEach, describe, it } from "@std/testing/bdd";
import { stub } from "@std/testing/mock";

import { BasicScope } from "@udibo/oauth2/server";

import app from "./main.ts";
import { tokenReader } from "./oauth2/server.ts";

/**
 * Tokens the stubbed `getToken` recognises. Any token not in this map
 * resolves to `undefined` and the protected route returns 401 —
 * mirroring the real introspection response for an inactive token.
 */
const activeTokens: Record<string, {
  client: string;
  user: string;
  scope?: string;
}> = {
  "good-token": { client: "spa", user: "user-1" },
  "read-only": { client: "spa", user: "user-1", scope: "read" },
  "admin-token": {
    client: "spa",
    user: "user-admin",
    scope: "read write admin",
  },
};

describe("api-service example", () => {
  let getTokenStub: ReturnType<
    typeof stub<
      typeof tokenReader,
      "getToken"
    >
  >;

  beforeEach(() => {
    getTokenStub = stub(tokenReader, "getToken", (token: string) => {
      const claims = activeTokens[token];
      if (!claims) return Promise.resolve(undefined);
      return Promise.resolve({
        accessToken: token,
        client: { id: claims.client },
        user: { id: claims.user },
        scope: claims.scope ? new BasicScope(claims.scope) : undefined,
      });
    });
  });

  afterEach(() => {
    getTokenStub.restore();
  });

  it("GET / serves the endpoint walkthrough homepage", async () => {
    const res = await app.request("/");
    assertStrictEquals(res.status, 200);
    assertEquals(res.headers.get("content-type")?.includes("text/html"), true);
    const html = await res.text();
    assertEquals(html.includes("API service"), true);
    assertEquals(html.includes("/api/admin"), true);
  });

  it("GET / homepage links the authorize URL with this server's redirect_uri", async () => {
    const res = await app.request("/");
    const html = await res.text();
    assertEquals(
      html.includes(
        "http://localhost:8001/oauth2/authorize?response_type=code",
      ),
      true,
    );
    assertEquals(
      html.includes(
        encodeURIComponent("http://localhost:8002/dev/callback"),
      ),
      true,
    );
  });

  it("GET / homepage authorize URL carries PKCE and sets the verifier cookie", async () => {
    const res = await app.request("/");
    const html = await res.text();
    assertEquals(html.includes("code_challenge="), true);
    assertEquals(html.includes("code_challenge_method=S256"), true);
    assertEquals(
      res.headers.get("set-cookie")?.includes("demo_pkce_verifier="),
      true,
    );
  });

  it("GET / homepage exposes a token tester for every /api/* endpoint", async () => {
    const res = await app.request("/");
    const html = await res.text();
    assertEquals(html.includes("tester-token"), true);
    assertEquals(html.includes("/api/public"), true);
    assertEquals(html.includes("/api/private"), true);
    assertEquals(html.includes("/api/write"), true);
    assertEquals(html.includes("/api/admin"), true);
  });

  it("GET /dev/callback without code or error renders an info page", async () => {
    const res = await app.request("/dev/callback");
    assertStrictEquals(res.status, 200);
    const html = await res.text();
    assertEquals(html.includes("Dev callback"), true);
    assertEquals(html.includes("redirect URI"), true);
  });

  it("GET / homepage links the auth server's /device page for user approval", async () => {
    const res = await app.request("/");
    const html = await res.text();
    assertEquals(html.includes("requestDeviceCodes"), true);
    assertEquals(html.includes("pollDevice"), true);
    assertEquals(html.includes("/dev/device-authorization"), true);
    assertEquals(
      html.includes("AUTH_SERVER_URL + '/device?user_code='"),
      true,
    );
  });

  it("GET /dev/callback?error=... renders an error page without contacting the auth server", async () => {
    const res = await app.request(
      "/dev/callback?error=access_denied&error_description=user+denied+consent",
    );
    assertStrictEquals(res.status, 200);
    const html = await res.text();
    assertEquals(html.includes("Authorization error"), true);
    assertEquals(html.includes("access_denied"), true);
    assertEquals(html.includes("user denied consent"), true);
  });

  it("GET /api/public works without a token", async () => {
    const res = await app.request("/api/public");
    assertStrictEquals(res.status, 200);
    const body = await res.json();
    assertStrictEquals(typeof body.message, "string");
  });

  it("GET /api/private returns 401 without a token", async () => {
    const res = await app.request("/api/private");
    assertStrictEquals(res.status, 401);
    const www = res.headers.get("WWW-Authenticate");
    assertStrictEquals(www, 'Bearer realm="Example API"');
  });

  it("GET /api/private returns 401 when the auth server rejects the token", async () => {
    const res = await app.request("/api/private", {
      headers: { Authorization: "Bearer totally-invalid" },
    });
    assertStrictEquals(res.status, 401);
    const www = res.headers.get("WWW-Authenticate");
    assertEquals(www?.includes("invalid_token"), true);
  });

  it("GET /api/private returns 200 for an active token", async () => {
    const res = await app.request("/api/private", {
      headers: { Authorization: "Bearer good-token" },
    });
    assertStrictEquals(res.status, 200);
    const body = await res.json();
    assertStrictEquals(body.client, "spa");
    assertStrictEquals(body.user, "user-1");
  });

  it("GET /api/write returns 403 when the token lacks the required scope", async () => {
    const res = await app.request("/api/write", {
      headers: { Authorization: "Bearer read-only" },
    });
    assertStrictEquals(res.status, 403);
    const www = res.headers.get("WWW-Authenticate");
    assertEquals(www?.includes("insufficient_scope"), true);
    assertEquals(www?.includes('scope="write"'), true);
  });

  it("GET /api/admin returns 200 for a token with admin scope", async () => {
    const res = await app.request("/api/admin", {
      headers: { Authorization: "Bearer admin-token" },
    });
    assertStrictEquals(res.status, 200);
    const body = await res.json();
    assertStrictEquals(body.user, "user-admin");
    assertEquals(body.scope?.includes("admin"), true);
  });

  it("GET /api/admin returns 403 for a token without admin scope", async () => {
    const res = await app.request("/api/admin", {
      headers: { Authorization: "Bearer good-token" },
    });
    assertStrictEquals(res.status, 403);
    const www = res.headers.get("WWW-Authenticate");
    assertEquals(www?.includes("insufficient_scope"), true);
    assertEquals(www?.includes('scope="admin"'), true);
  });
});
