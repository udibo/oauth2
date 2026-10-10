import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type MockInstance,
  vi,
} from "vitest";

import { BasicScope } from "@udibo/oauth2/server";

import app from "./main.ts";
import { CLIENT_ID, CLIENT_SECRET, tokenReader } from "./oauth2/server.ts";

/**
 * Tokens the stubbed `getToken` recognises. Any token not in this map
 * resolves to `undefined` and the protected route returns 401 —
 * mirroring the real introspection response for an inactive token.
 */
const activeTokens: Record<
  string,
  {
    client: string;
    user: string;
    scope?: string;
  }
> = {
  "good-token": { client: "spa", user: "user-1" },
  "read-only": { client: "spa", user: "user-1", scope: "read" },
  "admin-token": {
    client: "spa",
    user: "user-admin",
    scope: "read write admin",
  },
};

describe("api-service example", () => {
  let getTokenSpy: MockInstance<typeof tokenReader.getToken>;

  beforeEach(() => {
    getTokenSpy = vi
      .spyOn(tokenReader, "getToken")
      .mockImplementation((token: string) => {
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
    getTokenSpy.mockRestore();
  });

  it("GET / serves the endpoint walkthrough homepage", async () => {
    const res = await app.request("/");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain("API service");
    expect(html).toContain("/api/admin");
  });

  it("GET / homepage shows credential placeholders without the configured secret", async () => {
    const res = await app.request("/");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).not.toContain(CLIENT_SECRET);
    expect(
      html.split(`-u "${CLIENT_ID}:&lt;client-secret&gt;"`).length - 1,
    ).toBe(4);
  });

  it("GET / homepage links the authorize URL with this server's redirect_uri", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).toContain(
      "http://localhost:8001/oauth2/authorize?response_type=code",
    );
    expect(html).toContain(
      encodeURIComponent("http://localhost:8002/dev/callback"),
    );
  });

  it("GET / homepage authorize URL carries PKCE and sets the verifier cookie", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).toContain("code_challenge=");
    expect(html).toContain("code_challenge_method=S256");
    expect(res.headers.get("set-cookie")).toContain("demo_pkce_verifier=");
  });

  it("GET / homepage exposes a token tester for every /api/* endpoint", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).toContain("tester-token");
    expect(html).toContain("/api/public");
    expect(html).toContain("/api/private");
    expect(html).toContain("/api/write");
    expect(html).toContain("/api/admin");
  });

  it("GET /dev/callback without code or error renders an info page", async () => {
    const res = await app.request("/dev/callback");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Dev callback");
    expect(html).toContain("redirect URI");
  });

  it("GET / homepage links the auth server's /device page for user approval", async () => {
    const res = await app.request("/");
    const html = await res.text();
    expect(html).toContain("requestDeviceCodes");
    expect(html).toContain("pollDevice");
    expect(html).toContain("/dev/device-authorization");
    expect(html).toContain("AUTH_SERVER_URL + '/device?user_code='");
  });

  it("GET /dev/callback?error=... renders an error page without contacting the auth server", async () => {
    const res = await app.request(
      "/dev/callback?error=access_denied&error_description=user+denied+consent",
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Authorization error");
    expect(html).toContain("access_denied");
    expect(html).toContain("user denied consent");
  });

  it("GET /api/public works without a token", async () => {
    const res = await app.request("/api/public");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(typeof body.message).toBe("string");
  });

  it("GET /api/private returns 401 without a token", async () => {
    const res = await app.request("/api/private");
    expect(res.status).toBe(401);
    const www = res.headers.get("WWW-Authenticate");
    expect(www).toBe('Bearer realm="Example API"');
  });

  it("GET /api/private returns 401 when the auth server rejects the token", async () => {
    const res = await app.request("/api/private", {
      headers: { Authorization: "Bearer totally-invalid" },
    });
    expect(res.status).toBe(401);
    const www = res.headers.get("WWW-Authenticate");
    expect(www).toContain("invalid_token");
  });

  it("GET /api/private returns 200 for an active token", async () => {
    const res = await app.request("/api/private", {
      headers: { Authorization: "Bearer good-token" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.client).toBe("spa");
    expect(body.user).toBe("user-1");
  });

  it("GET /api/write returns 403 when the token lacks the required scope", async () => {
    const res = await app.request("/api/write", {
      headers: { Authorization: "Bearer read-only" },
    });
    expect(res.status).toBe(403);
    const www = res.headers.get("WWW-Authenticate");
    expect(www).toContain("insufficient_scope");
    expect(www).toContain('scope="write"');
  });

  it("GET /api/admin returns 200 for a token with admin scope", async () => {
    const res = await app.request("/api/admin", {
      headers: { Authorization: "Bearer admin-token" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.user).toBe("user-admin");
    expect(body.scope).toContain("admin");
  });

  it("GET /api/admin returns 403 for a token without admin scope", async () => {
    const res = await app.request("/api/admin", {
      headers: { Authorization: "Bearer good-token" },
    });
    expect(res.status).toBe(403);
    const www = res.headers.get("WWW-Authenticate");
    expect(www).toContain("insufficient_scope");
    expect(www).toContain('scope="admin"');
  });
});
