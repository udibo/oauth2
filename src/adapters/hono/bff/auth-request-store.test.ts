import { assert, beforeEach, describe, expect, it, vi } from "vitest";
import { thrown } from "../../../_test_assert.ts";
import { Hono } from "hono";

import { AuthorizationCodeGrant } from "../../../server/grants/authorization-code.ts";
import {
  AuthorizationServer,
  localAuthServerFetch,
} from "../../../server/authorization-server.ts";
import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../../../testing/_test_fixtures.ts";
import type { AuthRequestRecord } from "../../../client/mod.ts";
import { DirectClient } from "../../../client/mod.ts";

import {
  EncryptedCookieAuthRequestStorage,
  encryptedCookieAuthRequestStorage,
  type EncryptedCookieAuthRequestStorageOptions,
} from "./auth-request-store.ts";
import { HonoBff } from "./bff.ts";
import { EncryptedCookieSessionStore } from "./session-store.ts";

const SECRET = "test-secret-at-least-32-bytes-long!!";
const OTHER_SECRET = "another-secret-at-least-32-bytes-long";
const COOKIE_NAME = "oauth2_auth_request";

const ISSUER = "http://localhost";
const TOKEN_URL = `${ISSUER}/token`;
const AUTHORIZE_URL = `${ISSUER}/authorize`;
const REDIRECT_URI = `${ISSUER}/auth/callback`;

function record(overrides: Partial<AuthRequestRecord> = {}): AuthRequestRecord {
  return {
    codeVerifier: "verifier",
    returnTo: "/home",
    createdAt: Date.now(),
    ...overrides,
  };
}

function cookieHeader(response: Response, name: string): string | undefined {
  const setCookie = response.headers.get("set-cookie");
  if (!setCookie) return undefined;
  const match = new RegExp(`${name}=([^;]*)`).exec(setCookie);
  if (!match || match[1] === "") return undefined;
  return `${name}=${match[1]}`;
}

/** An app exposing the storage's operations, driven over real cookies. */
function storageApp(options: EncryptedCookieAuthRequestStorageOptions) {
  const store = new EncryptedCookieAuthRequestStorage(options);
  const app = new Hono();
  app.post("/set", async (c) => {
    const body = await c.req.json();
    await store.forRequest(c).set(body.state, body.value);
    return c.body(null, 204);
  });
  app.get("/get", async (c) => {
    return c.json(await store.forRequest(c).get(c.req.query("state")!));
  });
  app.post("/delete", async (c) => {
    await store.forRequest(c).delete(c.req.query("state")!);
    return c.body(null, 204);
  });
  app.post("/clear", async (c) => {
    await store.forRequest(c).clear();
    return c.body(null, 204);
  });
  return app;
}

async function seal(
  app: Hono,
  entries: Array<[string, AuthRequestRecord]>,
): Promise<string | undefined> {
  let cookie: string | undefined;
  for (const [state, value] of entries) {
    const response = await app.request("/set", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(cookie ? { cookie } : {}),
      },
      body: JSON.stringify({ state, value }),
    });
    expect(response.status).toBe(204);
    cookie = cookieHeader(response, COOKIE_NAME) ?? cookie;
  }
  return cookie;
}

async function readBack(
  app: Hono,
  cookie: string | undefined,
  state: string,
): Promise<AuthRequestRecord | null> {
  const response = await app.request(`/get?state=${state}`, {
    headers: cookie ? { cookie } : {},
  });
  return await response.json();
}

describe("encryptedCookieAuthRequestStorage", () => {
  it("builds the same storage as the class constructor", () => {
    const storage = encryptedCookieAuthRequestStorage({ secret: SECRET });
    assert(storage instanceof EncryptedCookieAuthRequestStorage);
  });
});

describe("EncryptedCookieAuthRequestStorage", () => {
  const app = storageApp({ secret: SECRET, cookie: { secure: false } });

  it("round-trips a record through the cookie", async () => {
    const value = record();
    const cookie = await seal(app, [["state-1", value]]);
    expect(await readBack(app, cookie, "state-1")).toStrictEqual(value);
  });

  it("marks the cookie HttpOnly and SameSite=Lax so it survives the IdP redirect", async () => {
    const response = await app.request("/set", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ state: "state-1", value: record() }),
    });
    const setCookie = response.headers.get("set-cookie") ?? "";
    expect(/HttpOnly/i.test(setCookie)).toBe(true);
    expect(/SameSite=Lax/i.test(setCookie)).toBe(true);
  });

  it("reads nothing from a cookie sealed with a different secret", async () => {
    const cookie = await seal(app, [["state-1", record()]]);
    const other = storageApp({
      secret: OTHER_SECRET,
      cookie: { secure: false },
    });
    expect(await readBack(other, cookie, "state-1")).toStrictEqual(null);
  });

  it("drops records older than the ttl", async () => {
    const cookie = await seal(app, [
      ["state-1", record({ createdAt: Date.now() - 11 * 60 * 1000 })],
    ]);
    expect(await readBack(app, cookie, "state-1")).toStrictEqual(null);
  });

  it("keeps concurrent sign-ins up to maxPending, evicting the oldest", async () => {
    const now = Date.now();
    const cookie = await seal(app, [
      ["oldest", record({ createdAt: now - 3000 })],
      ["older", record({ createdAt: now - 2000 })],
      ["newer", record({ createdAt: now - 1000 })],
      ["newest", record({ createdAt: now })],
    ]);

    expect(await readBack(app, cookie, "oldest")).toStrictEqual(null);
    expect((await readBack(app, cookie, "older"))?.createdAt).toBe(now - 2000);
    expect((await readBack(app, cookie, "newest"))?.createdAt).toBe(now);
  });

  it("starts no key derivation until a request touches the storage", async () => {
    using digest = vi.spyOn(crypto.subtle, "digest");
    const lazy = storageApp({ secret: SECRET, cookie: { secure: false } });
    expect(digest).toHaveBeenCalledTimes(0);

    await seal(lazy, [["state-1", record()]]);
    expect(digest).toHaveBeenCalledTimes(1);
  });

  it("forgets a record after delete", async () => {
    const cookie = await seal(app, [["state-1", record()]]);
    const response = await app.request("/delete?state=state-1", {
      method: "POST",
      headers: cookie ? { cookie } : {},
    });
    expect(response.status).toBe(204);
    expect(
      await readBack(app, cookieHeader(response, COOKIE_NAME), "state-1"),
    ).toStrictEqual(null);
  });

  it("clears every pending record at once", async () => {
    const cookie = await seal(app, [
      ["state-1", record()],
      ["state-2", record()],
    ]);
    const response = await app.request("/clear", {
      method: "POST",
      headers: cookie ? { cookie } : {},
    });
    expect(
      await readBack(app, cookieHeader(response, COOKIE_NAME), "state-1"),
    ).toStrictEqual(null);
  });

  describe("cookie name", () => {
    async function setCookieHeader(
      options: EncryptedCookieAuthRequestStorageOptions,
    ): Promise<string> {
      const response = await storageApp(options).request("/set", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ state: "state-1", value: record() }),
      });
      return response.headers.get("set-cookie") ?? "";
    }

    it("defaults to __Host- + Secure + Path=/ with no Domain", async () => {
      const setCookie = await setCookieHeader({ secret: SECRET });
      expect(setCookie.includes("__Host-oauth2_auth_request=")).toBe(true);
      expect(setCookie.includes("Secure")).toBe(true);
      expect(setCookie.includes("Path=/")).toBe(true);
      expect(setCookie.includes("Domain=")).toBe(false);
    });

    it("drops the __Host- prefix when Secure is disabled (local HTTP)", async () => {
      const setCookie = await setCookieHeader({
        secret: SECRET,
        cookie: { secure: false },
      });
      expect(setCookie.includes("__Host-")).toBe(false);
      expect(/(^|[^-])oauth2_auth_request=/.test(setCookie)).toBe(true);
    });

    it("drops the __Host- prefix when a domain is set", async () => {
      const setCookie = await setCookieHeader({
        secret: SECRET,
        cookie: { domain: "example.com" },
      });
      expect(setCookie.includes("__Host-")).toBe(false);
      expect(setCookie.includes("Domain=example.com")).toBe(true);
    });

    it("drops the __Host- prefix when the path is not /", async () => {
      const setCookie = await setCookieHeader({
        secret: SECRET,
        cookie: { path: "/auth" },
      });
      expect(setCookie.includes("__Host-")).toBe(false);
      expect(setCookie.includes("Path=/auth")).toBe(true);
    });

    it("round-trips under the prefixed default name", async () => {
      const secureApp = storageApp({ secret: SECRET });
      const value = record();
      const response = await secureApp.request("/set", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ state: "state-1", value }),
      });
      const cookie = cookieHeader(response, "__Host-oauth2_auth_request");
      expect(await readBack(secureApp, cookie, "state-1")).toStrictEqual(value);
    });

    it("honors an explicit unprefixed name alongside a domain", async () => {
      const setCookie = await setCookieHeader({
        secret: SECRET,
        cookie: { name: "pending", domain: "example.com" },
      });
      expect(setCookie.includes("pending=")).toBe(true);
      expect(setCookie.includes("__Host-")).toBe(false);
    });

    it("throws when an explicit __Host- name is combined with secure: false", () => {
      thrown(
        () =>
          new EncryptedCookieAuthRequestStorage({
            secret: SECRET,
            cookie: { name: "__Host-pending", secure: false },
          }),
        Error,
        "cookie.secure is false",
      );
    });

    it("throws when an explicit __Host- name is combined with a domain", () => {
      thrown(
        () =>
          new EncryptedCookieAuthRequestStorage({
            secret: SECRET,
            cookie: { name: "__Host-pending", domain: "example.com" },
          }),
        Error,
        'cookie.domain is "example.com"',
      );
    });

    it("throws when an explicit __Host- name is combined with a non-/ path", () => {
      thrown(
        () =>
          new EncryptedCookieAuthRequestStorage({
            secret: SECRET,
            cookie: { name: "__Host-pending", path: "/auth" },
          }),
        Error,
        'cookie.path is "/auth"',
      );
    });

    it("throws when an explicit __Secure- name is combined with secure: false", () => {
      thrown(
        () =>
          new EncryptedCookieAuthRequestStorage({
            secret: SECRET,
            cookie: { name: "__Secure-pending", secure: false },
          }),
        Error,
        '"__Secure-" prefix',
      );
    });

    it("matches the prefixes case-insensitively, as browsers do", () => {
      thrown(
        () =>
          new EncryptedCookieAuthRequestStorage({
            secret: SECRET,
            cookie: { name: "__host-pending", domain: "example.com" },
          }),
        Error,
        '"__Host-" prefix',
      );
    });

    it("names the lost pending request in the error", () => {
      thrown(
        () =>
          new EncryptedCookieAuthRequestStorage({
            secret: SECRET,
            cookie: { name: "__Host-pending", secure: false },
          }),
        Error,
        "unknown state parameter",
      );
    });
  });
});

const testUser: TestUser = { id: "user-1", username: "demo" };
const testClient: TestClient = {
  id: "bff-client",
  confidential: true,
  grants: ["authorization_code"],
  redirectUris: [REDIRECT_URI],
};
const CLIENT_SECRET = "shh";

/**
 * Builds an authorization server plus a factory for independent BFF instances
 * over it — one instance per simulated isolate, sharing nothing in process.
 */
async function buildFixture() {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  const authorizationCodeService = new MemoryAuthorizationCodeService({
    clientService,
    userService,
  });

  await userService.add(testUser, "password");
  await clientService.add(testClient, CLIENT_SECRET, testUser.id);

  const authServer = new AuthorizationServer({
    resolve: () => ({
      services: { clientService, tokenService },
      issuer: ISSUER,
      tokenEndpoint: TOKEN_URL,
      authorizationEndpoint: AUTHORIZE_URL,
    }),
    grants: {
      authorization_code: new AuthorizationCodeGrant({
        resolve: () => ({
          clientService,
          tokenService,
          authorizationCodeService,
        }),
      }),
    },
  });

  function isolate(options: { statelessAuthRequests: boolean }) {
    const client = new DirectClient({
      clientId: testClient.id,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
      endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
      fetch: localAuthServerFetch(authServer),
    });
    const bff = new HonoBff({
      client,
      defaultReturnTo: "/home",
      cookie: { secure: false },
      csrf: false,
      sessionStore: new EncryptedCookieSessionStore({ secret: SECRET }),
      ...(options.statelessAuthRequests
        ? {
            authRequestStorage: new EncryptedCookieAuthRequestStorage({
              secret: SECRET,
              cookie: { secure: false },
            }),
          }
        : {}),
    });
    const app = new Hono();
    app.route("/auth", bff.routes());
    return app;
  }

  return { authServer, isolate };
}

async function followAuthorize(
  authServer: AuthorizationServer<TestClient, TestUser>,
  authorizeUrl: string,
): Promise<string> {
  const response = await authServer.handleAuthorizeRequest(
    new Request(authorizeUrl),
    () => Promise.resolve({ user: testUser }),
  );
  expect(response.status).toBe(302);
  return response.headers.get("Location")!;
}

describe("BFF sign-in across isolates", () => {
  let fixture: Awaited<ReturnType<typeof buildFixture>>;

  beforeEach(async () => {
    fixture = await buildFixture();
  });

  async function signIn(statelessAuthRequests: boolean): Promise<Response> {
    const login = await fixture
      .isolate({ statelessAuthRequests })
      .request("/auth/login");
    expect(login.status).toBe(302);
    await login.body?.cancel();

    const callbackUrl = await followAuthorize(
      fixture.authServer,
      login.headers.get("location")!,
    );
    const browser = login.headers
      .getSetCookie()
      .map((cookie) => cookie.split(";")[0])
      .filter((pair) => !pair.endsWith("="));

    // A different instance than the one that started the flow.
    return await fixture
      .isolate({ statelessAuthRequests })
      .request(new URL(callbackUrl).pathname + new URL(callbackUrl).search, {
        headers: { cookie: browser.join("; ") },
      });
  }

  it("completes when the pending request rides in a cookie", async () => {
    const response = await signIn(true);
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/home");
    await response.body?.cancel();
  });

  it("fails when the pending request lives in the starting isolate's memory", async () => {
    const response = await signIn(false);
    expect(response.status).toBe(400);
    expect((await response.json()).error).toBe("invalid_grant");
  });
});
