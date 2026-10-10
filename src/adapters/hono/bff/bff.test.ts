import { assert, beforeEach, describe, expect, it, vi } from "vitest";
import { serve } from "../../../_test_server.ts";
import { thrown } from "../../../_test_assert.ts";
import { Hono } from "hono";

import { AuthorizationCodeGrant } from "../../../server/grants/authorization-code.ts";
import { RefreshTokenGrant } from "../../../server/grants/refresh-token.ts";
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
import {
  type AuthRequestRecord,
  type AuthRequestStorage,
  DirectClient,
} from "../../../client/mod.ts";
import { HonoAuthorizationServer } from "../authorization-server.ts";
import { HonoResourceServer } from "../resource-server.ts";

import { HonoBff } from "./bff.ts";
import {
  EncryptedCookieSessionStore,
  MemorySessionStore,
  type SessionData,
} from "./session-store.ts";
import {
  createAuthenticatedTestSession,
  createTestSession,
  readTestSession,
} from "./testing.ts";

const ISSUER = "http://localhost";
const TOKEN_URL = `${ISSUER}/token`;
const AUTHORIZE_URL = `${ISSUER}/authorize`;
const REVOKE_URL = `${ISSUER}/revoke`;
const REDIRECT_URI = `${ISSUER}/auth/callback`;

/**
 * The parameters `DirectClient` puts on every authorize URL for the fixture
 * below, sorted — the whole set an unconfigured BFF is allowed to send.
 */
const BASE_AUTHORIZE_PARAMS = [
  "client_id",
  "code_challenge",
  "code_challenge_method",
  "redirect_uri",
  "response_type",
  "state",
];

/**
 * Restated here rather than imported, so shrinking the list the BFF enforces
 * cannot also shrink what these tests demand of it.
 */
const RESERVED_AUTHORIZE_PARAMS = [
  "response_type",
  "client_id",
  "redirect_uri",
  "state",
  "code_challenge",
  "code_challenge_method",
  "response_mode",
  "nonce",
  "request",
  "request_uri",
];

const testUser: TestUser = { id: "user-1", username: "demo" };
const testClient: TestClient = {
  id: "bff-client",
  confidential: true,
  grants: ["authorization_code", "refresh_token"],
  redirectUris: [REDIRECT_URI],
};
const CLIENT_SECRET = "shh";

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
      revocationEndpoint: REVOKE_URL,
    }),
    grants: {
      authorization_code: new AuthorizationCodeGrant({
        resolve: () => ({
          clientService,
          tokenService,
          authorizationCodeService,
        }),
        allowRefreshToken: true,
      }),
      refresh_token: new RefreshTokenGrant({
        resolve: () => ({ clientService, tokenService }),
      }),
    },
  });

  const oauthClient = new DirectClient({
    clientId: testClient.id,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    endpoints: {
      authorization: AUTHORIZE_URL,
      token: TOKEN_URL,
      revocation: REVOKE_URL,
    },
    fetch: localAuthServerFetch(authServer),
  });

  return {
    authServer,
    clientService,
    tokenService,
    userService,
    authorizationCodeService,
    oauthClient,
  };
}

async function performAuthorizeRedirect(
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

function cookieValue(response: Response, name: string): string | undefined {
  const setCookie = response.headers.get("set-cookie");
  if (!setCookie) return undefined;
  const match = new RegExp(`${name}=([^;]+)`).exec(setCookie);
  return match?.[1];
}

/** The `name=value` pairs a browser would keep from a response. */
function jar(response: Response): string[] {
  return response.headers.getSetCookie().map((cookie) => cookie.split(";")[0]);
}

function withCookies(
  init: RequestInit | undefined,
  pairs: string[],
): RequestInit {
  const headers = new Headers(init?.headers);
  const existing = headers.get("cookie");
  headers.set("cookie", [...(existing ? [existing] : []), ...pairs].join("; "));
  return { ...init, headers };
}

describe("HonoBff", () => {
  let fixture: Awaited<ReturnType<typeof buildFixture>>;

  beforeEach(async () => {
    fixture = await buildFixture();
  });

  function makeBff(
    extra: Partial<ConstructorParameters<typeof HonoBff>[0]> = {},
  ) {
    return new HonoBff({
      client: fixture.oauthClient,
      defaultReturnTo: "/home",
      cookie: { secure: false },
      csrf: false,
      ...extra,
    });
  }

  /** Like {@link makeBff} but with CSRF on (the package default). */
  function makeCsrfBff(
    extra: Partial<ConstructorParameters<typeof HonoBff>[0]> = {},
  ) {
    return new HonoBff({
      client: fixture.oauthClient,
      defaultReturnTo: "/home",
      cookie: { secure: false },
      ...extra,
    });
  }

  function makeApp(bff: HonoBff): Hono {
    const app = new Hono();
    app.route("/auth", bff.routes());
    return app;
  }

  /**
   * Drives the real login flow end to end and returns the callback response —
   * for tests where the authorize / callback round-trip is the subject. Tests
   * that only need an authenticated caller should seed one with the shipped
   * `createTestSession` / `createAuthenticatedTestSession` helpers instead.
   */
  async function completeLogin(
    app: Hono,
    loginPath = "/auth/login",
    callbackInit?: RequestInit,
  ): Promise<Response> {
    const { callbackPath, cookies } = await beginLogin(app, loginPath);
    return await app.request(callbackPath, withCookies(callbackInit, cookies));
  }

  /**
   * Drives `/auth/login` and the authorize redirect, stopping at the callback
   * — for tests that need to tamper with what the browser brings back.
   * `cookies` is what a browser would carry into the callback.
   */
  async function beginLogin(
    app: Hono,
    loginPath = "/auth/login",
  ): Promise<{ callbackPath: string; state: string; cookies: string[] }> {
    const loginRes = await app.request(loginPath);
    const authorizeUrl = loginRes.headers.get("Location")!;
    await loginRes.body?.cancel();
    const callback = await performAuthorizeRedirect(
      fixture.authServer,
      authorizeUrl,
    );
    return {
      callbackPath: callback.slice(ISSUER.length),
      state: new URL(callback).searchParams.get("state")!,
      cookies: jar(loginRes),
    };
  }

  /** A `Cookie` header for a session minted by the real login flow. */
  async function loginCookie(
    app: Hono,
    cookieName = "oauth2_session",
  ): Promise<string> {
    const cbRes = await completeLogin(app);
    const value = cookieValue(cbRes, cookieName)!;
    await cbRes.body?.cancel();
    return `${cookieName}=${value}`;
  }

  /** A `Cookie` header for a session the BFF's resource server will accept. */
  function protectedSession(bff: HonoBff): Promise<string> {
    return createAuthenticatedTestSession(bff, {
      tokenService: fixture.tokenService,
      client: testClient,
      user: testUser,
    });
  }

  describe("loginContinuation", () => {
    it("resumes an in-flight authorize URL unchanged", () => {
      const bff = makeBff();
      const authorizeUrl =
        "/authorize?response_type=code&client_id=bff-client&state=abc";
      expect(bff.loginContinuation(authorizeUrl)).toBe(authorizeUrl);
    });

    it("starts a fresh login for a normal path", () => {
      const bff = makeBff();
      expect(bff.loginContinuation("/dashboard")).toBe(
        "/auth/login?return_to=%2Fdashboard",
      );
    });

    it("falls back to defaultReturnTo when returnTo is missing", () => {
      const bff = makeBff();
      expect(bff.loginContinuation(undefined)).toBe(
        "/auth/login?return_to=%2Fhome",
      );
    });

    it("guards against open redirects (off-site → fresh login to default)", () => {
      const bff = makeBff();
      for (const evil of ["https://evil.example/x", "//evil.example", "/\\e"]) {
        expect(bff.loginContinuation(evil)).toBe(
          "/auth/login?return_to=%2Fhome",
        );
      }
    });

    it("matches the authorize path exactly (not by prefix)", () => {
      const bff = makeBff();
      expect(bff.loginContinuation("/authorized-devices")).toBe(
        "/auth/login?return_to=%2Fauthorized-devices",
      );
    });

    it("honors a custom login path", () => {
      const bff = makeBff({ paths: { login: "/auth/signin" } });
      expect(bff.loginContinuation("/x")).toBe("/auth/signin?return_to=%2Fx");
    });
  });

  describe("CSRF protection", () => {
    const CSRF = { "x-csrf": "1" };

    function csrfApp(
      extra: Partial<ConstructorParameters<typeof HonoBff>[0]> = {},
    ): { bff: HonoBff; app: Hono } {
      const bff = makeCsrfBff(extra);
      return { bff, app: makeApp(bff) };
    }

    function seedSession(bff: HonoBff): Promise<string> {
      return createTestSession(bff, { user: { sub: testUser.id } });
    }

    it("completes the callback without the CSRF header (state, not the header, guards it)", async () => {
      const { bff, app } = csrfApp();
      const cbRes = await completeLogin(app);
      expect(cbRes.status).toBe(302);

      const cookie = `oauth2_session=${cookieValue(cbRes, "oauth2_session")}`;
      assert(await readTestSession(bff, cookie));
      const res = await app.request("/auth/session", {
        headers: { cookie, ...CSRF },
      });
      expect((await res.json()).isAuthenticated).toBe(true);
    });

    it("allows an anonymous /auth/session probe (no cookie, no header)", async () => {
      const { app } = csrfApp();
      const res = await app.request("/auth/session");
      expect(res.status).toBe(200);
      expect((await res.json()).isAuthenticated).toBe(false);
    });

    it("rejects a credentialed /auth/session without the header (403)", async () => {
      const { bff, app } = csrfApp();
      const cookie = await seedSession(bff);
      const res = await app.request("/auth/session", { headers: { cookie } });
      expect(res.status).toBe(403);
      await res.body?.cancel();
    });

    it("accepts a credentialed /auth/session with the header", async () => {
      const { bff, app } = csrfApp();
      const cookie = await seedSession(bff);
      const res = await app.request("/auth/session", {
        headers: { cookie, ...CSRF },
      });
      expect(res.status).toBe(200);
      expect((await res.json()).isAuthenticated).toBe(true);
    });

    it("enriches the authenticated payload with sessionExpiresIn + logoutUrl (no tokens)", async () => {
      const { bff, app } = csrfApp();
      const cookie = await seedSession(bff);
      const res = await app.request("/auth/session", {
        headers: { cookie, ...CSRF },
      });
      const body = await res.json();
      expect(body.isAuthenticated).toBe(true);
      expect(body.logoutUrl).toBe("/auth/logout");
      expect(typeof body.sessionExpiresIn).toStrictEqual("number");
      expect(body.sessionExpiresIn >= 0).toStrictEqual(true);
      expect("tokens" in body).toStrictEqual(false);
      expect("accessToken" in body).toStrictEqual(false);
    });

    it("keeps the anonymous payload minimal (backward compatible)", async () => {
      const { app } = csrfApp();
      const res = await app.request("/auth/session");
      expect(await res.json()).toStrictEqual({
        isAuthenticated: false,
        user: null,
      });
    });

    it("rejects POST /auth/logout without the header and keeps the session", async () => {
      const { bff, app } = csrfApp();
      const cookie = await seedSession(bff);
      const res = await app.request("/auth/logout", {
        method: "POST",
        headers: { cookie },
      });
      expect(res.status).toBe(403);
      await res.body?.cancel();
      assert(await readTestSession(bff, cookie));
    });

    it("accepts POST /auth/logout with the header", async () => {
      const { bff, app } = csrfApp();
      const cookie = await seedSession(bff);
      const res = await app.request("/auth/logout", {
        method: "POST",
        headers: { cookie, ...CSRF },
      });
      expect(res.status).toBe(302);
      await res.body?.cancel();
      expect(await readTestSession(bff, cookie)).toBe(null);
    });

    it("rejects a cross-origin GET /auth/logout (same-origin guard)", async () => {
      const { bff, app } = csrfApp();
      const cookie = await seedSession(bff);
      const res = await app.request("http://localhost/auth/logout", {
        headers: { cookie, origin: "https://evil.example" },
      });
      expect(res.status).toBe(403);
      await res.body?.cancel();
      assert(await readTestSession(bff, cookie));
    });

    it("allows a same-origin GET /auth/logout via the Origin fallback", async () => {
      const { bff, app } = csrfApp();
      const res = await app.request("http://localhost/auth/logout", {
        headers: {
          cookie: await seedSession(bff),
          origin: "http://localhost",
        },
      });
      expect(res.status).toBe(302);
      await res.body?.cancel();
    });

    it("allows a same-origin GET /auth/logout via the Referer fallback", async () => {
      const { bff, app } = csrfApp();
      const res = await app.request("http://localhost/auth/logout", {
        headers: {
          cookie: await seedSession(bff),
          referer: "http://localhost/dashboard",
        },
      });
      expect(res.status).toBe(302);
      await res.body?.cancel();
    });

    it("rejects a GET /auth/logout carrying no Sec-Fetch-Site, Origin, or Referer", async () => {
      const { bff, app } = csrfApp();
      const cookie = await seedSession(bff);
      const res = await app.request("http://localhost/auth/logout", {
        headers: { cookie },
      });
      expect(res.status).toBe(403);
      await res.body?.cancel();
      assert(await readTestSession(bff, cookie));
    });

    it("allows GET /auth/logout with Sec-Fetch-Site: same-origin", async () => {
      const { bff, app } = csrfApp();
      const res = await app.request("http://localhost/auth/logout", {
        headers: {
          cookie: await seedSession(bff),
          "sec-fetch-site": "same-origin",
        },
      });
      expect(res.status).toBe(302);
      await res.body?.cancel();
    });

    it("allows GET /auth/logout with Sec-Fetch-Site: none (bookmark or address bar)", async () => {
      const { bff, app } = csrfApp();
      const res = await app.request("http://localhost/auth/logout", {
        headers: {
          cookie: await seedSession(bff),
          "sec-fetch-site": "none",
        },
      });
      expect(res.status).toBe(302);
      await res.body?.cancel();
    });

    it("rejects GET /auth/logout with Sec-Fetch-Site: cross-site or same-site", async () => {
      const { bff, app } = csrfApp();
      for (const site of ["cross-site", "same-site"]) {
        const cookie = await seedSession(bff);
        const res = await app.request("http://localhost/auth/logout", {
          headers: { cookie, "sec-fetch-site": site },
        });
        expect(res.status, `${site} should be rejected`).toBe(403);
        await res.body?.cancel();
        assert(
          await readTestSession(bff, cookie),
          `${site} must not destroy the session`,
        );
      }
    });

    it("lets Sec-Fetch-Site override a matching Origin (cross-site wins)", async () => {
      const { bff, app } = csrfApp();
      const cookie = await seedSession(bff);
      const res = await app.request("http://localhost/auth/logout", {
        headers: {
          cookie,
          origin: "http://localhost",
          "sec-fetch-site": "cross-site",
        },
      });
      expect(res.status).toBe(403);
      await res.body?.cancel();
      assert(await readTestSession(bff, cookie));
    });

    it("rejects an unrecognized Sec-Fetch-Site value", async () => {
      const { bff, app } = csrfApp();
      const cookie = await seedSession(bff);
      const res = await app.request("http://localhost/auth/logout", {
        headers: { cookie, "sec-fetch-site": "Same-Origin" },
      });
      expect(res.status).toBe(403);
      await res.body?.cancel();
      assert(await readTestSession(bff, cookie));
    });

    it("leaves an anonymous GET /auth/logout unguarded (no session to abuse)", async () => {
      const { app } = csrfApp();
      const res = await app.request("http://localhost/auth/logout");
      expect(res.status).toBe(302);
      await res.body?.cancel();
    });

    it("protect() rejects the cookie path without the header (403)", async () => {
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService: fixture.tokenService } }),
      });
      const bff = makeCsrfBff({ resourceServer });
      const app = new Hono();
      app.route("/auth", bff.routes());
      app.use("/api/*", bff.protect());
      let served = 0;
      app.get("/api/me", (c) => {
        served++;
        return c.text("ok");
      });

      const cookie = await protectedSession(bff);
      const denied = await app.request("/api/me", { headers: { cookie } });
      expect(denied.status).toBe(403);
      await denied.body?.cancel();
      expect(served).toBe(0);

      const allowed = await app.request("/api/me", {
        headers: { cookie, ...CSRF },
      });
      expect(allowed.status).toBe(200);
      await allowed.body?.cancel();
      expect(served).toBe(1);
    });

    it("protect() lets an inbound bearer past the header requirement and authenticates it, not the session", async () => {
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService: fixture.tokenService } }),
      });
      const bff = makeCsrfBff({ resourceServer });
      const app = new Hono();
      app.use("/api/*", bff.protect());
      app.get("/api/me", (c) => c.json(resourceServer.getContext(c).user));

      const cookie = await protectedSession(bff);
      const bearerUser: TestUser = { id: "user-2", username: "machine" };
      await fixture.userService.add(bearerUser, "password");
      await fixture.tokenService.save({
        accessToken: "inbound-token",
        accessTokenExpiresAt: new Date(Date.now() + 60_000),
        client: testClient,
        user: bearerUser,
      });

      const res = await app.request("/api/me", {
        headers: { cookie, authorization: "Bearer inbound-token" },
      });
      expect(res.status).toBe(200);
      expect((await res.json()).id).toBe(bearerUser.id);
    });

    it("attachToken() rejects the cookie path without the header and attaches nothing", async () => {
      const bff = makeCsrfBff();
      const app = new Hono();
      app.use("/api/*", bff.attachToken());
      const seen: (string | undefined)[] = [];
      app.get("/api/echo", (c) => {
        seen.push(c.req.header("Authorization"));
        return c.text("ok");
      });

      const cookie = await createTestSession(bff, {
        tokens: { accessToken: "session-token" },
      });
      const denied = await app.request("/api/echo", { headers: { cookie } });
      expect(denied.status).toBe(403);
      await denied.body?.cancel();
      expect(seen).toStrictEqual([]);

      const allowed = await app.request("/api/echo", {
        headers: { cookie, ...CSRF },
      });
      expect(allowed.status).toBe(200);
      await allowed.body?.cancel();
      expect(seen).toStrictEqual(["Bearer session-token"]);
    });

    it("attachToken() lets an inbound bearer past the header requirement, then overwrites it with the session token", async () => {
      const bff = makeCsrfBff();
      const app = new Hono();
      app.use("/api/*", bff.attachToken());
      const seen: (string | undefined)[] = [];
      app.get("/api/echo", (c) => {
        seen.push(c.req.header("Authorization"));
        return c.text("ok");
      });

      const cookie = await createTestSession(bff, {
        tokens: { accessToken: "session-token" },
      });
      const res = await app.request("/api/echo", {
        headers: { cookie, authorization: "Bearer inbound-token" },
      });
      expect(res.status).toBe(200);
      await res.body?.cancel();
      expect(seen).toStrictEqual(["Bearer session-token"]);
    });

    it("proxy() refuses a bearer token on the cookie path (no bearer bypass there)", async () => {
      const bff = makeCsrfBff();
      const app = new Hono();
      let upstreamCalls = 0;
      app.all(
        "/api/*",
        bff.proxy("https://upstream.example", {
          stripPrefix: "/api",
          fetch: () => {
            upstreamCalls++;
            return Promise.resolve(new Response("upstream"));
          },
        }),
      );

      const cookie = await createTestSession(bff, {
        tokens: { accessToken: "session-token" },
      });
      const res = await app.request("/api/me", {
        headers: { cookie, authorization: "Bearer inbound-token" },
      });
      expect(res.status).toBe(403);
      expect((await res.json()).error).toBe("csrf_validation_failed");
      expect(upstreamCalls).toBe(0);
    });

    it("supports a custom header name + value", async () => {
      const { bff, app } = csrfApp({
        csrf: { headerName: "X-Token-Handler", headerValue: "v1" },
      });
      const cookie = await seedSession(bff);
      const bad = await app.request("/auth/session", {
        headers: { cookie, "x-token-handler": "no" },
      });
      expect(bad.status).toBe(403);
      await bad.body?.cancel();
      const ok = await app.request("/auth/session", {
        headers: { cookie, "x-token-handler": "v1" },
      });
      expect(ok.status).toBe(200);
      await ok.body?.cancel();
    });

    it("csrf:false disables the check entirely", async () => {
      const bff = makeBff();
      const app = makeApp(bff);
      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
      });
      const res = await app.request("/auth/session", { headers: { cookie } });
      expect(res.status).toBe(200);
    });
  });

  describe("cookie defaults (IETF BCP)", () => {
    async function setCookieAfterLogin(bff: HonoBff): Promise<string> {
      const app = makeApp(bff);
      const cbRes = await completeLogin(app);
      const setCookie = cbRes.headers.get("set-cookie") ?? "";
      await cbRes.body?.cancel();
      return setCookie;
    }

    it("defaults to __Host- + SameSite=Strict + Secure + Path=/ when secure", async () => {
      const bff = new HonoBff({
        client: fixture.oauthClient,
        defaultReturnTo: "/",
        csrf: false,
      });
      const setCookie = await setCookieAfterLogin(bff);
      expect(setCookie.includes("__Host-oauth2_session=")).toStrictEqual(true);
      expect(setCookie.includes("SameSite=Strict")).toStrictEqual(true);
      expect(setCookie.includes("Secure")).toStrictEqual(true);
      expect(setCookie.includes("Path=/")).toStrictEqual(true);
      expect(setCookie.includes("HttpOnly")).toStrictEqual(true);
    });

    it("drops the __Host- prefix when Secure is disabled (local HTTP)", async () => {
      const bff = makeBff();
      const setCookie = await setCookieAfterLogin(bff);
      expect(setCookie.includes("__Host-")).toStrictEqual(false);
      expect(/(^|[^-])oauth2_session=/.test(setCookie)).toStrictEqual(true);
    });

    it("honors an explicit name and SameSite override", async () => {
      const bff = new HonoBff({
        client: fixture.oauthClient,
        defaultReturnTo: "/",
        csrf: false,
        cookie: { name: "sess", sameSite: "Lax", secure: true },
      });
      const setCookie = await setCookieAfterLogin(bff);
      expect(setCookie.includes("sess=")).toStrictEqual(true);
      expect(setCookie.includes("SameSite=Lax")).toStrictEqual(true);
    });

    it("drops the __Host- prefix when cookie.domain is set without a name", () => {
      const bff = new HonoBff({
        client: fixture.oauthClient,
        defaultReturnTo: "/",
        csrf: false,
        cookie: { domain: "example.com" },
      });
      expect(bff.cookieName).toBe("oauth2_session");
    });

    it("drops the __Host- prefix when cookie.path is not / without a name", () => {
      const bff = new HonoBff({
        client: fixture.oauthClient,
        defaultReturnTo: "/",
        csrf: false,
        cookie: { path: "/app" },
      });
      expect(bff.cookieName).toBe("oauth2_session");
    });

    it("emits a Domain-scoped cookie with no prefix for a domain deployment", async () => {
      const bff = new HonoBff({
        client: fixture.oauthClient,
        defaultReturnTo: "/",
        csrf: false,
        cookie: { domain: "example.com" },
      });
      const setCookie = await setCookieAfterLogin(bff);
      expect(setCookie.includes("__Host-")).toStrictEqual(false);
      expect(setCookie.includes("__Secure-")).toStrictEqual(false);
      expect(/(^|[^-])oauth2_session=/.test(setCookie)).toStrictEqual(true);
      expect(setCookie.includes("Domain=example.com")).toStrictEqual(true);
      expect(setCookie.includes("Secure")).toStrictEqual(true);
    });

    it("keeps the __Host- prefix when only SameSite and Max-Age are customized", () => {
      const bff = new HonoBff({
        client: fixture.oauthClient,
        defaultReturnTo: "/",
        csrf: false,
        sessionMaxAgeMs: 3600 * 1000,
        cookie: { sameSite: "Lax", maxAge: 3600 },
      });
      expect(bff.cookieName).toBe("__Host-oauth2_session");
    });

    it("throws when an explicit __Host- name is combined with a domain", () => {
      thrown(
        () =>
          new HonoBff({
            client: fixture.oauthClient,
            defaultReturnTo: "/",
            csrf: false,
            cookie: { name: "__Host-sess", domain: "example.com" },
          }),
        Error,
        'cookie.domain is "example.com"',
      );
    });

    it("throws when an explicit __Host- name is combined with a non-/ path", () => {
      thrown(
        () =>
          new HonoBff({
            client: fixture.oauthClient,
            defaultReturnTo: "/",
            csrf: false,
            cookie: { name: "__Host-sess", path: "/app" },
          }),
        Error,
        'cookie.path is "/app"',
      );
    });

    it("throws when an explicit __Host- name is combined with secure: false", () => {
      thrown(
        () =>
          new HonoBff({
            client: fixture.oauthClient,
            defaultReturnTo: "/",
            csrf: false,
            cookie: { name: "__Host-sess", secure: false },
          }),
        Error,
        "cookie.secure is false",
      );
    });

    it("throws when an explicit __Secure- name is combined with secure: false", () => {
      thrown(
        () =>
          new HonoBff({
            client: fixture.oauthClient,
            defaultReturnTo: "/",
            csrf: false,
            cookie: { name: "__Secure-sess", secure: false },
          }),
        Error,
        '"__Secure-" prefix',
      );
    });

    it("matches the prefixes case-insensitively, as browsers do", () => {
      thrown(
        () =>
          new HonoBff({
            client: fixture.oauthClient,
            defaultReturnTo: "/",
            csrf: false,
            cookie: { name: "__host-sess", domain: "example.com" },
          }),
        Error,
        '"__Host-" prefix',
      );
    });

    it("accepts an explicit __Host- name when every attribute satisfies it", () => {
      const bff = new HonoBff({
        client: fixture.oauthClient,
        defaultReturnTo: "/",
        csrf: false,
        cookie: { name: "__Host-sess", secure: true, path: "/" },
      });
      expect(bff.cookieName).toBe("__Host-sess");
    });

    it("accepts an unprefixed explicit name alongside a domain", () => {
      const bff = new HonoBff({
        client: fixture.oauthClient,
        defaultReturnTo: "/",
        csrf: false,
        cookie: { name: "sess", domain: "example.com" },
      });
      expect(bff.cookieName).toBe("sess");
    });
  });

  describe("session lifetime", () => {
    const DAY_SECONDS = 24 * 60 * 60;
    const DEFAULT_SECONDS = 14 * DAY_SECONDS;

    async function sessionSetCookie(bff: HonoBff): Promise<string> {
      const app = makeApp(bff);
      const cbRes = await completeLogin(app);
      const setCookie = cbRes.headers
        .getSetCookie()
        .find((cookie) => cookie.startsWith(`${bff.cookieName}=`))!;
      await cbRes.body?.cancel();
      return setCookie;
    }

    it("gives a BFF configured with no cookie or session options a Max-Age", async () => {
      const setCookie = await sessionSetCookie(makeBff());
      expect(setCookie).toContain(`Max-Age=${DEFAULT_SECONDS}`);
    });

    it("matches the cookie's Max-Age to the stateless store's default bound", async () => {
      const store = new EncryptedCookieSessionStore({
        secret: crypto.getRandomValues(new Uint8Array(32)),
      });
      const setCookie = await sessionSetCookie(
        makeBff({ sessionStore: store }),
      );
      expect(setCookie).toContain(`Max-Age=${store.maxAgeMs / 1000}`);
    });

    it("derives the cookie's Max-Age from sessionMaxAgeMs", async () => {
      const setCookie = await sessionSetCookie(
        makeBff({ sessionMaxAgeMs: 3 * DAY_SECONDS * 1000 }),
      );
      expect(setCookie).toContain(`Max-Age=${3 * DAY_SECONDS}`);
    });

    it("re-stamps the Max-Age when a refresh rotates the cookie, not only at the callback", async () => {
      const { tokenService } = fixture;
      tokenService.accessTokenLifetime = 1;
      const bff = makeBff({
        refreshSkewSeconds: 60,
        sessionStore: new EncryptedCookieSessionStore({
          secret: crypto.getRandomValues(new Uint8Array(32)),
        }),
      });
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService } }),
      });
      const app = makeApp(bff);
      app.use("/api/*", bff.attachToken(), resourceServer.protect());
      app.get("/api/me", (c) => c.json({ ok: true }));

      const cbRes = await completeLogin(app);
      const sess = cookieValue(cbRes, "oauth2_session")!;
      await cbRes.body?.cancel();

      const res = await app.request("/api/me", {
        headers: { cookie: `oauth2_session=${sess}`, "x-csrf": "1" },
      });
      expect(res.status).toBe(200);
      await res.body?.cancel();
      const rotated = res.headers
        .getSetCookie()
        .find((cookie) => cookie.startsWith("oauth2_session="))!;
      expect(rotated.startsWith(`oauth2_session=${sess};`)).toStrictEqual(
        false,
      );
      expect(rotated).toContain(`Max-Age=${DEFAULT_SECONDS}`);
    });

    it("throws when cookie.maxAge is shorter than the session lifetime", () => {
      thrown(
        () => makeBff({ cookie: { secure: false, maxAge: 3600 } }),
        Error,
        "the browser drops the cookie while the session stays active and listed",
      );
    });

    it("throws when a store outlives the cookie the BFF would write", () => {
      thrown(
        () =>
          makeBff({
            sessionStore: new EncryptedCookieSessionStore({
              secret: crypto.getRandomValues(new Uint8Array(32)),
              maxAgeMs: 30 * DAY_SECONDS * 1000,
            }),
          }),
        Error,
        "shorter than the session lifetime (2592000s)",
      );
    });

    it("points a store/cookie mismatch at sessionMaxAgeMs, the knob that was never set", () => {
      const error = thrown(
        () =>
          makeBff({
            sessionStore: new EncryptedCookieSessionStore({
              secret: crypto.getRandomValues(new Uint8Array(32)),
              maxAgeMs: 30 * DAY_SECONDS * 1000,
            }),
          }),
        Error,
      );
      expect(
        error.message,
        "naming cookie.maxAge sends the reader to an option they never set",
      ).toContain("taken from sessionMaxAgeMs");
      expect(
        error.message,
        "the remedy must name the knob and the value that resolves it",
      ).toContain(`Set sessionMaxAgeMs to ${30 * DAY_SECONDS * 1000}`);
    });

    it("accepts a cookie that outlives the session, which ends first", async () => {
      const setCookie = await sessionSetCookie(
        makeBff({
          sessionMaxAgeMs: DAY_SECONDS * 1000,
          cookie: { secure: false, maxAge: 2 * DAY_SECONDS },
        }),
      );
      expect(setCookie).toContain(`Max-Age=${2 * DAY_SECONDS}`);
    });

    it("rejects a lifetime past the 400-day cookie cap at construction, not at the first response", () => {
      thrown(
        () => makeBff({ sessionMaxAgeMs: 401 * DAY_SECONDS * 1000 }),
        Error,
        "must not exceed 400 days",
      );
    });

    it('bounds the server-side session when cookie.maxAge is "session"', async () => {
      const bff = makeBff({
        sessionMaxAgeMs: DAY_SECONDS * 1000,
        cookie: { secure: false, maxAge: "session" },
      });
      const app = makeApp(bff);

      const setCookie = await sessionSetCookie(bff);
      expect(setCookie.includes("Max-Age")).toStrictEqual(false);

      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
        createdAt: Date.now() - (DAY_SECONDS * 1000 + 1),
      });
      const res = await app.request("/auth/session", { headers: { cookie } });
      expect((await res.json()).isAuthenticated).toBe(false);
    });

    it("destroys a session older than sessionMaxAgeMs and clears its cookie", async () => {
      const store = new MemorySessionStore();
      const bff = makeBff({ sessionStore: store, sessionMaxAgeMs: 60 * 1000 });
      const app = makeApp(bff);
      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
        createdAt: Date.now() - 61_000,
      });

      const res = await app.request("/auth/session", { headers: { cookie } });

      expect((await res.json()).isAuthenticated).toBe(false);
      expect(res.headers.getSetCookie().join("\n")).toContain("Max-Age=0");
      expect(await store.read(cookie.split("=")[1])).toBe(null);
    });

    it("keeps a session younger than sessionMaxAgeMs", async () => {
      const bff = makeBff({ sessionMaxAgeMs: 60 * 1000 });
      const app = makeApp(bff);
      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
        createdAt: Date.now() - 59_000,
      });

      const res = await app.request("/auth/session", { headers: { cookie } });
      expect((await res.json()).isAuthenticated).toBe(true);
    });

    it("leaves the session's age to the app in sessionMode: shared", async () => {
      const store = new MemorySessionStore();
      const bff = makeBff({
        sessionStore: store,
        sessionMode: "shared",
        sessionMaxAgeMs: 60 * 1000,
        cookie: { name: "session_id", secure: false },
      });
      const app = makeApp(bff);
      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
        createdAt: Date.now() - 3_600_000,
      });

      const res = await app.request("/auth/session", { headers: { cookie } });
      expect((await res.json()).isAuthenticated).toBe(true);
    });

    it("does not age out a session whose createdAt a store failed to preserve", async () => {
      const bff = makeBff({ sessionMaxAgeMs: 60 * 1000 });
      const app = makeApp(bff);
      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
        createdAt: 0,
      });

      const res = await app.request("/auth/session", { headers: { cookie } });
      expect((await res.json()).isAuthenticated).toBe(true);
    });

    it("never re-stamps the app's session cookie in shared mode (#726)", async () => {
      const { tokenService } = fixture;
      tokenService.accessTokenLifetime = 1;
      const sharedStore = new MemorySessionStore();
      const now = Date.now();
      const appSessionId = await sharedStore.create({
        tokens: { accessToken: "", tokenType: "Bearer" },
        createdAt: now,
        updatedAt: now,
      });
      const bff = makeBff({
        sessionStore: sharedStore,
        sessionMode: "shared",
        sessionMaxAgeMs: 60 * 1000,
        refreshSkewSeconds: 60,
        cookie: { name: "session_id", secure: false },
      });
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService } }),
      });
      const app = makeApp(bff);
      app.use("/api/*", bff.attachToken(), resourceServer.protect());
      app.get("/api/me", (c) => c.json({ ok: true }));

      const cbRes = await completeLogin(app, "/auth/login", {
        headers: { cookie: `session_id=${appSessionId}` },
      });
      await cbRes.body?.cancel();
      expect(
        cookieValue(cbRes, "session_id"),
        "the callback must not replace the attributes the app chose",
      ).toBe(undefined);

      const refreshed = await app.request("/api/me", {
        headers: { cookie: `session_id=${appSessionId}`, "x-csrf": "1" },
      });
      await refreshed.body?.cancel();
      expect(refreshed.status).toBe(200);
      expect(
        refreshed.headers.get("set-cookie"),
        "the refresh re-stamp must not replace them either",
      ).toBe(null);
    });

    it("mints an ephemeral cookie in shared mode, leaving the lifetime to the app", async () => {
      const bff = makeBff({
        sessionStore: new MemorySessionStore(),
        sessionMode: "shared",
        cookie: { name: "session_id", secure: false },
      });
      const app = makeApp(bff);

      const res = await completeLogin(app, "/auth/login");
      await res.body?.cancel();

      expect(res.status).toBe(302);
      assert(
        cookieValue(res, "session_id") !== undefined,
        "the BFF still writes the session it created",
      );
      const sessionCookie = res.headers
        .getSetCookie()
        .find(
          (line) =>
            line.startsWith("session_id=") && !line.startsWith("session_id=;"),
        );
      assert(sessionCookie, "the BFF wrote the session cookie");
      expect(
        /Max-Age/i.test(sessionCookie),
        "the app owns the lifetime, so the BFF stamps no Max-Age of its own",
      ).toStrictEqual(false);
    });

    it("uses an explicit cookie.maxAge for the cookie it mints in shared mode", async () => {
      const bff = makeBff({
        sessionStore: new MemorySessionStore(),
        sessionMode: "shared",
        cookie: { name: "session_id", secure: false, maxAge: 60 },
      });
      const app = makeApp(bff);

      const res = await completeLogin(app, "/auth/login");
      await res.body?.cancel();

      assert(cookieValue(res, "session_id") !== undefined);
      expect(res.headers.get("set-cookie") ?? "").toMatch(/Max-Age=60\b/);
    });
  });

  describe("RP-Initiated Logout", () => {
    function makeRpBff(
      extra: Partial<ConstructorParameters<typeof HonoBff>[0]> = {},
    ) {
      const client = new DirectClient({
        clientId: testClient.id,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        endpoints: {
          authorization: AUTHORIZE_URL,
          token: TOKEN_URL,
          revocation: REVOKE_URL,
          endSession: `${ISSUER}/end_session`,
        },
        fetch: localAuthServerFetch(fixture.authServer),
      });
      return new HonoBff({
        client,
        cookie: { secure: false },
        defaultReturnTo: "/",
        csrf: false,
        rpInitiatedLogout: true,
        ...extra,
      });
    }

    function seed(bff: HonoBff, idToken?: string): Promise<string> {
      return bff.sessionStore.create({
        tokens: { accessToken: "at", tokenType: "Bearer", idToken },
        refreshToken: "rt",
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
    }

    it("redirects to the end-session endpoint with id_token_hint + post_logout_redirect_uri", async () => {
      const bff = makeRpBff();
      const app = makeApp(bff);
      const cookie = await seed(bff, "the-id-token");
      const res = await app.request(
        "http://localhost/auth/logout?return_to=/done",
        { method: "POST", headers: { cookie: `oauth2_session=${cookie}` } },
      );
      expect(res.status).toBe(302);
      const loc = new URL(res.headers.get("Location")!);
      expect(loc.origin + loc.pathname).toBe(`${ISSUER}/end_session`);
      expect(loc.searchParams.get("id_token_hint")).toBe("the-id-token");
      expect(loc.searchParams.get("post_logout_redirect_uri")).toBe(
        `${ISSUER}/done`,
      );
      expect(
        (res.headers.get("set-cookie") ?? "").includes("oauth2_session="),
      ).toStrictEqual(true);
    });

    it("omits id_token_hint when the session has no id_token", async () => {
      const bff = makeRpBff();
      const app = makeApp(bff);
      const cookie = await seed(bff);
      const res = await app.request("http://localhost/auth/logout", {
        method: "POST",
        headers: { cookie: `oauth2_session=${cookie}` },
      });
      const loc = new URL(res.headers.get("Location")!);
      expect(loc.origin + loc.pathname).toBe(`${ISSUER}/end_session`);
      expect(loc.searchParams.has("id_token_hint")).toBe(false);
      expect(loc.searchParams.get("post_logout_redirect_uri")).toBe(
        `${ISSUER}/`,
      );
      await res.body?.cancel();
    });

    it("guards post_logout_redirect_uri against open redirects", async () => {
      const bff = makeRpBff();
      const app = makeApp(bff);
      const cookie = await seed(bff, "x");
      const res = await app.request(
        "http://localhost/auth/logout?return_to=https://evil.example/x",
        { method: "POST", headers: { cookie: `oauth2_session=${cookie}` } },
      );
      const loc = new URL(res.headers.get("Location")!);
      expect(loc.searchParams.get("post_logout_redirect_uri")).toBe(
        `${ISSUER}/`,
      );
      await res.body?.cancel();
    });

    it("falls back to a local redirect when no end-session endpoint is known, and says so once", async () => {
      const bff = makeBff({ rpInitiatedLogout: true });
      const app = makeApp(bff);
      const warnings: string[] = [];
      using _warn = vi
        .spyOn(console, "warn")
        .mockImplementation(
          (...args: unknown[]) => void warnings.push(String(args[0])),
        );

      for (const _attempt of [1, 2]) {
        const cookie = await bff.sessionStore.create({
          tokens: { accessToken: "at", tokenType: "Bearer" },
          createdAt: Date.now(),
          updatedAt: Date.now(),
        });
        const res = await app.request("/auth/logout?return_to=/done", {
          method: "POST",
          headers: { cookie: `oauth2_session=${cookie}` },
        });
        expect(res.status).toBe(302);
        expect(res.headers.get("Location")).toBe("/done");
        await res.body?.cancel();
      }

      expect(
        warnings.length,
        "the operator is told the logout is local-only — once, not per request",
      ).toBe(1);
      expect(warnings[0]).toContain("rpInitiatedLogout is enabled");
      expect(warnings[0]).toContain("endpoints.endSession");
    });

    it("default (off) does a plain local redirect even with an end-session endpoint", async () => {
      const bff = makeRpBff({ rpInitiatedLogout: false });
      const app = makeApp(bff);
      const cookie = await seed(bff, "x");
      const res = await app.request("/auth/logout?return_to=/done", {
        method: "POST",
        headers: { cookie: `oauth2_session=${cookie}` },
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/done");
      await res.body?.cancel();
    });
  });

  describe("Back-Channel Logout", () => {
    function makeBcBff(
      verify: (t: string) => { sub?: string; sid?: string } | null,
      maxBodyBytes?: number,
    ) {
      const store = new MemorySessionStore();
      const bff = new HonoBff({
        client: fixture.oauthClient,
        cookie: { secure: false },
        defaultReturnTo: "/",
        csrf: false,
        sessionStore: store,
        backchannelLogout: {
          verifyLogoutToken: verify,
          ...(maxBodyBytes === undefined ? {} : { maxBodyBytes }),
        },
      });
      return { bff, store };
    }

    function seed(
      store: MemorySessionStore,
      data: Partial<Parameters<MemorySessionStore["create"]>[0]>,
    ): Promise<string> {
      return store.create({
        tokens: { accessToken: "at", tokenType: "Bearer" },
        createdAt: Date.now(),
        updatedAt: Date.now(),
        ...data,
      });
    }

    function post(app: Hono, body: Record<string, string>) {
      return app.request("/auth/backchannel", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(body),
      });
    }

    it("is not mounted unless backchannelLogout is configured", async () => {
      const res = await makeApp(makeBff()).request("/auth/backchannel", {
        method: "POST",
      });
      expect(res.status).toBe(404);
      await res.body?.cancel();
    });

    it("destroys all of a subject's sessions for a sub-only logout_token", async () => {
      const { bff, store } = makeBcBff(() => ({ sub: "user-1" }));
      const app = makeApp(bff);
      const a = await seed(store, { user: { sub: "user-1" } });
      const b = await seed(store, { user: { sub: "user-1" } });
      const other = await seed(store, { user: { sub: "user-2" } });

      const res = await post(app, { logout_token: "tok" });
      expect(res.status).toBe(200);
      expect(res.headers.get("cache-control")).toBe("no-store");
      await res.body?.cancel();
      expect(await store.read(a)).toBe(null);
      expect(await store.read(b)).toBe(null);
      expect((await store.read(other)) !== null).toStrictEqual(true);
    });

    it("destroys only the matching session for a sid logout_token", async () => {
      const { bff, store } = makeBcBff(() => ({ sub: "user-1", sid: "S1" }));
      const app = makeApp(bff);
      const target = await seed(store, { user: { sub: "user-1" }, sid: "S1" });
      const kept = await seed(store, { user: { sub: "user-1" }, sid: "S2" });

      const res = await post(app, { logout_token: "tok" });
      expect(res.status).toBe(200);
      await res.body?.cancel();
      expect(await store.read(target)).toBe(null);
      expect((await store.read(kept)) !== null).toStrictEqual(true);
    });

    it("rejects a missing logout_token (400)", async () => {
      const { bff } = makeBcBff(() => ({ sub: "x" }));
      const res = await post(makeApp(bff), {});
      expect(res.status).toBe(400);
      await res.body?.cancel();
    });

    it("rejects when the verifier throws or returns null (400)", async () => {
      const thrower = makeBcBff(() => {
        throw new Error("bad signature");
      });
      const resT = await post(makeApp(thrower.bff), { logout_token: "tok" });
      expect(resT.status).toBe(400);
      await resT.body?.cancel();

      const nuller = makeBcBff(() => null);
      const resN = await post(makeApp(nuller.bff), { logout_token: "tok" });
      expect(resN.status).toBe(400);
      await resN.body?.cancel();
    });

    describe("request body limit", () => {
      const DEFAULT_LIMIT = 64 * 1024;
      const CHUNK_BYTES = 16 * 1024;

      /** A logout body padded with an ignored parameter to exactly `bytes`. */
      function paddedLogout(bytes: number): string {
        const prefix = "logout_token=tok&pad=";
        return prefix + "a".repeat(bytes - prefix.length);
      }

      function countingStream(form: string) {
        const bytes = new TextEncoder().encode(form);
        const state = { pulled: 0, cancelled: false };
        const stream = new ReadableStream<Uint8Array>({
          pull(controller) {
            if (state.pulled >= bytes.byteLength) return controller.close();
            const chunk = bytes.subarray(
              state.pulled,
              state.pulled + CHUNK_BYTES,
            );
            state.pulled += chunk.byteLength;
            controller.enqueue(chunk);
          },
          cancel() {
            state.cancelled = true;
          },
        });
        return { stream, state };
      }

      function makeCountingBff(maxBodyBytes?: number) {
        const verified: string[] = [];
        const { bff } = makeBcBff((token) => {
          verified.push(token);
          return { sub: "user-1" };
        }, maxBodyBytes);
        return { app: makeApp(bff), verified };
      }

      async function withHttpServer(
        app: Hono,
        fn: (url: string) => Promise<void>,
      ): Promise<void> {
        await using http = await serve(app.fetch);
        await fn(`${http.origin}/auth/backchannel`);
      }

      async function assertRefused(res: Response): Promise<void> {
        expect(res.status).toBe(400);
        expect(res.headers.get("cache-control")).toBe("no-store");
        const body = await res.json();
        expect(body.error).toBe("invalid_request");
        expect(body.error_description).toBe("request body is too large");
      }

      const formHeaders = {
        "content-type": "application/x-www-form-urlencoded",
      };

      it("accepts a body of exactly the default 64 KiB limit", async () => {
        const { app, verified } = makeCountingBff();
        await withHttpServer(app, async (url) => {
          const res = await fetch(url, {
            method: "POST",
            headers: formHeaders,
            body: paddedLogout(DEFAULT_LIMIT),
          });
          await res.body?.cancel();
          expect(res.status).toBe(200);
          expect(verified).toStrictEqual(["tok"]);
        });
      });

      it("refuses a body whose Content-Length declares one byte over the limit, before verifying the logout_token", async () => {
        const { app, verified } = makeCountingBff();
        await withHttpServer(app, async (url) => {
          const res = await fetch(url, {
            method: "POST",
            headers: formHeaders,
            body: paddedLogout(DEFAULT_LIMIT + 1),
          });
          await assertRefused(res);
          expect(verified).toStrictEqual([]);
        });
      });

      it("counts the bytes of a chunked body that carries no Content-Length", async () => {
        const { app, verified } = makeCountingBff();
        const { stream } = countingStream(paddedLogout(1024 * 1024));
        await withHttpServer(app, async (url) => {
          const res = await fetch(url, {
            method: "POST",
            headers: formHeaders,
            body: stream,
            duplex: "half",
          } as RequestInit);
          await assertRefused(res);
          expect(verified).toStrictEqual([]);
        });
      });

      it("stops reading at the limit when Content-Length understates the body", async () => {
        const { app, verified } = makeCountingBff();
        const { stream, state } = countingStream(paddedLogout(4 * 1024 * 1024));
        const res = await app.request("/auth/backchannel", {
          method: "POST",
          headers: { ...formHeaders, "content-length": "64" },
          body: stream,
          duplex: "half",
        } as RequestInit);
        await assertRefused(res);
        assert(
          state.pulled <= DEFAULT_LIMIT + CHUNK_BYTES,
          `read ${state.pulled} bytes past a ${DEFAULT_LIMIT}-byte limit`,
        );
        assert(state.cancelled, "the request body stream was not cancelled");
        expect(verified).toStrictEqual([]);
      });

      it("refuses a body whose Content-Length declares more than the limit without reading it", async () => {
        const { app, verified } = makeCountingBff();
        const { stream, state } = countingStream(paddedLogout(1024 * 1024));
        const res = await app.request("/auth/backchannel", {
          method: "POST",
          headers: { ...formHeaders, "content-length": `${1024 * 1024}` },
          body: stream,
          duplex: "half",
        } as RequestInit);
        await assertRefused(res);
        expect(state.pulled).toBe(0);
        expect(verified).toStrictEqual([]);
      });

      it("applies a configured maxBodyBytes", async () => {
        const { app, verified } = makeCountingBff(512);
        await withHttpServer(app, async (url) => {
          const atLimit = await fetch(url, {
            method: "POST",
            headers: formHeaders,
            body: paddedLogout(512),
          });
          await atLimit.body?.cancel();
          expect(atLimit.status).toBe(200);

          const overLimit = await fetch(url, {
            method: "POST",
            headers: formHeaders,
            body: paddedLogout(513),
          });
          await assertRefused(overLimit);
          expect(verified).toStrictEqual(["tok"]);
        });
      });

      it("logs out when an earlier middleware already parsed the body", async () => {
        const { bff, store } = makeBcBff(() => ({ sub: "user-1" }));
        const session = await seed(store, { user: { sub: "user-1" } });
        const app = new Hono();
        app.use(async (c, next) => {
          await c.req.parseBody();
          await next();
        });
        app.route("/auth", bff.routes());

        const res = await post(app, { logout_token: "tok" });
        await res.body?.cancel();
        expect(res.status).toBe(200);
        expect(await store.read(session)).toBe(null);
      });

      it("rejects a maxBodyBytes that is not a positive integer", () => {
        for (const maxBodyBytes of [0, -1, 1.5, Number.NaN, Infinity]) {
          thrown(
            () => makeBcBff(() => null, maxBodyBytes),
            RangeError,
            "maxBodyBytes",
          );
        }
      });
    });

    it("throws at construction with a stateless (incapable) store", () => {
      thrown(
        () =>
          new HonoBff({
            client: fixture.oauthClient,
            sessionStore: new EncryptedCookieSessionStore({
              secret: crypto.getRandomValues(new Uint8Array(32)),
            }),
            backchannelLogout: { verifyLogoutToken: () => ({ sub: "x" }) },
          }),
      );
    });
  });

  describe("deriveRedirectUri", () => {
    it("derives redirect_uri from the callback path at authorize AND matches it at exchange", async () => {
      const client = new DirectClient({
        clientId: testClient.id,
        clientSecret: CLIENT_SECRET,
        endpoints: {
          authorization: AUTHORIZE_URL,
          token: TOKEN_URL,
          revocation: REVOKE_URL,
        },
        fetch: localAuthServerFetch(fixture.authServer),
      });
      const bff = new HonoBff({
        client,
        cookie: { secure: false },
        defaultReturnTo: "/",
        csrf: false,
        deriveRedirectUri: true,
      });
      const app = makeApp(bff);

      const loginRes = await app.request("http://localhost/auth/login");
      const authorizeUrl = loginRes.headers.get("Location")!;
      expect(new URL(authorizeUrl).searchParams.get("redirect_uri")).toBe(
        "http://localhost/auth/callback",
      );

      const callback = await performAuthorizeRedirect(
        fixture.authServer,
        authorizeUrl,
      );
      const cbRes = await app.request(
        callback.slice(ISSUER.length),
        withCookies(undefined, jar(loginRes)),
      );
      expect(cbRes.status).toBe(302);
      expect(typeof cookieValue(cbRes, "oauth2_session")).toStrictEqual(
        "string",
      );
    });
  });

  describe("extra authorize parameters", () => {
    /** The authorize URL `/auth/login` produces, and its query parameters. */
    async function authorizeUrl(app: Hono, path = "/auth/login"): Promise<URL> {
      const res = await app.request(path);
      expect(res.status).toBe(302);
      const location = res.headers.get("Location")!;
      await res.body?.cancel();
      return new URL(location);
    }

    function paramNames(url: URL): string[] {
      return [...url.searchParams.keys()].sort();
    }

    it("sends only the client's own parameters when neither option is set", async () => {
      const url = await authorizeUrl(makeApp(makeBff()));
      expect(paramNames(url)).toStrictEqual(BASE_AUTHORIZE_PARAMS);
    });

    it("adds a configured extraParams entry to the authorize request", async () => {
      const app = makeApp(makeBff({ extraParams: { organization: "acme" } }));
      const url = await authorizeUrl(app);
      expect(url.searchParams.get("organization")).toStrictEqual("acme");
      expect(paramNames(url)).toStrictEqual(
        [...BASE_AUTHORIZE_PARAMS, "organization"].sort(),
      );
    });

    it("keeps a configured extraParams entry out of the browser's reach", async () => {
      const app = makeApp(makeBff({ extraParams: { organization: "acme" } }));
      const url = await authorizeUrl(app, "/auth/login?organization=evil");
      expect(url.searchParams.getAll("organization")).toStrictEqual(["acme"]);
    });

    it("drops a query parameter no option named", async () => {
      const url = await authorizeUrl(
        makeApp(makeBff()),
        "/auth/login?organization=acme",
      );
      expect(paramNames(url)).toStrictEqual(BASE_AUTHORIZE_PARAMS);
    });

    it("drops a query parameter when a different name is forwarded", async () => {
      const app = makeApp(makeBff({ forwardedParams: ["ui_locales"] }));
      const url = await authorizeUrl(app, "/auth/login?organization=acme");
      expect(paramNames(url)).toStrictEqual(BASE_AUTHORIZE_PARAMS);
    });

    it("forwards a query parameter forwardedParams names", async () => {
      const app = makeApp(makeBff({ forwardedParams: ["organization"] }));
      const url = await authorizeUrl(app, "/auth/login?organization=acme");
      expect(url.searchParams.get("organization")).toStrictEqual("acme");
      expect(paramNames(url)).toStrictEqual(
        [...BASE_AUTHORIZE_PARAMS, "organization"].sort(),
      );
    });

    it("omits a forwarded parameter the request did not carry", async () => {
      const app = makeApp(makeBff({ forwardedParams: ["organization"] }));
      const url = await authorizeUrl(app, "/auth/login?return_to=/dashboard");
      expect(paramNames(url)).toStrictEqual(BASE_AUTHORIZE_PARAMS);
    });

    it("sends one value for a forwarded parameter the request repeats", async () => {
      const app = makeApp(makeBff({ forwardedParams: ["organization"] }));
      const url = await authorizeUrl(
        app,
        "/auth/login?organization=acme&organization=evil",
      );
      expect(url.searchParams.getAll("organization")).toStrictEqual(["acme"]);
    });

    it("reads a forwarded parameter from the query string, not a POST body", async () => {
      const app = makeApp(makeBff({ forwardedParams: ["organization"] }));
      const res = await app.request("/auth/login", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: "organization=acme",
      });
      expect(res.status).toBe(302);
      const url = new URL(res.headers.get("Location")!);
      await res.body?.cancel();
      expect(paramNames(url)).toStrictEqual(BASE_AUTHORIZE_PARAMS);
    });

    it("percent-encodes a forwarded value instead of breaking the Location header", async () => {
      const app = makeApp(makeBff({ forwardedParams: ["organization"] }));
      const injection = "acme\r\nX-Injected: 1";
      const res = await app.request(
        `/auth/login?organization=${encodeURIComponent(injection)}`,
      );
      expect(res.status).toBe(302);
      const location = res.headers.get("Location")!;
      await res.body?.cancel();
      expect(/[\r\n]/.test(location)).toBeFalsy();
      expect(res.headers.get("x-injected")).toBe(null);
      expect(new URL(location).searchParams.get("organization")).toStrictEqual(
        injection,
      );
    });

    it("completes the sign-in the extra parameters rode along with", async () => {
      const app = makeApp(
        makeBff({
          extraParams: { ui_locales: "en" },
          forwardedParams: ["organization"],
        }),
      );
      const res = await completeLogin(
        app,
        "/auth/login?organization=acme&return_to=/welcome",
      );
      expect(res.headers.get("Location")).toBe("/welcome");
      expect(typeof cookieValue(res, "oauth2_session")).toStrictEqual("string");
    });

    for (const name of ["acr_values", "ACR_VALUES", "max_age", "MAX_AGE"]) {
      it(`refuses browser-chosen authentication control ${name}`, () => {
        thrown(() => makeBff({ forwardedParams: [name] }), Error);
      });
    }

    it("keeps authentication controls server-pinned despite browser overrides", async () => {
      const bff = makeBff({ extraParams: { acr_values: "mfa", max_age: "0" } });
      const app = makeApp(bff);
      const response = await app.request(
        "/auth/login?acr_values=single&max_age=9999",
      );
      const location = new URL(response.headers.get("location")!);
      await response.body?.cancel();
      expect(location.searchParams.get("acr_values")).toStrictEqual("mfa");
      expect(location.searchParams.get("max_age")).toStrictEqual("0");
    });

    for (const reserved of RESERVED_AUTHORIZE_PARAMS) {
      it(`refuses "${reserved}" in extraParams at construction`, () => {
        thrown(
          () => makeBff({ extraParams: { [reserved]: "x" } }),
          Error,
          `extraParams may not name the authorize parameter "${reserved}"`,
        );
      });

      it(`refuses "${reserved}" in forwardedParams at construction`, () => {
        thrown(
          () => makeBff({ forwardedParams: [reserved] }),
          Error,
          `forwardedParams may not name the authorize parameter "${reserved}"`,
        );
      });
    }

    it("matches a reserved name whatever its case", () => {
      thrown(
        () => makeBff({ forwardedParams: ["Redirect_URI"] }),
        Error,
        `forwardedParams may not name the authorize parameter "Redirect_URI"`,
      );
      thrown(
        () => makeBff({ extraParams: { CODE_CHALLENGE_METHOD: "plain" } }),
        Error,
        "may not name the authorize parameter",
      );
    });

    it("refuses a blank parameter name", () => {
      thrown(
        () => makeBff({ extraParams: { "": "x" } }),
        Error,
        'extraParams may not use "" as an authorize-parameter name',
      );
      thrown(
        () => makeBff({ forwardedParams: ["  "] }),
        Error,
        'forwardedParams may not use "  " as an authorize-parameter name',
      );
    });

    it("refuses a reserved name padded with whitespace", () => {
      for (const padded of [" state", "state\n", "STATE\t", "redirect_uri "]) {
        thrown(
          () => makeBff({ forwardedParams: [padded] }),
          Error,
          `forwardedParams may not use ${JSON.stringify(padded)} as an ` +
            "authorize-parameter name",
        );
      }
    });

    it("refuses a padded name that is not reserved at all", () => {
      thrown(
        () => makeBff({ forwardedParams: [" organization"] }),
        Error,
        'forwardedParams may not use " organization" as an ' +
          "authorize-parameter name",
      );
    });

    it("refuses a name that is both pinned and forwarded", () => {
      thrown(
        () =>
          makeBff({
            extraParams: { organization: "acme" },
            forwardedParams: ["organization"],
          }),
        Error,
        'forwardedParams may not list "organization" while extraParams sets ' +
          '"organization"',
      );
    });

    it("refuses a forwarded name that only differs in case from a pinned one", () => {
      thrown(
        () =>
          makeBff({
            extraParams: { organization: "acme" },
            forwardedParams: ["Organization"],
          }),
        Error,
        'forwardedParams may not list "Organization" while extraParams sets ' +
          '"organization"',
      );
    });

    it("ignores a name pushed onto forwardedParams after construction", async () => {
      const names = ["organization"];
      const app = makeApp(makeBff({ forwardedParams: names }));
      names.push("redirect_uri");
      const url = await authorizeUrl(
        app,
        "/auth/login?organization=acme&redirect_uri=" +
          encodeURIComponent("https://evil.example.com/steal"),
      );
      expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
      expect(url.searchParams.get("organization")).toStrictEqual("acme");
      expect(paramNames(url)).toStrictEqual(
        [...BASE_AUTHORIZE_PARAMS, "organization"].sort(),
      );
    });

    it("ignores an entry added to extraParams after construction", async () => {
      const pinned: Record<string, string> = { organization: "acme" };
      const app = makeApp(makeBff({ extraParams: pinned }));
      pinned.redirect_uri = "https://evil.example.com/steal";
      const url = await authorizeUrl(app);
      expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
      expect(paramNames(url)).toStrictEqual(
        [...BASE_AUTHORIZE_PARAMS, "organization"].sort(),
      );
    });

    it("does not carry one request's forwarded value into the next", async () => {
      const app = makeApp(makeBff({ forwardedParams: ["organization"] }));
      const attacker = await authorizeUrl(
        app,
        "/auth/login?organization=attacker-org",
      );
      expect(attacker.searchParams.get("organization")).toStrictEqual(
        "attacker-org",
      );

      const victim = await authorizeUrl(app, "/auth/login");
      expect(victim.searchParams.has("organization")).toBeFalsy();
      expect(paramNames(victim)).toStrictEqual(BASE_AUTHORIZE_PARAMS);
    });

    it("gives a second request its own value for the same forwarded name", async () => {
      const app = makeApp(makeBff({ forwardedParams: ["organization"] }));
      const first = await authorizeUrl(app, "/auth/login?organization=first");
      expect(first.searchParams.getAll("organization")).toStrictEqual([
        "first",
      ]);

      const second = await authorizeUrl(app, "/auth/login?organization=second");
      expect(second.searchParams.getAll("organization")).toStrictEqual([
        "second",
      ]);
      expect(paramNames(second)).toStrictEqual(
        [...BASE_AUTHORIZE_PARAMS, "organization"].sort(),
      );
    });

    it("keeps concurrent sign-ins' forwarded values apart", async () => {
      const app = makeApp(makeBff({ forwardedParams: ["organization"] }));
      const [alice, bob] = await Promise.all([
        authorizeUrl(app, "/auth/login?organization=alice-org"),
        authorizeUrl(app, "/auth/login?organization=bob-org"),
      ]);
      expect(alice.searchParams.getAll("organization")).toStrictEqual([
        "alice-org",
      ]);
      expect(bob.searchParams.getAll("organization")).toStrictEqual([
        "bob-org",
      ]);
    });

    it("does not confuse an inherited property name for a pinned one", async () => {
      const app = makeApp(
        makeBff({ extraParams: {}, forwardedParams: ["toString"] }),
      );
      const url = await authorizeUrl(app, "/auth/login?toString=ok");
      expect(url.searchParams.get("toString")).toStrictEqual("ok");
    });

    it("forwards an explicitly allowed prototype setter name", async () => {
      const app = makeApp(makeBff({ forwardedParams: ["__proto__"] }));
      const url = await authorizeUrl(app, "/auth/login?__proto__=configured");
      expect(url.searchParams.getAll("__proto__")).toStrictEqual([
        "configured",
      ]);
    });

    it("preserves a pinned prototype setter name", async () => {
      const app = makeApp(
        makeBff({
          extraParams: { ["__proto__"]: "configured" },
        }),
      );
      const url = await authorizeUrl(app, "/auth/login?__proto__=untrusted");
      expect(url.searchParams.getAll("__proto__")).toStrictEqual([
        "configured",
      ]);
    });

    it("ignores a scope the browser puts on the login URL", async () => {
      const app = makeApp(makeBff({ scope: "openid profile" }));
      const url = await authorizeUrl(app, "/auth/login?scope=openid+admin");
      expect(url.searchParams.getAll("scope")).toStrictEqual([
        "openid profile",
      ]);
    });

    it("requests no scope when the browser asks for one and none is configured", async () => {
      const url = await authorizeUrl(
        makeApp(makeBff()),
        "/auth/login?scope=admin",
      );
      expect(paramNames(url)).toStrictEqual(BASE_AUTHORIZE_PARAMS);
    });

    it("ignores a prompt the browser puts on the login URL", async () => {
      const url = await authorizeUrl(
        makeApp(makeBff()),
        "/auth/login?prompt=none",
      );
      expect(url.searchParams.has("prompt")).toBeFalsy();
      expect(paramNames(url)).toStrictEqual(BASE_AUTHORIZE_PARAMS);
    });

    it("sends the configured scope when the browser asks for none", async () => {
      const app = makeApp(makeBff({ scope: "openid profile" }));
      const url = await authorizeUrl(app, "/auth/login?return_to=/dashboard");
      expect(url.searchParams.getAll("scope")).toStrictEqual([
        "openid profile",
      ]);
    });

    it("forwards a scope when forwardedParams names it", async () => {
      const app = makeApp(
        makeBff({ scope: "openid profile", forwardedParams: ["scope"] }),
      );
      const url = await authorizeUrl(app, "/auth/login?scope=openid+email");
      expect(url.searchParams.getAll("scope")).toStrictEqual(["openid email"]);
      expect(paramNames(url)).toStrictEqual(
        [...BASE_AUTHORIZE_PARAMS, "scope"].sort(),
      );
    });

    it("falls back to the configured scope when a forwarding request omits it", async () => {
      const app = makeApp(
        makeBff({ scope: "openid profile", forwardedParams: ["scope"] }),
      );
      const url = await authorizeUrl(app, "/auth/login?return_to=/dashboard");
      expect(url.searchParams.getAll("scope")).toStrictEqual([
        "openid profile",
      ]);
    });

    it("keeps the configured scope when a forwarding request sends an empty scope", async () => {
      const app = makeApp(
        makeBff({ scope: "openid profile", forwardedParams: ["scope"] }),
      );
      const url = await authorizeUrl(app, "/auth/login?scope=");
      expect(url.searchParams.getAll("scope")).toStrictEqual([
        "openid profile",
      ]);
      expect(paramNames(url)).toStrictEqual(
        [...BASE_AUTHORIZE_PARAMS, "scope"].sort(),
      );
    });

    it("records the configured scope when a forwarding request sends an empty scope", async () => {
      const records = new Map<string, AuthRequestRecord>();
      const storage: AuthRequestStorage = {
        set: (state, value) => {
          records.set(state, value);
        },
        get: (state) => records.get(state) ?? null,
        delete: (state) => {
          records.delete(state);
        },
        clear: () => {
          records.clear();
        },
      };
      const app = makeApp(
        makeBff({
          scope: "openid profile",
          forwardedParams: ["scope"],
          authRequestStorage: { forRequest: () => storage },
        }),
      );
      const url = await authorizeUrl(app, "/auth/login?scope=");
      const state = url.searchParams.get("state")!;
      expect(records.get(state)?.scope).toStrictEqual("openid profile");
    });

    it("records a forwarded scope as the scope the authorization requested", async () => {
      const records = new Map<string, AuthRequestRecord>();
      const storage: AuthRequestStorage = {
        set: (state, value) => {
          records.set(state, value);
        },
        get: (state) => records.get(state) ?? null,
        delete: (state) => {
          records.delete(state);
        },
        clear: () => {
          records.clear();
        },
      };
      const app = makeApp(
        makeBff({
          scope: "openid profile",
          forwardedParams: ["scope"],
          authRequestStorage: { forRequest: () => storage },
        }),
      );
      const url = await authorizeUrl(app, "/auth/login?scope=openid+email");
      const state = url.searchParams.get("state")!;
      expect(records.get(state)?.scope).toStrictEqual("openid email");
    });

    it("sends one scope when a forwarded name differs from it only in case", async () => {
      const app = makeApp(
        makeBff({ scope: "openid profile", forwardedParams: ["Scope"] }),
      );
      const url = await authorizeUrl(app, "/auth/login?Scope=openid+email");
      expect(url.searchParams.getAll("scope")).toStrictEqual(["openid email"]);
      expect(url.searchParams.has("Scope")).toBeFalsy();
    });

    it("forwards a prompt when forwardedParams names it", async () => {
      const app = makeApp(makeBff({ forwardedParams: ["prompt"] }));
      const url = await authorizeUrl(app, "/auth/login?prompt=login");
      expect(url.searchParams.getAll("prompt")).toStrictEqual(["login"]);
    });

    it("keeps a pinned prompt out of the browser's reach", async () => {
      const app = makeApp(makeBff({ extraParams: { prompt: "consent" } }));
      const url = await authorizeUrl(app, "/auth/login?prompt=none");
      expect(url.searchParams.getAll("prompt")).toStrictEqual(["consent"]);
    });

    it("sends one prompt when a pinned name differs from it only in case", async () => {
      const app = makeApp(makeBff({ extraParams: { Prompt: "consent" } }));
      const url = await authorizeUrl(app, "/auth/login?prompt=none");
      expect(url.searchParams.getAll("prompt")).toStrictEqual(["consent"]);
      expect(url.searchParams.has("Prompt")).toBeFalsy();
    });

    it("refuses a pinned scope beside the scope option", () => {
      thrown(
        () =>
          makeBff({
            scope: "openid",
            extraParams: { scope: "openid email" },
          }),
        Error,
        'extraParams may not set "scope" while HonoBffOptions.scope is set',
      );
    });

    it("refuses a pinned scope that differs from the option only in case", () => {
      thrown(
        () =>
          makeBff({
            scope: "openid",
            extraParams: { Scope: "openid email" },
          }),
        Error,
        'extraParams may not set "Scope" while HonoBffOptions.scope is set',
      );
    });
  });

  describe("login handler", () => {
    it("forwards prompt=none once forwardedParams names prompt (silent renew)", async () => {
      const bff = makeBff({ forwardedParams: ["prompt"] });
      const app = makeApp(bff);
      const res = await app.request("/auth/login?prompt=none&return_to=/x");
      expect(res.status).toBe(302);
      const url = new URL(res.headers.get("Location")!);
      expect(url.searchParams.get("prompt")).toBe("none");
      await res.body?.cancel();
    });

    it("redirects to the authorize endpoint with PKCE + return_to preserved", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const res = await app.request("/auth/login?return_to=/dashboard");
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get("Location")!);
      expect(location.origin + location.pathname).toBe(AUTHORIZE_URL);
      expect(location.searchParams.get("response_type")).toBe("code");
      expect(location.searchParams.get("client_id")).toBe(testClient.id);
      expect(location.searchParams.get("code_challenge_method")).toBe("S256");
      expect(typeof location.searchParams.get("state")).toStrictEqual("string");
      expect(typeof location.searchParams.get("code_challenge")).toStrictEqual(
        "string",
      );
    });
  });

  describe("callback handler", () => {
    it("exchanges the code, sets a session cookie, and redirects to return_to", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const res = await completeLogin(app, "/auth/login?return_to=/welcome");
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/welcome");

      const sess = cookieValue(res, "oauth2_session");
      expect(typeof sess).toStrictEqual("string");
    });

    it("falls back to defaultReturnTo when the authorize request didn't carry one", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const res = await completeLogin(app);
      expect(res.headers.get("Location")).toBe("/home");
    });

    it("returns a JSON error when the callback URL carries ?error=...", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const res = await app.request(
        "/auth/callback?error=access_denied&error_description=nope&state=x",
      );
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe("access_denied");
    });

    it("returns a friendly 400 (not an unhandled 500) when the code exchange fails", async () => {
      const bff = makeBff();
      const app = makeApp(bff);
      const { state, cookies } = await beginLogin(app);
      const res = await app.request(
        `/auth/callback?code=nope&state=${state}`,
        withCookies(undefined, cookies),
      );
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_grant");
    });

    it("routes callback failures through onCallbackError when provided", async () => {
      const seen: string[] = [];
      const bff = makeBff({
        onCallbackError: (c, { error }) => {
          seen.push(error);
          return c.redirect(`/sign-in?error=${error}`);
        },
      });
      const app = makeApp(bff);

      const { state, cookies } = await beginLogin(app);
      const grantRes = await app.request(
        `/auth/callback?code=nope&state=${state}`,
        withCookies(undefined, cookies),
      );
      expect(grantRes.status).toBe(302);
      expect(grantRes.headers.get("Location")).toBe(
        "/sign-in?error=invalid_grant",
      );

      const idpRes = await app.request(
        "/auth/callback?error=access_denied&state=x",
      );
      expect(idpRes.headers.get("Location")).toBe(
        "/sign-in?error=access_denied",
      );
      const missingRes = await app.request("/auth/callback");
      expect(missingRes.headers.get("Location")).toBe(
        "/sign-in?error=invalid_request",
      );

      expect(seen).toStrictEqual([
        "invalid_grant",
        "access_denied",
        "invalid_request",
      ]);
    });

    it("ignores an external return_to and falls back (open-redirect guard)", async () => {
      const bff = makeBff();
      const app = makeApp(bff);
      const res = await completeLogin(
        app,
        `/auth/login?return_to=${encodeURIComponent("https://evil.example/x")}`,
      );
      expect(res.headers.get("Location")).toBe("/home");
    });
  });

  describe("a sign-in in a browser that already holds a session", () => {
    class LiveSessionStore extends MemorySessionStore {
      readonly live = new Set<string>();
      failCreate = false;
      failDestroy = false;

      override async create(data: SessionData): Promise<string> {
        if (this.failCreate) throw new Error("store unavailable");
        const cookieValue = await super.create(data);
        this.live.add(cookieValue);
        return cookieValue;
      }

      override async destroy(cookieValue: string): Promise<void> {
        if (this.failDestroy) throw new Error("store unavailable");
        await super.destroy(cookieValue);
        this.live.delete(cookieValue);
      }
    }

    async function signInAgain(
      app: Hono,
      earlier: string,
      loginPath = "/auth/login",
    ): Promise<Response> {
      return await completeLogin(app, loginPath, {
        headers: { cookie: `oauth2_session=${earlier}` },
      });
    }

    async function probe(app: Hono, value: string): Promise<boolean> {
      const res = await app.request("/auth/session", {
        headers: { cookie: `oauth2_session=${value}` },
      });
      return (await res.json()).isAuthenticated;
    }

    it("destroys the session it replaces, so the earlier cookie reads as signed out", async () => {
      const store = new LiveSessionStore();
      const app = makeApp(makeBff({ sessionStore: store }));
      const earlier = cookieValue(await completeLogin(app), "oauth2_session")!;

      const res = await signInAgain(app, earlier);
      expect(res.status).toBe(302);
      const current = cookieValue(res, "oauth2_session")!;

      expect(current).not.toBe(earlier);
      expect(await store.read(earlier)).toBe(null);
      expect(await probe(app, earlier)).toBeFalsy();
      assert(await probe(app, current));
      expect([...store.live]).toStrictEqual([current]);
    });

    it("leaves no session behind once the replacing session signs out", async () => {
      const store = new LiveSessionStore();
      const app = makeApp(makeBff({ sessionStore: store }));
      const earlier = cookieValue(await completeLogin(app), "oauth2_session")!;
      const current = cookieValue(
        await signInAgain(app, earlier, "/auth/login?return_to=/switched"),
        "oauth2_session",
      )!;

      const out = await app.request("/auth/logout", {
        headers: { cookie: `oauth2_session=${current}` },
      });
      expect(out.status).toBe(302);

      expect(store.live.size).toStrictEqual(0);
      expect(await probe(app, earlier)).toBeFalsy();
      expect(await probe(app, current)).toBeFalsy();
    });

    it("does not revoke the replaced session's refresh token, which can share the new session's sign-in at the authorization server", async () => {
      const store = new LiveSessionStore();
      const app = makeApp(makeBff({ sessionStore: store }));
      const earlier = cookieValue(await completeLogin(app), "oauth2_session")!;
      const refreshToken = (await store.read(earlier))!.refreshToken!;

      await (await signInAgain(app, earlier)).body?.cancel();

      assert(await fixture.tokenService.getRefreshToken(refreshToken));
    });

    it("keeps the session when the authorization server returns an error instead of a code", async () => {
      const store = new LiveSessionStore();
      const app = makeApp(makeBff({ sessionStore: store }));
      const earlier = cookieValue(await completeLogin(app), "oauth2_session")!;
      const { state, cookies } = await beginLogin(app);

      const res = await app.request(
        `/auth/callback?error=invalid_request&state=${state}`,
        withCookies(
          { headers: { cookie: `oauth2_session=${earlier}` } },
          cookies,
        ),
      );
      expect(res.status).toBe(400);
      await res.body?.cancel();

      assert(await probe(app, earlier));
      expect([...store.live]).toStrictEqual([earlier]);
    });

    it("keeps the session when the code exchange fails", async () => {
      const store = new LiveSessionStore();
      const app = makeApp(makeBff({ sessionStore: store }));
      const earlier = cookieValue(await completeLogin(app), "oauth2_session")!;
      const { state, cookies } = await beginLogin(app);

      const res = await app.request(
        `/auth/callback?code=nope&state=${state}`,
        withCookies(
          { headers: { cookie: `oauth2_session=${earlier}` } },
          cookies,
        ),
      );
      expect(res.status).toBe(400);
      await res.body?.cancel();

      assert(await probe(app, earlier));
      expect([...store.live]).toStrictEqual([earlier]);
    });

    it("keeps the session when the callback's state was not started in this browser", async () => {
      const store = new LiveSessionStore();
      const app = makeApp(makeBff({ sessionStore: store }));
      const earlier = cookieValue(await completeLogin(app), "oauth2_session")!;
      const { callbackPath } = await beginLogin(app);

      const res = await app.request(callbackPath, {
        headers: { cookie: `oauth2_session=${earlier}` },
      });
      expect(res.status).toBe(400);
      await res.body?.cancel();

      assert(await probe(app, earlier));
      expect([...store.live]).toStrictEqual([earlier]);
    });

    it("keeps the session when resolveUser fails", async () => {
      const store = new LiveSessionStore();
      let directoryDown = false;
      const app = makeApp(
        makeBff({
          sessionStore: store,
          resolveUser: (_tokens, user) => {
            if (directoryDown) throw new Error("directory unavailable");
            return user;
          },
        }),
      );
      const earlier = cookieValue(await completeLogin(app), "oauth2_session")!;
      directoryDown = true;

      const res = await signInAgain(app, earlier);
      expect(res.status).toBe(400);
      await res.body?.cancel();

      assert(await probe(app, earlier));
      expect([...store.live]).toStrictEqual([earlier]);
    });

    it("keeps only the earlier session when destroying it fails, never two", async () => {
      const store = new LiveSessionStore();
      const app = makeApp(makeBff({ sessionStore: store }));
      const earlier = cookieValue(await completeLogin(app), "oauth2_session")!;
      store.failDestroy = true;

      const res = await signInAgain(app, earlier);
      expect(res.status).toBe(400);
      await res.body?.cancel();

      expect([...store.live]).toStrictEqual([earlier]);
    });

    it("leaves the browser signed out when creating the replacement fails", async () => {
      const store = new LiveSessionStore();
      const app = makeApp(makeBff({ sessionStore: store }));
      const earlier = cookieValue(await completeLogin(app), "oauth2_session")!;
      store.failCreate = true;

      const res = await signInAgain(app, earlier);
      expect(res.status).toBe(400);
      await res.body?.cancel();

      expect(await probe(app, earlier)).toBeFalsy();
      expect(store.live.size).toStrictEqual(0);
    });

    it("signs in when the cookie the browser brings names no session", async () => {
      const store = new LiveSessionStore();
      const app = makeApp(makeBff({ sessionStore: store }));

      const res = await signInAgain(app, "not-a-session");
      expect(res.status).toBe(302);
      const current = cookieValue(res, "oauth2_session")!;

      assert(await probe(app, current));
      expect([...store.live]).toStrictEqual([current]);
    });

    it("signs in over a stateless session, replacing the cookie that carried it", async () => {
      const store = new EncryptedCookieSessionStore({
        secret: crypto.getRandomValues(new Uint8Array(32)),
      });
      const app = makeApp(makeBff({ sessionStore: store }));
      const earlier = cookieValue(await completeLogin(app), "oauth2_session")!;

      const res = await signInAgain(app, earlier);
      expect(res.status).toBe(302);
      const current = cookieValue(res, "oauth2_session")!;

      expect(current).not.toBe(earlier);
      assert(await probe(app, current));
    });
  });

  describe("session-sharing mode", () => {
    it("attaches tokens to the app's existing session instead of minting its own", async () => {
      const sharedStore = new MemorySessionStore();
      const now = Date.now();
      const loginSessionId = await sharedStore.create({
        tokens: { accessToken: "", tokenType: "Bearer" },
        createdAt: now,
        updatedAt: now,
      });

      const bff = makeBff({
        sessionStore: sharedStore,
        sessionMode: "shared",
        cookie: { name: "session_id", secure: false },
      });
      const app = makeApp(bff);

      const cbRes = await completeLogin(app, "/auth/login?return_to=/welcome", {
        headers: { cookie: `session_id=${loginSessionId}` },
      });
      expect(cbRes.status).toBe(302);

      expect(
        cookieValue(cbRes, "session_id"),
        "the app's cookie is unchanged, so re-stamping it would only replace the app's attributes",
      ).toBe(undefined);
      const stored = await sharedStore.read(loginSessionId);
      expect((stored?.tokens.accessToken?.length ?? 0) > 0).toStrictEqual(true);
    });

    it("keeps a remember-me cookie's attributes by never re-setting an unchanged value", async () => {
      const sharedStore = new MemorySessionStore();
      const now = Date.now();
      const loginSessionId = await sharedStore.create({
        tokens: { accessToken: "", tokenType: "Bearer" },
        createdAt: now,
        updatedAt: now,
      });
      const { tokenService } = fixture;
      tokenService.accessTokenLifetime = 1;
      const bff = makeBff({
        sessionStore: sharedStore,
        sessionMode: "shared",
        cookie: { name: "session_id", secure: false },
        refreshSkewSeconds: 60,
      });
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService } }),
      });
      const app = makeApp(bff);
      app.use("/api/*", bff.attachToken(), resourceServer.protect());
      app.get("/api/me", (c) => c.json({ ok: true }));

      await completeLogin(app, "/auth/login?return_to=/welcome", {
        headers: { cookie: `session_id=${loginSessionId}` },
      });
      const refreshed = await app.request("/api/me", {
        headers: { cookie: `session_id=${loginSessionId}`, "x-csrf": "1" },
      });
      expect(refreshed.status).toBe(200);
      expect(
        refreshed.headers.get("set-cookie"),
        "a token refresh that keeps the cookie value must not re-stamp the cookie either",
      ).toBe(null);
      const stored = await sharedStore.read(loginSessionId);
      expect((stored?.tokens.accessToken?.length ?? 0) > 0).toStrictEqual(true);
    });

    it("falls back to creating a session when no cookie is present at callback", async () => {
      const sharedStore = new MemorySessionStore();
      const bff = makeBff({
        sessionStore: sharedStore,
        sessionMode: "shared",
        sessionMaxAgeMs: 60 * 1000,
        cookie: { name: "session_id", secure: false },
      });
      const app = makeApp(bff);

      const cbRes = await completeLogin(app);
      expect(cbRes.status).toBe(302);
      expect(typeof cookieValue(cbRes, "session_id")).toStrictEqual("string");
    });
  });

  describe("session probe", () => {
    it("returns isAuthenticated=false when there's no cookie", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const res = await app.request("/auth/session");
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body).toStrictEqual({ isAuthenticated: false, user: null });
    });

    it("returns isAuthenticated=true and the user claims after login", async () => {
      const bff = makeBff({
        resolveUser: () => ({ id: "user-1", plan: "enterprise" }),
      });
      const app = makeApp(bff);

      const cbRes = await completeLogin(app);
      const sess = cookieValue(cbRes, "oauth2_session")!;

      const res = await app.request("/auth/session", {
        headers: { cookie: `oauth2_session=${sess}` },
      });
      const body = await res.json();
      expect(body.isAuthenticated).toBe(true);
      expect(body.user).toStrictEqual({ id: "user-1", plan: "enterprise" });
    });
  });

  describe("readSession", () => {
    function makeRenderingApp(bff: HonoBff): Hono {
      const app = makeApp(bff);
      app.get("/page", async (c) => c.json(await bff.readSession(c)));
      return app;
    }

    it("reports nobody signed in when the request carries no session cookie", async () => {
      const app = makeRenderingApp(makeBff());

      const res = await app.request("/page");

      expect(await res.json()).toStrictEqual({
        isAuthenticated: false,
        user: null,
        sessionExpiresIn: null,
        logoutUrl: null,
      });
      expect(res.headers.get("set-cookie")).toBe(null);
    });

    it("reports the signed-in user, when the token expires and how to sign out, and no token", async () => {
      const bff = makeBff({
        resolveUser: () => ({ sub: testUser.id, plan: "enterprise" }),
      });
      const app = makeRenderingApp(bff);
      const cookie = await loginCookie(app);

      const res = await app.request("/page", { headers: { cookie } });

      const session = await res.json();
      expect(Object.keys(session).sort()).toStrictEqual([
        "isAuthenticated",
        "logoutUrl",
        "sessionExpiresIn",
        "user",
      ]);
      expect(session.isAuthenticated).toBe(true);
      expect(session.user).toStrictEqual({
        sub: testUser.id,
        plan: "enterprise",
      });
      expect(session.logoutUrl).toBe("/auth/logout");
      assert(
        session.sessionExpiresIn > 0,
        `sessionExpiresIn was ${session.sessionExpiresIn}`,
      );
    });

    it("answers what the session probe answers for the same session", async () => {
      const bff = makeBff();
      const app = makeRenderingApp(bff);
      const cookie = await loginCookie(app);

      const probed = await (
        await app.request("/auth/session", {
          headers: { cookie },
        })
      ).json();
      const read = await (
        await app.request("/page", { headers: { cookie } })
      ).json();

      expect(read).toStrictEqual(probed);
    });

    it("needs no CSRF header, because it never answers a browser directly", async () => {
      const bff = makeCsrfBff();
      const app = makeRenderingApp(bff);
      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
      });

      const probe = await app.request("/auth/session", { headers: { cookie } });
      await probe.body?.cancel();
      expect(probe.status).toBe(403);
      const res = await app.request("/page", { headers: { cookie } });
      expect((await res.json()).isAuthenticated).toBe(true);
    });

    it("reports nobody signed in for a cookie the store no longer holds", async () => {
      const app = makeRenderingApp(makeBff());

      const res = await app.request("/page", {
        headers: { cookie: "oauth2_session=forgotten" },
      });

      expect((await res.json()).isAuthenticated).toBe(false);
    });

    it("destroys a session older than sessionMaxAgeMs and clears its cookie", async () => {
      const store = new MemorySessionStore();
      const bff = makeBff({ sessionStore: store, sessionMaxAgeMs: 60 * 1000 });
      const app = makeRenderingApp(bff);
      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
        createdAt: Date.now() - 61_000,
      });

      const res = await app.request("/page", { headers: { cookie } });

      expect((await res.json()).isAuthenticated).toBe(false);
      expect(res.headers.getSetCookie().join("\n")).toContain("Max-Age=0");
      expect(await store.read(cookie.split("=")[1])).toBe(null);
    });

    it("keeps a session younger than sessionMaxAgeMs without touching its cookie", async () => {
      const bff = makeBff({ sessionMaxAgeMs: 60 * 1000 });
      const app = makeRenderingApp(bff);
      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
        createdAt: Date.now() - 59_000,
      });

      const res = await app.request("/page", { headers: { cookie } });

      expect((await res.json()).isAuthenticated).toBe(true);
      expect(res.headers.get("set-cookie")).toBe(null);
    });

    it("leaves the session's age to the app in sessionMode: shared", async () => {
      const bff = makeBff({
        sessionMode: "shared",
        sessionMaxAgeMs: 60 * 1000,
        cookie: { name: "session_id", secure: false },
      });
      const app = makeRenderingApp(bff);
      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
        createdAt: Date.now() - 3_600_000,
      });

      const res = await app.request("/page", { headers: { cookie } });

      expect((await res.json()).isAuthenticated).toBe(true);
    });

    it("sets no caching policy, leaving the page's own to the app", async () => {
      const bff = makeBff();
      const app = makeRenderingApp(bff);
      const cookie = await loginCookie(app);

      const res = await app.request("/page", { headers: { cookie } });
      await res.body?.cancel();

      expect(res.headers.get("cache-control")).toBe(null);
    });
  });

  describe("logout handler", () => {
    it("destroys the session, clears the cookie, and redirects", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
      });

      const res = await app.request("/auth/logout", {
        method: "POST",
        headers: { cookie },
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/home");
      const cleared = res.headers.get("set-cookie") ?? "";
      expect(cleared.includes("oauth2_session=")).toStrictEqual(true);
      expect(await readTestSession(bff, cookie)).toBe(null);

      const probe = await app.request("/auth/session", { headers: { cookie } });
      expect(await probe.json()).toStrictEqual({
        isAuthenticated: false,
        user: null,
      });
    });

    it("is reachable via GET (the React client navigates here) and clears the session", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const cookie = await createTestSession(bff, {
        user: { sub: testUser.id },
      });

      const res = await app.request("/auth/logout", { headers: { cookie } });
      expect(res.status).toBe(302);
      expect(
        (res.headers.get("set-cookie") ?? "").includes("oauth2_session="),
      ).toStrictEqual(true);
      expect(await readTestSession(bff, cookie)).toBe(null);

      const probe = await app.request("/auth/session", { headers: { cookie } });
      expect(await probe.json()).toStrictEqual({
        isAuthenticated: false,
        user: null,
      });
    });

    it("ignores an external return_to (open-redirect guard)", async () => {
      const bff = makeBff();
      const app = makeApp(bff);
      for (const evil of [
        "https://evil.example/x",
        "//evil.example",
        "/\\evil.example",
      ]) {
        const res = await app.request(
          `/auth/logout?return_to=${encodeURIComponent(evil)}`,
        );
        expect(res.status).toBe(302);
        expect(res.headers.get("Location")).toBe("/home");
      }
    });
  });

  describe("routes mounting", () => {
    it("registers under the default /auth base", async () => {
      const app = makeApp(makeBff());
      expect((await app.request("/auth/session")).status).toBe(200);
      expect((await app.request("/session")).status).toBe(404);
    });

    it("registers under a configured basePath", async () => {
      const bff = makeBff({
        paths: {
          basePath: "/session",
          login: "/session/login",
          callback: "/session/callback",
          logout: "/session/logout",
          session: "/session/whoami",
          backchannel: "/session/backchannel",
        },
      });
      const app = new Hono();
      app.route("/session", bff.routes());

      expect((await app.request("/session/whoami")).status).toBe(200);
      expect((await app.request("/session/session/whoami")).status).toBe(404);
    });

    it("mounts the configured paths verbatim when basePath is empty", async () => {
      const bff = makeBff({ paths: { basePath: "" } });
      const app = new Hono();
      app.route("", bff.routes());

      expect((await app.request("/auth/session")).status).toBe(200);
      expect((await app.request("/session")).status).toBe(404);
    });

    it("ignores a trailing slash on basePath instead of double-prefixing", async () => {
      const app = makeApp(makeBff({ paths: { basePath: "/auth/" } }));
      expect((await app.request("/auth/session")).status).toBe(200);
      expect((await app.request("/auth/auth/session")).status).toBe(404);
    });
  });

  describe("path validation", () => {
    it("rejects a path that falls outside a non-empty basePath", () => {
      const error = thrown(
        () =>
          makeBff({
            paths: {
              basePath: "/session",
              login: "/session/login",
              callback: "/session/callback",
              logout: "/session/logout",
              session: "/whoami",
              backchannel: "/session/backchannel",
            },
          }),
        Error,
        'session ("/whoami")',
      );
      expect(error.message).toContain('basePath "/session"');
    });

    it("rejects a path equal to basePath", () => {
      thrown(
        () => makeBff({ paths: { basePath: "/auth", session: "/auth" } }),
        Error,
        'session ("/auth")',
      );
    });

    it("ignores the backchannel path while back-channel logout is off", async () => {
      const app = makeApp(
        makeBff({ paths: { basePath: "/auth", backchannel: "/elsewhere" } }),
      );
      expect((await app.request("/auth/session")).status).toBe(200);
      expect((await app.request("/elsewhere")).status).toBe(404);
    });

    it("checks the backchannel path once back-channel logout is on", () => {
      thrown(
        () =>
          makeBff({
            backchannelLogout: {
              verifyLogoutToken: () => Promise.resolve({ sub: "u1" }),
            },
            paths: { basePath: "/auth", backchannel: "/elsewhere" },
          }),
        Error,
        'backchannel ("/elsewhere")',
      );
    });
  });

  describe("attachToken middleware", () => {
    it("attaches Authorization: Bearer to in-process API calls", async () => {
      const bff = makeBff();
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService: fixture.tokenService } }),
      });
      const app = new Hono();
      app.route("/auth", bff.routes());
      app.use("/api/*", bff.attachToken(), resourceServer.protect());
      app.get("/api/me", (c) => c.json(resourceServer.getContext(c).user));

      const cookie = await protectedSession(bff);

      const res = await app.request("/api/me", { headers: { cookie } });
      expect(res.status).toBe(200);
      const user = await res.json();
      expect(user.id).toBe(testUser.id);
    });

    it("attaches Authorization even when raw request headers are immutable", async () => {
      const bff = makeBff();
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService: fixture.tokenService } }),
      });
      const app = new Hono();
      app.route("/auth", bff.routes());
      app.use("/api/*", bff.attachToken(), resourceServer.protect());
      app.get("/api/me", (c) => c.json(resourceServer.getContext(c).user));

      const cookie = await protectedSession(bff);

      const req = new Request("http://localhost/api/me", {
        headers: { cookie },
      });
      req.headers.set = () => {
        throw new TypeError("Cannot change headers: headers are immutable");
      };

      const res = await app.fetch(req);
      expect(res.status).toBe(200);
      const user = await res.json();
      expect(user.id).toBe(testUser.id);
    });

    it("refreshes the access token when it's near expiry and updates the session", async () => {
      const { tokenService } = fixture;
      tokenService.accessTokenLifetime = 1;

      const bff = new HonoBff({
        client: fixture.oauthClient,
        cookie: { secure: false },
        defaultReturnTo: "/",
        refreshSkewSeconds: 60,
      });

      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService } }),
      });
      const app = new Hono();
      app.route("/auth", bff.routes());
      app.use("/api/*", bff.attachToken(), resourceServer.protect());
      app.get("/api/me", (c) => c.json({ ok: true }));

      const cbRes = await completeLogin(app);
      const sess = cookieValue(cbRes, "oauth2_session")!;

      const res = await app.request("/api/me", {
        headers: { cookie: `oauth2_session=${sess}`, "x-csrf": "1" },
      });
      expect(res.status).toBe(200);

      expect(
        res.headers.get("set-cookie"),
        "a stateful store keeps the cookie value, so nothing needs re-setting",
      ).toBe(null);
      const refreshed = await bff.sessionStore.read(sess);
      expect((refreshed?.tokens.accessToken?.length ?? 0) > 0).toStrictEqual(
        true,
      );
    });

    it("re-sets the cookie when a stateless store rotates its value on refresh", async () => {
      const { tokenService } = fixture;
      tokenService.accessTokenLifetime = 1;

      const bff = new HonoBff({
        client: fixture.oauthClient,
        cookie: { secure: false },
        defaultReturnTo: "/",
        refreshSkewSeconds: 60,
        sessionStore: new EncryptedCookieSessionStore({
          secret: "0123456789abcdef0123456789abcdef",
        }),
      });
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService } }),
      });
      const app = new Hono();
      app.route("/auth", bff.routes());
      app.use("/api/*", bff.attachToken(), resourceServer.protect());
      app.get("/api/me", (c) => c.json({ ok: true }));

      const cbRes = await completeLogin(app);
      const sess = cookieValue(cbRes, "oauth2_session")!;

      const res = await app.request("/api/me", {
        headers: { cookie: `oauth2_session=${sess}`, "x-csrf": "1" },
      });
      expect(res.status).toBe(200);
      const rotated = cookieValue(res, "oauth2_session");
      expect(typeof rotated).toStrictEqual("string");
      expect(rotated !== sess).toStrictEqual(true);
    });

    it("keeps the session's sid across a refresh so back-channel logout still matches", async () => {
      const { tokenService } = fixture;
      tokenService.accessTokenLifetime = 1;

      const store = new MemorySessionStore();
      const bff = new HonoBff({
        client: fixture.oauthClient,
        cookie: { secure: false },
        defaultReturnTo: "/",
        csrf: false,
        refreshSkewSeconds: 60,
        sessionStore: store,
        backchannelLogout: { verifyLogoutToken: () => ({ sid: "S1" }) },
      });

      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService } }),
      });
      const app = new Hono();
      app.route("/auth", bff.routes());
      app.use("/api/*", bff.attachToken(), resourceServer.protect());
      app.get("/api/me", (c) => c.json({ ok: true }));

      const cbRes = await completeLogin(app);
      const sess = cookieValue(cbRes, "oauth2_session")!;

      const seeded = (await store.read(sess))!;
      await store.update(sess, { ...seeded, sid: "S1" });

      const apiRes = await app.request("/api/me", {
        headers: { cookie: `oauth2_session=${sess}` },
      });
      expect(apiRes.status).toBe(200);
      await apiRes.body?.cancel();

      const afterRefresh = (await store.read(sess))!;
      expect(afterRefresh.tokens.accessToken).not.toBe(
        seeded.tokens.accessToken,
      );

      const logoutRes = await app.request("/auth/backchannel", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ logout_token: "tok" }),
      });
      expect(logoutRes.status).toBe(200);
      await logoutRes.body?.cancel();

      expect(await store.read(sess)).toBe(null);
    });
  });

  describe("protect convenience", () => {
    it("composes attachToken + resourceServer.protect against a HonoResourceServer", async () => {
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService: fixture.tokenService } }),
      });
      const bff = makeBff({ resourceServer });

      const app = new Hono();
      app.route("/auth", bff.routes());
      app.use("/api/*", bff.protect());
      app.get("/api/me", (c) => c.json(resourceServer.getContext(c).user));

      const cookie = await protectedSession(bff);

      const res = await app.request("/api/me", { headers: { cookie } });
      expect(res.status).toBe(200);
      const user = await res.json();
      expect(user.id).toBe(testUser.id);
    });

    it("composes against a HonoAuthorizationServer (own-issuer topology)", async () => {
      const honoAuthServer = new HonoAuthorizationServer({
        resolve: () => ({
          services: {
            clientService: fixture.clientService,
            tokenService: fixture.tokenService,
          },
          issuer: ISSUER,
          tokenEndpoint: TOKEN_URL,
          authorizationEndpoint: AUTHORIZE_URL,
          revocationEndpoint: REVOKE_URL,
        }),
        grants: fixture.authServer.grants,
      });
      const bff = makeBff({ resourceServer: honoAuthServer });
      const app = new Hono();
      app.route("/auth", bff.routes());
      app.use("/api/*", bff.protect());
      app.get("/api/whoami", (c) => c.text("ok"));

      const cookie = await protectedSession(bff);

      const res = await app.request("/api/whoami", { headers: { cookie } });
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });

    it("authenticates the session against a resolve-configured resource server using the real host", async () => {
      const otherUserService = new MemoryUserService();
      const otherClientService = new MemoryClientService(otherUserService);
      const emptyTokenService = new MemoryTokenService({
        clientService: otherClientService,
        userService: otherUserService,
      });
      const resourceServer = new HonoResourceServer({
        resolve: (request) => ({
          services: {
            tokenService:
              new URL(request.url).hostname === "tenant-ok.local"
                ? fixture.tokenService
                : emptyTokenService,
          },
        }),
      });
      const bff = makeBff({ resourceServer });
      const app = new Hono();
      app.route("/auth", bff.routes());
      app.use("/api/*", bff.protect());
      app.get("/api/me", (c) => c.json(resourceServer.getContext(c).user));

      const cookie = await protectedSession(bff);

      const ok = await app.request("http://tenant-ok.local/api/me", {
        headers: { cookie },
      });
      expect(ok.status).toBe(200);
      expect((await ok.json()).id).toBe(testUser.id);

      const bad = await app.request("http://tenant-bad.local/api/me", {
        headers: { cookie },
      });
      expect(bad.status).toBe(401);
      await bad.body?.cancel();
    });

    it("works after an upstream middleware has already consumed the request body", async () => {
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService: fixture.tokenService } }),
      });
      const bff = makeBff({ resourceServer });
      const app = new Hono();
      app.route("/auth", bff.routes());
      app.use("/api/*", async (c, next) => {
        if (c.req.method !== "GET" && c.req.method !== "HEAD") {
          await c.req.json().catch(() => undefined);
        }
        await next();
      });
      app.use("/api/*", bff.protect());
      app.post("/api/echo", async (c) => {
        const body = await c.req.json().catch(() => null);
        return c.json({
          sub: (resourceServer.getContext(c).user as { id: string }).id,
          received: body,
        });
      });

      const cookie = await protectedSession(bff);

      const res = await app.request("/api/echo", {
        method: "POST",
        headers: { cookie, "content-type": "application/json" },
        body: JSON.stringify({ hello: "world" }),
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.sub).toStrictEqual(testUser.id);
      expect(body.received).toStrictEqual({ hello: "world" });
    });

    it("returns 401 when no session cookie is attached", async () => {
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService: fixture.tokenService } }),
      });
      const bff = makeBff({ resourceServer });
      const app = new Hono();
      app.use("/api/*", bff.protect());
      app.get("/api/me", (c) => c.text("forbidden zone"));

      const res = await app.request("/api/me");
      expect(res.status).toBe(401);
    });

    it("accepts a direct Authorization: Bearer token (machine-to-machine) with no session cookie", async () => {
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService: fixture.tokenService } }),
      });
      const bff = makeBff({ resourceServer });
      const app = new Hono();
      app.use("/api/*", bff.protect());
      app.get("/api/me", (c) => c.json(resourceServer.getContext(c).user));

      const cookie = await protectedSession(bff);
      const accessToken = (await readTestSession(bff, cookie))!.tokens
        .accessToken;

      const res = await app.request("/api/me", {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(res.status).toBe(200);
      expect((await res.json()).id).toBe(testUser.id);
    });

    it("rejects an invalid inbound bearer token with 401", async () => {
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService: fixture.tokenService } }),
      });
      const bff = makeBff({ resourceServer });
      const app = new Hono();
      app.use("/api/*", bff.protect());
      app.get("/api/me", (c) => c.text("forbidden zone"));

      const res = await app.request("/api/me", {
        headers: { authorization: "Bearer not-a-real-token" },
      });
      expect(res.status).toBe(401);
    });

    it("rejects with a clear error when constructed without resourceServer", () => {
      const bff = makeBff();
      let thrown: unknown;
      try {
        bff.protect();
      } catch (err) {
        thrown = err;
      }
      expect(thrown instanceof Error).toStrictEqual(true);
      expect(
        (thrown as Error).message.includes("resourceServer"),
      ).toStrictEqual(true);
    });

    it("requireScope rejects with a clear error when constructed without resourceServer", () => {
      const bff = makeBff();
      let thrown: unknown;
      try {
        bff.requireScope("read");
      } catch (err) {
        thrown = err;
      }
      expect(thrown instanceof Error).toStrictEqual(true);
      expect(
        (thrown as Error).message.includes("resourceServer"),
      ).toStrictEqual(true);
    });

    it("requireScope delegates to the configured resource server's guard", () => {
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService: fixture.tokenService } }),
      });
      const bff = makeBff({ resourceServer });
      expect(typeof bff.requireScope("read")).toBe("function");
    });
  });

  describe("login-state binding", () => {
    it("binds the state to the browser with an HttpOnly, SameSite=Lax cookie carrying a Max-Age", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const res = await app.request("/auth/login");
      await res.body?.cancel();

      const cookie = res.headers
        .getSetCookie()
        .find((c) => c.startsWith(`${bff.loginStateCookieName}=`))!;
      expect(typeof cookie).toStrictEqual("string");
      expect(cookie).toContain("HttpOnly");
      expect(cookie).toContain("SameSite=Lax");
      expect(cookie).toContain("Max-Age=600");
      expect(cookie).toContain("Path=/");
    });

    it("names the login-state cookie __Host- and marks it Secure by default", () => {
      const bff = new HonoBff({ client: fixture.oauthClient });
      expect(bff.loginStateCookieName).toBe("__Host-oauth2_login_state");
    });

    it("honors loginStateTtlMs as the login-state cookie's Max-Age", async () => {
      const bff = makeBff({ loginStateTtlMs: 90_000 });
      const app = makeApp(bff);

      const res = await app.request("/auth/login");
      await res.body?.cancel();

      expect(res.headers.getSetCookie().join("\n")).toContain("Max-Age=90");
    });

    it("rejects a callback whose browser carries no login-state cookie", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const { callbackPath } = await beginLogin(app);
      const res = await app.request(callbackPath);

      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_request");
      expect(cookieValue(res, "oauth2_session")).toBe(undefined);
    });

    it("rejects a callback whose login-state cookie is for a different browser's sign-in", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const attacker = await beginLogin(app);
      const victim = await beginLogin(app);

      const res = await app.request(
        attacker.callbackPath,
        withCookies(undefined, victim.cookies),
      );

      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_request");
      expect(
        cookieValue(res, "oauth2_session"),
        "a login the victim's browser never started must not open a session",
      ).toBe(undefined);
    });

    it("attaches nothing to an existing shared session when the state is unvouched", async () => {
      const sharedStore = new MemorySessionStore();
      const now = Date.now();
      const appSessionId = await sharedStore.create({
        tokens: { accessToken: "", tokenType: "Bearer" },
        createdAt: now,
        updatedAt: now,
      });
      const bff = makeBff({
        sessionStore: sharedStore,
        sessionMode: "shared",
        cookie: { name: "session_id", secure: false },
      });
      const app = makeApp(bff);

      const attacker = await beginLogin(app);
      const res = await app.request(attacker.callbackPath, {
        headers: { cookie: `session_id=${appSessionId}` },
      });

      expect(res.status).toBe(400);
      expect(
        (await sharedStore.read(appSessionId))?.tokens.accessToken,
        "the attacker's grant must never land on the victim's session row",
      ).toBe("");
    });

    it("clears the login-state cookie once the callback completes", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const res = await completeLogin(app);
      await res.body?.cancel();

      expect(res.status).toBe(302);
      const cleared = res.headers
        .getSetCookie()
        .find((c) => c.startsWith(`${bff.loginStateCookieName}=`))!;
      expect(cleared).toContain("Max-Age=0");
    });

    it("refuses to replay a state the callback already consumed", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const { callbackPath, cookies } = await beginLogin(app);
      const first = await app.request(
        callbackPath,
        withCookies(undefined, cookies),
      );
      await first.body?.cancel();
      expect(first.status).toBe(302);

      const replay = await app.request(
        callbackPath,
        withCookies(undefined, jar(first)),
      );
      expect(replay.status).toBe(400);
      expect((await replay.json()).error).toBe("invalid_request");
    });

    it("keeps sign-ins started in several tabs completable", async () => {
      const bff = makeBff();
      const app = makeApp(bff);

      const firstTab = await beginLogin(app, "/auth/login?return_to=/first");
      const secondTab = await app.request(
        "/auth/login?return_to=/second",
        withCookies(undefined, firstTab.cookies),
      );
      await secondTab.body?.cancel();
      const secondCallback = await performAuthorizeRedirect(
        fixture.authServer,
        secondTab.headers.get("Location")!,
      );
      const browser = jar(secondTab);

      const second = await app.request(
        secondCallback.slice(ISSUER.length),
        withCookies(undefined, browser),
      );
      await second.body?.cancel();
      expect(second.headers.get("Location")).toBe("/second");

      const first = await app.request(
        firstTab.callbackPath,
        withCookies(undefined, jar(second)),
      );
      await first.body?.cancel();
      expect(
        first.headers.get("Location"),
        "the tab that started first must still be able to finish",
      ).toBe("/first");
    });
  });

  describe("cache headers", () => {
    it("marks every auth route no-store and Vary: Cookie", async () => {
      const bff = makeBff();
      const app = makeApp(bff);
      const cookie = await loginCookie(app);

      const responses = {
        login: await app.request("/auth/login"),
        callback: await app.request("/auth/callback"),
        session: await app.request("/auth/session", { headers: { cookie } }),
        logout: await app.request("/auth/logout", {
          headers: { cookie, "sec-fetch-site": "same-origin" },
        }),
      };

      for (const [route, res] of Object.entries(responses)) {
        await res.body?.cancel();
        expect(
          res.headers.get("cache-control"),
          `${route} must not be cached`,
        ).toBe("no-store");
        expect(res.headers.get("vary"), route).toBe("Cookie");
      }
    });
  });

  describe("transient refresh failures", () => {
    function unavailableBff(
      extra: Partial<ConstructorParameters<typeof HonoBff>[0]> = {},
    ): HonoBff {
      return new HonoBff({
        client: new DirectClient({
          clientId: testClient.id,
          clientSecret: CLIENT_SECRET,
          redirectUri: REDIRECT_URI,
          endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
          fetch: () => Promise.reject(new TypeError("connection reset")),
        }),
        cookie: { secure: false },
        csrf: false,
        refreshSkewSeconds: 60,
        ...extra,
      });
    }

    async function expiringSession(bff: HonoBff): Promise<string> {
      return await createTestSession(bff, {
        refreshToken: "refresh-1",
        tokens: { accessTokenExpiresAt: Date.now() + 5_000 },
      });
    }

    it("answers 502 from attachToken instead of signing the user out", async () => {
      const store = new MemorySessionStore();
      const bff = unavailableBff({ sessionStore: store });
      const cookie = await expiringSession(bff);
      const app = new Hono();
      app.use("/api/*", bff.attachToken());
      app.get("/api/me", (c) => c.json({ ok: true }));

      const res = await app.request("/api/me", { headers: { cookie } });

      expect(res.status).toBe(502);
      expect((await res.json()).error).toBe("temporarily_unavailable");
      expect(res.headers.get("set-cookie")).toBe(null);
      expect(
        (await store.read(cookie.split("=")[1])) !== null,
        "one bad minute at the IdP must not end the session",
      ).toStrictEqual(true);
    });

    it("answers 502 from protect instead of signing the user out", async () => {
      const resourceServer = new HonoResourceServer({
        resolve: () => ({ services: { tokenService: fixture.tokenService } }),
      });
      const store = new MemorySessionStore();
      const bff = unavailableBff({ sessionStore: store, resourceServer });
      const cookie = await expiringSession(bff);
      const app = new Hono();
      app.use("/api/*", bff.protect());
      app.get("/api/me", (c) => c.json({ ok: true }));

      const res = await app.request("/api/me", { headers: { cookie } });

      expect(res.status).toBe(502);
      expect((await res.json()).error).toBe("temporarily_unavailable");
      expect((await store.read(cookie.split("=")[1])) !== null).toStrictEqual(
        true,
      );
    });
  });

  describe("session store swap", () => {
    it("is usable as a drop-in for MemorySessionStore", async () => {
      const encrypted = new EncryptedCookieSessionStore({
        secret: crypto.getRandomValues(new Uint8Array(32)),
      });
      const bff = makeBff({ sessionStore: encrypted });
      const app = makeApp(bff);

      const probe = await app.request("/auth/session", {
        headers: { cookie: await loginCookie(app) },
      });
      const body = await probe.json();
      expect(body.isAuthenticated).toBe(true);
    });
  });
});
