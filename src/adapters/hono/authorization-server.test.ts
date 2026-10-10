import { assert, beforeEach, describe, expect, it } from "vitest";
import { Hono } from "hono";

import { BasicScope } from "../../models/scope.ts";
import {
  challengeMethods,
  generateCodeChallenge,
  generateCodeVerifier,
} from "../../utils/pkce.ts";
import { AuthorizationCodeGrant } from "../../server/grants/authorization-code.ts";
import { ClientCredentialsGrant } from "../../server/grants/client-credentials.ts";
import {
  basicAuthHeader,
  formRequestInit,
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../../testing/_test_fixtures.ts";

import {
  ENDPOINT_METHODS,
  ENDPOINT_PATHS,
} from "../../server/authorization-server.ts";

import { HonoAuthorizationServer } from "./authorization-server.ts";

const testUser: TestUser = { id: "user-1", username: "testuser" };
const testClient: TestClient = {
  id: "client-1",
  confidential: true,
  grants: ["client_credentials", "authorization_code"],
  redirectUris: ["https://example.com/callback"],
};
const otherClient: TestClient = {
  id: "client-2",
  confidential: true,
  grants: ["client_credentials"],
  redirectUris: ["https://other.example.com/callback"],
};

function createTestServices() {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  const authorizationCodeService = new MemoryAuthorizationCodeService({
    clientService,
    userService,
  });
  return { userService, clientService, tokenService, authorizationCodeService };
}

function createTestServer() {
  const services = createTestServices();

  const clientCredentialsGrant = new ClientCredentialsGrant({
    resolve: () => ({
      clientService: services.clientService,
      tokenService: services.tokenService,
    }),
  });

  const authorizationCodeGrant = new AuthorizationCodeGrant({
    resolve: () => ({
      clientService: services.clientService,
      tokenService: services.tokenService,
      authorizationCodeService: services.authorizationCodeService,
    }),
    requirePKCE: false,
  });

  const server = new HonoAuthorizationServer({
    resolve: () => ({
      services: {
        clientService: services.clientService,
        tokenService: services.tokenService,
      },
      issuer: "https://auth.example.com",
      tokenEndpoint: "https://auth.example.com/oauth2/token",
      authorizationEndpoint: "https://auth.example.com/oauth2/authorize",
    }),
    grants: {
      client_credentials: clientCredentialsGrant,
      authorization_code: authorizationCodeGrant,
    },
    scopesSupported: ["read", "write"],
  });

  return { server, ...services };
}

describe("HonoAuthorizationServer", () => {
  let server: ReturnType<typeof createTestServer>["server"];

  beforeEach(async () => {
    const result = createTestServer();
    server = result.server;
    await result.userService.add(testUser, "password");
    await result.clientService.add(testClient, "secret", testUser.id);
  });

  describe("routes()", () => {
    it("mounts exactly the paths and verbs the endpoint table declares", () => {
      const app = server.routes({
        authenticateUser: () => Promise.resolve({ user: testUser }),
      });
      const expected = Object.entries(ENDPOINT_PATHS)
        .flatMap(([key, path]) =>
          ENDPOINT_METHODS[key as keyof typeof ENDPOINT_PATHS].map(
            (method) => `${method} ${path}`,
          ),
        )
        .sort();
      expect(
        app.routes.map(({ method, path }) => `${method} ${path}`).sort(),
      ).toStrictEqual(expected);
    });

    it("tables the discovery documents' paths and each endpoint's verbs", () => {
      expect(ENDPOINT_PATHS.metadata).toBe(
        "/.well-known/oauth-authorization-server",
      );
      expect(ENDPOINT_PATHS.oidcMetadata).toBe(
        "/.well-known/openid-configuration",
      );
      expect([...ENDPOINT_METHODS.metadata]).toStrictEqual(["GET"]);
      expect([...ENDPOINT_METHODS.token]).toStrictEqual(["POST"]);
      expect([...ENDPOINT_METHODS.userinfo]).toStrictEqual(["GET", "POST"]);
    });

    it("mounts all standard endpoints under the configured base path", async () => {
      const app = new Hono();
      app.route(
        "/oauth2",
        server.routes({
          authenticateUser: () =>
            Promise.resolve({
              user: testUser,
              authorizedScope: new BasicScope("read"),
            }),
        }),
      );

      const metadata = await app.request(
        "/oauth2/.well-known/oauth-authorization-server",
      );
      expect(metadata.status).toBe(200);
      const body = await metadata.json();
      expect(body.issuer).toBe("https://auth.example.com");
      expect(
        body.grant_types_supported.includes("client_credentials"),
      ).toStrictEqual(true);
    });

    it("tokenHandler: issues an access token via client credentials", async () => {
      const app = new Hono();
      app.route(
        "/oauth2",
        server.routes({
          authenticateUser: () => Promise.resolve({ user: testUser }),
        }),
      );

      const res = await app.request(
        "/oauth2/token",
        formRequestInit(
          { grant_type: "client_credentials" },
          basicAuthHeader("client-1", "secret"),
        ),
      );

      expect(res.status).toBe(200);
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      const body = await res.json();
      expect(body.token_type).toBe("Bearer");
      expect(typeof body.access_token).toBe("string");
    });

    it("authorizeHandler: passes the Hono context to authenticateUser", async () => {
      const app = new Hono();
      let contextSeen = false;
      app.route(
        "/oauth2",
        server.routes({
          authenticateUser: (c) => {
            contextSeen =
              typeof c.req.url === "string" &&
              c.req.url.includes("/oauth2/authorize");
            return Promise.resolve({
              user: testUser,
              authorizedScope: new BasicScope("read"),
            });
          },
        }),
      );

      const url = new URL("http://localhost/oauth2/authorize");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", "client-1");
      url.searchParams.set("state", "xyz");
      url.searchParams.set("scope", "read");
      url.searchParams.set("redirect_uri", "https://example.com/callback");

      const res = await app.request(url.pathname + url.search);

      expect(res.status).toBe(302);
      const location = res.headers.get("Location");
      expect(
        location?.startsWith("https://example.com/callback?"),
      ).toStrictEqual(true);
      expect(location?.includes("code=")).toStrictEqual(true);
      expect(location?.includes("state=xyz")).toStrictEqual(true);
      expect(contextSeen).toBe(true);
    });

    it("authorizeHandler: passes the Hono context to handleConsent", async () => {
      const app = new Hono();
      let consentContextSeen = false;
      app.route(
        "/oauth2",
        server.routes({
          authenticateUser: () =>
            Promise.resolve({
              user: testUser,
              authorizedScope: new BasicScope("read"),
            }),
          handleConsent: (c, _client, _scope, _user) => {
            consentContextSeen = typeof c.req.url === "string";
            return Promise.resolve({ approved: true });
          },
        }),
      );

      const url = new URL("http://localhost/oauth2/authorize");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", "client-1");
      url.searchParams.set("state", "xyz");
      url.searchParams.set("scope", "write");
      url.searchParams.set("redirect_uri", "https://example.com/callback");

      const res = await app.request(url.pathname + url.search);
      expect(res.status).toBe(302);
      expect(consentContextSeen).toBe(true);
    });

    it("authorizeHandler: returns Response from authenticateUser as-is", async () => {
      const app = new Hono();
      app.route(
        "/oauth2",
        server.routes({
          authenticateUser: (c) => {
            return Promise.resolve(
              c.redirect("/login?return_to=%2Foauth2%2Fauthorize"),
            );
          },
        }),
      );

      const url = new URL("http://localhost/oauth2/authorize");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", "client-1");
      url.searchParams.set("state", "xyz");
      url.searchParams.set("redirect_uri", "https://example.com/callback");

      const res = await app.request(url.pathname + url.search);
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe(
        "/login?return_to=%2Foauth2%2Fauthorize",
      );
    });

    it("authorizeHandler: returns Response from handleConsent as-is", async () => {
      const app = new Hono();
      app.route(
        "/oauth2",
        server.routes({
          authenticateUser: () =>
            Promise.resolve({
              user: testUser,
              authorizedScope: new BasicScope(""),
            }),
          handleConsent: (c) => Promise.resolve(c.html("<h1>Consent</h1>")),
        }),
      );

      const url = new URL("http://localhost/oauth2/authorize");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", "client-1");
      url.searchParams.set("state", "xyz");
      url.searchParams.set("scope", "write");
      url.searchParams.set("redirect_uri", "https://example.com/callback");

      const res = await app.request(url.pathname + url.search);
      expect(res.status).toBe(200);
      expect(
        res.headers.get("Content-Type")?.startsWith("text/html"),
      ).toStrictEqual(true);
      expect(await res.text()).toBe("<h1>Consent</h1>");
    });

    it("revocationHandler: returns 200 for unknown token per RFC 7009", async () => {
      const app = new Hono();
      app.route(
        "/oauth2",
        server.routes({
          authenticateUser: () => Promise.resolve({ user: testUser }),
        }),
      );

      const res = await app.request(
        "/oauth2/revoke",
        formRequestInit(
          { token: "nonexistent" },
          basicAuthHeader("client-1", "secret"),
        ),
      );

      expect(res.status).toBe(200);
    });

    it("introspectionHandler: returns active=false for unknown token", async () => {
      const app = new Hono();
      app.route(
        "/oauth2",
        server.routes({
          authenticateUser: () => Promise.resolve({ user: testUser }),
        }),
      );

      const res = await app.request(
        "/oauth2/introspect",
        formRequestInit(
          { token: "nope" },
          basicAuthHeader("client-1", "secret"),
        ),
      );

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.active).toBe(false);
    });
  });

  describe("revocation endpoint (RFC 7009)", () => {
    async function createRevocationApp() {
      const result = createTestServer();
      await result.userService.add(testUser, "password");
      await result.clientService.add(testClient, "secret", testUser.id);
      await result.clientService.add(otherClient, "other-secret", testUser.id);

      const app = new Hono();
      app.route(
        "/oauth2",
        result.server.routes({
          authenticateUser: () => Promise.resolve({ user: testUser }),
        }),
      );
      return { app, ...result };
    }

    function revoke(
      app: Hono,
      fields: Record<string, string>,
      clientId: string,
      clientSecret: string,
    ) {
      return app.request(
        "/oauth2/revoke",
        formRequestInit(fields, basicAuthHeader(clientId, clientSecret)),
      );
    }

    async function saveTokens(
      tokenService: MemoryTokenService<TestClient, TestUser, BasicScope>,
      client: TestClient,
      prefix: string,
    ) {
      await tokenService.save({
        accessToken: `${prefix}-access`,
        accessTokenExpiresAt: new Date(Date.now() + 3600_000),
        refreshToken: `${prefix}-refresh`,
        refreshTokenExpiresAt: new Date(Date.now() + 86_400_000),
        client,
        user: testUser,
        scope: new BasicScope("read"),
      });
    }

    it("leaves another client's access token alone and still answers 200", async () => {
      const { app, tokenService } = await createRevocationApp();
      await saveTokens(tokenService, otherClient, "victim");

      const res = await revoke(
        app,
        { token: "victim-access" },
        "client-1",
        "secret",
      );

      expect(res.status).toBe(200);
      assert.exists(await tokenService.getToken("victim-access"));
    });

    it("leaves another client's refresh token alone and still answers 200", async () => {
      const { app, tokenService } = await createRevocationApp();
      await saveTokens(tokenService, otherClient, "victim");

      const res = await revoke(
        app,
        { token: "victim-refresh", token_type_hint: "refresh_token" },
        "client-1",
        "secret",
      );

      expect(res.status).toBe(200);
      assert.exists(await tokenService.getRefreshToken("victim-refresh"));
    });

    it("revokes the authenticated client's own access token", async () => {
      const { app, tokenService } = await createRevocationApp();
      await saveTokens(tokenService, testClient, "mine");

      const res = await revoke(
        app,
        { token: "mine-access" },
        "client-1",
        "secret",
      );

      expect(res.status).toBe(200);
      expect(await tokenService.getToken("mine-access")).toBe(undefined);
    });

    it("revokes a refresh token presented with the wrong token_type_hint", async () => {
      const { app, tokenService } = await createRevocationApp();
      await saveTokens(tokenService, testClient, "mine");

      const res = await revoke(
        app,
        { token: "mine-refresh", token_type_hint: "access_token" },
        "client-1",
        "secret",
      );

      expect(res.status).toBe(200);
      expect(await tokenService.getRefreshToken("mine-refresh")).toBe(
        undefined,
      );
    });
  });

  describe("introspection endpoint (RFC 7662)", () => {
    async function createIntrospectionApp() {
      const result = createTestServer();
      await result.userService.add(testUser, "password");
      await result.clientService.add(testClient, "secret", testUser.id);

      const app = new Hono();
      app.route(
        "/oauth2",
        result.server.routes({
          authenticateUser: () => Promise.resolve({ user: testUser }),
        }),
      );

      const refreshTokenExpiresAt = new Date(Date.now() + 86_400_000);
      await result.tokenService.save({
        accessToken: "expired-access",
        accessTokenExpiresAt: new Date(Date.now() - 1000),
        refreshToken: "live-refresh",
        refreshTokenExpiresAt,
        client: testClient,
        user: testUser,
        scope: new BasicScope("read"),
      });

      return { app, refreshTokenExpiresAt, ...result };
    }

    function introspect(app: Hono, fields: Record<string, string>) {
      return app.request(
        "/oauth2/introspect",
        formRequestInit(fields, basicAuthHeader("client-1", "secret")),
      );
    }

    it("reports a live refresh token as active, expiring on its own expiry", async () => {
      const { app, refreshTokenExpiresAt } = await createIntrospectionApp();

      const res = await introspect(app, {
        token: "live-refresh",
        token_type_hint: "refresh_token",
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.active).toBe(true);
      expect(body.client_id).toBe("client-1");
      expect(body.scope).toBe("read");
      expect(body.exp).toBe(Math.floor(refreshTokenExpiresAt.getTime() / 1000));
    });

    it("resolves a refresh token whose token_type_hint names the other type", async () => {
      const { app } = await createIntrospectionApp();

      const res = await introspect(app, {
        token: "live-refresh",
        token_type_hint: "access_token",
      });

      expect((await res.json()).active).toBe(true);
    });

    it("omits token_type for a refresh token and names Bearer for an access token", async () => {
      const { app, tokenService } = await createIntrospectionApp();
      await tokenService.save({
        accessToken: "live-access",
        accessTokenExpiresAt: new Date(Date.now() + 3600_000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read"),
      });

      const refresh = await introspect(app, { token: "live-refresh" });
      const refreshBody = await refresh.json();
      expect(refreshBody.active).toBe(true);
      expect(refreshBody.token_type).toBe(undefined);

      const access = await introspect(app, { token: "live-access" });
      expect((await access.json()).token_type).toBe("Bearer");
    });

    it("reports a revoked refresh token as inactive", async () => {
      const { app, tokenService } = await createIntrospectionApp();
      await tokenService.revoke("live-refresh", "refresh_token");

      const res = await introspect(app, {
        token: "live-refresh",
        token_type_hint: "refresh_token",
      });

      expect((await res.json()).active).toBe(false);
    });

    it("reports an expired access token as inactive", async () => {
      const { app } = await createIntrospectionApp();

      const res = await introspect(app, { token: "expired-access" });

      expect((await res.json()).active).toBe(false);
    });
  });

  describe("code_challenge format (RFC 7636 Section 4.2)", () => {
    function authorizeUrl(params: Record<string, string>): string {
      const url = new URL("http://localhost/oauth2/authorize");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", "client-1");
      url.searchParams.set("state", "xyz");
      url.searchParams.set("scope", "read");
      url.searchParams.set("redirect_uri", "https://example.com/callback");
      for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
      }
      return url.pathname + url.search;
    }

    function authorizeApp(
      authorizationServer: ReturnType<typeof createTestServer>["server"],
    ): Hono {
      const app = new Hono();
      app.route(
        "/oauth2",
        authorizationServer.routes({
          authenticateUser: () =>
            Promise.resolve({
              user: testUser,
              authorizedScope: new BasicScope("read"),
            }),
        }),
      );
      return app;
    }

    it("refuses an S256 code_challenge outside the 43-128 unreserved characters", async () => {
      const res = await authorizeApp(server).request(
        authorizeUrl({
          code_challenge: "too-short",
          code_challenge_method: "S256",
        }),
      );

      expect(res.status).toBe(302);
      const location = new URL(res.headers.get("Location")!);
      expect(location.searchParams.get("error")).toBe("invalid_request");
      expect(location.searchParams.get("code")).toBe(null);
    });

    it("accepts an S256 code_challenge of the length RFC 7636 fixes", async () => {
      const res = await authorizeApp(server).request(
        authorizeUrl({
          code_challenge: await generateCodeChallenge(generateCodeVerifier()),
          code_challenge_method: "S256",
        }),
      );

      expect(res.status).toBe(302);
      assert.exists(
        new URL(res.headers.get("Location")!).searchParams.get("code"),
      );
    });

    it("leaves the challenge shape to a server that registered its own challenge method", async () => {
      const services = createTestServices();
      await services.userService.add(testUser, "password");
      await services.clientService.add(testClient, "secret", testUser.id);
      const customServer = new HonoAuthorizationServer({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
          issuer: "https://auth.example.com",
        }),
        grants: {
          authorization_code: new AuthorizationCodeGrant({
            resolve: () => ({
              clientService: services.clientService,
              tokenService: services.tokenService,
              authorizationCodeService: services.authorizationCodeService,
            }),
            challengeMethods: {
              "first-8": (verifier) => Promise.resolve(verifier.slice(0, 8)),
            },
          }),
        },
      });

      const res = await authorizeApp(customServer).request(
        authorizeUrl({
          code_challenge: "abcdefgh",
          code_challenge_method: "first-8",
        }),
      );

      expect(res.status).toBe(302);
      assert.exists(
        new URL(res.headers.get("Location")!).searchParams.get("code"),
      );
    });
  });

  describe("metadata PKCE advertisement (RFC 8414)", () => {
    it("advertises every own challenge method the authorization code grant accepts", async () => {
      const services = createTestServices();
      const plainOnPrototype = {
        plain: (verifier: string) => Promise.resolve(verifier),
      };
      const grant = new AuthorizationCodeGrant<
        TestClient,
        TestUser,
        BasicScope
      >({
        resolve: () => ({
          clientService: services.clientService,
          tokenService: services.tokenService,
          authorizationCodeService: services.authorizationCodeService,
        }),
        challengeMethods: Object.assign(Object.create(plainOnPrototype), {
          S256: challengeMethods.S256,
          "S256-alt": challengeMethods.S256,
        }),
      });
      const metadataServer = new HonoAuthorizationServer({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
          issuer: "https://auth.example.com",
        }),
        grants: { authorization_code: grant },
      });

      const res = await metadataServer.handleMetadataRequest(
        new Request(
          "https://auth.example.com/.well-known/oauth-authorization-server",
        ),
      );

      expect((await res.json()).code_challenge_methods_supported).toStrictEqual(
        ["S256", "S256-alt"],
      );
    });

    it("omits code_challenge_methods_supported without an authorization code grant", async () => {
      const services = createTestServices();
      const metadataServer = new HonoAuthorizationServer({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
          issuer: "https://auth.example.com",
        }),
        grants: {
          client_credentials: new ClientCredentialsGrant({
            resolve: () => ({
              clientService: services.clientService,
              tokenService: services.tokenService,
            }),
          }),
        },
      });

      const res = await metadataServer.handleMetadataRequest(
        new Request(
          "https://auth.example.com/.well-known/oauth-authorization-server",
        ),
      );

      expect((await res.json()).code_challenge_methods_supported).toBe(
        undefined,
      );
    });
  });

  describe("individual handler factories", () => {
    it("can be mounted individually at custom paths", async () => {
      const app = new Hono();
      app.post("/custom/token", server.tokenHandler());
      app.get("/custom/meta", server.metadataHandler());

      const metaRes = await app.request("/custom/meta");
      expect(metaRes.status).toBe(200);
      const meta = await metaRes.json();
      expect(meta.issuer).toBe("https://auth.example.com");

      const tokenRes = await app.request(
        "/custom/token",
        formRequestInit(
          { grant_type: "client_credentials" },
          basicAuthHeader("client-1", "secret"),
        ),
      );
      expect(tokenRes.status).toBe(200);
    });
  });

  describe("protect() inherited from resource-server adapter", () => {
    it("protects a route on the same Hono app with a token issued here", async () => {
      const app = new Hono();
      app.route(
        "/oauth2",
        server.routes({
          authenticateUser: () => Promise.resolve({ user: testUser }),
        }),
      );
      app.use("/api/*", server.protect());
      app.get("/api/me", (c) => {
        const ctx = server.getContext(c);
        return c.json({ clientId: ctx.client.id });
      });

      const tokenRes = await app.request(
        "/oauth2/token",
        formRequestInit(
          { grant_type: "client_credentials" },
          basicAuthHeader("client-1", "secret"),
        ),
      );
      const { access_token } = await tokenRes.json();

      const apiRes = await app.request("/api/me", {
        headers: { Authorization: `Bearer ${access_token}` },
      });

      expect(apiRes.status).toBe(200);
      const body = await apiRes.json();
      expect(body.clientId).toBe("client-1");
    });
  });

  describe("requireScope() inherited from resource-server adapter", () => {
    it("enforces per-route scopes after a single protect()", async () => {
      const app = new Hono();
      app.route(
        "/oauth2",
        server.routes({
          authenticateUser: () => Promise.resolve({ user: testUser }),
        }),
      );
      app.use("/api/*", server.protect());
      app.get("/api/read", server.requireScope("read"), (c) => c.text("r"));
      app.post("/api/write", server.requireScope("write"), (c) => c.text("w"));

      const tokenRes = await app.request(
        "/oauth2/token",
        formRequestInit(
          {
            grant_type: "client_credentials",
            scope: "read",
          },
          basicAuthHeader("client-1", "secret"),
        ),
      );
      const { access_token } = await tokenRes.json();

      const read = await app.request("/api/read", {
        headers: { Authorization: `Bearer ${access_token}` },
      });
      expect(read.status).toBe(200);

      const write = await app.request("/api/write", {
        method: "POST",
        headers: { Authorization: `Bearer ${access_token}` },
      });
      expect(write.status).toBe(403);
      expect(
        write.headers.get("WWW-Authenticate")?.includes("insufficient_scope"),
      ).toStrictEqual(true);
    });
  });
});
