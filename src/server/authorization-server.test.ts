import { beforeEach, describe, expect, it } from "vitest";
import { rejection, thrown } from "../_test_assert.ts";
import { BasicScope } from "../models/scope.ts";
import { OAuth2Error, ServerError } from "../errors.ts";
import type { Token } from "../models/token.ts";
import {
  basicAuthHeader,
  formRequest,
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
  tokenRequest,
} from "../testing/_test_fixtures.ts";
import { ClientCredentialsGrant } from "./grants/client-credentials.ts";
import { RefreshTokenGrant } from "./grants/refresh-token.ts";
import { AuthorizationCodeGrant } from "./grants/authorization-code.ts";
import { DeviceAuthorizationGrant } from "./grants/device-authorization.ts";
import {
  AuthorizationServer,
  type AuthorizationServerOptions,
} from "./authorization-server.ts";
import type { DispatchableGrant } from "./grants/grant.ts";
import {
  generateSigningKey,
  StaticSigningKeyProvider,
} from "./signing-keys.ts";
import { isPublicSuffix } from "./public-suffix/mod.ts";
import type { IsPublicSuffix } from "./redirect-uri.ts";

const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

/** A grant that dispatches token requests but serves no endpoint of its own. */
class TokenOnlyGrant implements DispatchableGrant<
  TestClient,
  TestUser,
  BasicScope
> {
  readonly grantType: string;

  constructor(grantType: string) {
    this.grantType = grantType;
  }

  getAuthenticatedClient(): Promise<TestClient> {
    return Promise.resolve(testClient);
  }

  token(): Promise<Token<TestClient, TestUser, BasicScope>> {
    return Promise.reject(new Error("not implemented"));
  }
}

function createDeviceServer(
  options: { verificationUri?: string } = {
    verificationUri: "https://auth.example.com/device",
  },
) {
  const services = createTestServices();
  const deviceAuthorizationService = new MemoryDeviceAuthorizationService({
    clientService: services.clientService,
    userService: services.userService,
  });
  const deviceGrant = new DeviceAuthorizationGrant({
    resolve: () => ({
      clientService: services.clientService,
      tokenService: services.tokenService,
      deviceAuthorizationService,
    }),
  });
  const server = new AuthorizationServer({
    resolve: () => ({
      services: {
        clientService: services.clientService,
        tokenService: services.tokenService,
      },
      issuer: "https://auth.example.com",
      verificationUri: options.verificationUri,
    }),
    grants: { [DEVICE_GRANT_TYPE]: deviceGrant },
  });
  return { server, ...services, deviceAuthorizationService };
}

function deviceRequest(
  body: Record<string, string>,
  headers: Record<string, string> = {},
): Request {
  return formRequest("http://localhost/device_authorization", body, headers);
}

const testUser: TestUser = { id: "user-1", username: "testuser" };
const testClient: TestClient = {
  id: "client-1",
  confidential: true,
  grants: ["client_credentials", "authorization_code", "refresh_token"],
  redirectUris: ["https://example.com/callback"],
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

function createTestServer(
  options: {
    isPublicSuffix?: IsPublicSuffix;
    canIntrospectToken?: AuthorizationServerOptions<
      TestClient,
      TestUser,
      BasicScope
    >["canIntrospectToken"];
    introspectionClaims?: (
      token: Token<TestClient, TestUser, BasicScope>,
    ) => Record<string, unknown>;
    subjectOf?: (user: TestUser) => string;
  } = { isPublicSuffix },
) {
  const services = createTestServices();

  const clientCredentialsGrant = new ClientCredentialsGrant({
    resolve: () => ({
      clientService: services.clientService,
      tokenService: services.tokenService,
    }),
  });

  const refreshTokenGrant = new RefreshTokenGrant({
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
    allowRefreshToken: true,
    requirePKCE: false,
  });

  const server = new AuthorizationServer({
    resolve: () => ({
      services: {
        clientService: services.clientService,
        tokenService: services.tokenService,
      },
      issuer: "https://auth.example.com",
    }),
    grants: {
      client_credentials: clientCredentialsGrant,
      refresh_token: refreshTokenGrant,
      authorization_code: authorizationCodeGrant,
    },
    isPublicSuffix: options.isPublicSuffix,
    introspectionClaims: options.introspectionClaims,
    canIntrospectToken: options.canIntrospectToken,
    subjectOf: options.subjectOf,
  });

  return {
    server,
    ...services,
    authorizationCodeGrant,
  };
}

async function setupTestData(services: ReturnType<typeof createTestServices>) {
  await services.userService.add(testUser, "password");
  await services.clientService.add(testClient, "secret", testUser.id);
}

describe("AuthorizationServer", () => {
  describe("constructor", () => {
    it("should inherit from ResourceServer", () => {
      const { server } = createTestServer();
      expect(typeof server.authenticate).toBe("function");
    });

    it("should set issuer", async () => {
      const { server } = createTestServer();
      const context = await server.authorizationContext(
        new Request("http://localhost/token"),
      );
      expect(context.issuer).toBe("https://auth.example.com");
    });

    it("should copy grants", () => {
      const { server } = createTestServer();
      expect(typeof server.grants["client_credentials"]).toBe("object");
    });

    it("throws when a grant is registered under a mismatched key", () => {
      const services = createTestServices();
      const refreshTokenGrant = new RefreshTokenGrant({
        resolve: () => ({
          clientService: services.clientService,
          tokenService: services.tokenService,
        }),
      });
      thrown(
        () =>
          new AuthorizationServer({
            resolve: () => ({
              services: {
                clientService: services.clientService,
                tokenService: services.tokenService,
              },
              issuer: "https://auth.example.com",
            }),
            grants: { client_credentials: refreshTokenGrant },
          }),
        Error,
        "the map key must equal grant.grantType",
      );
    });
  });

  describe("bearerToken", () => {
    it("should create bearer token response body", () => {
      const { server, clientService, tokenService } = createTestServer();
      const token: Token<TestClient, TestUser> = {
        accessToken: "access-123",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
      };

      const body = server.bearerToken(token, { clientService, tokenService });

      expect(body.token_type).toBe("Bearer");
      expect(body.access_token).toBe("access-123");
      expect(body.expires_in).toBe(3600);
    });

    it("derives expires_in from the token's own expiry, not the service default", () => {
      const { server, clientService, tokenService } = createTestServer();
      const token: Token<TestClient, TestUser> = {
        accessToken: "access-123",
        accessTokenExpiresAt: new Date(Date.now() + 120000),
        client: testClient,
        user: testUser,
      };

      const body = server.bearerToken(token, { clientService, tokenService });

      expect(body.expires_in).toBe(120);
    });

    it("falls back to the service lifetime when the token has no expiry", () => {
      const { server, clientService, tokenService } = createTestServer();
      const token: Token<TestClient, TestUser> = {
        accessToken: "access-123",
        client: testClient,
        user: testUser,
      };

      const body = server.bearerToken(token, { clientService, tokenService });

      expect(body.expires_in).toBe(tokenService.accessTokenLifetime);
    });

    it("should include refresh-token when present", () => {
      const { server, clientService, tokenService } = createTestServer();
      const token = {
        accessToken: "access-123",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "refresh-123",
        refreshTokenExpiresAt: new Date(Date.now() + 86400000),
        client: testClient,
        user: testUser,
      };

      const body = server.bearerToken(token, { clientService, tokenService });

      expect(body.refresh_token).toBe("refresh-123");
    });

    it("should include scope when present", () => {
      const { server, clientService, tokenService } = createTestServer();
      const token: Token<TestClient, TestUser> = {
        accessToken: "access-123",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read write"),
      };

      const body = server.bearerToken(token, { clientService, tokenService });

      expect(body.scope).toBe("read write");
    });
  });

  describe("createTokenResponse", () => {
    it("should create JSON response with correct headers", async () => {
      const { server, clientService, tokenService } = createTestServer();
      const token: Token<TestClient, TestUser> = {
        accessToken: "access-123",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
      };

      const response = await server.createTokenResponse(token, {
        services: { clientService, tokenService },
      });

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe(
        "application/json;charset=UTF-8",
      );
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.get("Pragma")).toBe("no-cache");

      const body = await response.json();
      expect(body.access_token).toBe("access-123");
    });
  });

  describe("createErrorResponse", () => {
    it("should create error response using configured format", async () => {
      const { server } = createTestServer();
      const error = new Error("test error");

      const response = server.createErrorResponse(error);

      expect(response.status).toBe(500);
      const body = await response.json();
      expect(body.error).toBe("server_error");
    });

    it("should create Problem Details response when errorFormat is problem-details", async () => {
      const services = createTestServices();
      const server = new AuthorizationServer({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
        }),
        grants: {},
        errorFormat: "problem-details",
      });
      const error = new OAuth2Error("test error");

      const response = server.createErrorResponse(error);

      expect(response.status).toBe(500);
      expect(response.headers.get("content-type")).toBe(
        "application/problem+json",
      );
      const body = await response.json();
      expect(body.error).toBe("server_error");
      expect(body.status).toBe(500);
      expect(body.title).toBe("OAuth2 Error");
    });
  });

  describe("handleTokenRequest", () => {
    let server: ReturnType<typeof createTestServer>["server"];
    let clientService: MemoryClientService<TestClient, TestUser>;
    let tokenService: MemoryTokenService<TestClient, TestUser>;
    let authorizationCodeService: MemoryAuthorizationCodeService<
      TestClient,
      TestUser
    >;

    beforeEach(async () => {
      const result = createTestServer();
      server = result.server;
      clientService = result.clientService;
      tokenService = result.tokenService;
      authorizationCodeService = result.authorizationCodeService;
      await setupTestData(result);
    });

    it("should reject non-POST requests", async () => {
      const request = new Request("http://localhost/token", {
        method: "GET",
      });

      const response = await server.handleTokenRequest(request);

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toBe("method must be POST");
    });

    it("should reject wrong content type", async () => {
      const request = new Request("http://localhost/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      const response = await server.handleTokenRequest(request);

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error_description?.includes("content-type")).toBe(true);
    });

    it("should require grant_type parameter", async () => {
      const request = tokenRequest({});

      const response = await server.handleTokenRequest(request);

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error_description).toBe("grant_type parameter required");
    });

    it("leaves the request body unread for the caller", async () => {
      const request = tokenRequest(
        { grant_type: "client_credentials" },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleTokenRequest(request);

      expect(response.status).toBe(200);
      expect(request.bodyUsed).toBe(false);
      const body = await request.formData();
      expect(body.get("grant_type")).toBe("client_credentials");
    });

    it("answers invalid_client when a public client presents a secret it was never issued", async () => {
      const publicClient: TestClient = {
        id: "stray-secret-client",
        grants: ["refresh_token"],
      };
      await clientService.add(publicClient);

      const asPublic = await server.handleTokenRequest(
        tokenRequest({
          grant_type: "refresh_token",
          client_id: publicClient.id,
          refresh_token: "unknown",
        }),
      );
      expect(asPublic.status).toBe(400);
      expect((await asPublic.json()).error).toBe("invalid_grant");

      const response = await server.handleTokenRequest(
        tokenRequest({
          grant_type: "refresh_token",
          client_id: publicClient.id,
          client_secret: "never-issued",
          refresh_token: "unknown",
        }),
      );

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toBe("invalid_client");
      expect(body.error_description).toBe("client authentication failed");
    });

    it("should reject unsupported grant type", async () => {
      const request = tokenRequest({ grant_type: "unknown" });

      const response = await server.handleTokenRequest(request);

      expect(response.status).toBe(400);
      const responseBody = await response.json();
      expect(responseBody.error).toBe("unsupported_grant_type");
    });

    it("should reject client not authorized for grant type", async () => {
      const limitedClient: TestClient = {
        id: "limited-client",
        confidential: true,
        grants: ["authorization_code"],
      };
      await clientService.add(limitedClient, "secret");

      const request = tokenRequest(
        { grant_type: "client_credentials" },
        basicAuthHeader("limited-client", "secret"),
      );

      const response = await server.handleTokenRequest(request);

      expect(response.status).toBe(401);
      const responseBody = await response.json();
      expect(responseBody.error).toBe("unauthorized_client");
    });

    it("sends WWW-Authenticate on 401 when Basic credentials are invalid", async () => {
      const request = tokenRequest(
        { grant_type: "client_credentials" },
        basicAuthHeader("client-1", "wrong-secret"),
      );

      const response = await server.handleTokenRequest(request);

      expect(response.status).toBe(401);
      const responseBody = await response.json();
      expect(responseBody.error).toBe("invalid_client");
      expect(response.headers.get("WWW-Authenticate") ?? "").toContain("Basic");
    });

    it("should handle client-credentials grant", async () => {
      const request = tokenRequest(
        { grant_type: "client_credentials" },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleTokenRequest(request);

      expect(response.status).toBe(200);
      const responseBody = await response.json();
      expect(responseBody.token_type).toBe("Bearer");
      expect(typeof responseBody.access_token).toBe("string");
    });

    it("should handle refresh-token grant", async () => {
      const existingToken = {
        accessToken: "old-access",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "refresh-123",
        refreshTokenExpiresAt: new Date(Date.now() + 86400000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(existingToken);

      const request = tokenRequest(
        {
          grant_type: "refresh_token",
          refresh_token: "refresh-123",
        },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleTokenRequest(request);

      expect(response.status).toBe(200);
      const responseBody = await response.json();
      expect(typeof responseBody.access_token).toBe("string");
    });

    it("should handle authorization-code grant", async () => {
      const authCode = {
        code: "auth-code-123",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      };
      await authorizationCodeService.save(authCode);

      const request = tokenRequest(
        {
          grant_type: "authorization_code",
          code: "auth-code-123",
        },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleTokenRequest(request);

      expect(response.status).toBe(200);
      const responseBody = await response.json();
      expect(typeof responseBody.access_token).toBe("string");
      expect(typeof responseBody.refresh_token).toBe("string");
    });
  });

  describe("parseAuthorizeParameters", () => {
    it("should parse all authorization parameters", () => {
      const { server } = createTestServer();
      const url =
        "http://localhost/authorize?response_type=code&client_id=client-1&redirect_uri=https://example.com/callback&state=xyz&scope=read%20write&code_challenge=challenge&code_challenge_method=S256";
      const request = new Request(url);

      const params = server.parseAuthorizeParameters(request);

      expect(params.responseType).toBe("code");
      expect(params.clientId).toBe("client-1");
      expect(params.redirectUri).toBe("https://example.com/callback");
      expect(params.state).toBe("xyz");
      expect(params.scope).toBe("read write");
      expect(params.challenge).toBe("challenge");
      expect(params.challengeMethod).toBe("S256");
    });

    it("should return undefined for missing parameters", () => {
      const { server } = createTestServer();
      const request = new Request("http://localhost/authorize");

      const params = server.parseAuthorizeParameters(request);

      expect(params.responseType).toBe(undefined);
      expect(params.clientId).toBe(undefined);
    });
  });

  describe("handleAuthorizeRequest", () => {
    let server: ReturnType<typeof createTestServer>["server"];
    let clientService: MemoryClientService<TestClient, TestUser>;

    const authenticateUser = () =>
      Promise.resolve({
        user: testUser,
        authorizedScope: new BasicScope("read write"),
      });

    beforeEach(async () => {
      const result = createTestServer();
      server = result.server;
      clientService = result.clientService;
      await setupTestData(result);
    });

    it("should require client_id", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error_description).toBe("client_id parameter required");
    });

    it("should validate client has redirect URIs", async () => {
      const noRedirectClient: TestClient = {
        id: "no-redirect",
        grants: ["authorization_code"],
      };
      await clientService.add(noRedirectClient);

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=no-redirect&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error_description).toBe("no authorized redirect_uri");
    });

    it("should validate redirect_uri is authorized", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&redirect_uri=https://evil.com/callback&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error_description).toBe("redirect_uri not authorized");
    });

    it("should authorize a redirect_uri covered by a wildcard registration", async () => {
      await clientService.add({
        id: "preview-client",
        grants: ["authorization_code"],
        redirectUris: ["https://myapp-*.myorg.deno.net/auth/callback"],
      });

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=preview-client&redirect_uri=https://myapp-a1b2.myorg.deno.net/auth/callback&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(302);
      const url = new URL(response.headers.get("Location")!);
      expect(url.origin).toBe("https://myapp-a1b2.myorg.deno.net");
      expect(url.pathname).toBe("/auth/callback");
      expect(url.searchParams.has("code")).toBe(true);
    });

    it("should refuse a wildcard registration when no public suffix list is configured", async () => {
      const listless = createTestServer({});
      await setupTestData(listless);
      await listless.clientService.add({
        id: "preview-client-listless",
        grants: ["authorization_code"],
        redirectUris: ["https://myapp-*.myorg.deno.net/auth/callback"],
      });

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=preview-client-listless&redirect_uri=https://myapp-a1b2.myorg.deno.net/auth/callback&state=xyz",
      );

      const response = await listless.server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error_description).toBe("redirect_uri not authorized");
    });

    it("should refuse a host a wildcard registration cannot reach", async () => {
      await clientService.add({
        id: "preview-client-2",
        grants: ["authorization_code"],
        redirectUris: ["https://myapp-*.myorg.deno.net/auth/callback"],
      });

      for (const redirectUri of [
        "https://myapp-a1.evil.myorg.deno.net/auth/callback",
        "http://myapp-a1.myorg.deno.net/auth/callback",
        "https://myapp-a1.myorg.deno.net/auth/callback?next=x",
      ]) {
        const request = new Request(
          `http://localhost/authorize?response_type=code&client_id=preview-client-2&redirect_uri=${encodeURIComponent(
            redirectUri,
          )}&state=xyz`,
        );

        const response = await server.handleAuthorizeRequest(
          request,
          authenticateUser,
        );

        expect(response.status, redirectUri).toBe(401);
        const body = await response.json();
        expect(body.error_description, redirectUri).toBe(
          "redirect_uri not authorized",
        );
      }
    });

    it("should never redirect to a wildcard pattern as the default redirect_uri", async () => {
      await clientService.add({
        id: "preview-client-3",
        grants: ["authorization_code"],
        redirectUris: ["https://myapp-*.myorg.deno.net/auth/callback"],
      });

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=preview-client-3&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error_description).toBe(
        "redirect_uri required when every registered redirect_uri is a pattern",
      );
    });

    it("should fall back to the first literal redirect_uri, skipping patterns", async () => {
      await clientService.add({
        id: "preview-client-4",
        grants: ["authorization_code"],
        redirectUris: [
          "https://myapp-*.myorg.deno.net/auth/callback",
          "https://myapp.myorg.deno.net/auth/callback",
        ],
      });

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=preview-client-4&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(302);
      const url = new URL(response.headers.get("Location")!);
      expect(url.origin).toBe("https://myapp.myorg.deno.net");
    });

    it("should require state parameter", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      expect(url.searchParams.get("error")).toBe("invalid_request");
    });

    it("should require response_type parameter", async () => {
      const request = new Request(
        "http://localhost/authorize?client_id=client-1&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      expect(url.searchParams.get("error")).toBe("invalid_request");
      expect(url.searchParams.get("state")).toBe("xyz");
    });

    it("should validate response_type is 'code'", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=token&client_id=client-1&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      expect(url.searchParams.get("error")).toBe("unsupported_response_type");
      expect(url.searchParams.get("error_description")).toBe(
        "response_type not supported",
      );
    });

    it("should require authentication", async () => {
      const unauthenticatedUser = () => Promise.resolve(null);
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        unauthenticatedUser,
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      expect(url.searchParams.get("error")).toBe("access_denied");
    });

    it("should generate authorization code on success", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      expect(url.searchParams.has("code")).toBe(true);
      expect(url.searchParams.get("state")).toBe("xyz");
      expect(url.origin).toBe("https://example.com");
    });

    it("should use provided redirect_uri", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&redirect_uri=https://example.com/callback&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("Location")!;
      expect(location.startsWith("https://example.com/callback")).toBe(true);
    });

    it("should validate PKCE challenge_method", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz&code_challenge=challenge&code_challenge_method=plain",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      expect(url.searchParams.get("error_description")).toBe(
        "unsupported code_challenge_method",
      );
    });

    it("should require code_challenge when code_challenge_method set", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz&code_challenge_method=S256",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      expect(
        url.searchParams
          .get("error_description")
          ?.includes("code_challenge required"),
      ).toBe(true);
    });

    it("rejects a missing code_challenge at authorize-time when PKCE is required", async () => {
      const result = createTestServer();
      result.authorizationCodeGrant.requirePKCE = true;
      await setupTestData(result);

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz",
      );
      const response = await result.server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(302);
      const url = new URL(response.headers.get("Location")!);
      expect(url.searchParams.get("error")).toBe("invalid_request");
      expect(url.searchParams.get("error_description") ?? "").toContain(
        "PKCE is required",
      );
      expect(url.searchParams.has("code")).toBe(false);
    });

    it("does not leak an internal server_error message into the redirect", async () => {
      const leakyAuth = () =>
        Promise.reject(new ServerError("db dsn=postgres://secret@host"));
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz",
      );
      const response = await server.handleAuthorizeRequest(request, leakyAuth);

      expect(response.status).toBe(302);
      const url = new URL(response.headers.get("Location")!);
      expect(url.searchParams.get("error")).toBe("server_error");
      expect(
        (url.searchParams.get("error_description") ?? "").includes("secret"),
      ).toStrictEqual(false);
    });

    it("should handle consent flow", async () => {
      const limitedAuth = () =>
        Promise.resolve({
          user: testUser,
          authorizedScope: new BasicScope("read"),
        });

      const handleConsent = () =>
        Promise.resolve({
          approved: true,
          scope: new BasicScope("read write"),
        });

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz&scope=read%20write",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        limitedAuth,
        handleConsent,
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      expect(url.searchParams.has("code")).toBe(true);
    });

    it("should reject when user denies consent", async () => {
      const limitedAuth = () =>
        Promise.resolve({
          user: testUser,
          authorizedScope: new BasicScope("read"),
        });

      const handleConsent = () =>
        Promise.resolve({
          approved: false,
        });

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz&scope=write",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        limitedAuth,
        handleConsent,
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      expect(url.searchParams.get("error")).toBe("access_denied");
    });

    it("should return Response from authenticateUser directly", async () => {
      const loginRedirect = () =>
        Promise.resolve(
          new Response(null, {
            status: 302,
            headers: { Location: "/login?return_to=%2Fauthorize" },
          }),
        );

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        loginRedirect,
      );

      expect(response.status).toBe(302);
      expect(response.headers.get("Location")).toBe(
        "/login?return_to=%2Fauthorize",
      );
    });

    it("should return Response from handleConsent directly", async () => {
      const limitedAuth = () =>
        Promise.resolve({
          user: testUser,
          authorizedScope: new BasicScope(""),
        });
      const renderConsent = () =>
        Promise.resolve(
          new Response("<html>consent</html>", {
            status: 200,
            headers: { "Content-Type": "text/html" },
          }),
        );

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz&scope=write",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        limitedAuth,
        renderConsent,
      );

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe("text/html");
      expect(await response.text()).toBe("<html>consent</html>");
    });

    it("auto-grants when no consent handler is configured (assumes consent)", async () => {
      const result = createTestServer();
      await setupTestData(result);
      const limitedAuth = () =>
        Promise.resolve({
          user: testUser,
          authorizedScope: new BasicScope("read"),
        });

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz&scope=write",
      );

      const response = await result.server.handleAuthorizeRequest(
        request,
        limitedAuth,
      );

      expect(response.status).toBe(302);
      const url = new URL(response.headers.get("Location")!);
      const code = url.searchParams.get("code");
      expect(typeof code).toBe("string");
      expect(url.searchParams.get("error")).toBe(null);

      const saved = await result.authorizationCodeService.get(code!);
      expect(saved?.scope?.toString()).toBe("write");
    });

    it("should reject client not authorized for authorization_code grant", async () => {
      const noAuthCodeClient: TestClient = {
        id: "no-auth-code",
        grants: ["client_credentials"],
        redirectUris: ["https://example.com/callback"],
      };
      await clientService.add(noAuthCodeClient);

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=no-auth-code&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toBe("unauthorized_client");
      expect(body.error_description).toBe(
        "client is not authorized to use the authorization_code grant type",
      );
    });
  });

  describe("handleRevocationRequest", () => {
    let server: ReturnType<typeof createTestServer>["server"];
    let tokenService: MemoryTokenService<TestClient, TestUser>;

    beforeEach(async () => {
      const result = createTestServer();
      server = result.server;
      tokenService = result.tokenService;
      await setupTestData(result);
    });

    it("should reject non-POST requests", async () => {
      const request = new Request("http://localhost/revoke", {
        method: "GET",
      });

      const response = await server.handleRevocationRequest(request);

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid_request");
    });

    it("should reject wrong content type", async () => {
      const request = new Request("http://localhost/revoke", {
        method: "POST",
        headers: {
          ...basicAuthHeader("client-1", "secret"),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ token: "revoke-me" }),
      });

      const response = await server.handleRevocationRequest(request);

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid_request");
      expect(body.error_description?.includes("content-type")).toBe(true);
    });

    it("should require client authentication per RFC 7009", async () => {
      const request = formRequest("http://localhost/revoke", { token: "test" });

      const response = await server.handleRevocationRequest(request);

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toBe("invalid_client");
    });

    it("should require token parameter", async () => {
      const request = formRequest(
        "http://localhost/revoke",
        {},
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleRevocationRequest(request);

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error_description).toBe("token parameter required");
    });

    it("should revoke token and return 200", async () => {
      const token: Token<TestClient, TestUser> = {
        accessToken: "revoke-me",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(token);

      const request = formRequest(
        "http://localhost/revoke",
        {
          token: "revoke-me",
        },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleRevocationRequest(request);

      expect(response.status).toBe(200);

      const revokedToken = await tokenService.getToken("revoke-me");
      expect(revokedToken).toBe(undefined);
    });

    it("should return 200 even for non-existent token", async () => {
      const request = formRequest(
        "http://localhost/revoke",
        {
          token: "non-existent",
        },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleRevocationRequest(request);

      expect(response.status).toBe(200);
    });

    it("should pass token_type_hint to service", async () => {
      const token = {
        accessToken: "access-123",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "refresh-revoke",
        refreshTokenExpiresAt: new Date(Date.now() + 86400000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(token);

      const request = formRequest(
        "http://localhost/revoke",
        {
          token: "refresh-revoke",
          token_type_hint: "refresh_token",
        },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleRevocationRequest(request);

      expect(response.status).toBe(200);
    });
  });

  describe("getMetadata", () => {
    it("should return server metadata", async () => {
      const result = createTestServer();
      await setupTestData(result);

      const context = await result.server.authorizationContext(
        new Request("http://localhost/.well-known/oauth-authorization-server"),
      );
      const metadata = result.server.getMetadata(context);

      expect(metadata.issuer).toBe("https://auth.example.com");
      expect(metadata.grant_types_supported).toStrictEqual([
        "client_credentials",
        "refresh_token",
        "authorization_code",
      ]);
      expect(metadata.token_endpoint_auth_methods_supported).toStrictEqual([
        "client_secret_basic",
        "client_secret_post",
        "none",
      ]);
      expect(metadata.code_challenge_methods_supported).toStrictEqual(["S256"]);
      expect(metadata.response_types_supported).toStrictEqual(["code"]);
    });

    it("advertises `none`, the method it accepts from a client with no secret", async () => {
      const result = createTestServer();
      await setupTestData(result);
      const publicClient: TestClient = {
        id: "public-client",
        confidential: false,
        grants: ["authorization_code"],
        redirectUris: ["https://example.com/callback"],
      };
      await result.clientService.add(publicClient);
      await result.authorizationCodeService.save({
        code: "public-code",
        expiresAt: new Date(Date.now() + 300000),
        client: publicClient,
        user: testUser,
      });

      const context = await result.server.authorizationContext(
        new Request("http://localhost/.well-known/oauth-authorization-server"),
      );
      const metadata = result.server.getMetadata(context);

      expect(metadata.token_endpoint_auth_methods_supported).toStrictEqual([
        "client_secret_basic",
        "client_secret_post",
        "none",
      ]);

      const response = await result.server.handleTokenRequest(
        tokenRequest({
          grant_type: "authorization_code",
          code: "public-code",
          client_id: "public-client",
        }),
      );

      expect(response.status).toBe(200);
      expect(typeof (await response.json()).access_token).toBe("string");
    });

    it("should return empty response_types when no authorization-code grant", async () => {
      const services = createTestServices();

      const clientCredentialsGrant = new ClientCredentialsGrant({
        resolve: () => ({
          clientService: services.clientService,
          tokenService: services.tokenService,
        }),
      });

      const server = new AuthorizationServer({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
          issuer: "https://auth.example.com",
        }),
        grants: {
          client_credentials: clientCredentialsGrant,
        },
      });

      const context = await server.authorizationContext(
        new Request("http://localhost/.well-known/oauth-authorization-server"),
      );
      const metadata = server.getMetadata(context);

      expect(metadata.response_types_supported).toStrictEqual([]);
    });

    it("throws when issuer is not configured (RFC 8414)", async () => {
      const services = createTestServices();
      const clientCredentialsGrant = new ClientCredentialsGrant({
        resolve: () => ({
          clientService: services.clientService,
          tokenService: services.tokenService,
        }),
      });
      const server = new AuthorizationServer({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
        }),
        grants: { client_credentials: clientCredentialsGrant },
      });

      const context = await server.authorizationContext(
        new Request("http://localhost/.well-known/oauth-authorization-server"),
      );
      thrown(
        () => server.getMetadata(context),
        Error,
        "issuer must be configured",
      );
    });
  });

  describe("handleDeviceAuthorizationRequest", () => {
    it("names the grant when the registered device grant cannot serve the endpoint", async () => {
      const services = createTestServices();
      const publicClient: TestClient = {
        id: "device-public",
        confidential: false,
        grants: [DEVICE_GRANT_TYPE],
      };
      await services.clientService.add(publicClient);

      const server = new AuthorizationServer({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
          issuer: "https://auth.example.com",
          verificationUri: "https://auth.example.com/device",
        }),
        grants: { [DEVICE_GRANT_TYPE]: new TokenOnlyGrant(DEVICE_GRANT_TYPE) },
        throwOnError: true,
      });

      const error = await rejection(
        () =>
          server.handleDeviceAuthorizationRequest(
            deviceRequest({ client_id: "device-public" }),
          ),
        ServerError,
      );
      expect(error.message).toContain("TokenOnlyGrant");
      expect(error.message).toContain("must extend DeviceAuthorizationGrant");
    });

    it("authenticates a public client with client_id only", async () => {
      const { server, clientService } = createDeviceServer();
      const publicClient: TestClient = {
        id: "device-public",
        confidential: false,
        grants: [DEVICE_GRANT_TYPE],
      };
      await clientService.add(publicClient);

      const response = await server.handleDeviceAuthorizationRequest(
        deviceRequest({ client_id: "device-public" }),
      );

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(typeof body.device_code).toBe("string");
      expect(typeof body.user_code).toBe("string");
      expect(body.verification_uri).toBe("https://auth.example.com/device");
    });

    it("rejects a confidential client that does not authenticate (RFC 8628 Section 3.1)", async () => {
      const { server, clientService } = createDeviceServer();
      const confidentialClient: TestClient = {
        id: "device-confidential",
        confidential: true,
        grants: [DEVICE_GRANT_TYPE],
      };
      await clientService.add(confidentialClient, "device-secret");

      const response = await server.handleDeviceAuthorizationRequest(
        deviceRequest({ client_id: "device-confidential" }),
      );

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toBe("invalid_client");
    });

    it("accepts a confidential client with valid Basic credentials", async () => {
      const { server, clientService } = createDeviceServer();
      const confidentialClient: TestClient = {
        id: "device-confidential-2",
        confidential: true,
        grants: [DEVICE_GRANT_TYPE],
      };
      await clientService.add(confidentialClient, "device-secret");

      const response = await server.handleDeviceAuthorizationRequest(
        deviceRequest(
          {},
          basicAuthHeader("device-confidential-2", "device-secret"),
        ),
      );

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(typeof body.device_code).toBe("string");
    });

    it("challenges with WWW-Authenticate when Basic credentials are wrong", async () => {
      const { server, clientService } = createDeviceServer();
      const confidentialClient: TestClient = {
        id: "device-confidential-3",
        confidential: true,
        grants: [DEVICE_GRANT_TYPE],
      };
      await clientService.add(confidentialClient, "device-secret");

      const response = await server.handleDeviceAuthorizationRequest(
        deviceRequest({}, basicAuthHeader("device-confidential-3", "wrong")),
      );

      expect(response.status).toBe(401);
      expect(response.headers.get("WWW-Authenticate") ?? "").toContain("Basic");
    });

    it("fails fast when verificationUri is not configured (RFC 8628)", async () => {
      const { server, clientService } = createDeviceServer({});
      const publicClient: TestClient = {
        id: "device-no-vuri",
        confidential: false,
        grants: [DEVICE_GRANT_TYPE],
      };
      await clientService.add(publicClient);

      const response = await server.handleDeviceAuthorizationRequest(
        deviceRequest({ client_id: "device-no-vuri" }),
      );

      expect(response.status).toBe(500);
      const body = await response.json();
      expect(body.error).toBe("server_error");
    });
  });

  describe("client-authenticated endpoints", () => {
    const endpointClient: TestClient = {
      id: "endpoint-client",
      confidential: true,
      grants: [
        "client_credentials",
        "authorization_code",
        "refresh_token",
        DEVICE_GRANT_TYPE,
      ],
    };

    function createEndpointServer() {
      const services = createTestServices();
      const deviceAuthorizationService = new MemoryDeviceAuthorizationService({
        clientService: services.clientService,
        userService: services.userService,
      });
      const resolve = () => ({
        clientService: services.clientService,
        tokenService: services.tokenService,
      });
      const server = new AuthorizationServer({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
          issuer: "https://auth.example.com",
          verificationUri: "https://auth.example.com/device",
        }),
        grants: {
          client_credentials: new ClientCredentialsGrant({ resolve }),
          refresh_token: new RefreshTokenGrant({ resolve }),
          [DEVICE_GRANT_TYPE]: new DeviceAuthorizationGrant({
            resolve: () => ({ ...resolve(), deviceAuthorizationService }),
          }),
        },
      });
      return { server, ...services };
    }

    type EndpointServer = ReturnType<typeof createEndpointServer>["server"];

    const endpoints: {
      name: string;
      url: string;
      body: Record<string, string>;
      handle: (server: EndpointServer, request: Request) => Promise<Response>;
    }[] = [
      {
        name: "token",
        url: "http://localhost/token",
        body: { grant_type: "client_credentials" },
        handle: (server, request) => server.handleTokenRequest(request),
      },
      {
        name: "revocation",
        url: "http://localhost/revoke",
        body: { token: "unknown-token" },
        handle: (server, request) => server.handleRevocationRequest(request),
      },
      {
        name: "introspection",
        url: "http://localhost/introspect",
        body: { token: "unknown-token" },
        handle: (server, request) => server.handleIntrospectionRequest(request),
      },
      {
        name: "device authorization",
        url: "http://localhost/device_authorization",
        body: {},
        handle: (server, request) =>
          server.handleDeviceAuthorizationRequest(request),
      },
    ];

    for (const endpoint of endpoints) {
      describe(endpoint.name, () => {
        let server: EndpointServer;

        beforeEach(async () => {
          const result = createEndpointServer();
          server = result.server;
          await result.userService.add(testUser, "password");
          await result.clientService.add(endpointClient, "secret", testUser.id);
        });

        function request(
          init: { method?: string; headers?: Record<string, string> } = {},
          body: Record<string, string> = endpoint.body,
        ): Request {
          return new Request(endpoint.url, {
            method: init.method ?? "POST",
            headers: {
              "content-type": "application/x-www-form-urlencoded",
              ...init.headers,
            },
            body: init.method === "GET" ? undefined : new URLSearchParams(body),
          });
        }

        function authenticated(
          body: Record<string, string> = endpoint.body,
        ): Request {
          return request(
            {
              headers: basicAuthHeader("endpoint-client", "secret"),
            },
            body,
          );
        }

        it("rejects a request that is not POST", async () => {
          const response = await endpoint.handle(
            server,
            request({ method: "GET" }),
          );

          expect(response.status).toBe(400);
          const body = await response.json();
          expect(body.error).toBe("invalid_request");
          expect(body.error_description).toBe("method must be POST");
        });

        it("rejects a content type that is not form-urlencoded", async () => {
          const response = await endpoint.handle(
            server,
            new Request(endpoint.url, {
              method: "POST",
              headers: {
                "content-type": "application/json",
                ...basicAuthHeader("endpoint-client", "secret"),
              },
              body: JSON.stringify(endpoint.body),
            }),
          );

          expect(response.status).toBe(400);
          const body = await response.json();
          expect(body.error).toBe("invalid_request");
          expect(body.error_description).toBe(
            "content-type header must be application/x-www-form-urlencoded",
          );
        });

        it("rejects a body that cannot be parsed as a form", async () => {
          const response = await endpoint.handle(
            server,
            new Request(endpoint.url, {
              method: "POST",
              headers: {
                "content-type":
                  "multipart/form-data; boundary=application/x-www-form-urlencoded",
                ...basicAuthHeader("endpoint-client", "secret"),
              },
              body: "not a form",
            }),
          );

          expect(response.status).toBe(400);
          const body = await response.json();
          expect(body.error).toBe("invalid_request");
          expect(body.error_description).toBe(
            "body must be application/x-www-form-urlencoded",
          );
        });

        it("rejects a request presenting no client credentials", async () => {
          const response = await endpoint.handle(server, request());

          expect(response.status).toBe(401);
          const body = await response.json();
          expect(body.error).toBe("invalid_client");
          expect(body.error_description).toBe("client authentication required");
        });

        it("rejects wrong Basic credentials with a challenge", async () => {
          const response = await endpoint.handle(
            server,
            request({
              headers: basicAuthHeader("endpoint-client", "wrong"),
            }),
          );

          expect(response.status).toBe(401);
          const body = await response.json();
          expect(body.error).toBe("invalid_client");
          expect(body.error_description).toBe("client authentication failed");
          expect(response.headers.get("WWW-Authenticate") ?? "").toContain(
            "Basic",
          );
        });

        it("rejects wrong body credentials", async () => {
          const response = await endpoint.handle(
            server,
            request(
              {},
              {
                ...endpoint.body,
                client_id: "endpoint-client",
                client_secret: "wrong",
              },
            ),
          );

          expect(response.status).toBe(401);
          const body = await response.json();
          expect(body.error).toBe("invalid_client");
          expect(body.error_description).toBe("client authentication failed");
        });

        it("rejects an unsupported Authorization header", async () => {
          const response = await endpoint.handle(
            server,
            request({ headers: { authorization: "Bearer some-token" } }),
          );

          expect(response.status).toBe(401);
          const body = await response.json();
          expect(body.error).toBe("invalid_client");
          expect(body.error_description).toBe(
            "unsupported authorization header",
          );
        });

        it("falls back to body credentials when the Authorization header is not Basic", async () => {
          const response = await endpoint.handle(
            server,
            request(
              { headers: { authorization: "Bearer some-token" } },
              {
                ...endpoint.body,
                client_id: "endpoint-client",
                client_secret: "secret",
              },
            ),
          );

          expect(response.status).toBe(200);
        });

        it("accepts a well-formed authenticated request", async () => {
          const response = await endpoint.handle(server, authenticated());

          expect(response.status).toBe(200);
        });
      });
    }
  });

  describe("handleAuthorizeRequest - edge cases", () => {
    it("should return error when no authorization_code grant configured", async () => {
      const services = createTestServices();
      await setupTestData(services);

      const clientCredentialsGrant = new ClientCredentialsGrant({
        resolve: () => ({
          clientService: services.clientService,
          tokenService: services.tokenService,
        }),
      });

      const server = new AuthorizationServer({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
        }),
        grants: {
          client_credentials: clientCredentialsGrant,
        },
      });

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(request, () =>
        Promise.resolve({
          user: testUser,
          authorizedScope: new BasicScope("read"),
        }),
      );

      expect(response.status).toBe(500);
      const body = await response.json();
      expect(body.error).toBe("server_error");
      expect(body.error_description).toBe(
        "The server encountered an unexpected condition.",
      );
    });

    it("names the grant when the registered authorization_code grant cannot serve the endpoint", async () => {
      const services = createTestServices();
      await setupTestData(services);

      const server = new AuthorizationServer({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
        }),
        grants: {
          authorization_code: new TokenOnlyGrant("authorization_code"),
        },
        throwOnError: true,
      });

      const error = await rejection(
        () =>
          server.handleAuthorizeRequest(
            new Request(
              "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz",
            ),
            () => Promise.resolve({ user: testUser }),
          ),
        ServerError,
      );
      expect(error.message).toContain("TokenOnlyGrant");
      expect(error.message).toContain("must extend AuthorizationCodeGrant");
    });

    it("should include error_uri in redirect when present", async () => {
      const result = createTestServer();
      await setupTestData(result);

      const errorClient: TestClient = {
        id: "error-uri-client",
        grants: ["authorization_code"],
        redirectUris: ["https://example.com/callback"],
      };
      await result.clientService.add(errorClient);

      result.authorizationCodeGrant.validateChallengeMethod = (
        _method?: string | null,
      ) => {
        const error = new OAuth2Error(400, "test error with uri", {
          extensions: {
            error: "test_error",
            error_uri: "https://example.com/docs/error",
          },
        });
        throw error;
      };

      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=error-uri-client&state=xyz&code_challenge=test",
      );

      const response = await result.server.handleAuthorizeRequest(request, () =>
        Promise.resolve({
          user: testUser,
          authorizedScope: new BasicScope("read"),
        }),
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      expect(url.searchParams.get("error")).toBe("test_error");
      expect(url.searchParams.get("error_uri")).toBe(
        "https://example.com/docs/error",
      );
    });
  });

  describe("handleIntrospectionRequest", () => {
    for (const kind of ["accessToken", "refreshToken"] as const) {
      for (const hint of [undefined, "access_token", "refresh_token"]) {
        it(`applies introspection policy to ${kind} with hint ${hint}`, async () => {
          let claimCalls = 0;
          const decisions: string[] = [];
          const result = createTestServer({
            canIntrospectToken: (client, token, tokenType) => {
              decisions.push(`${client.id}:${tokenType}`);
              return Promise.resolve(
                client.id.toString() === token.client.id.toString(),
              );
            },
            introspectionClaims: () => {
              claimCalls++;
              return { private_claim: "owner-only" };
            },
          });
          await setupTestData(result);
          await result.clientService.add({ id: "public-client", grants: [] });
          const token = await result.tokenService.save({
            accessToken: "owned-access",
            refreshToken: "owned-refresh",
            accessTokenExpiresAt: new Date(Date.now() + 300_000),
            refreshTokenExpiresAt: new Date(Date.now() + 600_000),
            client: testClient,
            user: testUser,
            scope: new BasicScope("read"),
          });
          const fields = {
            token: token[kind],
            ...(hint ? { token_type_hint: hint } : {}),
          };
          const denied = await result.server.handleIntrospectionRequest(
            formRequest("http://localhost/introspect", {
              ...fields,
              client_id: "public-client",
            }),
          );
          expect(denied.status).toBe(200);
          expect(await denied.json()).toStrictEqual({ active: false });
          expect(claimCalls).toBe(0);
          expect(denied.headers.get("Cache-Control")).toBe("no-store");
          const allowed = await result.server.handleIntrospectionRequest(
            formRequest(
              "http://localhost/introspect",
              fields,
              basicAuthHeader("client-1", "secret"),
            ),
          );
          expect(allowed.status).toBe(200);
          const body = await allowed.json();
          expect(body.active).toBe(true);
          expect(body.private_claim).toBe("owner-only");
          expect(claimCalls).toBe(1);
          const tokenType =
            kind === "accessToken" ? "access_token" : "refresh_token";
          expect(decisions).toStrictEqual([
            `public-client:${tokenType}`,
            `client-1:${tokenType}`,
          ]);
          const revoked = await result.server.handleRevocationRequest(
            formRequest("http://localhost/revoke", {
              ...fields,
              client_id: "public-client",
            }),
          );
          expect(revoked.status).toBe(200);
          expect(await revoked.text()).toBe("");
          expect(
            (await result.tokenService.getToken(token.accessToken))
              ?.accessToken,
          ).toBe(token.accessToken);
          expect(
            (await result.tokenService.getRefreshToken(token.refreshToken))
              ?.refreshToken,
          ).toBe(token.refreshToken);
        });
      }
    }

    for (const explicitPolicy of [false, true]) {
      it(`allows authorized cross-client resource-server introspection with explicit policy ${explicitPolicy}`, async () => {
        const result = createTestServer({
          canIntrospectToken: explicitPolicy
            ? (client, _token, tokenType) =>
                client.id === "resource-server" && tokenType === "access_token"
            : undefined,
        });
        await setupTestData(result);
        await result.clientService.add(
          { id: "resource-server", grants: [] },
          "resource-secret",
        );
        await result.tokenService.save({
          accessToken: "api-token",
          client: testClient,
          user: testUser,
        });
        const response = await result.server.handleIntrospectionRequest(
          formRequest(
            "http://localhost/introspect",
            { token: "api-token" },
            basicAuthHeader("resource-server", "resource-secret"),
          ),
        );
        expect(response.status).toBe(200);
        expect((await response.json()).active).toBe(true);
      });
    }

    it("returns no token claims when the policy rejects with an error", async () => {
      const result = createTestServer({
        canIntrospectToken: () =>
          Promise.reject(new Error("policy unavailable")),
      });
      await setupTestData(result);
      await result.tokenService.save({
        accessToken: "policy-token",
        client: testClient,
        user: testUser,
      });
      const response = await result.server.handleIntrospectionRequest(
        formRequest(
          "http://localhost/introspect",
          { token: "policy-token" },
          basicAuthHeader("client-1", "secret"),
        ),
      );
      expect(response.status).toBe(500);
      const body = await response.json();
      expect(body.error).toBe("server_error");
      expect(body.active).toBe(undefined);
      expect(body.sub).toBe(undefined);
    });

    let server: ReturnType<typeof createTestServer>["server"];
    let tokenService: MemoryTokenService<TestClient, TestUser>;

    beforeEach(async () => {
      const result = createTestServer();
      server = result.server;
      tokenService = result.tokenService;
      await setupTestData(result);
    });

    it("should reject non-POST requests", async () => {
      const request = new Request("http://localhost/introspect", {
        method: "GET",
      });

      const response = await server.handleIntrospectionRequest(request);

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid_request");
    });

    it("should reject wrong content type", async () => {
      const request = new Request("http://localhost/introspect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: "test" }),
      });

      const response = await server.handleIntrospectionRequest(request);

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error_description?.includes("content-type")).toBe(true);
    });

    it("should require client authentication", async () => {
      const request = formRequest("http://localhost/introspect", {
        token: "test-token",
      });

      const response = await server.handleIntrospectionRequest(request);

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toBe("invalid_client");
    });

    it("should require token parameter", async () => {
      const request = formRequest(
        "http://localhost/introspect",
        {},
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleIntrospectionRequest(request);

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error_description).toBe("token parameter required");
    });

    it("should return inactive for non-existent token", async () => {
      const request = formRequest(
        "http://localhost/introspect",
        {
          token: "non-existent",
        },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleIntrospectionRequest(request);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.active).toBe(false);
    });

    it("should return inactive for expired token", async () => {
      const expiredToken: Token<TestClient, TestUser> = {
        accessToken: "expired-token",
        accessTokenExpiresAt: new Date(Date.now() - 1000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(expiredToken);

      const request = formRequest(
        "http://localhost/introspect",
        {
          token: "expired-token",
        },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleIntrospectionRequest(request);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.active).toBe(false);
    });

    it("should return active with token info for valid token", async () => {
      const validToken: Token<TestClient, TestUser> = {
        accessToken: "valid-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read write"),
      };
      await tokenService.save(validToken);

      const request = formRequest(
        "http://localhost/introspect",
        {
          token: "valid-token",
        },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleIntrospectionRequest(request);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.active).toBe(true);
      expect(body.client_id).toBe("client-1");
      expect(body.token_type).toBe("Bearer");
      expect(body.scope).toBe("read write");
      expect(body.iss).toBe("https://auth.example.com");
      expect(body.sub).toBe("user-1");
      expect(body.username).toBe("testuser");
      expect(typeof body.exp).toBe("number");
    });

    it("merges introspectionClaims into an active response, protocol fields winning", async () => {
      const result = createTestServer({
        isPublicSuffix,
        introspectionClaims: (token) => ({
          permissions: ["posts:write"],
          org_id: "org-1",
          org_roles: ["admin"],
          subject_marker: token.user?.id,
          active: false,
          scope: "forged",
          client_id: "forged",
          sub: "forged",
        }),
      });
      await setupTestData(result);
      const validToken: Token<TestClient, TestUser> = {
        accessToken: "claimed-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read"),
      };
      await result.tokenService.save(validToken);

      const request = formRequest(
        "http://localhost/introspect",
        {
          token: "claimed-token",
        },
        basicAuthHeader("client-1", "secret"),
      );
      const response = await result.server.handleIntrospectionRequest(request);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.permissions).toStrictEqual(["posts:write"]);
      expect(body.org_id).toBe("org-1");
      expect(body.org_roles).toStrictEqual(["admin"]);
      expect(body.subject_marker).toBe("user-1");
      expect(body.active).toBe(true);
      expect(body.scope).toBe("read");
      expect(body.client_id).toBe("client-1");
      expect(body.sub).toBe("user-1");
    });

    it("derives sub from subjectOf, so introspection agrees with the id_token and UserInfo", async () => {
      const result = createTestServer({
        isPublicSuffix,
        subjectOf: (user) => `acct:${user.id}`,
      });
      await setupTestData(result);
      await result.tokenService.save({
        accessToken: "subject-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read"),
      });

      const response = await result.server.handleIntrospectionRequest(
        formRequest(
          "http://localhost/introspect",
          {
            token: "subject-token",
          },
          basicAuthHeader("client-1", "secret"),
        ),
      );

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.sub).toBe("acct:user-1");
      expect(body.username).toBe("testuser");
    });

    it("keeps sub and username off a token with no user even when introspectionClaims supplies them", async () => {
      const result = createTestServer({
        isPublicSuffix,
        introspectionClaims: () => ({
          sub: "forged",
          username: "forged",
          permissions: ["posts:write"],
        }),
      });
      await setupTestData(result);
      await result.tokenService.save({
        accessToken: "machine-token-with-hook",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        scope: new BasicScope("read"),
      });

      const response = await result.server.handleIntrospectionRequest(
        formRequest(
          "http://localhost/introspect",
          {
            token: "machine-token-with-hook",
          },
          basicAuthHeader("client-1", "secret"),
        ),
      );

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.active).toBe(true);
      expect(body.permissions).toStrictEqual(["posts:write"]);
      expect(
        body.sub,
        "a hook must not make a machine token look like it has a resource owner",
      ).toBe(undefined);
      expect(body.username).toBe(undefined);
    });

    it("should omit sub and username for a token with no user, identifying it by client_id alone", async () => {
      const machineToken: Token<TestClient, TestUser> = {
        accessToken: "machine-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        scope: new BasicScope("read"),
      };
      await tokenService.save(machineToken);

      const request = new Request("http://localhost/introspect", {
        method: "POST",
        headers: {
          Authorization: `Basic ${btoa("client-1:secret")}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ token: "machine-token" }),
      });

      const response = await server.handleIntrospectionRequest(request);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.active).toBe(true);
      expect(body.client_id).toBe("client-1");
      expect(body.sub).toBe(undefined);
      expect(body.username).toBe(undefined);
    });

    it("should include cache headers", async () => {
      const request = formRequest(
        "http://localhost/introspect",
        {
          token: "any-token",
        },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleIntrospectionRequest(request);

      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.get("Pragma")).toBe("no-cache");
    });
  });

  describe("handleMetadataRequest", () => {
    it("should return server metadata", async () => {
      const services = createTestServices();
      await setupTestData(services);

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
      });

      const server = new AuthorizationServer({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
          issuer: "https://auth.example.com",
          authorizationEndpoint: "https://auth.example.com/authorize",
          tokenEndpoint: "https://auth.example.com/token",
          revocationEndpoint: "https://auth.example.com/revoke",
          introspectionEndpoint: "https://auth.example.com/introspect",
        }),
        grants: {
          client_credentials: clientCredentialsGrant,
          authorization_code: authorizationCodeGrant,
        },
        scopesSupported: ["read", "write", "admin"],
      });

      const request = new Request(
        "http://localhost/.well-known/oauth-authorization-server",
      );

      const response = await server.handleMetadataRequest(request);

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe(
        "application/json;charset=UTF-8",
      );

      const body = await response.json();
      expect(body.issuer).toBe("https://auth.example.com");
      expect(body.authorization_endpoint).toBe(
        "https://auth.example.com/authorize",
      );
      expect(body.token_endpoint).toBe("https://auth.example.com/token");
      expect(body.revocation_endpoint).toBe("https://auth.example.com/revoke");
      expect(body.introspection_endpoint).toBe(
        "https://auth.example.com/introspect",
      );
      expect(body.grant_types_supported).toStrictEqual([
        "client_credentials",
        "authorization_code",
      ]);
      expect(body.response_types_supported).toStrictEqual(["code"]);
      expect(body.scopes_supported).toStrictEqual(["read", "write", "admin"]);
    });
  });

  describe("resolve (single instance, per-request services)", () => {
    function tenantServices(accessTokenLifetime: number) {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new MemoryTokenService({
        clientService,
        userService,
        accessTokenLifetime,
      });
      const authorizationCodeService = new MemoryAuthorizationCodeService({
        clientService,
        userService,
      });
      return {
        userService,
        clientService,
        tokenService,
        authorizationCodeService,
      };
    }

    const sharedClient: TestClient = {
      id: "shared",
      confidential: true,
      grants: ["client_credentials"],
    };

    async function seed(
      services: ReturnType<typeof tenantServices>,
      ownerId: string,
    ) {
      await services.userService.add({ id: ownerId, username: ownerId }, "pw");
      await services.clientService.add(sharedClient, "secret", ownerId);
    }

    async function buildServer() {
      const tenantA = tenantServices(1111);
      const tenantB = tenantServices(2222);
      await seed(tenantA, "owner-a");
      await seed(tenantB, "owner-b");

      const ccGrant = new ClientCredentialsGrant({
        resolve: (request) => {
          const t =
            new URL(request.url).searchParams.get("tenant") === "b"
              ? tenantB
              : tenantA;
          return {
            clientService: t.clientService,
            tokenService: t.tokenService,
          };
        },
      });

      const server = new AuthorizationServer({
        grants: { client_credentials: ccGrant },
        resolve: (request) => {
          const t =
            new URL(request.url).searchParams.get("tenant") === "b"
              ? tenantB
              : tenantA;
          return {
            services: {
              clientService: t.clientService,
              tokenService: t.tokenService,
            },
            issuer:
              t === tenantB ? "https://b.example.com" : "https://a.example.com",
          };
        },
      });
      return server;
    }

    function tenantTokenRequest(tenant: string): Request {
      return formRequest(`http://localhost/token?tenant=${tenant}`, {
        grant_type: "client_credentials",
        client_id: "shared",
        client_secret: "secret",
      });
    }

    it("routes token issuance through the per-request resolved services", async () => {
      const server = await buildServer();

      const resB = await server.handleTokenRequest(tenantTokenRequest("b"));
      expect(resB.status).toBe(200);
      expect((await resB.json()).expires_in).toBe(2222);

      const resA = await server.handleTokenRequest(tenantTokenRequest("a"));
      expect(resA.status).toBe(200);
      expect((await resA.json()).expires_in).toBe(1111);
    });

    it("serves metadata with the per-request issuer", async () => {
      const server = await buildServer();
      const metaRequest = (tenant: string) =>
        new Request(
          `http://localhost/.well-known/oauth-authorization-server?tenant=${tenant}`,
        );

      const resB = await server.handleMetadataRequest(metaRequest("b"));
      expect((await resB.json()).issuer).toBe("https://b.example.com");

      const resA = await server.handleMetadataRequest(metaRequest("a"));
      expect((await resA.json()).issuer).toBe("https://a.example.com");
    });
  });
});

describe("discovery scopes from per-request context", () => {
  for (const oidc of [false, true]) {
    it(`isolates concurrent ${oidc ? "OIDC" : "OAuth2"} scope vocabularies and keeps the option default`, async () => {
      const services = createTestServices();
      const defaults = ["read", "write", "admin"];
      const scopesByHost: Record<string, string[] | undefined> = {
        "a.example.com": ["openid", "profile"],
        "b.example.com": ["openid", "email"],
        "empty.example.com": [],
      };
      const resolved = Promise.withResolvers<void>();
      let resolving = 0;
      const server = new AuthorizationServer({
        scopesSupported: defaults,
        signingKeys: new StaticSigningKeyProvider(await generateSigningKey()),
        grants: {},
        resolve: async (request) => {
          const url = new URL(request.url);
          const context = {
            services: {
              clientService: services.clientService,
              tokenService: services.tokenService,
            },
            issuer: url.origin,
            scopesSupported: scopesByHost[url.hostname],
          };
          if (++resolving === 4) resolved.resolve();
          await resolved.promise;
          return context;
        },
      });
      const request = (host: string) =>
        new Request(
          `https://${host}/.well-known/${
            oidc ? "openid-configuration" : "oauth-authorization-server"
          }`,
        );
      const metadata = async (host: string) => {
        const response = oidc
          ? await server.handleOidcMetadataRequest(request(host))
          : await server.handleMetadataRequest(request(host));
        expect(response.status).toStrictEqual(200);
        return await response.json();
      };
      const hosts = [
        "default.example.com",
        "a.example.com",
        "b.example.com",
        "empty.example.com",
      ];
      const documents = await Promise.all(hosts.map(metadata));

      expect(documents.map((document) => document.issuer)).toStrictEqual(
        hosts.map((host) => `https://${host}`),
      );
      expect(
        documents.map((document) => document.scopes_supported),
      ).toStrictEqual([
        defaults,
        ["openid", "profile"],
        ["openid", "email"],
        [],
      ]);
      expect(server.scopesSupported).toStrictEqual(defaults);
      expect(
        (await metadata("default.example.com")).scopes_supported,
      ).toStrictEqual(defaults);
    });
  }

  it("omits scopes when neither the request nor the options advertise them", async () => {
    const services = createTestServices();
    const server = new AuthorizationServer({
      grants: {},
      resolve: () => ({
        services: {
          clientService: services.clientService,
          tokenService: services.tokenService,
        },
        issuer: "https://auth.example.com",
      }),
    });

    const response = await server.handleMetadataRequest(
      new Request(
        "https://auth.example.com/.well-known/oauth-authorization-server",
      ),
    );
    expect(response.status).toStrictEqual(200);
    expect("scopes_supported" in (await response.json())).toStrictEqual(false);
  });
});
