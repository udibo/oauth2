import {
  assertEquals,
  assertRejects,
  assertStrictEquals,
  assertStringIncludes,
  assertThrows,
} from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";
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
import { AuthorizationServer } from "./authorization-server.ts";
import type { DispatchableGrant } from "./grants/grant.ts";
import { isPublicSuffix } from "./public-suffix/mod.ts";
import type { IsPublicSuffix } from "./redirect-uri.ts";

const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

/** A grant that dispatches token requests but serves no endpoint of its own. */
class TokenOnlyGrant
  implements DispatchableGrant<TestClient, TestUser, BasicScope> {
  constructor(readonly grantType: string) {}

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
    introspectionClaims?: (
      token: Token<TestClient, TestUser, BasicScope>,
    ) => Record<string, unknown>;
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
  });

  return {
    server,
    ...services,
    authorizationCodeGrant,
  };
}

async function setupTestData(
  services: ReturnType<typeof createTestServices>,
) {
  await services.userService.add(testUser, "password");
  await services.clientService.add(testClient, "secret", testUser.id);
}

describe("AuthorizationServer", () => {
  describe("constructor", () => {
    it("should inherit from ResourceServer", () => {
      const { server } = createTestServer();
      assertStrictEquals(typeof server.authenticate, "function");
    });

    it("should set issuer", async () => {
      const { server } = createTestServer();
      const context = await server.authorizationContext(
        new Request("http://localhost/token"),
      );
      assertStrictEquals(context.issuer, "https://auth.example.com");
    });

    it("should copy grants", () => {
      const { server } = createTestServer();
      assertStrictEquals(
        typeof server.grants["client_credentials"],
        "object",
      );
    });

    it("throws when a grant is registered under a mismatched key", () => {
      const services = createTestServices();
      const refreshTokenGrant = new RefreshTokenGrant({
        resolve: () => ({
          clientService: services.clientService,
          tokenService: services.tokenService,
        }),
      });
      assertThrows(
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

      assertStrictEquals(body.token_type, "Bearer");
      assertStrictEquals(body.access_token, "access-123");
      assertStrictEquals(body.expires_in, 3600);
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

      assertStrictEquals(body.expires_in, 120);
    });

    it("falls back to the service lifetime when the token has no expiry", () => {
      const { server, clientService, tokenService } = createTestServer();
      const token: Token<TestClient, TestUser> = {
        accessToken: "access-123",
        client: testClient,
        user: testUser,
      };

      const body = server.bearerToken(token, { clientService, tokenService });

      assertStrictEquals(body.expires_in, tokenService.accessTokenLifetime);
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

      assertStrictEquals(body.refresh_token, "refresh-123");
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

      assertStrictEquals(body.scope, "read write");
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

      assertStrictEquals(response.status, 200);
      assertStrictEquals(
        response.headers.get("Content-Type"),
        "application/json;charset=UTF-8",
      );
      assertStrictEquals(response.headers.get("Cache-Control"), "no-store");
      assertStrictEquals(response.headers.get("Pragma"), "no-cache");

      const body = await response.json();
      assertStrictEquals(body.access_token, "access-123");
    });
  });

  describe("createErrorResponse", () => {
    it("should create error response using configured format", async () => {
      const { server } = createTestServer();
      const error = new Error("test error");

      const response = server.createErrorResponse(error);

      assertStrictEquals(response.status, 500);
      const body = await response.json();
      assertStrictEquals(body.error, "server_error");
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

      assertStrictEquals(response.status, 500);
      assertStrictEquals(
        response.headers.get("content-type"),
        "application/problem+json",
      );
      const body = await response.json();
      assertStrictEquals(body.error, "server_error");
      assertStrictEquals(body.status, 500);
      assertStrictEquals(body.title, "OAuth2 Error");
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

      assertStrictEquals(response.status, 400);
      const body = await response.json();
      assertStrictEquals(body.error, "invalid_request");
      assertStrictEquals(body.error_description, "method must be POST");
    });

    it("should reject wrong content type", async () => {
      const request = new Request("http://localhost/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      const response = await server.handleTokenRequest(request);

      assertStrictEquals(response.status, 400);
      const body = await response.json();
      assertStrictEquals(
        body.error_description?.includes("content-type"),
        true,
      );
    });

    it("should require grant_type parameter", async () => {
      const request = tokenRequest({});

      const response = await server.handleTokenRequest(request);

      assertStrictEquals(response.status, 400);
      const body = await response.json();
      assertStrictEquals(
        body.error_description,
        "grant_type parameter required",
      );
    });

    it("leaves the request body unread for the caller", async () => {
      const request = tokenRequest(
        { grant_type: "client_credentials" },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleTokenRequest(request);

      assertStrictEquals(response.status, 200);
      assertStrictEquals(request.bodyUsed, false);
      const body = await request.formData();
      assertStrictEquals(body.get("grant_type"), "client_credentials");
    });

    it("should reject unsupported grant type", async () => {
      const request = tokenRequest({ grant_type: "unknown" });

      const response = await server.handleTokenRequest(request);

      assertStrictEquals(response.status, 400);
      const responseBody = await response.json();
      assertStrictEquals(responseBody.error, "unsupported_grant_type");
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

      assertStrictEquals(response.status, 401);
      const responseBody = await response.json();
      assertStrictEquals(responseBody.error, "unauthorized_client");
    });

    it("sends WWW-Authenticate on 401 when Basic credentials are invalid", async () => {
      const request = tokenRequest(
        { grant_type: "client_credentials" },
        basicAuthHeader("client-1", "wrong-secret"),
      );

      const response = await server.handleTokenRequest(request);

      assertStrictEquals(response.status, 401);
      const responseBody = await response.json();
      assertStrictEquals(responseBody.error, "invalid_client");
      assertStringIncludes(
        response.headers.get("WWW-Authenticate") ?? "",
        "Basic",
      );
    });

    it("should handle client-credentials grant", async () => {
      const request = tokenRequest(
        { grant_type: "client_credentials" },
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleTokenRequest(request);

      assertStrictEquals(response.status, 200);
      const responseBody = await response.json();
      assertStrictEquals(responseBody.token_type, "Bearer");
      assertStrictEquals(typeof responseBody.access_token, "string");
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

      const request = tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "refresh-123",
      }, basicAuthHeader("client-1", "secret"));

      const response = await server.handleTokenRequest(request);

      assertStrictEquals(response.status, 200);
      const responseBody = await response.json();
      assertStrictEquals(typeof responseBody.access_token, "string");
    });

    it("should handle authorization-code grant", async () => {
      const authCode = {
        code: "auth-code-123",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      };
      await authorizationCodeService.save(authCode);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "auth-code-123",
      }, basicAuthHeader("client-1", "secret"));

      const response = await server.handleTokenRequest(request);

      assertStrictEquals(response.status, 200);
      const responseBody = await response.json();
      assertStrictEquals(typeof responseBody.access_token, "string");
      assertStrictEquals(typeof responseBody.refresh_token, "string");
    });
  });

  describe("parseAuthorizeParameters", () => {
    it("should parse all authorization parameters", () => {
      const { server } = createTestServer();
      const url =
        "http://localhost/authorize?response_type=code&client_id=client-1&redirect_uri=https://example.com/callback&state=xyz&scope=read%20write&code_challenge=challenge&code_challenge_method=S256";
      const request = new Request(url);

      const params = server.parseAuthorizeParameters(request);

      assertStrictEquals(params.responseType, "code");
      assertStrictEquals(params.clientId, "client-1");
      assertStrictEquals(params.redirectUri, "https://example.com/callback");
      assertStrictEquals(params.state, "xyz");
      assertStrictEquals(params.scope, "read write");
      assertStrictEquals(params.challenge, "challenge");
      assertStrictEquals(params.challengeMethod, "S256");
    });

    it("should return undefined for missing parameters", () => {
      const { server } = createTestServer();
      const request = new Request("http://localhost/authorize");

      const params = server.parseAuthorizeParameters(request);

      assertStrictEquals(params.responseType, undefined);
      assertStrictEquals(params.clientId, undefined);
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

      assertStrictEquals(response.status, 400);
      const body = await response.json();
      assertStrictEquals(
        body.error_description,
        "client_id parameter required",
      );
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

      assertStrictEquals(response.status, 401);
      const body = await response.json();
      assertStrictEquals(body.error_description, "no authorized redirect_uri");
    });

    it("should validate redirect_uri is authorized", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&redirect_uri=https://evil.com/callback&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      assertStrictEquals(response.status, 401);
      const body = await response.json();
      assertStrictEquals(body.error_description, "redirect_uri not authorized");
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

      assertStrictEquals(response.status, 302);
      const url = new URL(response.headers.get("Location")!);
      assertStrictEquals(url.origin, "https://myapp-a1b2.myorg.deno.net");
      assertStrictEquals(url.pathname, "/auth/callback");
      assertStrictEquals(url.searchParams.has("code"), true);
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

      assertStrictEquals(response.status, 401);
      const body = await response.json();
      assertStrictEquals(body.error_description, "redirect_uri not authorized");
    });

    it("should refuse a host a wildcard registration cannot reach", async () => {
      await clientService.add({
        id: "preview-client-2",
        grants: ["authorization_code"],
        redirectUris: ["https://myapp-*.myorg.deno.net/auth/callback"],
      });

      for (
        const redirectUri of [
          "https://myapp-a1.evil.myorg.deno.net/auth/callback",
          "http://myapp-a1.myorg.deno.net/auth/callback",
          "https://myapp-a1.myorg.deno.net/auth/callback?next=x",
        ]
      ) {
        const request = new Request(
          `http://localhost/authorize?response_type=code&client_id=preview-client-2&redirect_uri=${
            encodeURIComponent(redirectUri)
          }&state=xyz`,
        );

        const response = await server.handleAuthorizeRequest(
          request,
          authenticateUser,
        );

        assertStrictEquals(response.status, 401, redirectUri);
        const body = await response.json();
        assertStrictEquals(
          body.error_description,
          "redirect_uri not authorized",
          redirectUri,
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

      assertStrictEquals(response.status, 400);
      const body = await response.json();
      assertStrictEquals(
        body.error_description,
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

      assertStrictEquals(response.status, 302);
      const url = new URL(response.headers.get("Location")!);
      assertStrictEquals(url.origin, "https://myapp.myorg.deno.net");
    });

    it("should require state parameter", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      assertStrictEquals(response.status, 302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      assertStrictEquals(url.searchParams.get("error"), "invalid_request");
    });

    it("should require response_type parameter", async () => {
      const request = new Request(
        "http://localhost/authorize?client_id=client-1&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      assertStrictEquals(response.status, 302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      assertStrictEquals(url.searchParams.get("error"), "invalid_request");
      assertStrictEquals(url.searchParams.get("state"), "xyz");
    });

    it("should validate response_type is 'code'", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=token&client_id=client-1&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      assertStrictEquals(response.status, 302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      assertStrictEquals(
        url.searchParams.get("error"),
        "unsupported_response_type",
      );
      assertStrictEquals(
        url.searchParams.get("error_description"),
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

      assertStrictEquals(response.status, 302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      assertStrictEquals(url.searchParams.get("error"), "access_denied");
    });

    it("should generate authorization code on success", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      assertStrictEquals(response.status, 302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      assertStrictEquals(url.searchParams.has("code"), true);
      assertStrictEquals(url.searchParams.get("state"), "xyz");
      assertStrictEquals(url.origin, "https://example.com");
    });

    it("should use provided redirect_uri", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&redirect_uri=https://example.com/callback&state=xyz",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      assertStrictEquals(response.status, 302);
      const location = response.headers.get("Location")!;
      assertStrictEquals(
        location.startsWith("https://example.com/callback"),
        true,
      );
    });

    it("should validate PKCE challenge_method", async () => {
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz&code_challenge=challenge&code_challenge_method=plain",
      );

      const response = await server.handleAuthorizeRequest(
        request,
        authenticateUser,
      );

      assertStrictEquals(response.status, 302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      assertStrictEquals(
        url.searchParams.get("error_description"),
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

      assertStrictEquals(response.status, 302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      assertStrictEquals(
        url.searchParams.get("error_description")?.includes(
          "code_challenge required",
        ),
        true,
      );
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

      assertStrictEquals(response.status, 302);
      const url = new URL(response.headers.get("Location")!);
      assertStrictEquals(url.searchParams.get("error"), "invalid_request");
      assertStringIncludes(
        url.searchParams.get("error_description") ?? "",
        "PKCE is required",
      );
      assertStrictEquals(url.searchParams.has("code"), false);
    });

    it("does not leak an internal server_error message into the redirect", async () => {
      const leakyAuth = () =>
        Promise.reject(new ServerError("db dsn=postgres://secret@host"));
      const request = new Request(
        "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz",
      );
      const response = await server.handleAuthorizeRequest(request, leakyAuth);

      assertStrictEquals(response.status, 302);
      const url = new URL(response.headers.get("Location")!);
      assertStrictEquals(url.searchParams.get("error"), "server_error");
      assertEquals(
        (url.searchParams.get("error_description") ?? "").includes("secret"),
        false,
      );
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

      assertStrictEquals(response.status, 302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      assertStrictEquals(url.searchParams.has("code"), true);
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

      assertStrictEquals(response.status, 302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      assertStrictEquals(url.searchParams.get("error"), "access_denied");
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

      assertStrictEquals(response.status, 302);
      assertStrictEquals(
        response.headers.get("Location"),
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

      assertStrictEquals(response.status, 200);
      assertStrictEquals(response.headers.get("Content-Type"), "text/html");
      assertStrictEquals(await response.text(), "<html>consent</html>");
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

      assertStrictEquals(response.status, 302);
      const url = new URL(response.headers.get("Location")!);
      const code = url.searchParams.get("code");
      assertStrictEquals(typeof code, "string");
      assertStrictEquals(url.searchParams.get("error"), null);

      const saved = await result.authorizationCodeService.get(code!);
      assertStrictEquals(saved?.scope?.toString(), "write");
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

      assertStrictEquals(response.status, 401);
      const body = await response.json();
      assertStrictEquals(body.error, "unauthorized_client");
      assertStrictEquals(
        body.error_description,
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

      assertStrictEquals(response.status, 400);
      const body = await response.json();
      assertStrictEquals(body.error, "invalid_request");
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

      assertStrictEquals(response.status, 400);
      const body = await response.json();
      assertStrictEquals(body.error, "invalid_request");
      assertStrictEquals(
        body.error_description?.includes("content-type"),
        true,
      );
    });

    it("should require client authentication per RFC 7009", async () => {
      const request = formRequest("http://localhost/revoke", { token: "test" });

      const response = await server.handleRevocationRequest(request);

      assertStrictEquals(response.status, 401);
      const body = await response.json();
      assertStrictEquals(body.error, "invalid_client");
    });

    it("should require token parameter", async () => {
      const request = formRequest(
        "http://localhost/revoke",
        {},
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleRevocationRequest(request);

      assertStrictEquals(response.status, 400);
      const body = await response.json();
      assertStrictEquals(body.error_description, "token parameter required");
    });

    it("should revoke token and return 200", async () => {
      const token: Token<TestClient, TestUser> = {
        accessToken: "revoke-me",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(token);

      const request = formRequest("http://localhost/revoke", {
        token: "revoke-me",
      }, basicAuthHeader("client-1", "secret"));

      const response = await server.handleRevocationRequest(request);

      assertStrictEquals(response.status, 200);

      const revokedToken = await tokenService.getToken("revoke-me");
      assertStrictEquals(revokedToken, undefined);
    });

    it("should return 200 even for non-existent token", async () => {
      const request = formRequest("http://localhost/revoke", {
        token: "non-existent",
      }, basicAuthHeader("client-1", "secret"));

      const response = await server.handleRevocationRequest(request);

      assertStrictEquals(response.status, 200);
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

      const request = formRequest("http://localhost/revoke", {
        token: "refresh-revoke",
        token_type_hint: "refresh_token",
      }, basicAuthHeader("client-1", "secret"));

      const response = await server.handleRevocationRequest(request);

      assertStrictEquals(response.status, 200);
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

      assertStrictEquals(metadata.issuer, "https://auth.example.com");
      assertEquals(
        metadata.grant_types_supported,
        ["client_credentials", "refresh_token", "authorization_code"],
      );
      assertEquals(
        metadata.token_endpoint_auth_methods_supported,
        ["client_secret_basic", "client_secret_post", "none"],
      );
      assertEquals(metadata.code_challenge_methods_supported, ["S256"]);
      assertEquals(metadata.response_types_supported, ["code"]);
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

      assertEquals(
        metadata.token_endpoint_auth_methods_supported,
        ["client_secret_basic", "client_secret_post", "none"],
      );

      const response = await result.server.handleTokenRequest(tokenRequest({
        grant_type: "authorization_code",
        code: "public-code",
        client_id: "public-client",
      }));

      assertStrictEquals(response.status, 200);
      assertStrictEquals(typeof (await response.json()).access_token, "string");
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

      assertEquals(metadata.response_types_supported, []);
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
      assertThrows(
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

      const error = await assertRejects(
        () =>
          server.handleDeviceAuthorizationRequest(
            deviceRequest({ client_id: "device-public" }),
          ),
        ServerError,
      );
      assertStringIncludes(error.message, "TokenOnlyGrant");
      assertStringIncludes(
        error.message,
        "must extend DeviceAuthorizationGrant",
      );
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

      assertStrictEquals(response.status, 200);
      const body = await response.json();
      assertStrictEquals(typeof body.device_code, "string");
      assertStrictEquals(typeof body.user_code, "string");
      assertStrictEquals(
        body.verification_uri,
        "https://auth.example.com/device",
      );
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

      assertStrictEquals(response.status, 401);
      const body = await response.json();
      assertStrictEquals(body.error, "invalid_client");
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

      assertStrictEquals(response.status, 200);
      const body = await response.json();
      assertStrictEquals(typeof body.device_code, "string");
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

      assertStrictEquals(response.status, 401);
      assertStringIncludes(
        response.headers.get("WWW-Authenticate") ?? "",
        "Basic",
      );
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

      assertStrictEquals(response.status, 500);
      const body = await response.json();
      assertStrictEquals(body.error, "server_error");
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
          await result.clientService.add(
            endpointClient,
            "secret",
            testUser.id,
          );
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
          return request({
            headers: basicAuthHeader("endpoint-client", "secret"),
          }, body);
        }

        it("rejects a request that is not POST", async () => {
          const response = await endpoint.handle(
            server,
            request({ method: "GET" }),
          );

          assertStrictEquals(response.status, 400);
          const body = await response.json();
          assertStrictEquals(body.error, "invalid_request");
          assertStrictEquals(body.error_description, "method must be POST");
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

          assertStrictEquals(response.status, 400);
          const body = await response.json();
          assertStrictEquals(body.error, "invalid_request");
          assertStrictEquals(
            body.error_description,
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

          assertStrictEquals(response.status, 400);
          const body = await response.json();
          assertStrictEquals(body.error, "invalid_request");
          assertStrictEquals(
            body.error_description,
            "body must be application/x-www-form-urlencoded",
          );
        });

        it("rejects a request presenting no client credentials", async () => {
          const response = await endpoint.handle(server, request());

          assertStrictEquals(response.status, 401);
          const body = await response.json();
          assertStrictEquals(body.error, "invalid_client");
          assertStrictEquals(
            body.error_description,
            "client authentication required",
          );
        });

        it("rejects wrong Basic credentials with a challenge", async () => {
          const response = await endpoint.handle(
            server,
            request({
              headers: basicAuthHeader("endpoint-client", "wrong"),
            }),
          );

          assertStrictEquals(response.status, 401);
          const body = await response.json();
          assertStrictEquals(body.error, "invalid_client");
          assertStrictEquals(
            body.error_description,
            "client authentication failed",
          );
          assertStringIncludes(
            response.headers.get("WWW-Authenticate") ?? "",
            "Basic",
          );
        });

        it("rejects wrong body credentials", async () => {
          const response = await endpoint.handle(
            server,
            request({}, {
              ...endpoint.body,
              client_id: "endpoint-client",
              client_secret: "wrong",
            }),
          );

          assertStrictEquals(response.status, 401);
          const body = await response.json();
          assertStrictEquals(body.error, "invalid_client");
          assertStrictEquals(
            body.error_description,
            "client authentication failed",
          );
        });

        it("rejects an unsupported Authorization header", async () => {
          const response = await endpoint.handle(
            server,
            request({ headers: { authorization: "Bearer some-token" } }),
          );

          assertStrictEquals(response.status, 401);
          const body = await response.json();
          assertStrictEquals(body.error, "invalid_client");
          assertStrictEquals(
            body.error_description,
            "unsupported authorization header",
          );
        });

        it("falls back to body credentials when the Authorization header is not Basic", async () => {
          const response = await endpoint.handle(
            server,
            request({ headers: { authorization: "Bearer some-token" } }, {
              ...endpoint.body,
              client_id: "endpoint-client",
              client_secret: "secret",
            }),
          );

          assertStrictEquals(response.status, 200);
        });

        it("accepts a well-formed authenticated request", async () => {
          const response = await endpoint.handle(server, authenticated());

          assertStrictEquals(response.status, 200);
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

      const response = await server.handleAuthorizeRequest(
        request,
        () =>
          Promise.resolve({
            user: testUser,
            authorizedScope: new BasicScope("read"),
          }),
      );

      assertStrictEquals(response.status, 500);
      const body = await response.json();
      assertStrictEquals(body.error, "server_error");
      assertStrictEquals(
        body.error_description,
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

      const error = await assertRejects(
        () =>
          server.handleAuthorizeRequest(
            new Request(
              "http://localhost/authorize?response_type=code&client_id=client-1&state=xyz",
            ),
            () => Promise.resolve({ user: testUser }),
          ),
        ServerError,
      );
      assertStringIncludes(error.message, "TokenOnlyGrant");
      assertStringIncludes(
        error.message,
        "must extend AuthorizationCodeGrant",
      );
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

      const response = await result.server.handleAuthorizeRequest(
        request,
        () =>
          Promise.resolve({
            user: testUser,
            authorizedScope: new BasicScope("read"),
          }),
      );

      assertStrictEquals(response.status, 302);
      const location = response.headers.get("Location")!;
      const url = new URL(location);
      assertStrictEquals(url.searchParams.get("error"), "test_error");
      assertStrictEquals(
        url.searchParams.get("error_uri"),
        "https://example.com/docs/error",
      );
    });
  });

  describe("handleIntrospectionRequest", () => {
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

      assertStrictEquals(response.status, 400);
      const body = await response.json();
      assertStrictEquals(body.error, "invalid_request");
    });

    it("should reject wrong content type", async () => {
      const request = new Request("http://localhost/introspect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: "test" }),
      });

      const response = await server.handleIntrospectionRequest(request);

      assertStrictEquals(response.status, 400);
      const body = await response.json();
      assertStrictEquals(
        body.error_description?.includes("content-type"),
        true,
      );
    });

    it("should require client authentication", async () => {
      const request = formRequest("http://localhost/introspect", {
        token: "test-token",
      });

      const response = await server.handleIntrospectionRequest(request);

      assertStrictEquals(response.status, 401);
      const body = await response.json();
      assertStrictEquals(body.error, "invalid_client");
    });

    it("should require token parameter", async () => {
      const request = formRequest(
        "http://localhost/introspect",
        {},
        basicAuthHeader("client-1", "secret"),
      );

      const response = await server.handleIntrospectionRequest(request);

      assertStrictEquals(response.status, 400);
      const body = await response.json();
      assertStrictEquals(body.error_description, "token parameter required");
    });

    it("should return inactive for non-existent token", async () => {
      const request = formRequest("http://localhost/introspect", {
        token: "non-existent",
      }, basicAuthHeader("client-1", "secret"));

      const response = await server.handleIntrospectionRequest(request);

      assertStrictEquals(response.status, 200);
      const body = await response.json();
      assertStrictEquals(body.active, false);
    });

    it("should return inactive for expired token", async () => {
      const expiredToken: Token<TestClient, TestUser> = {
        accessToken: "expired-token",
        accessTokenExpiresAt: new Date(Date.now() - 1000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(expiredToken);

      const request = formRequest("http://localhost/introspect", {
        token: "expired-token",
      }, basicAuthHeader("client-1", "secret"));

      const response = await server.handleIntrospectionRequest(request);

      assertStrictEquals(response.status, 200);
      const body = await response.json();
      assertStrictEquals(body.active, false);
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

      const request = formRequest("http://localhost/introspect", {
        token: "valid-token",
      }, basicAuthHeader("client-1", "secret"));

      const response = await server.handleIntrospectionRequest(request);

      assertStrictEquals(response.status, 200);
      const body = await response.json();
      assertStrictEquals(body.active, true);
      assertStrictEquals(body.client_id, "client-1");
      assertStrictEquals(body.token_type, "Bearer");
      assertStrictEquals(body.scope, "read write");
      assertStrictEquals(body.iss, "https://auth.example.com");
      assertStrictEquals(body.sub, "user-1");
      assertStrictEquals(body.username, "testuser");
      assertStrictEquals(typeof body.exp, "number");
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

      const request = formRequest("http://localhost/introspect", {
        token: "claimed-token",
      }, basicAuthHeader("client-1", "secret"));
      const response = await result.server.handleIntrospectionRequest(request);

      assertStrictEquals(response.status, 200);
      const body = await response.json();
      assertEquals(body.permissions, ["posts:write"]);
      assertStrictEquals(body.org_id, "org-1");
      assertEquals(body.org_roles, ["admin"]);
      assertStrictEquals(body.subject_marker, "user-1");
      assertStrictEquals(body.active, true);
      assertStrictEquals(body.scope, "read");
      assertStrictEquals(body.client_id, "client-1");
      assertStrictEquals(body.sub, "user-1");
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

      assertStrictEquals(response.status, 200);
      const body = await response.json();
      assertStrictEquals(body.active, true);
      assertStrictEquals(body.client_id, "client-1");
      assertStrictEquals(body.sub, undefined);
      assertStrictEquals(body.username, undefined);
    });

    it("should include cache headers", async () => {
      const request = formRequest("http://localhost/introspect", {
        token: "any-token",
      }, basicAuthHeader("client-1", "secret"));

      const response = await server.handleIntrospectionRequest(request);

      assertStrictEquals(response.headers.get("Cache-Control"), "no-store");
      assertStrictEquals(response.headers.get("Pragma"), "no-cache");
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

      assertStrictEquals(response.status, 200);
      assertStrictEquals(
        response.headers.get("Content-Type"),
        "application/json;charset=UTF-8",
      );

      const body = await response.json();
      assertStrictEquals(body.issuer, "https://auth.example.com");
      assertStrictEquals(
        body.authorization_endpoint,
        "https://auth.example.com/authorize",
      );
      assertStrictEquals(body.token_endpoint, "https://auth.example.com/token");
      assertStrictEquals(
        body.revocation_endpoint,
        "https://auth.example.com/revoke",
      );
      assertStrictEquals(
        body.introspection_endpoint,
        "https://auth.example.com/introspect",
      );
      assertEquals(body.grant_types_supported, [
        "client_credentials",
        "authorization_code",
      ]);
      assertEquals(body.response_types_supported, ["code"]);
      assertEquals(body.scopes_supported, ["read", "write", "admin"]);
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
          const t = new URL(request.url).searchParams.get("tenant") === "b"
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
          const t = new URL(request.url).searchParams.get("tenant") === "b"
            ? tenantB
            : tenantA;
          return {
            services: {
              clientService: t.clientService,
              tokenService: t.tokenService,
            },
            issuer: t === tenantB
              ? "https://b.example.com"
              : "https://a.example.com",
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
      assertStrictEquals(resB.status, 200);
      assertStrictEquals((await resB.json()).expires_in, 2222);

      const resA = await server.handleTokenRequest(tenantTokenRequest("a"));
      assertStrictEquals(resA.status, 200);
      assertStrictEquals((await resA.json()).expires_in, 1111);
    });

    it("serves metadata with the per-request issuer", async () => {
      const server = await buildServer();
      const metaRequest = (tenant: string) =>
        new Request(
          `http://localhost/.well-known/oauth-authorization-server?tenant=${tenant}`,
        );

      const resB = await server.handleMetadataRequest(metaRequest("b"));
      assertStrictEquals((await resB.json()).issuer, "https://b.example.com");

      const resA = await server.handleMetadataRequest(metaRequest("a"));
      assertStrictEquals((await resA.json()).issuer, "https://a.example.com");
    });
  });
});
