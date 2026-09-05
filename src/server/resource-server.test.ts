import { assertRejects, assertStrictEquals } from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";
import { BasicScope } from "../models/scope.ts";
import {
  AccessDeniedError,
  InsufficientScopeError,
  InvalidTokenError,
  type OAuth2Error,
  ServerError,
  UnauthorizedClientError,
} from "../errors.ts";
import {
  formRequest,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../testing/_test_fixtures.ts";
import type { Token } from "../models/token.ts";
import { BEARER_TOKEN, ResourceServer } from "./resource-server.ts";

const testUser: TestUser = { id: "user-1", username: "testuser" };
const testClient: TestClient = { id: "client-1" };

function createTestServices() {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  return { userService, clientService, tokenService };
}

function createTestServer() {
  const services = createTestServices();
  const server = new ResourceServer<TestClient, TestUser>({
    resolve: () => ({ services: { tokenService: services.tokenService } }),
  });
  return { server, ...services };
}

async function setupTestData(
  services: ReturnType<typeof createTestServices>,
) {
  await services.userService.add(testUser, "password");
  await services.clientService.add(testClient);
}

describe("BEARER_TOKEN", () => {
  it("should match valid Bearer token", () => {
    const match = BEARER_TOKEN.exec("Bearer abc123");
    assertStrictEquals(match?.[1], "abc123");
  });

  it("should match case-insensitive Bearer", () => {
    const match = BEARER_TOKEN.exec("bearer abc123");
    assertStrictEquals(match?.[1], "abc123");
  });

  it("should match BEARER in uppercase", () => {
    const match = BEARER_TOKEN.exec("BEARER abc123");
    assertStrictEquals(match?.[1], "abc123");
  });

  it("should handle leading whitespace", () => {
    const match = BEARER_TOKEN.exec("  Bearer abc123");
    assertStrictEquals(match?.[1], "abc123");
  });

  it("should handle trailing whitespace", () => {
    const match = BEARER_TOKEN.exec("Bearer abc123  ");
    assertStrictEquals(match?.[1], "abc123");
  });

  it("should match token with special chars", () => {
    const match = BEARER_TOKEN.exec("Bearer abc-123_456.789~+/==");
    assertStrictEquals(match?.[1], "abc-123_456.789~+/==");
  });

  it("should not match Basic auth", () => {
    const match = BEARER_TOKEN.exec("Basic abc123");
    assertStrictEquals(match, null);
  });

  it("should not match missing token", () => {
    const match = BEARER_TOKEN.exec("Bearer ");
    assertStrictEquals(match, null);
  });
});

describe("ResourceServer", () => {
  describe("constructor", () => {
    it("should use default Scope class", () => {
      const { server } = createTestServer();
      const scope = new server.Scope("read write");
      assertStrictEquals(scope.toString(), "read write");
    });

    it("should use default realm", () => {
      const { server } = createTestServer();
      assertStrictEquals(server.realm, "Service");
    });

    it("should allow custom realm", () => {
      const services = createTestServices();
      const server = new ResourceServer<TestClient, TestUser>({
        resolve: () => ({ services: { tokenService: services.tokenService } }),
        realm: "MyAPI",
      });
      assertStrictEquals(server.realm, "MyAPI");
    });
  });

  describe("createErrorResponse", () => {
    it("should create JSON error response", async () => {
      const { server } = createTestServer();
      const error = new AccessDeniedError("test error");

      const response = server.createErrorResponse(error);

      assertStrictEquals(response.status, 401);
      assertStrictEquals(
        response.headers.get("Content-Type"),
        "application/json;charset=UTF-8",
      );
      const body = await response.json();
      assertStrictEquals(body.error, "access_denied");
      assertStrictEquals(body.error_description, "test error");
    });

    it("should wrap non-OAuth2 errors as ServerError", async () => {
      const { server } = createTestServer();
      const error = new Error("unexpected");

      const response = server.createErrorResponse(error);

      assertStrictEquals(response.status, 500);
      const body = await response.json();
      assertStrictEquals(body.error, "server_error");
    });

    it("should copy headers from the error to the response", () => {
      const { server } = createTestServer();
      const error = new AccessDeniedError("access denied");
      error.headers.set("WWW-Authenticate", 'Bearer realm="Service"');
      error.headers.set("X-Custom", "value");

      const response = server.createErrorResponse(error);

      assertStrictEquals(
        response.headers.get("WWW-Authenticate"),
        'Bearer realm="Service"',
      );
      assertStrictEquals(response.headers.get("X-Custom"), "value");
    });

    it("should populate error_uri from error.type when only type is set", async () => {
      const { server } = createTestServer();
      const error = new AccessDeniedError("denied", {
        type: "https://errors.example/access-denied",
      });

      const response = server.createErrorResponse(error);

      const body = await response.json();
      assertStrictEquals(
        body.error_uri,
        "https://errors.example/access-denied",
      );
      assertStrictEquals(
        error.extensions.error_uri,
        "https://errors.example/access-denied",
      );
    });

    it("should populate type from error_uri when only error_uri is set", async () => {
      const { server } = createTestServer();
      const error = new AccessDeniedError("denied", {
        extensions: {
          error: "access_denied",
          error_uri: "https://errors.example/ad",
        },
      });

      const response = server.createErrorResponse(error);

      const body = await response.json();
      assertStrictEquals(body.error_uri, "https://errors.example/ad");
      assertStrictEquals(error.type, "https://errors.example/ad");
    });

    it("should throw the oauth2 error when throwOnError is true", () => {
      const services = createTestServices();
      const server = new ResourceServer<TestClient, TestUser>({
        resolve: () => ({ services: { tokenService: services.tokenService } }),
        throwOnError: true,
      });

      let thrown: unknown;
      try {
        server.handleError(new Error("unexpected"));
      } catch (error) {
        thrown = error;
      }
      assertStrictEquals(thrown instanceof ServerError, true);
    });

    it("should apply the prepare callback before throwing", () => {
      const services = createTestServices();
      const server = new ResourceServer<TestClient, TestUser>({
        resolve: () => ({ services: { tokenService: services.tokenService } }),
        throwOnError: true,
      });

      let thrown: OAuth2Error | undefined;
      try {
        server.handleError(
          new ServerError("boom"),
          (e) => e.headers.set("X-Prepared", "yes"),
        );
      } catch (error) {
        thrown = error as OAuth2Error;
      }
      assertStrictEquals(thrown?.headers.get("X-Prepared"), "yes");
    });

    it("should return response normally when throwOnError is false", () => {
      const { server } = createTestServer();
      const response = server.handleError(new AccessDeniedError("denied"));
      assertStrictEquals(response.status, 401);
    });
  });

  describe("createErrorResponse with problem-details format", () => {
    function createProblemDetailsServer() {
      const services = createTestServices();
      const server = new ResourceServer<TestClient, TestUser>({
        resolve: () => ({ services: { tokenService: services.tokenService } }),
        errorFormat: "problem-details",
      });
      return { server, ...services };
    }

    it("should create Problem Details error response", async () => {
      const { server } = createProblemDetailsServer();
      const error = new AccessDeniedError("test error");

      const response = server.createErrorResponse(error);

      assertStrictEquals(response.status, 401);
      assertStrictEquals(
        response.headers.get("content-type"),
        "application/problem+json",
      );
      const body = await response.json();
      assertStrictEquals(body.error, "access_denied");
      assertStrictEquals(body.status, 401);
      assertStrictEquals(body.title, "Access Denied");
      assertStrictEquals(body.detail, "test error");
    });

    it("should wrap non-OAuth2 errors as ServerError", async () => {
      const { server } = createProblemDetailsServer();
      const error = new Error("unexpected");

      const response = server.createErrorResponse(error);

      assertStrictEquals(response.status, 500);
      const body = await response.json();
      assertStrictEquals(body.error, "server_error");
      assertStrictEquals(body.status, 500);
      assertStrictEquals(
        body.detail,
        "The server encountered an unexpected condition.",
      );
    });

    it("should copy headers from the error to the response", () => {
      const { server } = createProblemDetailsServer();
      const error = new AccessDeniedError("access denied");
      error.headers.set("WWW-Authenticate", 'Bearer realm="Service"');

      const response = server.createErrorResponse(error);

      assertStrictEquals(
        response.headers.get("WWW-Authenticate"),
        'Bearer realm="Service"',
      );
    });

    it("should include oauth2 extensions in Problem Details body", async () => {
      const { server } = createProblemDetailsServer();
      const error = new AccessDeniedError("denied", {
        type: "https://errors.example/access-denied",
      });

      const response = server.createErrorResponse(error);

      const body = await response.json();
      assertStrictEquals(body.error, "access_denied");
      assertStrictEquals(body.detail, "denied");
      assertStrictEquals(body.type, "https://errors.example/access-denied");
      assertStrictEquals(
        body.error_uri,
        "https://errors.example/access-denied",
      );
    });
  });

  describe("buildWwwAuthenticate", () => {
    it("should build basic WWW-Authenticate header", () => {
      const { server } = createTestServer();
      const result = server.buildWwwAuthenticate();
      assertStrictEquals(result, 'Bearer realm="Service"');
    });

    it("should include error attributes when error provided", () => {
      const { server } = createTestServer();
      const error = new InvalidTokenError("token expired");
      const result = server.buildWwwAuthenticate(error);
      assertStrictEquals(
        result,
        'Bearer realm="Service", error="invalid_token", error_description="token expired"',
      );
    });

    it("should include scope when provided explicitly", () => {
      const { server } = createTestServer();
      const error = new InvalidTokenError("access denied");
      const result = server.buildWwwAuthenticate(error, "read write");
      assertStrictEquals(
        result,
        'Bearer realm="Service", error="invalid_token", error_description="access denied", scope="read write"',
      );
    });

    it("should use requiredScope from InsufficientScopeError", () => {
      const { server } = createTestServer();
      const error = new InsufficientScopeError("need more permissions");
      error.extensions.requiredScope = "admin delete";
      const result = server.buildWwwAuthenticate(error);
      assertStrictEquals(
        result,
        'Bearer realm="Service", error="insufficient_scope", error_description="need more permissions", scope="admin delete"',
      );
    });

    it("omits the error code when the request presented no credentials", () => {
      const { server } = createTestServer();
      const result = server.buildWwwAuthenticate(
        new AccessDeniedError("authentication required"),
      );
      assertStrictEquals(result, 'Bearer realm="Service"');
    });

    it("omits an error code RFC 6750 does not register as a challenge code", () => {
      const { server } = createTestServer();
      const result = server.buildWwwAuthenticate(
        new UnauthorizedClientError("client may not use this grant"),
      );
      assertStrictEquals(result, 'Bearer realm="Service"');
    });

    it("still names the required scope when the challenge carries no error code", () => {
      const { server } = createTestServer();
      const result = server.buildWwwAuthenticate(
        new AccessDeniedError("authentication required"),
        "read",
      );
      assertStrictEquals(result, 'Bearer realm="Service", scope="read"');
    });

    it("should prefer explicit scope over error requiredScope", () => {
      const { server } = createTestServer();
      const error = new InsufficientScopeError("insufficient");
      error.extensions.requiredScope = "admin";
      const result = server.buildWwwAuthenticate(error, "custom");
      assertStrictEquals(
        result,
        'Bearer realm="Service", error="insufficient_scope", error_description="insufficient", scope="custom"',
      );
    });
  });

  describe("getAccessToken", () => {
    it("should extract token from Authorization header", async () => {
      const { server } = createTestServer();
      const request = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer test-token" },
      });

      const token = await server.getAccessToken(request);
      assertStrictEquals(token, "test-token");
    });

    it("should handle case-insensitive Bearer", async () => {
      const { server } = createTestServer();
      const request = new Request("http://localhost/api", {
        headers: { Authorization: "bearer test-token" },
      });

      const token = await server.getAccessToken(request);
      assertStrictEquals(token, "test-token");
    });

    it("should extract token from POST body", async () => {
      const { server } = createTestServer();
      const request = formRequest("http://localhost/api", {
        access_token: "body-token",
      });

      const token = await server.getAccessToken(request);
      assertStrictEquals(token, "body-token");
    });

    it("should prefer Authorization header over body", async () => {
      const { server } = createTestServer();
      const request = formRequest("http://localhost/api", {
        access_token: "body-token",
      }, { Authorization: "Bearer header-token" });

      const token = await server.getAccessToken(request);
      assertStrictEquals(token, "header-token");
    });

    it("should return null when no token present", async () => {
      const { server } = createTestServer();
      const request = new Request("http://localhost/api");

      const token = await server.getAccessToken(request);
      assertStrictEquals(token, null);
    });

    it("should return null for invalid Authorization header", async () => {
      const { server } = createTestServer();
      const request = new Request("http://localhost/api", {
        headers: { Authorization: "Basic abc123" },
      });

      const token = await server.getAccessToken(request);
      assertStrictEquals(token, null);
    });

    it("should not check body for GET requests", async () => {
      const { server } = createTestServer();
      const request = new Request(
        "http://localhost/api?access_token=query-token",
      );

      const token = await server.getAccessToken(request);
      assertStrictEquals(token, null);
    });
  });

  describe("getToken", () => {
    let server: ResourceServer<TestClient, TestUser>;
    let tokenService: MemoryTokenService<TestClient, TestUser>;

    beforeEach(async () => {
      const result = createTestServer();
      server = result.server;
      tokenService = result.tokenService;
      await setupTestData(result);
    });

    it("should return valid token", async () => {
      const savedToken: Token<TestClient, TestUser> = {
        accessToken: "valid-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(savedToken);

      const token = await server.getToken("valid-token", { tokenService });
      assertStrictEquals(token.accessToken, "valid-token");
    });

    it("should throw InvalidTokenError for non-existent token", async () => {
      await assertRejects(
        () => server.getToken("non-existent", { tokenService }),
        InvalidTokenError,
        "invalid access token",
      );
    });

    it("should throw InvalidTokenError for expired token", async () => {
      const expiredToken: Token<TestClient, TestUser> = {
        accessToken: "expired-token",
        accessTokenExpiresAt: new Date(Date.now() - 1000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(expiredToken);

      await assertRejects(
        () => server.getToken("expired-token", { tokenService }),
        InvalidTokenError,
        "access token has expired",
      );
    });

    it("accepts a token that expired within the configured clock skew", async () => {
      const services = createTestServices();
      await setupTestData(services);
      const skewedServer = new ResourceServer<TestClient, TestUser>({
        resolve: () => ({ services: { tokenService: services.tokenService } }),
        clockSkewSeconds: 30,
      });
      await services.tokenService.save({
        accessToken: "drifted-token",
        accessTokenExpiresAt: new Date(Date.now() - 10_000),
        client: testClient,
        user: testUser,
      });

      const token = await skewedServer.getToken("drifted-token", {
        tokenService: services.tokenService,
      });

      assertStrictEquals(token.accessToken, "drifted-token");
    });

    it("refuses a token that expired beyond the configured clock skew", async () => {
      const services = createTestServices();
      await setupTestData(services);
      const skewedServer = new ResourceServer<TestClient, TestUser>({
        resolve: () => ({ services: { tokenService: services.tokenService } }),
        clockSkewSeconds: 30,
      });
      await services.tokenService.save({
        accessToken: "long-expired-token",
        accessTokenExpiresAt: new Date(Date.now() - 31_000),
        client: testClient,
        user: testUser,
      });

      await assertRejects(
        () =>
          skewedServer.getToken("long-expired-token", {
            tokenService: services.tokenService,
          }),
        InvalidTokenError,
        "access token has expired",
      );
    });

    it("refuses a token the moment it expires when no clock skew is configured", async () => {
      const expiredToken: Token<TestClient, TestUser> = {
        accessToken: "just-expired-token",
        accessTokenExpiresAt: new Date(Date.now() - 1),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(expiredToken);

      await assertRejects(
        () => server.getToken("just-expired-token", { tokenService }),
        InvalidTokenError,
        "access token has expired",
      );
    });

    it("should accept token without expiration", async () => {
      const noExpiryToken: Token<TestClient, TestUser> = {
        accessToken: "no-expiry-token",
        client: testClient,
        user: testUser,
      };
      await tokenService.save(noExpiryToken);

      const token = await server.getToken("no-expiry-token", { tokenService });
      assertStrictEquals(token.accessToken, "no-expiry-token");
    });
  });

  describe("authenticate", () => {
    let server: ResourceServer<TestClient, TestUser>;
    let tokenService: MemoryTokenService<TestClient, TestUser>;

    beforeEach(async () => {
      const result = createTestServer();
      server = result.server;
      tokenService = result.tokenService;
      await setupTestData(result);
    });

    it("should return authenticated context", async () => {
      const savedToken: Token<TestClient, TestUser> = {
        accessToken: "auth-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read write"),
      };
      await tokenService.save(savedToken);

      const request = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer auth-token" },
      });

      const context = await server.authenticate(request);

      assertStrictEquals(context.token.accessToken, "auth-token");
      assertStrictEquals(context.client.id, testClient.id);
      assertStrictEquals(context.user?.id, testUser.id);
      assertStrictEquals(context.scope?.toString(), "read write");
    });

    it("should throw AccessDeniedError when no token provided", async () => {
      const request = new Request("http://localhost/api");

      await assertRejects(
        () => server.authenticate(request),
        AccessDeniedError,
        "authentication required",
      );
    });

    it("should verify required scope as string", async () => {
      const savedToken: Token<TestClient, TestUser> = {
        accessToken: "scoped-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read write delete"),
      };
      await tokenService.save(savedToken);

      const request = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer scoped-token" },
      });

      const context = await server.authenticate(request, "read");

      assertStrictEquals(context.token.accessToken, "scoped-token");
    });

    it("should verify required scope as Scope object", async () => {
      const savedToken: Token<TestClient, TestUser> = {
        accessToken: "scoped-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read write delete"),
      };
      await tokenService.save(savedToken);

      const request = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer scoped-token" },
      });

      const context = await server.authenticate(
        request,
        new BasicScope("read write"),
      );

      assertStrictEquals(context.token.accessToken, "scoped-token");
    });

    it("should throw InsufficientScopeError for insufficient scope (HTTP 403)", async () => {
      const savedToken: Token<TestClient, TestUser> = {
        accessToken: "limited-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read"),
      };
      await tokenService.save(savedToken);

      const request = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer limited-token" },
      });

      await assertRejects(
        () => server.authenticate(request, "write"),
        InsufficientScopeError,
        "insufficient scope",
      );
    });

    it("should throw InsufficientScopeError when token has no scope but scope required", async () => {
      const savedToken: Token<TestClient, TestUser> = {
        accessToken: "no-scope-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(savedToken);

      const request = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer no-scope-token" },
      });

      await assertRejects(
        () => server.authenticate(request, "read"),
        InsufficientScopeError,
        "insufficient scope",
      );
    });

    it("should include required scope in InsufficientScopeError", async () => {
      const savedToken: Token<TestClient, TestUser> = {
        accessToken: "limited-token-2",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read"),
      };
      await tokenService.save(savedToken);

      const request = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer limited-token-2" },
      });

      try {
        await server.authenticate(request, "admin");
        throw new Error("Should have thrown");
      } catch (error) {
        if (error instanceof InsufficientScopeError) {
          assertStrictEquals(
            (error.extensions as { requiredScope?: string }).requiredScope,
            "admin",
          );
        } else {
          throw error;
        }
      }
    });

    it("should not require scope when not specified", async () => {
      const savedToken: Token<TestClient, TestUser> = {
        accessToken: "any-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(savedToken);

      const request = new Request("http://localhost/api", {
        headers: { Authorization: "Bearer any-token" },
      });

      const context = await server.authenticate(request);

      assertStrictEquals(context.token.accessToken, "any-token");
    });
  });

  describe("resolve (per-request services)", () => {
    it("authenticate uses the services resolved from the request", async () => {
      const tenantA = createTestServices();
      const tenantB = createTestServices();
      await setupTestData(tenantA);
      await setupTestData(tenantB);
      await tenantA.tokenService.save({
        accessToken: "token-a",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
      });
      await tenantB.tokenService.save({
        accessToken: "token-b",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
      });

      const server = new ResourceServer<TestClient, TestUser>({
        resolve: (request) => ({
          services: {
            tokenService: request.headers.get("x-tenant") === "b"
              ? tenantB.tokenService
              : tenantA.tokenService,
          },
        }),
      });

      const context = await server.authenticate(
        new Request("http://localhost/api", {
          headers: { Authorization: "Bearer token-b", "x-tenant": "b" },
        }),
      );
      assertStrictEquals(context.token.accessToken, "token-b");

      await assertRejects(
        () =>
          server.authenticate(
            new Request("http://localhost/api", {
              headers: { Authorization: "Bearer token-b", "x-tenant": "a" },
            }),
          ),
        InvalidTokenError,
      );
    });

    it("defaults to the static services when no resolve is given", async () => {
      const { server, tokenService, ...services } = createTestServer();
      await setupTestData({ tokenService, ...services });
      await tokenService.save({
        accessToken: "default-token",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        client: testClient,
        user: testUser,
      });

      const context = await server.authenticate(
        new Request("http://localhost/api", {
          headers: { Authorization: "Bearer default-token" },
        }),
      );
      assertStrictEquals(context.token.accessToken, "default-token");
    });
  });
});
