import { describe, expect, it, vi } from "vitest";
import { rejection } from "../../_test_assert.ts";
import type { BasicScope } from "../../models/scope.ts";
import { InvalidGrantError, InvalidRequestError } from "../../errors.ts";
import { AuthorizationServer } from "../authorization-server.ts";
import {
  basicAuthHeader,
  exchangeToken,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
  tokenRequest,
} from "../../testing/_test_fixtures.ts";
import { PasswordGrant } from "./password.ts";

const testUser: TestUser = { id: "user-1", username: "kyle" };
const testClient: TestClient = {
  id: "client-1",
  confidential: true,
  grants: ["password"],
};

async function createTestGrant(options: { allowRefreshToken?: boolean } = {}) {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });

  await userService.add(testUser, "hunter2");

  const grant = new PasswordGrant<TestClient, TestUser, BasicScope>({
    resolve: () => ({ clientService, tokenService, userService }),
    ...options,
  });

  return { grant, clientService, tokenService, userService };
}

describe("PasswordGrant", () => {
  describe("grantType", () => {
    it("should return password", async () => {
      const { grant } = await createTestGrant();
      expect(grant.grantType).toBe("password");
    });
  });

  describe("token", () => {
    it("should return access token for valid credentials", async () => {
      const { grant, clientService, tokenService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "password",
        username: "kyle",
        password: "hunter2",
      });

      const token = await exchangeToken(grant, request, testClient);

      expect(typeof token.accessToken).toBe("string");
      expect(token.client.id).toBe(testClient.id);
      expect(token.user?.id).toBe(testUser.id);
      expect(token.user?.username).toBe(testUser.username);

      const savedToken = await tokenService.getToken(token.accessToken);
      expect(savedToken?.accessToken).toBe(token.accessToken);
    });

    it("should include scope when requested", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "password",
        username: "kyle",
        password: "hunter2",
        scope: "read write",
      });

      const token = await exchangeToken(grant, request, testClient);

      expect(token.scope?.toString()).toBe("read write");
    });

    it("should work without scope parameter", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "password",
        username: "kyle",
        password: "hunter2",
      });

      const token = await exchangeToken(grant, request, testClient);

      expect(token.scope).toBe(undefined);
    });

    it("should throw InvalidRequestError when username is missing", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "password",
        password: "hunter2",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidRequestError,
        "username parameter required",
      );
    });

    it("should throw InvalidRequestError when username is empty", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "password",
        username: "",
        password: "hunter2",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidRequestError,
        "username parameter required",
      );
    });

    it("should throw InvalidRequestError when password is missing", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "password",
        username: "kyle",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidRequestError,
        "password parameter required",
      );
    });

    it("should throw InvalidRequestError when password is empty", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "password",
        username: "kyle",
        password: "",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidRequestError,
        "password parameter required",
      );
    });

    it("should throw InvalidGrantError when user not found", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "password",
        username: "unknown",
        password: "hunter2",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidGrantError,
        "user authentication failed",
      );
    });

    it("should throw InvalidGrantError when password is wrong", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "password",
        username: "kyle",
        password: "wrongpassword",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidGrantError,
        "user authentication failed",
      );
    });

    it("should include refresh token by default", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "password",
        username: "kyle",
        password: "hunter2",
      });

      const token = await exchangeToken(grant, request, testClient);

      expect("refreshToken" in token).toBe(true);
      expect(
        typeof (token as unknown as { refreshToken: string }).refreshToken,
      ).toBe("string");
    });

    it("should not include refresh token when allowRefreshToken is false", async () => {
      const { grant, clientService } = await createTestGrant({
        allowRefreshToken: false,
      });
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "password",
        username: "kyle",
        password: "hunter2",
      });

      const token = await exchangeToken(grant, request, testClient);

      expect("refreshToken" in token).toBe(false);
    });
  });

  describe("errors thrown by getAuthenticated", () => {
    function passwordTokenRequest(): Request {
      return tokenRequest(
        {
          grant_type: "password",
          username: "kyle",
          password: "hunter2",
        },
        basicAuthHeader("client-1", "secret"),
      );
    }

    function createTokenServer(
      services: Awaited<ReturnType<typeof createTestGrant>>,
    ) {
      return new AuthorizationServer<TestClient, TestUser, BasicScope>({
        resolve: () => ({
          services: {
            clientService: services.clientService,
            tokenService: services.tokenService,
          },
          issuer: "https://auth.example.com",
        }),
        grants: { password: services.grant },
      });
    }

    it("should propagate the thrown error unchanged", async () => {
      const services = await createTestGrant();
      await services.clientService.add(testClient, "secret");
      const thrown = new InvalidGrantError(
        "multi-factor authentication required",
      );
      using _getAuthenticated = vi
        .spyOn(services.userService, "getAuthenticated")
        .mockImplementation(() => Promise.reject(thrown));

      const error = await rejection(
        () => exchangeToken(services.grant, passwordTokenRequest(), testClient),
        InvalidGrantError,
        "multi-factor authentication required",
      );

      expect(error).toBe(thrown);
    });

    it("should render an OAuth2 error as its own code, not server_error", async () => {
      const services = await createTestGrant();
      await services.clientService.add(testClient, "secret");
      using _getAuthenticated = vi
        .spyOn(services.userService, "getAuthenticated")
        .mockImplementation(() =>
          Promise.reject(
            new InvalidGrantError("multi-factor authentication required"),
          ),
        );

      const response = await createTokenServer(services).handleTokenRequest(
        passwordTokenRequest(),
      );

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid_grant");
      expect(body.error_description).toBe(
        "multi-factor authentication required",
      );
    });

    it("should render a non-OAuth2 error as server_error", async () => {
      const services = await createTestGrant();
      await services.clientService.add(testClient, "secret");
      using _getAuthenticated = vi
        .spyOn(services.userService, "getAuthenticated")
        .mockImplementation(() =>
          Promise.reject(new Error("mfa store unreachable")),
        );

      const response = await createTokenServer(services).handleTokenRequest(
        passwordTokenRequest(),
      );

      expect(response.status).toBe(500);
      const body = await response.json();
      expect(body.error).toBe("server_error");
    });
  });
});
