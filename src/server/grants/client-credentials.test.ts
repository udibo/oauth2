import { assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import type { BasicScope } from "../../models/scope.ts";
import {
  exchangeToken,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
  tokenRequest,
} from "../../testing/_test_fixtures.ts";
import { ClientCredentialsGrant } from "./client-credentials.ts";

const testUser: TestUser = { id: "user-1", username: "service-account" };
const testClient: TestClient = { id: "client-1", confidential: true };

async function createTestGrant() {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });

  await userService.add(testUser, "password");

  const grant = new ClientCredentialsGrant<TestClient, TestUser, BasicScope>({
    resolve: () => ({ clientService, tokenService }),
  });

  return { grant, clientService, tokenService };
}

describe("ClientCredentialsGrant", () => {
  describe("grantType", () => {
    it("should return client_credentials", async () => {
      const { grant } = await createTestGrant();
      assertStrictEquals(grant.grantType, "client_credentials");
    });
  });

  describe("constructor", () => {
    it("should not allow refresh tokens", async () => {
      const { grant } = await createTestGrant();
      assertStrictEquals(grant.allowRefreshToken, false);
    });
  });

  describe("token", () => {
    it("should return access token for valid client", async () => {
      const { grant, clientService, tokenService } = await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const request = tokenRequest({ grant_type: "client_credentials" });

      const token = await exchangeToken(grant, request, testClient);

      assertStrictEquals(typeof token.accessToken, "string");
      assertStrictEquals(token.client.id, testClient.id);
      assertStrictEquals(token.user?.id, testUser.id);

      const savedToken = await tokenService.getToken(token.accessToken);
      assertStrictEquals(savedToken?.accessToken, token.accessToken);
    });

    it("should include scope when requested", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const request = tokenRequest({
        grant_type: "client_credentials",
        scope: "read write",
      });

      const token = await exchangeToken(grant, request, testClient);

      assertStrictEquals(token.scope?.toString(), "read write");
    });

    it("should issue a token with no user when the client resolves none", async () => {
      const { grant, clientService, tokenService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({ grant_type: "client_credentials" });

      const token = await exchangeToken(grant, request, testClient);

      assertStrictEquals(typeof token.accessToken, "string");
      assertStrictEquals(token.client.id, testClient.id);
      assertStrictEquals(token.user, undefined);
      assertStrictEquals("user" in token, false);

      const savedToken = await tokenService.getToken(token.accessToken);
      assertStrictEquals(savedToken?.accessToken, token.accessToken);
      assertStrictEquals(savedToken?.user, undefined);
    });

    it("should scope a token for a client that resolves no user", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const body = new URLSearchParams({
        grant_type: "client_credentials",
        scope: "read write",
      });
      const request = new Request("http://localhost/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });

      const token = await exchangeToken(grant, request, testClient);

      assertStrictEquals(token.scope?.toString(), "read write");
    });

    it("should revoke a token issued to a client with no user", async () => {
      const { grant, clientService, tokenService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const body = new URLSearchParams({ grant_type: "client_credentials" });
      const request = new Request("http://localhost/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });

      const token = await exchangeToken(grant, request, testClient);

      assertStrictEquals(await tokenService.revoke(token.accessToken), true);
      assertStrictEquals(
        await tokenService.getToken(token.accessToken),
        undefined,
      );
    });

    it("should not include refresh token", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const request = tokenRequest({ grant_type: "client_credentials" });

      const token = await exchangeToken(grant, request, testClient);

      assertStrictEquals("refreshToken" in token, false);
    });

    it("should work without scope parameter", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const request = tokenRequest({ grant_type: "client_credentials" });

      const token = await exchangeToken(grant, request, testClient);

      assertStrictEquals(token.scope, undefined);
    });
  });
});
