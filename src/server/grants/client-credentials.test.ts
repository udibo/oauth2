import { assert, describe, expect, it } from "vitest";
import type { BasicScope } from "../../models/scope.ts";
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
import { encodeBasicAuth } from "../../utils/basic-auth.ts";
import { AuthorizationServer } from "../authorization-server.ts";
import type { ClientServiceInterface } from "../services/client.ts";
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
      expect(grant.grantType).toBe("client_credentials");
    });
  });

  describe("constructor", () => {
    it("should not allow refresh tokens", async () => {
      const { grant } = await createTestGrant();
      expect(grant.allowRefreshToken).toBe(false);
    });
  });

  describe("token", () => {
    it("should return access token for valid client", async () => {
      const { grant, clientService, tokenService } = await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const request = tokenRequest({ grant_type: "client_credentials" });

      const token = await exchangeToken(grant, request, testClient);

      expect(typeof token.accessToken).toBe("string");
      expect(token.client.id).toBe(testClient.id);
      expect(token.user?.id).toBe(testUser.id);

      const savedToken = await tokenService.getToken(token.accessToken);
      expect(savedToken?.accessToken).toBe(token.accessToken);
    });

    it("should include scope when requested", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const request = tokenRequest({
        grant_type: "client_credentials",
        scope: "read write",
      });

      const token = await exchangeToken(grant, request, testClient);

      expect(token.scope?.toString()).toBe("read write");
    });

    it("should issue a token with no user when the client resolves none", async () => {
      const { grant, clientService, tokenService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({ grant_type: "client_credentials" });

      const token = await exchangeToken(grant, request, testClient);

      expect(typeof token.accessToken).toBe("string");
      expect(token.client.id).toBe(testClient.id);
      expect(token.user).toBe(undefined);
      expect("user" in token).toBe(false);

      const savedToken = await tokenService.getToken(token.accessToken);
      expect(savedToken?.accessToken).toBe(token.accessToken);
      expect(savedToken?.user).toBe(undefined);
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

      expect(token.scope?.toString()).toBe("read write");
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

      expect(await tokenService.revoke(token.accessToken)).toBe(true);
      expect(await tokenService.getToken(token.accessToken)).toBe(undefined);
    });

    it("should not include refresh token", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const request = tokenRequest({ grant_type: "client_credentials" });

      const token = await exchangeToken(grant, request, testClient);

      expect("refreshToken" in token).toBe(false);
    });

    it("should work without scope parameter", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const request = tokenRequest({ grant_type: "client_credentials" });

      const token = await exchangeToken(grant, request, testClient);

      expect(token.scope).toBe(undefined);
    });
  });

  describe("client authentication", () => {
    const machineClient: TestClient = {
      id: "machine",
      confidential: true,
      grants: ["client_credentials"],
    };
    const publicClient: TestClient = {
      id: "public",
      grants: ["client_credentials"],
    };

    async function createTestServer(
      wrapClientService?: (
        clientService: MemoryClientService<TestClient, TestUser>,
      ) => ClientServiceInterface<TestClient, TestUser>,
    ) {
      const userService = new MemoryUserService();
      const memoryClientService = new MemoryClientService(userService);
      await memoryClientService.add(machineClient, "machine-secret");
      await memoryClientService.add(publicClient);
      const clientService =
        wrapClientService?.(memoryClientService) ?? memoryClientService;
      const tokenService = new MemoryTokenService({
        clientService: memoryClientService,
        userService,
      });
      return new AuthorizationServer<TestClient, TestUser, BasicScope>({
        resolve: () => ({ services: { clientService, tokenService } }),
        grants: {
          client_credentials: new ClientCredentialsGrant<
            TestClient,
            TestUser,
            BasicScope
          >({ resolve: () => ({ clientService, tokenService }) }),
        },
      });
    }

    async function assertInvalidClient(response: Response) {
      const body = await response.json();
      expect(response.status, JSON.stringify(body)).toBe(401);
      expect(body.error).toBe("invalid_client");
      expect(body.access_token).toBe(undefined);
    }

    it("refuses a public client that presents only its client_id", async () => {
      const server = await createTestServer();
      const response = await server.handleTokenRequest(
        tokenRequest({
          grant_type: "client_credentials",
          client_id: publicClient.id,
        }),
      );
      await assertInvalidClient(response);
    });

    it("refuses a public client that presents an empty client_secret", async () => {
      const server = await createTestServer();
      const response = await server.handleTokenRequest(
        tokenRequest({
          grant_type: "client_credentials",
          client_id: publicClient.id,
          client_secret: "",
        }),
      );
      await assertInvalidClient(response);
    });

    it("refuses a public client authenticating with HTTP Basic and an empty password", async () => {
      const server = await createTestServer();
      const response = await server.handleTokenRequest(
        tokenRequest(
          { grant_type: "client_credentials" },
          { authorization: encodeBasicAuth(publicClient.id, "") },
        ),
      );
      await assertInvalidClient(response);
      assert.exists(response.headers.get("www-authenticate"));
    });

    it("refuses a public client whose Basic password is empty even when the body carries a client_secret", async () => {
      const server = await createTestServer();
      const response = await server.handleTokenRequest(
        tokenRequest(
          { grant_type: "client_credentials", client_secret: "junk" },
          { authorization: encodeBasicAuth(publicClient.id, "") },
        ),
      );
      await assertInvalidClient(response);
    });

    it("refuses a public client that presents a secret it was never issued", async () => {
      const server = await createTestServer();
      const response = await server.handleTokenRequest(
        tokenRequest({
          grant_type: "client_credentials",
          client_id: publicClient.id,
          client_secret: "invented",
        }),
      );
      await assertInvalidClient(response);
    });

    it("refuses a confidential client that omits its secret", async () => {
      const server = await createTestServer();
      const response = await server.handleTokenRequest(
        tokenRequest({
          grant_type: "client_credentials",
          client_id: machineClient.id,
        }),
      );
      await assertInvalidClient(response);
    });

    it("refuses a request without a secret even when the client service would resolve the client", async () => {
      const server = await createTestServer((clientService) => ({
        get: (id) => clientService.get(id),
        getAuthenticated: (id) => clientService.get(id),
        getUser: (client) => clientService.getUser(client),
      }));
      const secretless: Record<string, string>[] = [{}, { client_secret: "" }];
      for (const fields of secretless) {
        const response = await server.handleTokenRequest(
          tokenRequest({
            grant_type: "client_credentials",
            client_id: machineClient.id,
            ...fields,
          }),
        );
        await assertInvalidClient(response);
      }
    });

    it("issues a token to a confidential client presenting its secret in the body", async () => {
      const server = await createTestServer();
      const response = await server.handleTokenRequest(
        tokenRequest({
          grant_type: "client_credentials",
          client_id: machineClient.id,
          client_secret: "machine-secret",
        }),
      );
      const body = await response.json();
      expect(response.status, JSON.stringify(body)).toBe(200);
      expect(typeof body.access_token).toBe("string");
    });

    it("issues a token to a confidential client presenting its secret with HTTP Basic", async () => {
      const server = await createTestServer();
      const response = await server.handleTokenRequest(
        tokenRequest(
          { grant_type: "client_credentials" },
          basicAuthHeader(machineClient.id, "machine-secret"),
        ),
      );
      const body = await response.json();
      expect(response.status, JSON.stringify(body)).toBe(200);
      expect(typeof body.access_token).toBe("string");
    });
  });
});
