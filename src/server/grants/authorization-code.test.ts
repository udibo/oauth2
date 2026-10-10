import { assert, describe, expect, it } from "vitest";
import { rejection, thrown } from "../../_test_assert.ts";
import type { AuthorizationCode } from "../../models/authorization-code.ts";
import type { ClientInterface } from "../../models/client.ts";
import type { RefreshToken } from "../../models/token.ts";
import { BasicScope } from "../../models/scope.ts";
import {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  ServerError,
} from "../../errors.ts";
import {
  basicAuthHeader,
  exchangeToken,
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
  tokenRequest,
} from "../../testing/_test_fixtures.ts";
import type { ChallengeMethods } from "../../utils/pkce.ts";
import {
  generateCodeChallenge,
  generateCodeVerifier,
} from "../../utils/pkce.ts";
import { AuthorizationCodeGrant } from "./authorization-code.ts";

const INHERITED_MEMBER_NAMES = [
  "toString",
  "valueOf",
  "constructor",
  "hasOwnProperty",
  "isPrototypeOf",
  "__proto__",
];

/**
 * Test subclass exposing the protected `getClientCredentials` helper so the
 * tests below can exercise it directly (the production method is protected).
 */
class TestAuthorizationCodeGrant<
  Client extends ClientInterface,
  User,
  S extends BasicScope = BasicScope,
> extends AuthorizationCodeGrant<Client, User, S> {
  /** Public passthrough so tests can exercise the protected helper. */
  override getClientCredentials(request: Request, body: FormData) {
    return super.getClientCredentials(request, body);
  }
}

/**
 * Holds every `revoke` until two exchanges have both read the code, so the
 * read-then-delete window a real store faces under concurrency is exercised
 * deterministically instead of by luck of scheduling.
 */
class RacingAuthorizationCodeService extends MemoryAuthorizationCodeService<
  TestClient,
  TestUser,
  BasicScope
> {
  #bothRead = Promise.withResolvers<void>();
  #reads = 0;

  override async get(
    code: string,
  ): Promise<AuthorizationCode<TestClient, TestUser, BasicScope> | undefined> {
    const authorizationCode = await super.get(code);
    if (++this.#reads >= 2) this.#bothRead.resolve();
    return authorizationCode;
  }

  override async revoke(
    authorizationCode:
      | AuthorizationCode<TestClient, TestUser, BasicScope>
      | string,
  ): Promise<boolean> {
    await this.#bothRead.promise;
    return await super.revoke(authorizationCode);
  }
}

const testUser: TestUser = { id: "user-1", username: "testuser" };
const testClient: TestClient = { id: "client-1", confidential: true };
const publicClient: TestClient = { id: "public-client" };

async function createTestGrant(
  options: {
    allowRefreshToken?: boolean;
    challengeMethods?: ChallengeMethods;
    requireClientAuthentication?: boolean;
    requirePKCE?: boolean;
  } = {},
) {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  const authorizationCodeService = new MemoryAuthorizationCodeService({
    clientService,
    userService,
  });

  await userService.add(testUser, "password");

  const grant = new TestAuthorizationCodeGrant<
    TestClient,
    TestUser,
    BasicScope
  >({
    resolve: () => ({ clientService, tokenService, authorizationCodeService }),
    requirePKCE: false,
    ...options,
  });

  return {
    grant,
    clientService,
    tokenService,
    authorizationCodeService,
    userService,
  };
}

describe("AuthorizationCodeGrant", () => {
  describe("grantType", () => {
    it("should return authorization_code", async () => {
      const { grant } = await createTestGrant();
      expect(grant.grantType).toBe("authorization_code");
    });
  });

  describe("constructor", () => {
    it("should use default challengeMethods", async () => {
      const { grant } = await createTestGrant();
      expect(typeof grant.challengeMethods["S256"]).toBe("function");
    });

    it("should allow custom challengeMethods", () => {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new MemoryTokenService({
        clientService,
        userService,
      });
      const authorizationCodeService = new MemoryAuthorizationCodeService({
        clientService,
        userService,
      });

      const customMethod = (_verifier: string) =>
        Promise.resolve("custom-challenge");
      const grant = new TestAuthorizationCodeGrant<
        TestClient,
        TestUser,
        BasicScope
      >({
        resolve: () => ({
          clientService,
          tokenService,
          authorizationCodeService,
        }),
        challengeMethods: { custom: customMethod },
      });

      expect(grant.challengeMethods["custom"]).toBe(customMethod);
    });

    it("defaults requirePKCE to true when the option is omitted", () => {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new MemoryTokenService({
        clientService,
        userService,
      });
      const authorizationCodeService = new MemoryAuthorizationCodeService({
        clientService,
        userService,
      });
      const grant = new TestAuthorizationCodeGrant<
        TestClient,
        TestUser,
        BasicScope
      >({
        resolve: () => ({
          clientService,
          tokenService,
          authorizationCodeService,
        }),
      });

      expect(grant.requirePKCE).toBe(true);
    });
  });

  describe("getClient", () => {
    it("should return client by ID", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const client = await grant.getClient("client-1", clientService);
      expect(client.id).toBe("client-1");
    });

    it("should throw InvalidClientError for non-existent client", async () => {
      const { grant, clientService } = await createTestGrant();

      await rejection(
        () => grant.getClient("unknown", clientService),
        InvalidClientError,
        "client not found",
      );
    });
  });

  describe("getChallengeMethod", () => {
    it("should return S256 by default", async () => {
      const { grant } = await createTestGrant();
      const method = grant.getChallengeMethod();
      expect(typeof method).toBe("function");
    });

    it("should return S256 when specified", async () => {
      const { grant } = await createTestGrant();
      const method = grant.getChallengeMethod("S256");
      expect(typeof method).toBe("function");
    });

    it("should return undefined for unknown method", async () => {
      const { grant } = await createTestGrant();
      const method = grant.getChallengeMethod("unknown");
      expect(method).toBe(undefined);
    });

    it("returns no method for a name inherited from Object.prototype", async () => {
      const { grant } = await createTestGrant();
      for (const name of INHERITED_MEMBER_NAMES) {
        expect(grant.getChallengeMethod(name), name).toBe(undefined);
      }
    });

    it("returns a method a consumer added to their own challengeMethods map", async () => {
      const custom = (verifier: string) =>
        Promise.resolve(`custom:${verifier}`);
      const { grant } = await createTestGrant({
        challengeMethods: { custom },
      });
      expect(grant.getChallengeMethod("custom")).toBe(custom);
    });
  });

  describe("validateChallengeMethod", () => {
    it("should return true for S256", async () => {
      const { grant } = await createTestGrant();
      expect(grant.validateChallengeMethod("S256")).toBe(true);
    });

    it("should return true for null (defaults to S256)", async () => {
      const { grant } = await createTestGrant();
      expect(grant.validateChallengeMethod(null)).toBe(true);
    });

    it("should return false for unknown method", async () => {
      const { grant } = await createTestGrant();
      expect(grant.validateChallengeMethod("plain")).toBe(false);
    });

    it("rejects a code_challenge_method inherited from Object.prototype at the authorization endpoint", async () => {
      const { grant } = await createTestGrant();
      for (const name of INHERITED_MEMBER_NAMES) {
        expect(grant.validateChallengeMethod(name), name).toBe(false);
      }
    });
  });

  describe("verifyCode", () => {
    it("should verify valid code verifier", async () => {
      const { grant } = await createTestGrant();
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);

      const code = {
        code: "test-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
        challenge,
        challengeMethod: "S256",
      };

      const result = await grant.verifyCode(code, verifier);
      expect(result).toBe(true);
    });

    it("should reject invalid code verifier", async () => {
      const { grant } = await createTestGrant();
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);

      const code = {
        code: "test-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
        challenge,
        challengeMethod: "S256",
      };

      const result = await grant.verifyCode(code, "wrong-verifier");
      expect(result).toBe(false);
    });

    it("should return false when no challenge in code", async () => {
      const { grant } = await createTestGrant();
      const code = {
        code: "test-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      };

      const result = await grant.verifyCode(code, "any-verifier");
      expect(result).toBe(false);
    });

    it("should throw ServerError for unimplemented challenge method", async () => {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new MemoryTokenService({
        clientService,
        userService,
      });
      const authorizationCodeService = new MemoryAuthorizationCodeService({
        clientService,
        userService,
      });

      const grant = new TestAuthorizationCodeGrant<
        TestClient,
        TestUser,
        BasicScope
      >({
        resolve: () => ({
          clientService,
          tokenService,
          authorizationCodeService,
        }),
        challengeMethods: {},
      });

      const code = {
        code: "test-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
        challenge: "some-challenge",
        challengeMethod: "unknown",
      };

      await rejection(
        () => grant.verifyCode(code, "verifier"),
        ServerError,
        "code_challenge_method not implemented",
      );
    });

    it("verifies no verifier against a challengeMethod inherited from Object.prototype", async () => {
      const { grant } = await createTestGrant();

      for (const name of INHERITED_MEMBER_NAMES) {
        const code = {
          code: "prototype-code",
          expiresAt: new Date(Date.now() + 300000),
          client: testClient,
          user: testUser,
          challenge: "[object Undefined]",
          challengeMethod: name,
        };

        await rejection(
          () => grant.verifyCode(code, generateCodeVerifier()),
          ServerError,
          "code_challenge_method not implemented",
        );
      }
    });
  });

  describe("generateAuthorizationCode", () => {
    it("should generate basic authorization code", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const code = await grant.generateAuthorizationCode(
        {
          client: testClient,
          user: testUser,
        },
        new Request("http://localhost/authorize"),
      );

      expect(typeof code.code).toBe("string");
      expect(code.client.id).toBe(testClient.id);
      expect(code.user.id).toBe(testUser.id);
    });

    it("should include scope when provided", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");
      const scope = new BasicScope("read write");

      const code = await grant.generateAuthorizationCode(
        {
          client: testClient,
          user: testUser,
          scope,
        },
        new Request("http://localhost/authorize"),
      );

      expect(code.scope?.toString()).toBe("read write");
    });

    it("should include redirectUri when provided", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const code = await grant.generateAuthorizationCode(
        {
          client: testClient,
          user: testUser,
          redirectUri: "https://example.com/callback",
        },
        new Request("http://localhost/authorize"),
      );

      expect(code.redirectUri).toBe("https://example.com/callback");
    });

    it("should include PKCE challenge when provided", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const code = await grant.generateAuthorizationCode(
        {
          client: testClient,
          user: testUser,
          challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          challengeMethod: "S256",
        },
        new Request("http://localhost/authorize"),
      );

      expect(code.challenge).toBe(
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      );
      expect(code.challengeMethod).toBe("S256");
    });

    it("should save the authorization code", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(testClient, "secret");

      const code = await grant.generateAuthorizationCode(
        {
          client: testClient,
          user: testUser,
        },
        new Request("http://localhost/authorize"),
      );

      const saved = await authorizationCodeService.get(code.code);
      expect(saved?.client.id).toBe(code.client.id);
    });
  });

  describe("getClientCredentials", () => {
    it("should extract credentials from Basic Auth", async () => {
      const { grant } = await createTestGrant();
      const request = new Request("http://localhost/token", {
        method: "POST",
        headers: basicAuthHeader("client-1", "secret"),
      });

      const credentials = grant.getClientCredentials(request, new FormData());
      expect(credentials.clientId).toBe("client-1");
      expect(credentials.clientSecret).toBe("secret");
    });

    it("should extract credentials with code_verifier from body", async () => {
      const { grant } = await createTestGrant();
      const request = tokenRequest({
        client_id: "public-client",
        code_verifier: "test-verifier",
      });

      const credentials = grant.getClientCredentials(
        request,
        await request.clone().formData(),
      );
      expect(credentials.clientId).toBe("public-client");
      expect(credentials.codeVerifier).toBe("test-verifier");
      expect(credentials.clientSecret).toBe(undefined);
    });

    it("should throw InvalidClientError when no credentials", async () => {
      const { grant } = await createTestGrant();
      const request = tokenRequest({});

      thrown(
        () => grant.getClientCredentials(request, new FormData()),
        InvalidClientError,
        "client authentication required",
      );
    });

    it("keeps the client secret alongside a code_verifier when client authentication is required", async () => {
      const { grant } = await createTestGrant({
        requireClientAuthentication: true,
      });
      const request = tokenRequest(
        { code_verifier: "test-verifier" },
        basicAuthHeader("client-1", "secret"),
      );

      const credentials = grant.getClientCredentials(
        request,
        await request.clone().formData(),
      );
      expect(credentials.clientId).toBe("client-1");
      expect(credentials.clientSecret).toBe("secret");
      expect(credentials.codeVerifier).toBe("test-verifier");
    });

    it("should fall back to body client_id when Basic auth is invalid", async () => {
      const { grant } = await createTestGrant();
      const request = tokenRequest(
        { client_id: "body-client" },
        {
          Authorization: "Basic invalid!!!",
        },
      );

      const credentials = grant.getClientCredentials(
        request,
        await request.clone().formData(),
      );
      expect(credentials.clientId).toBe("body-client");
    });
  });

  describe("getAuthenticatedClient", () => {
    it("should authenticate client with secret", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = new Request("http://localhost/token", {
        method: "POST",
        headers: basicAuthHeader("client-1", "secret"),
      });

      const client = await grant.getAuthenticatedClient(
        request,
        new FormData(),
      );
      expect(client.id).toBe("client-1");
    });

    it("should get client for PKCE without secret", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(publicClient);

      const request = tokenRequest({
        client_id: "public-client",
        code_verifier: "test-verifier",
      });

      const client = await grant.getAuthenticatedClient(
        request,
        await request.clone().formData(),
      );
      expect(client.id).toBe("public-client");
    });

    it("refuses a public client that attaches a secret to its PKCE exchange", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(publicClient);

      const request = tokenRequest({
        client_id: "public-client",
        client_secret: "never-issued",
        code_verifier: "test-verifier",
      });
      const body = await request.clone().formData();

      await rejection(
        () => grant.getAuthenticatedClient(request, body),
        InvalidClientError,
        "client authentication failed",
      );
    });

    it("should throw InvalidClientError for non-existent PKCE client", async () => {
      const { grant } = await createTestGrant();

      const request = tokenRequest({
        client_id: "unknown",
        code_verifier: "test-verifier",
      });
      const body = await request.clone().formData();

      await rejection(
        () => grant.getAuthenticatedClient(request, body),
        InvalidClientError,
        "client authentication failed",
      );
    });

    it("supports an explicit legacy PKCE-only client authentication opt-out", async () => {
      const { grant, clientService } = await createTestGrant({
        requireClientAuthentication: false,
      });
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        client_id: "client-1",
        code_verifier: "test-verifier",
      });

      const client = await grant.getAuthenticatedClient(
        request,
        await request.clone().formData(),
      );
      expect(client.id).toBe("client-1");
    });

    it("requires confidential client authentication by default alongside PKCE", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        client_id: "client-1",
        code_verifier: "test-verifier",
      });
      const body = await request.clone().formData();

      await rejection(
        () => grant.getAuthenticatedClient(request, body),
        InvalidClientError,
        "client authentication failed",
      );
    });

    it("authenticates a confidential client that sends its secret with a code_verifier when client authentication is required", async () => {
      const { grant, clientService } = await createTestGrant({
        requireClientAuthentication: true,
      });
      await clientService.add(testClient, "secret");

      const request = tokenRequest(
        { code_verifier: "test-verifier" },
        basicAuthHeader("client-1", "secret"),
      );

      const client = await grant.getAuthenticatedClient(
        request,
        await request.clone().formData(),
      );
      expect(client.id).toBe("client-1");
    });

    it("accepts a public client that sends a code_verifier when client authentication is required", async () => {
      const { grant, clientService } = await createTestGrant({
        requireClientAuthentication: true,
      });
      await clientService.add(publicClient);

      const request = tokenRequest({
        client_id: "public-client",
        code_verifier: "test-verifier",
      });

      const client = await grant.getAuthenticatedClient(
        request,
        await request.clone().formData(),
      );
      expect(client.id).toBe("public-client");
    });
  });

  describe("token", () => {
    it("should throw InvalidRequestError when code missing", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({ grant_type: "authorization_code" });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidRequestError,
        "code parameter required",
      );
    });

    it("should throw InvalidGrantError for non-existent code", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "non-existent",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidGrantError,
        "invalid code",
      );
    });

    it("should throw InvalidGrantError for expired code", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(testClient, "secret");

      const expiredCode = {
        code: "expired-code",
        expiresAt: new Date(Date.now() - 1000),
        client: testClient,
        user: testUser,
      };
      await authorizationCodeService.save(expiredCode);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "expired-code",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidGrantError,
        "invalid code",
      );
    });

    it("should throw InvalidClientError when code belongs to different client", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      const otherClient: TestClient = { id: "other-client" };
      await clientService.add(testClient, "secret");
      await clientService.add(otherClient);

      const code = {
        code: "test-code",
        expiresAt: new Date(Date.now() + 300000),
        client: otherClient,
        user: testUser,
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "test-code",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidClientError,
        "code was issued to another client",
      );
    });

    it("should exchange valid code for token", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const code = {
        code: "valid-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "valid-code",
      });

      const token = await exchangeToken(grant, request, testClient);

      expect(typeof token.accessToken).toBe("string");
      expect(token.client.id).toBe(testClient.id);
      expect(token.user?.id).toBe(testUser.id);
    });

    it("should preserve scope from authorization code", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const scope = new BasicScope("read write");
      const code = {
        code: "scoped-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
        scope,
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "scoped-code",
      });

      const token = await exchangeToken(grant, request, testClient);

      expect(token.scope?.toString()).toBe("read write");
    });

    it("should verify PKCE code_verifier", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(publicClient, undefined, testUser.id);

      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);

      const code = {
        code: "pkce-code",
        expiresAt: new Date(Date.now() + 300000),
        client: publicClient,
        user: testUser,
        challenge,
        challengeMethod: "S256",
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "pkce-code",
        code_verifier: verifier,
      });

      const token = await exchangeToken(grant, request, publicClient);

      expect(typeof token.accessToken).toBe("string");
    });

    it("should reject code_verifier with invalid format per RFC 7636", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(publicClient, undefined, testUser.id);

      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);

      const code = {
        code: "pkce-format-code",
        expiresAt: new Date(Date.now() + 300000),
        client: publicClient,
        user: testUser,
        challenge,
        challengeMethod: "S256",
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "pkce-format-code",
        code_verifier: "wrong-verifier",
      });

      await rejection(
        () => exchangeToken(grant, request, publicClient),
        InvalidRequestError,
        "code_verifier must be 43-128 characters",
      );
    });

    it("should reject code_verifier that does not match challenge", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(publicClient, undefined, testUser.id);

      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);

      const code = {
        code: "pkce-mismatch-code",
        expiresAt: new Date(Date.now() + 300000),
        client: publicClient,
        user: testUser,
        challenge,
        challengeMethod: "S256",
      };
      await authorizationCodeService.save(code);

      const wrongVerifier = "a".repeat(43);
      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "pkce-mismatch-code",
        code_verifier: wrongVerifier,
      });

      await rejection(
        () => exchangeToken(grant, request, publicClient),
        InvalidGrantError,
        "code_verifier verification failed",
      );
    });

    it("should reject when challenge exists but no verifier provided", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);

      const code = {
        code: "pkce-missing-verifier-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
        challenge,
        challengeMethod: "S256",
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "pkce-missing-verifier-code",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidRequestError,
        "code_verifier required",
      );
    });

    it("requires PKCE by default (OAuth 2.1)", async () => {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new MemoryTokenService({
        clientService,
        userService,
      });
      const authorizationCodeService = new MemoryAuthorizationCodeService({
        clientService,
        userService,
      });
      await userService.add(testUser, "password");
      await clientService.add(testClient, "secret", testUser.id);
      const grant = new TestAuthorizationCodeGrant<
        TestClient,
        TestUser,
        BasicScope
      >({
        resolve: () => ({
          clientService,
          tokenService,
          authorizationCodeService,
        }),
      });
      await authorizationCodeService.save({
        code: "no-pkce-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      });

      await rejection(
        () =>
          exchangeToken(
            grant,
            tokenRequest({
              grant_type: "authorization_code",
              code: "no-pkce-code",
            }),
            testClient,
          ),
        InvalidRequestError,
        "PKCE is required for this grant",
      );
    });

    it("refuses a verifier-less exchange of a code issued without a challenge when PKCE is required", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant({ requirePKCE: true });
      await clientService.add(testClient, "secret", testUser.id);
      await authorizationCodeService.save({
        code: "challenge-less-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      });

      await rejection(
        () =>
          exchangeToken(
            grant,
            tokenRequest({
              grant_type: "authorization_code",
              code: "challenge-less-code",
            }),
            testClient,
          ),
        InvalidRequestError,
        "PKCE is required for this grant",
      );
    });

    it("refuses a verifier-less exchange of a code that carries a challenge when PKCE is required", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant({ requirePKCE: true });
      await clientService.add(testClient, "secret", testUser.id);
      const challenge = await generateCodeChallenge(generateCodeVerifier());
      await authorizationCodeService.save({
        code: "required-pkce-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
        challenge,
        challengeMethod: "S256",
      });

      await rejection(
        () =>
          exchangeToken(
            grant,
            tokenRequest({
              grant_type: "authorization_code",
              code: "required-pkce-code",
            }),
            testClient,
          ),
        InvalidRequestError,
        "code_verifier required",
      );
    });

    it("issues a token when PKCE is required and the verifier matches", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant({ requirePKCE: true });
      await clientService.add(testClient, "secret", testUser.id);
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      await authorizationCodeService.save({
        code: "required-pkce-ok-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
        challenge,
        challengeMethod: "S256",
      });

      const token = await exchangeToken(
        grant,
        tokenRequest({
          grant_type: "authorization_code",
          code: "required-pkce-ok-code",
          code_verifier: verifier,
        }),
        testClient,
      );

      expect(token.client.id).toBe(testClient.id);
    });

    it("should require redirect_uri when authorization code has one", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const code = {
        code: "redirect-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
        redirectUri: "https://example.com/callback",
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "redirect-code",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidGrantError,
        "redirect_uri parameter required",
      );
    });

    it("should verify redirect_uri matches", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const code = {
        code: "redirect-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
        redirectUri: "https://example.com/callback",
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "redirect-code",
        redirect_uri: "https://different.com/callback",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidGrantError,
        "incorrect redirect_uri",
      );
    });

    it("should reject redirect_uri when code has none", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const code = {
        code: "no-redirect-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "no-redirect-code",
        redirect_uri: "https://example.com/callback",
      });

      await rejection(
        () => exchangeToken(grant, request, testClient),
        InvalidGrantError,
        "did not expect redirect_uri parameter",
      );
    });

    it("should accept matching redirect_uri", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const code = {
        code: "redirect-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
        redirectUri: "https://example.com/callback",
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "redirect-code",
        redirect_uri: "https://example.com/callback",
      });

      const token = await exchangeToken(grant, request, testClient);

      expect(typeof token.accessToken).toBe("string");
    });

    it("should revoke authorization code after use", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const code = {
        code: "single-use-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "single-use-code",
      });

      await exchangeToken(grant, request, testClient);

      const revokedCode = await authorizationCodeService.get("single-use-code");
      expect(revokedCode).toBe(undefined);
    });

    it("should save the new token", async () => {
      const { grant, clientService, authorizationCodeService, tokenService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const code = {
        code: "save-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "save-code",
      });

      const token = await exchangeToken(grant, request, testClient);

      const savedToken = await tokenService.getToken(token.accessToken);
      expect(savedToken?.accessToken).toBe(token.accessToken);
    });

    it("should include refresh token by default", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const code = {
        code: "refresh-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "refresh-code",
      });

      const token = (await exchangeToken(
        grant,
        request,
        testClient,
      )) as RefreshToken<TestClient, TestUser, BasicScope>;

      expect("refreshToken" in token).toBe(true);
      expect(typeof token.refreshToken).toBe("string");
    });

    it("should not include refresh token when allowRefreshToken is false", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant({ allowRefreshToken: false });
      await clientService.add(testClient, "secret", testUser.id);

      const code = {
        code: "no-refresh-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      };
      await authorizationCodeService.save(code);

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "no-refresh-code",
      });

      const token = await exchangeToken(grant, request, testClient);

      expect("refreshToken" in token).toBe(false);
    });

    it("should throw InvalidGrantError and revoke tokens when code is replayed (RFC 6819)", async () => {
      const { grant, clientService, authorizationCodeService, tokenService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const code = {
        code: "reused-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      };
      await authorizationCodeService.save(code);

      const body1 = new URLSearchParams({
        grant_type: "authorization_code",
        code: "reused-code",
      });
      const request1 = tokenRequest(body1);
      const token = await exchangeToken(grant, request1, testClient);

      expect(token.code).toBe("reused-code");
      const savedToken = await tokenService.getToken(token.accessToken);
      expect(savedToken !== undefined).toBe(true);

      const body2 = new URLSearchParams({
        grant_type: "authorization_code",
        code: "reused-code",
      });
      const request2 = tokenRequest(body2);

      await rejection(
        () => exchangeToken(grant, request2, testClient),
        InvalidGrantError,
        "code already used",
      );

      const revokedToken = await tokenService.getToken(token.accessToken);
      expect(revokedToken).toBe(undefined);
    });

    it("issues no token for a code whose challenge_method is inherited from Object.prototype", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant();
      await clientService.add(publicClient, undefined, testUser.id);

      await authorizationCodeService.save({
        code: "prototype-method-code",
        expiresAt: new Date(Date.now() + 300000),
        client: publicClient,
        user: testUser,
        challenge: "[object Undefined]",
        challengeMethod: "toString",
      });

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "prototype-method-code",
        code_verifier: generateCodeVerifier(),
      });

      await rejection(
        () => exchangeToken(grant, request, publicClient),
        ServerError,
        "code_challenge_method not implemented",
      );
    });

    it("exchanges a code verified by a consumer-supplied challenge method", async () => {
      const { grant, clientService, authorizationCodeService } =
        await createTestGrant({
          challengeMethods: {
            custom: (verifier: string) => Promise.resolve(`custom:${verifier}`),
          },
        });
      await clientService.add(publicClient, undefined, testUser.id);

      const verifier = generateCodeVerifier();
      await authorizationCodeService.save({
        code: "custom-method-code",
        expiresAt: new Date(Date.now() + 300000),
        client: publicClient,
        user: testUser,
        challenge: `custom:${verifier}`,
        challengeMethod: "custom",
      });

      const request = tokenRequest({
        grant_type: "authorization_code",
        code: "custom-method-code",
        code_verifier: verifier,
      });

      const token = await exchangeToken(grant, request, publicClient);

      expect(typeof token.accessToken).toBe("string");
    });

    it("issues a token to only one of two concurrent exchanges of the same code", async () => {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new MemoryTokenService({
        clientService,
        userService,
      });
      const authorizationCodeService = new RacingAuthorizationCodeService({
        clientService,
        userService,
      });
      await userService.add(testUser, "password");
      await clientService.add(testClient, "secret", testUser.id);

      const grant = new TestAuthorizationCodeGrant<
        TestClient,
        TestUser,
        BasicScope
      >({
        resolve: () => ({
          clientService,
          tokenService,
          authorizationCodeService,
        }),
        requirePKCE: false,
      });

      await authorizationCodeService.save({
        code: "raced-code",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        user: testUser,
      });

      const exchange = () =>
        exchangeToken(
          grant,
          tokenRequest({
            grant_type: "authorization_code",
            code: "raced-code",
          }),
          testClient,
        );
      const results = await Promise.allSettled([exchange(), exchange()]);

      const issued = results.filter((result) => result.status === "fulfilled");
      const refused = results.filter((result) => result.status === "rejected");
      expect(issued.length).toBe(1);
      expect(refused.length).toBe(1);
      assert.instanceOf(
        (refused[0] as PromiseRejectedResult).reason,
        InvalidGrantError,
      );
    });
  });
});
