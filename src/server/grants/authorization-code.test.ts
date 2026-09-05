import {
  assertInstanceOf,
  assertRejects,
  assertStrictEquals,
  assertThrows,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";
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
class RacingAuthorizationCodeService
  extends MemoryAuthorizationCodeService<TestClient, TestUser, BasicScope> {
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
      assertStrictEquals(grant.grantType, "authorization_code");
    });
  });

  describe("constructor", () => {
    it("should use default challengeMethods", async () => {
      const { grant } = await createTestGrant();
      assertStrictEquals(typeof grant.challengeMethods["S256"], "function");
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

      assertStrictEquals(grant.challengeMethods["custom"], customMethod);
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

      assertStrictEquals(grant.requirePKCE, true);
    });
  });

  describe("getClient", () => {
    it("should return client by ID", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const client = await grant.getClient("client-1", clientService);
      assertStrictEquals(client.id, "client-1");
    });

    it("should throw InvalidClientError for non-existent client", async () => {
      const { grant, clientService } = await createTestGrant();

      await assertRejects(
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
      assertStrictEquals(typeof method, "function");
    });

    it("should return S256 when specified", async () => {
      const { grant } = await createTestGrant();
      const method = grant.getChallengeMethod("S256");
      assertStrictEquals(typeof method, "function");
    });

    it("should return undefined for unknown method", async () => {
      const { grant } = await createTestGrant();
      const method = grant.getChallengeMethod("unknown");
      assertStrictEquals(method, undefined);
    });

    it("returns no method for a name inherited from Object.prototype", async () => {
      const { grant } = await createTestGrant();
      for (const name of INHERITED_MEMBER_NAMES) {
        assertStrictEquals(grant.getChallengeMethod(name), undefined, name);
      }
    });

    it("returns a method a consumer added to their own challengeMethods map", async () => {
      const custom = (verifier: string) =>
        Promise.resolve(`custom:${verifier}`);
      const { grant } = await createTestGrant({
        challengeMethods: { custom },
      });
      assertStrictEquals(grant.getChallengeMethod("custom"), custom);
    });
  });

  describe("validateChallengeMethod", () => {
    it("should return true for S256", async () => {
      const { grant } = await createTestGrant();
      assertStrictEquals(grant.validateChallengeMethod("S256"), true);
    });

    it("should return true for null (defaults to S256)", async () => {
      const { grant } = await createTestGrant();
      assertStrictEquals(grant.validateChallengeMethod(null), true);
    });

    it("should return false for unknown method", async () => {
      const { grant } = await createTestGrant();
      assertStrictEquals(grant.validateChallengeMethod("plain"), false);
    });

    it("rejects a code_challenge_method inherited from Object.prototype at the authorization endpoint", async () => {
      const { grant } = await createTestGrant();
      for (const name of INHERITED_MEMBER_NAMES) {
        assertStrictEquals(grant.validateChallengeMethod(name), false, name);
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
      assertStrictEquals(result, true);
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
      assertStrictEquals(result, false);
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
      assertStrictEquals(result, false);
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

      await assertRejects(
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

        await assertRejects(
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

      assertStrictEquals(typeof code.code, "string");
      assertStrictEquals(code.client.id, testClient.id);
      assertStrictEquals(code.user.id, testUser.id);
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

      assertStrictEquals(code.scope?.toString(), "read write");
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

      assertStrictEquals(code.redirectUri, "https://example.com/callback");
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

      assertStrictEquals(
        code.challenge,
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      );
      assertStrictEquals(code.challengeMethod, "S256");
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
      assertStrictEquals(saved?.client.id, code.client.id);
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
      assertStrictEquals(credentials.clientId, "client-1");
      assertStrictEquals(credentials.clientSecret, "secret");
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
      assertStrictEquals(credentials.clientId, "public-client");
      assertStrictEquals(credentials.codeVerifier, "test-verifier");
      assertStrictEquals(credentials.clientSecret, undefined);
    });

    it("should throw InvalidClientError when no credentials", async () => {
      const { grant } = await createTestGrant();
      const request = tokenRequest({});

      assertThrows(
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
      assertStrictEquals(credentials.clientId, "client-1");
      assertStrictEquals(credentials.clientSecret, "secret");
      assertStrictEquals(credentials.codeVerifier, "test-verifier");
    });

    it("should fall back to body client_id when Basic auth is invalid", async () => {
      const { grant } = await createTestGrant();
      const request = tokenRequest({ client_id: "body-client" }, {
        Authorization: "Basic invalid!!!",
      });

      const credentials = grant.getClientCredentials(
        request,
        await request.clone().formData(),
      );
      assertStrictEquals(credentials.clientId, "body-client");
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
      assertStrictEquals(client.id, "client-1");
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
      assertStrictEquals(client.id, "public-client");
    });

    it("should throw InvalidClientError for non-existent PKCE client", async () => {
      const { grant } = await createTestGrant();

      const request = tokenRequest({
        client_id: "unknown",
        code_verifier: "test-verifier",
      });
      const body = await request.clone().formData();

      await assertRejects(
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
      assertStrictEquals(client.id, "client-1");
    });

    it("requires confidential client authentication by default alongside PKCE", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        client_id: "client-1",
        code_verifier: "test-verifier",
      });
      const body = await request.clone().formData();

      await assertRejects(
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
      assertStrictEquals(client.id, "client-1");
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
      assertStrictEquals(client.id, "public-client");
    });
  });

  describe("token", () => {
    it("should throw InvalidRequestError when code missing", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({ grant_type: "authorization_code" });

      await assertRejects(
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

      await assertRejects(
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

      await assertRejects(
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

      await assertRejects(
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

      assertStrictEquals(typeof token.accessToken, "string");
      assertStrictEquals(token.client.id, testClient.id);
      assertStrictEquals(token.user?.id, testUser.id);
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

      assertStrictEquals(token.scope?.toString(), "read write");
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

      assertStrictEquals(typeof token.accessToken, "string");
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

      await assertRejects(
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

      await assertRejects(
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

      await assertRejects(
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

      await assertRejects(
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

      await assertRejects(
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

      await assertRejects(
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

      assertStrictEquals(token.client.id, testClient.id);
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

      await assertRejects(
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

      await assertRejects(
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

      await assertRejects(
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

      assertStrictEquals(typeof token.accessToken, "string");
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

      const revokedCode = await authorizationCodeService.get(
        "single-use-code",
      );
      assertStrictEquals(revokedCode, undefined);
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
      assertStrictEquals(savedToken?.accessToken, token.accessToken);
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

      const token =
        (await exchangeToken(grant, request, testClient)) as RefreshToken<
          TestClient,
          TestUser,
          BasicScope
        >;

      assertStrictEquals("refreshToken" in token, true);
      assertStrictEquals(typeof token.refreshToken, "string");
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

      assertStrictEquals("refreshToken" in token, false);
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

      assertStrictEquals(token.code, "reused-code");
      const savedToken = await tokenService.getToken(token.accessToken);
      assertStrictEquals(savedToken !== undefined, true);

      const body2 = new URLSearchParams({
        grant_type: "authorization_code",
        code: "reused-code",
      });
      const request2 = tokenRequest(body2);

      await assertRejects(
        () => exchangeToken(grant, request2, testClient),
        InvalidGrantError,
        "code already used",
      );

      const revokedToken = await tokenService.getToken(token.accessToken);
      assertStrictEquals(revokedToken, undefined);
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

      await assertRejects(
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

      assertStrictEquals(typeof token.accessToken, "string");
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
      assertStrictEquals(issued.length, 1);
      assertStrictEquals(refused.length, 1);
      assertInstanceOf(
        (refused[0] as PromiseRejectedResult).reason,
        InvalidGrantError,
      );
    });
  });
});
