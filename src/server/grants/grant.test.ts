import {
  assertEquals,
  assertRejects,
  assertStrictEquals,
  assertThrows,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import type { ClientInterface } from "../../models/client.ts";
import type { RefreshToken, Token } from "../../models/token.ts";
import { BasicScope } from "../../models/scope.ts";
import { InvalidClientError, InvalidScopeError } from "../../errors.ts";
import type { ClientCredentials } from "../../models/client.ts";
import { basicAuthHeader, tokenRequest } from "../../testing/_test_fixtures.ts";
import type { ClientServiceInterface } from "../services/client.ts";
import type { TokenServiceInterface } from "../services/token.ts";
import { AbstractGrant } from "./grant.ts";

interface Client extends ClientInterface {
  id: string;
  secret?: string;
}

interface User {
  id: string;
  username: string;
}

type Scope = BasicScope;

class TestGrant extends AbstractGrant<Client, User> {
  readonly grantType = "test";

  /** Public passthrough so tests can exercise the protected helper. */
  override getClientCredentials(
    request: Request,
    body: FormData,
  ): ClientCredentials {
    return super.getClientCredentials(request, body);
  }

  token(
    _request: Request,
    _client: Client,
    _body: FormData,
  ): Promise<Token<Client, User>> {
    throw new Error("Not implemented in test");
  }
}

/** Inline mock client service for grant base class tests. */
class MockClientService implements ClientServiceInterface<Client, User> {
  private clients = new Map<string, Client>();
  private clientUsers = new Map<string, User>();

  addClient(client: Client, user?: User): void {
    this.clients.set(client.id, client);
    if (user) this.clientUsers.set(client.id, user);
  }

  get(id: string): Promise<Client | undefined> {
    return Promise.resolve(this.clients.get(id));
  }

  getAuthenticated(
    id: string,
    secret?: string,
  ): Promise<Client | undefined> {
    const client = this.clients.get(id);
    if (!client) return Promise.resolve(undefined);
    if (client.secret) {
      if (!secret || client.secret !== secret) {
        return Promise.resolve(undefined);
      }
    }
    return Promise.resolve(client);
  }

  getUser(client: Client | string): Promise<User | undefined> {
    const id = typeof client === "string" ? client : client.id;
    return Promise.resolve(this.clientUsers.get(id));
  }
}

/** Inline mock token service for grant base class tests. */
class MockTokenService implements TokenServiceInterface<Client, User> {
  accessTokenLifetime = 3600;
  refreshTokenLifetime = 86400;
  private acceptedScopeResult:
    | BasicScope
    | null
    | undefined
    | false;

  constructor(
    acceptedScopeResult?: BasicScope | null | undefined | false,
  ) {
    this.acceptedScopeResult = acceptedScopeResult;
  }

  acceptedScope(
    _client: Client,
    _user: User,
    _scope?: BasicScope | null,
  ): Promise<BasicScope | null | undefined | false> {
    return Promise.resolve(this.acceptedScopeResult);
  }

  generateAccessToken(): Promise<string> {
    return Promise.resolve(crypto.randomUUID());
  }

  generateRefreshToken(): Promise<string | undefined> {
    return Promise.resolve(crypto.randomUUID());
  }

  accessTokenExpiresAt(): Promise<Date | undefined> {
    return Promise.resolve(
      new Date(Date.now() + this.accessTokenLifetime * 1000),
    );
  }

  refreshTokenExpiresAt(): Promise<Date | undefined> {
    return Promise.resolve(
      new Date(Date.now() + this.refreshTokenLifetime * 1000),
    );
  }

  getToken(): Promise<Token<Client, User> | undefined> {
    return Promise.resolve(undefined);
  }

  getRefreshToken(): Promise<RefreshToken<Client, User> | undefined> {
    return Promise.resolve(undefined);
  }

  save(
    token: RefreshToken<Client, User>,
  ): Promise<RefreshToken<Client, User>>;
  save(token: Token<Client, User>): Promise<Token<Client, User>>;
  save(
    token: Token<Client, User> | RefreshToken<Client, User>,
  ): Promise<Token<Client, User> | RefreshToken<Client, User>> {
    return Promise.resolve(token);
  }

  revoke(
    token: Token<Client, User> | RefreshToken<Client, User>,
  ): Promise<boolean>;
  revoke(token: string, hint?: string | null): Promise<boolean>;
  revoke(
    _token:
      | Token<Client, User>
      | RefreshToken<Client, User>
      | string,
    _hint?: string | null,
  ): Promise<boolean> {
    return Promise.resolve(true);
  }

  revokeCode(_code: string): Promise<boolean> {
    return Promise.resolve(false);
  }
}

interface CreateTestGrantOptions {
  allowRefreshToken?: boolean;
  acceptedScopeResult?: Scope | null | undefined | false;
}

function createTestGrant(options: CreateTestGrantOptions = {}) {
  const clientService = new MockClientService();
  const tokenService = new MockTokenService(options.acceptedScopeResult);

  const grant = new TestGrant({
    resolve: () => ({ clientService, tokenService }),
    allowRefreshToken: options.allowRefreshToken,
  });

  return { grant, clientService, tokenService };
}

describe("AbstractGrant", () => {
  const testClient: Client = { id: "client-1", secret: "secret" };
  const testUser: User = { id: "user-1", username: "testuser" };

  describe("constructor", () => {
    it("should set default allowRefreshToken to false", () => {
      const { grant } = createTestGrant();
      assertStrictEquals(grant.allowRefreshToken, false);
    });

    it("should set allowRefreshToken when specified", () => {
      const { grant } = createTestGrant({ allowRefreshToken: true });
      assertStrictEquals(grant.allowRefreshToken, true);
    });

    it("should use default Scope class", () => {
      const { grant } = createTestGrant();
      const scope = new grant.Scope("read write");
      assertStrictEquals(scope.toString(), "read write");
    });
  });

  describe("grantType", () => {
    it("should return the grant type", () => {
      const { grant } = createTestGrant();
      assertStrictEquals(grant.grantType, "test");
    });
  });

  describe("parseScope", () => {
    it("should return undefined for null scope", () => {
      const { grant } = createTestGrant();
      const scope = grant.parseScope(null);
      assertStrictEquals(scope, undefined);
    });

    it("should return undefined for undefined scope", () => {
      const { grant } = createTestGrant();
      const scope = grant.parseScope(undefined);
      assertStrictEquals(scope, undefined);
    });

    it("should return undefined for empty string", () => {
      const { grant } = createTestGrant();
      const scope = grant.parseScope("");
      assertStrictEquals(scope, undefined);
    });

    it("should parse valid scope string", () => {
      const { grant } = createTestGrant();
      const scope = grant.parseScope("read write");
      assertStrictEquals(scope?.toString(), "read write");
    });
  });

  describe("acceptedScope", () => {
    it("should return accepted scope from token service", async () => {
      const acceptedScope = new BasicScope("read");
      const { grant, tokenService } = createTestGrant({
        acceptedScopeResult: acceptedScope,
      });
      const result = await grant.acceptedScope(
        testClient,
        testUser,
        new BasicScope("read write"),
        tokenService,
      );
      assertStrictEquals(result, acceptedScope);
    });

    it("should accept the requested scope as-is when token service returns null", async () => {
      const requested = new BasicScope("read");
      const { grant, tokenService } = createTestGrant({
        acceptedScopeResult: null,
      });
      const result = await grant.acceptedScope(
        testClient,
        testUser,
        requested,
        tokenService,
      );
      assertStrictEquals(result, requested);
    });

    it("should accept the requested scope as-is when token service returns undefined", async () => {
      const requested = new BasicScope("read write");
      const { grant, tokenService } = createTestGrant({
        acceptedScopeResult: undefined,
      });
      const result = await grant.acceptedScope(
        testClient,
        testUser,
        requested,
        tokenService,
      );
      assertStrictEquals(result, requested);
    });

    it("should return undefined when no scope was requested and none granted", async () => {
      const { grant, tokenService } = createTestGrant({
        acceptedScopeResult: undefined,
      });
      const result = await grant.acceptedScope(
        testClient,
        testUser,
        undefined,
        tokenService,
      );
      assertStrictEquals(result, undefined);
    });

    it("should throw InvalidScopeError when token service returns false with scope", async () => {
      const { grant, tokenService } = createTestGrant({
        acceptedScopeResult: false,
      });
      await assertRejects(
        () =>
          grant.acceptedScope(
            testClient,
            testUser,
            new BasicScope("invalid"),
            tokenService,
          ),
        InvalidScopeError,
        "invalid scope",
      );
    });

    it("should throw InvalidScopeError when token service returns false without scope", async () => {
      const { grant, tokenService } = createTestGrant({
        acceptedScopeResult: false,
      });
      await assertRejects(
        () =>
          grant.acceptedScope(testClient, testUser, undefined, tokenService),
        InvalidScopeError,
        "scope required",
      );
    });
  });

  describe("getClientCredentials", () => {
    it("should extract credentials from Basic Auth header", () => {
      const { grant } = createTestGrant();
      const request = new Request("http://localhost/token", {
        method: "POST",
        headers: basicAuthHeader("client-1", "secret"),
      });

      const credentials = grant.getClientCredentials(request, new FormData());
      assertEquals(credentials, {
        clientId: "client-1",
        clientSecret: "secret",
      });
    });

    it("should extract credentials from POST body", async () => {
      const { grant } = createTestGrant();
      const request = tokenRequest({
        client_id: "client-1",
        client_secret: "secret",
      });

      const credentials = grant.getClientCredentials(
        request,
        await request.clone().formData(),
      );
      assertEquals(credentials, {
        clientId: "client-1",
        clientSecret: "secret",
      });
    });

    it("should extract client_id only from POST body", async () => {
      const { grant } = createTestGrant();
      const request = tokenRequest({ client_id: "public-client" });

      const credentials = grant.getClientCredentials(
        request,
        await request.clone().formData(),
      );
      assertEquals(credentials, { clientId: "public-client" });
    });

    it("should throw InvalidClientError when no credentials", () => {
      const { grant } = createTestGrant();
      const request = new Request("http://localhost/token", { method: "POST" });

      assertThrows(
        () => grant.getClientCredentials(request, new FormData()),
        InvalidClientError,
        "client authentication required",
      );
    });

    it("should prefer Basic Auth over POST body", async () => {
      const { grant } = createTestGrant();
      const request = tokenRequest({
        client_id: "body-client",
        client_secret: "body-secret",
      }, basicAuthHeader("header-client", "header-secret"));

      const credentials = grant.getClientCredentials(
        request,
        await request.clone().formData(),
      );
      assertEquals(credentials, {
        clientId: "header-client",
        clientSecret: "header-secret",
      });
    });
  });

  describe("getAuthenticatedClient", () => {
    it("should return authenticated client", async () => {
      const { grant, clientService } = createTestGrant();
      clientService.addClient(testClient);

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

    it("should throw InvalidClientError for non-existent client", async () => {
      const { grant } = createTestGrant();

      const request = new Request("http://localhost/token", {
        method: "POST",
        headers: basicAuthHeader("unknown", "secret"),
      });

      await assertRejects(
        () => grant.getAuthenticatedClient(request, new FormData()),
        InvalidClientError,
        "client authentication failed",
      );
    });

    it("should throw InvalidClientError for wrong secret", async () => {
      const { grant, clientService } = createTestGrant();
      clientService.addClient(testClient);

      const request = new Request("http://localhost/token", {
        method: "POST",
        headers: basicAuthHeader("client-1", "wrong"),
      });

      await assertRejects(
        () => grant.getAuthenticatedClient(request, new FormData()),
        InvalidClientError,
        "client authentication failed",
      );
    });
  });

  describe("generateToken", () => {
    it("should generate token with access token", async () => {
      const { grant, clientService, tokenService } = createTestGrant();
      clientService.addClient(testClient, testUser);

      const token = await grant.generateToken(
        testClient,
        testUser,
        undefined,
        tokenService,
      );

      assertStrictEquals(typeof token.accessToken, "string");
      assertStrictEquals(token.client.id, testClient.id);
      assertStrictEquals(token.user?.id, testUser.id);
    });

    it("should include scope in token when provided", async () => {
      const { grant, clientService, tokenService } = createTestGrant();
      clientService.addClient(testClient, testUser);
      const scope = new BasicScope("read write");

      const token = await grant.generateToken(
        testClient,
        testUser,
        scope,
        tokenService,
      );

      assertStrictEquals(token.scope?.toString(), "read write");
    });

    it("should include expiration date", async () => {
      const { grant, clientService, tokenService } = createTestGrant();
      clientService.addClient(testClient, testUser);

      const before = Date.now();
      const token = await grant.generateToken(
        testClient,
        testUser,
        undefined,
        tokenService,
      );
      const after = Date.now();

      assertStrictEquals(token.accessTokenExpiresAt instanceof Date, true);
      assertStrictEquals(
        token.accessTokenExpiresAt!.getTime() >= before + 3600 * 1000,
        true,
      );
      assertStrictEquals(
        token.accessTokenExpiresAt!.getTime() <= after + 3600 * 1000,
        true,
      );
    });

    it("should include refresh token when allowRefreshToken is true", async () => {
      const { grant, clientService, tokenService } = createTestGrant({
        allowRefreshToken: true,
      });
      clientService.addClient(testClient, testUser);

      const token = await grant.generateToken(
        testClient,
        testUser,
        undefined,
        tokenService,
      );

      assertStrictEquals("refreshToken" in token, true);
      assertStrictEquals(
        typeof (token as Token<Client, User> & {
          refreshToken: string;
        }).refreshToken,
        "string",
      );
    });

    it("should not include refresh token when allowRefreshToken is false", async () => {
      const { grant, clientService, tokenService } = createTestGrant({
        allowRefreshToken: false,
      });
      clientService.addClient(testClient, testUser);

      const token = await grant.generateToken(
        testClient,
        testUser,
        undefined,
        tokenService,
      );

      assertStrictEquals("refreshToken" in token, false);
    });

    it("should omit the user key entirely when no user is given", async () => {
      const { grant, clientService, tokenService } = createTestGrant();
      clientService.addClient(testClient);

      const token = await grant.generateToken(
        testClient,
        undefined,
        undefined,
        tokenService,
      );

      assertStrictEquals(typeof token.accessToken, "string");
      assertStrictEquals(token.client.id, testClient.id);
      assertStrictEquals("user" in token, false);
    });

    it("should not include refresh token without a user, even when allowRefreshToken is true", async () => {
      const { grant, clientService, tokenService } = createTestGrant({
        allowRefreshToken: true,
      });
      clientService.addClient(testClient);

      const token = await grant.generateToken(
        testClient,
        undefined,
        undefined,
        tokenService,
      );

      assertStrictEquals("refreshToken" in token, false);
    });
  });

  describe("per-request services (resolve threading)", () => {
    it("generateToken uses services passed per call, not this.services", async () => {
      const { grant, clientService } = createTestGrant();
      clientService.addClient(testClient, testUser);

      const altTokenService = new MockTokenService();
      altTokenService.generateAccessToken = () =>
        Promise.resolve("sentinel-access-token");

      const token = await grant.generateToken(
        testClient,
        testUser,
        undefined,
        altTokenService,
      );

      assertStrictEquals(token.accessToken, "sentinel-access-token");
    });

    it("acceptedScope uses services passed per call, not this.services", async () => {
      const { grant } = createTestGrant();
      const altTokenService = new MockTokenService(new BasicScope("alt"));

      const result = await grant.acceptedScope(
        testClient,
        testUser,
        new BasicScope("read"),
        altTokenService,
      );

      assertStrictEquals(result?.toString(), "alt");
    });
  });
});
