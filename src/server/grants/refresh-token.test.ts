import { assertRejects, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { FakeTime } from "@std/testing/time";
import type { RefreshToken, Token } from "../../models/token.ts";
import { BasicScope } from "../../models/scope.ts";
import {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
} from "../../errors.ts";
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
import { RefreshTokenGrant } from "./refresh-token.ts";

/** A client-authenticated refresh-token exchange for the given token. */
function refreshRequest(refreshToken: string): Request {
  return tokenRequest(
    { grant_type: "refresh_token", refresh_token: refreshToken },
    basicAuthHeader("client-1", "secret"),
  );
}

const testUser: TestUser = { id: "user-1", username: "testuser" };
const testClient: TestClient = { id: "client-1", confidential: true };

async function createTestGrant() {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });

  await userService.add(testUser, "password");
  await clientService.add(testClient, "secret", testUser.id);

  const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
    resolve: () => ({ clientService, tokenService }),
  });

  return { grant, clientService, tokenService };
}

/**
 * MemoryTokenService subclass that doesn't generate new refresh tokens.
 * Used to test the case where we preserve the existing refresh token.
 */
class NoRotateTokenService
  extends MemoryTokenService<TestClient, TestUser, BasicScope> {
  override generateRefreshToken(): Promise<string | undefined> {
    return Promise.resolve(undefined);
  }
}

/**
 * MemoryTokenService subclass that counts which revocation path the grant
 * takes, to pin rotation onto `revokeRotated` when a service implements it.
 */
class RotationAwareTokenService
  extends MemoryTokenService<TestClient, TestUser, BasicScope> {
  rotatedCalls = 0;
  revokeCalls = 0;
  revokeRotated(
    token: RefreshToken<TestClient, TestUser, BasicScope>,
  ): Promise<boolean> {
    this.rotatedCalls++;
    return super.revoke(token);
  }
  override revoke(
    token:
      | Token<TestClient, TestUser, BasicScope>
      | RefreshToken<TestClient, TestUser, BasicScope>
      | string,
    hint?: string | null,
  ): Promise<boolean> {
    this.revokeCalls++;
    return typeof token === "string"
      ? super.revoke(token, hint)
      : super.revoke(token);
  }
}

describe("RefreshTokenGrant", () => {
  describe("grantType", () => {
    it("should return refresh_token", async () => {
      const { grant } = await createTestGrant();
      assertStrictEquals(grant.grantType, "refresh_token");
    });
  });

  describe("constructor", () => {
    it("should allow refresh tokens", async () => {
      const { grant } = await createTestGrant();
      assertStrictEquals(grant.allowRefreshToken, true);
    });
  });

  describe("token", () => {
    it("should throw InvalidRequestError when refresh-token missing", async () => {
      const { grant } = await createTestGrant();

      const request = tokenRequest({ grant_type: "refresh_token" });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        InvalidRequestError,
        "refresh_token parameter required",
      );
    });

    it("should throw InvalidGrantError for non-existent refresh token", async () => {
      const { grant } = await createTestGrant();

      const request = tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "non-existent",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        InvalidGrantError,
        "invalid refresh_token",
      );
    });

    it("should throw InvalidGrantError for expired refresh token", async () => {
      const { grant, tokenService } = await createTestGrant();

      const expiredToken: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: "access-123",
        accessTokenExpiresAt: new Date(Date.now() - 1000),
        refreshToken: "refresh-123",
        refreshTokenExpiresAt: new Date(Date.now() - 1000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(expiredToken);

      const request = tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "refresh-123",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        InvalidGrantError,
        "invalid refresh_token",
      );
    });

    it("should throw InvalidClientError when refresh token belongs to different client", async () => {
      const { grant, tokenService, clientService } = await createTestGrant();

      const otherClient: TestClient = { id: "other-client" };
      await clientService.add(otherClient);

      const existingToken: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: "access-123",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "refresh-123",
        refreshTokenExpiresAt: new Date(Date.now() + 86400000),
        client: otherClient,
        user: testUser,
      };
      await tokenService.save(existingToken);

      const request = tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "refresh-123",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        InvalidClientError,
        "refresh_token was issued to another client",
      );
    });

    it("should issue new token for valid refresh token", async () => {
      const { grant, tokenService } = await createTestGrant();

      const existingToken: RefreshToken<TestClient, TestUser, BasicScope> = {
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
      });

      const newToken = await exchangeToken(grant, request, testClient);

      assertStrictEquals(newToken.accessToken !== "old-access", true);
      assertStrictEquals(newToken.client.id, testClient.id);
      assertStrictEquals(newToken.user?.id, testUser.id);
    });

    it("should preserve scope from original token", async () => {
      const { grant, tokenService } = await createTestGrant();

      const scope = new BasicScope("read write");
      const existingToken: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: "old-access",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "refresh-123",
        refreshTokenExpiresAt: new Date(Date.now() + 86400000),
        client: testClient,
        user: testUser,
        scope,
      };
      await tokenService.save(existingToken);

      const request = tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "refresh-123",
      });

      const newToken = await exchangeToken(grant, request, testClient);

      assertStrictEquals(newToken.scope?.toString(), "read write");
    });

    it("narrows scope to the requested subset (RFC 6749 Section 6)", async () => {
      const { grant, tokenService } = await createTestGrant();

      const existingToken: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: "old-access",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "refresh-123",
        refreshTokenExpiresAt: new Date(Date.now() + 86400000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read write delete"),
      };
      await tokenService.save(existingToken);

      const request = tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "refresh-123",
        scope: "read write",
      });

      const newToken = await exchangeToken(grant, request, testClient);

      assertStrictEquals(newToken.scope?.toString(), "read write");
    });

    it("rejects a requested scope outside the original grant", async () => {
      const { grant, tokenService } = await createTestGrant();

      const existingToken: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: "old-access",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "refresh-123",
        refreshTokenExpiresAt: new Date(Date.now() + 86400000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read"),
      };
      await tokenService.save(existingToken);

      const request = tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "refresh-123",
        scope: "read write",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        InvalidScopeError,
        "requested scope exceeds the scope of the original grant",
      );
    });

    it("keeps the original scope when no scope parameter is sent", async () => {
      const { grant, tokenService } = await createTestGrant();

      const existingToken: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: "old-access",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "refresh-123",
        refreshTokenExpiresAt: new Date(Date.now() + 86400000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read write"),
      };
      await tokenService.save(existingToken);

      const request = tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "refresh-123",
      });

      const newToken = await exchangeToken(grant, request, testClient);

      assertStrictEquals(newToken.scope?.toString(), "read write");
    });

    it("should revoke old token", async () => {
      const { grant, tokenService } = await createTestGrant();

      const existingToken: RefreshToken<TestClient, TestUser, BasicScope> = {
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
      });

      await exchangeToken(grant, request, testClient);

      const oldRefresh = await tokenService.getRefreshToken("refresh-123");
      assertStrictEquals(oldRefresh, undefined);
    });

    it("rotates through revokeRotated when implemented, never revoke", async () => {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new RotationAwareTokenService({
        clientService,
        userService,
      });
      await userService.add(testUser, "password");
      await clientService.add(testClient, "secret", testUser.id);
      const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
        resolve: () => ({ clientService, tokenService }),
      });
      await tokenService.save({
        accessToken: "old-access",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "refresh-rotated",
        refreshTokenExpiresAt: new Date(Date.now() + 86400000),
        client: testClient,
        user: testUser,
      });

      await exchangeToken(grant, refreshRequest("refresh-rotated"), testClient);

      assertStrictEquals(tokenService.rotatedCalls, 1);
      assertStrictEquals(tokenService.revokeCalls, 0);
      assertStrictEquals(
        await tokenService.getRefreshToken("refresh-rotated"),
        undefined,
      );
    });

    it("should save new token", async () => {
      const { grant, tokenService } = await createTestGrant();

      const existingToken: RefreshToken<TestClient, TestUser, BasicScope> = {
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
      });

      const newToken = await exchangeToken(grant, request, testClient);

      const savedToken = await tokenService.getToken(newToken.accessToken);
      assertStrictEquals(savedToken?.accessToken, newToken.accessToken);
    });

    it("should work with token that has no expiration", async () => {
      const { grant, tokenService } = await createTestGrant();

      const existingToken: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: "old-access",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "refresh-123",
        client: testClient,
        user: testUser,
      };
      await tokenService.save(existingToken);

      const request = tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "refresh-123",
      });

      const newToken = await exchangeToken(grant, request, testClient);

      assertStrictEquals(typeof newToken.accessToken, "string");
      assertStrictEquals(newToken.accessToken !== "old-access", true);
    });

    it("should preserve existing refresh token when no new one generated", async () => {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new NoRotateTokenService({
        clientService,
        userService,
      });

      await userService.add(testUser, "password");
      await clientService.add(testClient, "secret", testUser.id);

      const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
        resolve: () => ({ clientService, tokenService }),
      });

      const existingToken: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: "old-access",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "existing-refresh-token",
        refreshTokenExpiresAt: new Date(Date.now() + 86400000),
        client: testClient,
        user: testUser,
      };
      await tokenService.save(existingToken);

      const request = tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "existing-refresh-token",
      });

      const newToken = await exchangeToken(grant, request, testClient);

      assertStrictEquals(newToken.accessToken !== "old-access", true);
      assertStrictEquals(newToken.refreshToken, "existing-refresh-token");
      assertStrictEquals(
        newToken.refreshTokenExpiresAt?.getTime(),
        existingToken.refreshTokenExpiresAt?.getTime(),
      );
    });

    it("should preserve refresh token without expiration when no new one generated", async () => {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new NoRotateTokenService({
        clientService,
        userService,
      });

      await userService.add(testUser, "password");
      await clientService.add(testClient, "secret", testUser.id);

      const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
        resolve: () => ({ clientService, tokenService }),
      });

      const existingToken: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: "old-access",
        accessTokenExpiresAt: new Date(Date.now() + 3600000),
        refreshToken: "no-expire-refresh",
        client: testClient,
        user: testUser,
      };
      await tokenService.save(existingToken);

      const request = tokenRequest({
        grant_type: "refresh_token",
        refresh_token: "no-expire-refresh",
      });

      const newToken = await exchangeToken(grant, request, testClient);

      assertStrictEquals(newToken.refreshToken, "no-expire-refresh");
      assertStrictEquals(newToken.refreshTokenExpiresAt, undefined);
    });
  });

  describe("reuse detection", () => {
    async function seedRefreshToken(
      tokenService: MemoryTokenService<TestClient, TestUser, BasicScope>,
      clientService: MemoryClientService<TestClient, TestUser>,
    ): Promise<RefreshToken<TestClient, TestUser, BasicScope>> {
      const client = (await clientService.get("client-1"))!;
      const token: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: crypto.randomUUID(),
        accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
        refreshToken: crypto.randomUUID(),
        refreshTokenExpiresAt: new Date(Date.now() + 86_400_000),
        client,
        user: testUser,
        familyId: crypto.randomUUID(),
      };
      await tokenService.save(token);
      return token;
    }

    it("rotations inherit the ancestor's familyId", async () => {
      const { grant, clientService, tokenService } = await createTestGrant();
      const original = await seedRefreshToken(tokenService, clientService);

      const rotated = await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        (await clientService.get("client-1"))!,
      );
      assertStrictEquals(rotated.familyId, original.familyId);

      const stored = await tokenService.getRefreshToken(rotated.refreshToken);
      assertStrictEquals(stored?.familyId, original.familyId);
    });

    it("replaying a rotated-out token revokes the family and reports the event", async () => {
      const reuseEvents: Array<{ familyId: string; familyRevoked: boolean }> =
        [];
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new MemoryTokenService({
        clientService,
        userService,
      });
      await userService.add(testUser, "password");
      await clientService.add(testClient, "secret", testUser.id);
      const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
        resolve: () => ({ clientService, tokenService }),
        onTokenReuse: (event) => {
          reuseEvents.push({
            familyId: event.familyId,
            familyRevoked: event.familyRevoked,
          });
        },
      });

      const original = await seedRefreshToken(tokenService, clientService);
      const client = (await clientService.get("client-1"))!;
      const rotated = await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      );

      await assertRejects(
        () =>
          exchangeToken(grant, refreshRequest(original.refreshToken), client),
        InvalidGrantError,
      );
      assertStrictEquals(reuseEvents.length, 1);
      assertStrictEquals(reuseEvents[0].familyId, original.familyId);
      assertStrictEquals(reuseEvents[0].familyRevoked, true);

      assertStrictEquals(
        await tokenService.getRefreshToken(rotated.refreshToken),
        undefined,
      );
      await assertRejects(
        () =>
          exchangeToken(grant, refreshRequest(rotated.refreshToken), client),
        InvalidGrantError,
      );
    });

    it("keeps invalid_grant when onTokenReuse throws (fire-and-forget)", async () => {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new MemoryTokenService({
        clientService,
        userService,
      });
      await userService.add(testUser, "password");
      await clientService.add(testClient, "secret", testUser.id);
      const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
        resolve: () => ({ clientService, tokenService }),
        onTokenReuse: () => {
          throw new Error("audit sink down");
        },
      });

      const original = await seedRefreshToken(tokenService, clientService);
      const client = (await clientService.get("client-1"))!;
      await exchangeToken(grant, refreshRequest(original.refreshToken), client);

      const error = await assertRejects(
        () =>
          exchangeToken(grant, refreshRequest(original.refreshToken), client),
        InvalidGrantError,
      );
      assertStrictEquals(error.status, 400);
    });

    it("degrades to a plain invalid_grant when the store lacks reuse support", async () => {
      const { grant, clientService, tokenService } = await createTestGrant();
      const original = await seedRefreshToken(tokenService, clientService);
      const client = (await clientService.get("client-1"))!;
      await exchangeToken(grant, refreshRequest(original.refreshToken), client);

      const bare: typeof tokenService = {
        accessTokenLifetime: tokenService.accessTokenLifetime,
        refreshTokenLifetime: tokenService.refreshTokenLifetime,
        acceptedScope: tokenService.acceptedScope.bind(tokenService),
        generateAccessToken: tokenService.generateAccessToken.bind(
          tokenService,
        ),
        generateRefreshToken: tokenService.generateRefreshToken.bind(
          tokenService,
        ),
        accessTokenExpiresAt: tokenService.accessTokenExpiresAt.bind(
          tokenService,
        ),
        refreshTokenExpiresAt: tokenService.refreshTokenExpiresAt.bind(
          tokenService,
        ),
        getToken: tokenService.getToken.bind(tokenService),
        getRefreshToken: tokenService.getRefreshToken.bind(tokenService),
        save: tokenService.save.bind(tokenService),
        revoke: tokenService.revoke.bind(tokenService),
        revokeCode: tokenService.revokeCode.bind(tokenService),
      } as typeof tokenService;
      const bareGrant = new RefreshTokenGrant<
        TestClient,
        TestUser,
        BasicScope
      >({
        resolve: () => ({ clientService, tokenService: bare }),
      });

      await assertRejects(
        () =>
          exchangeToken(
            bareGrant,
            refreshRequest(original.refreshToken),
            client,
          ),
        InvalidGrantError,
      );
    });
  });

  describe("family lifetime cap", () => {
    const START = new Date("2026-01-01T00:00:00.000Z");
    const DAY = 24 * 60 * 60 * 1000;

    async function createCappedGrant(
      options: {
        refreshTokenMaxLifetime?: number;
        client?: TestClient;
        rotates?: boolean;
      } = {},
    ) {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const TokenService = options.rotates === false
        ? NoRotateTokenService
        : MemoryTokenService;
      const tokenService = new TokenService<
        TestClient,
        TestUser,
        BasicScope
      >({
        clientService,
        userService,
        refreshTokenLifetime: 7 * 24 * 60 * 60,
        refreshTokenMaxLifetime: options.refreshTokenMaxLifetime,
      });
      await userService.add(testUser, "password");
      await clientService.add(
        options.client ?? testClient,
        "secret",
        testUser.id,
      );
      const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
        resolve: () => ({ clientService, tokenService }),
      });
      const client = (await clientService.get("client-1"))!;
      return { grant, client, clientService, tokenService };
    }

    async function seedFamily(
      tokenService: MemoryTokenService<TestClient, TestUser, BasicScope>,
      client: TestClient,
      familyCreatedAt: Date | undefined,
    ): Promise<RefreshToken<TestClient, TestUser, BasicScope>> {
      const token: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: crypto.randomUUID(),
        accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
        refreshToken: crypto.randomUUID(),
        refreshTokenExpiresAt: new Date(Date.now() + 7 * DAY),
        client,
        user: testUser,
        familyId: crypto.randomUUID(),
        familyCreatedAt,
      };
      await tokenService.save(token);
      return token;
    }

    it("keeps the sliding expiry while the cap is further out", async () => {
      using _time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 30 * 24 * 60 * 60,
      });
      const original = await seedFamily(tokenService, client, new Date());

      const rotated = await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      ) as RefreshToken<TestClient, TestUser, BasicScope>;

      assertStrictEquals(
        rotated.refreshTokenExpiresAt?.getTime(),
        START.getTime() + 7 * DAY,
      );
    });

    it("truncates the sliding expiry to the family's absolute cap", async () => {
      using _time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 30 * 24 * 60 * 60,
      });
      const original = await seedFamily(
        tokenService,
        client,
        new Date(START.getTime() - 29 * DAY),
      );

      const rotated = await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      ) as RefreshToken<TestClient, TestUser, BasicScope>;

      assertStrictEquals(
        rotated.refreshTokenExpiresAt?.getTime(),
        START.getTime() + DAY,
      );
    });

    it("rejects the exchange once the family's absolute cap is spent", async () => {
      using _time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 30 * 24 * 60 * 60,
      });
      const original = await seedFamily(
        tokenService,
        client,
        new Date(START.getTime() - 30 * DAY),
      );

      await assertRejects(
        () =>
          exchangeToken(grant, refreshRequest(original.refreshToken), client),
        InvalidGrantError,
        "refresh_token family expired",
      );
    });

    it("anchors the cap at the family's creation, not the last rotation", async () => {
      using time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 30 * 24 * 60 * 60,
      });
      let current = await seedFamily(tokenService, client, new Date());

      for (let rotation = 0; rotation < 5; rotation++) {
        time.tick(5 * DAY);
        current = await exchangeToken(
          grant,
          refreshRequest(current.refreshToken),
          client,
        ) as RefreshToken<TestClient, TestUser, BasicScope>;
        assertStrictEquals(current.familyCreatedAt?.getTime(), START.getTime());
      }

      assertStrictEquals(
        current.refreshTokenExpiresAt?.getTime(),
        START.getTime() + 30 * DAY,
      );

      time.tick(6 * DAY);
      await assertRejects(
        () =>
          exchangeToken(grant, refreshRequest(current.refreshToken), client),
        InvalidGrantError,
        "invalid refresh_token",
      );
    });

    it("renews the full sliding lifetime when no cap is configured", async () => {
      using _time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant();
      const original = await seedFamily(
        tokenService,
        client,
        new Date(START.getTime() - 60 * DAY),
      );

      const rotated = await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      ) as RefreshToken<TestClient, TestUser, BasicScope>;

      assertStrictEquals(
        rotated.refreshTokenExpiresAt?.getTime(),
        START.getTime() + 7 * DAY,
      );
    });

    it("leaves a record without a family anchor uncapped", async () => {
      using _time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 30 * 24 * 60 * 60,
      });
      const original = await seedFamily(tokenService, client, undefined);

      const rotated = await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      ) as RefreshToken<TestClient, TestUser, BasicScope>;

      assertStrictEquals(
        rotated.refreshTokenExpiresAt?.getTime(),
        START.getTime() + 7 * DAY,
      );
    });

    it("clamps the rotated access token to the family ceiling", async () => {
      using _time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 30 * 24 * 60 * 60,
      });
      const familyCreatedAt = new Date(START.getTime() - 30 * DAY + 600_000);
      const original = await seedFamily(tokenService, client, familyCreatedAt);

      const rotated = await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      );

      assertStrictEquals(
        rotated.accessTokenExpiresAt?.getTime(),
        familyCreatedAt.getTime() + 30 * DAY,
        "an access token minted just under the ceiling must not outlive it",
      );
    });

    it("clamps a new family's access token when the cap is shorter than the access lifetime", async () => {
      using _time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 600,
      });

      const issued = await grant.generateToken(
        client,
        testUser,
        undefined,
        tokenService,
      ) as RefreshToken<TestClient, TestUser, BasicScope>;

      assertStrictEquals(
        issued.accessTokenExpiresAt?.getTime(),
        START.getTime() + 600_000,
      );
      assertStrictEquals(
        issued.refreshTokenExpiresAt?.getTime(),
        START.getTime() + 600_000,
      );
    });

    it("clamps the preserved refresh token when the service issues no new one", async () => {
      using _time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 30 * 24 * 60 * 60,
        rotates: false,
      });
      const familyCreatedAt = new Date(START.getTime() - 30 * DAY + 600_000);
      const original = await seedFamily(tokenService, client, familyCreatedAt);

      const next = await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      ) as RefreshToken<TestClient, TestUser, BasicScope>;

      assertStrictEquals(next.refreshToken, original.refreshToken);
      assertStrictEquals(
        next.refreshTokenExpiresAt?.getTime(),
        familyCreatedAt.getTime() + 30 * DAY,
      );
      assertStrictEquals(
        next.accessTokenExpiresAt?.getTime(),
        familyCreatedAt.getTime() + 30 * DAY,
      );
    });

    it("anchors an anchorless record's rotation, capping the family from there", async () => {
      using time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 30 * 24 * 60 * 60,
      });
      const original = await seedFamily(tokenService, client, undefined);

      const rotated = await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      ) as RefreshToken<TestClient, TestUser, BasicScope>;

      assertStrictEquals(rotated.familyCreatedAt?.getTime(), START.getTime());
      const stored = await tokenService.getRefreshToken(rotated.refreshToken);
      assertStrictEquals(stored?.familyCreatedAt?.getTime(), START.getTime());

      time.tick(31 * DAY);
      await assertRejects(
        () =>
          exchangeToken(grant, refreshRequest(rotated.refreshToken), client),
        InvalidGrantError,
      );
    });

    it("caps per client when the client declares its own maximum", async () => {
      using _time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 30 * 24 * 60 * 60,
        client: { id: "client-1", refreshTokenMaxLifetime: 10 * 24 * 60 * 60 },
      });
      const original = await seedFamily(
        tokenService,
        client,
        new Date(START.getTime() - 5 * DAY),
      );

      const rotated = await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      ) as RefreshToken<TestClient, TestUser, BasicScope>;

      assertStrictEquals(
        rotated.refreshTokenExpiresAt?.getTime(),
        START.getTime() + 5 * DAY,
      );
    });
  });
});
