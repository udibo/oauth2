import { describe, expect, it } from "vitest";
import { FakeTime } from "../../_test_fake-time.ts";
import { rejection } from "../../_test_assert.ts";
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
class NoRotateTokenService extends MemoryTokenService<
  TestClient,
  TestUser,
  BasicScope
> {
  override generateRefreshToken(): Promise<string | undefined> {
    return Promise.resolve(undefined);
  }
}

/**
 * MemoryTokenService subclass that counts which revocation path the grant
 * takes, to pin rotation onto `revokeRotated` when a service implements it.
 */
class RotationAwareTokenService extends MemoryTokenService<
  TestClient,
  TestUser,
  BasicScope
> {
  rotatedCalls = 0;
  revokeCalls = 0;
  override revokeRotated(
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

type TestTokenService = MemoryTokenService<TestClient, TestUser, BasicScope>;

/**
 * The token service without `rotate`, so the grant claims and saves in two
 * calls. `beforeSave` runs before each `save` reaches the store.
 */
function twoStep(
  tokenService: TestTokenService,
  beforeSave?: () => Promise<void>,
): TestTokenService {
  return new Proxy(tokenService, {
    get(target, prop) {
      if (prop === "rotate") return undefined;
      if (prop === "save" && beforeSave) {
        return async (
          token: RefreshToken<TestClient, TestUser, BasicScope>,
        ) => {
          await beforeSave();
          return await target.save(token);
        };
      }
      const value = Reflect.get(target, prop, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

/**
 * MemoryTokenService subclass that counts the storage calls a refresh makes,
 * to pin rotation onto `rotate` when a service implements it.
 */
class CountingTokenService extends MemoryTokenService<
  TestClient,
  TestUser,
  BasicScope
> {
  calls: string[] = [];
  refuseRotation = false;
  override rotate(
    current: RefreshToken<TestClient, TestUser, BasicScope>,
    next: RefreshToken<TestClient, TestUser, BasicScope>,
  ): Promise<RefreshToken<TestClient, TestUser, BasicScope> | undefined> {
    this.calls.push("rotate");
    return this.refuseRotation
      ? Promise.resolve(undefined)
      : super.rotate(current, next);
  }
  override revokeRotated(
    token: RefreshToken<TestClient, TestUser, BasicScope>,
  ): Promise<boolean> {
    this.calls.push("revokeRotated");
    return super.revokeRotated(token);
  }
  override save(
    token: RefreshToken<TestClient, TestUser, BasicScope>,
  ): Promise<RefreshToken<TestClient, TestUser, BasicScope>>;
  override save(
    token: Token<TestClient, TestUser, BasicScope>,
  ): Promise<Token<TestClient, TestUser, BasicScope>>;
  override save(
    token:
      | Token<TestClient, TestUser, BasicScope>
      | RefreshToken<TestClient, TestUser, BasicScope>,
  ): Promise<
    | Token<TestClient, TestUser, BasicScope>
    | RefreshToken<TestClient, TestUser, BasicScope>
  > {
    this.calls.push("save");
    return super.save(token as RefreshToken<TestClient, TestUser, BasicScope>);
  }
}

describe("RefreshTokenGrant", () => {
  describe("grantType", () => {
    it("should return refresh_token", async () => {
      const { grant } = await createTestGrant();
      expect(grant.grantType).toBe("refresh_token");
    });
  });

  describe("constructor", () => {
    it("should allow refresh tokens", async () => {
      const { grant } = await createTestGrant();
      expect(grant.allowRefreshToken).toBe(true);
    });
  });

  describe("token", () => {
    it("should throw InvalidRequestError when refresh-token missing", async () => {
      const { grant } = await createTestGrant();

      const request = tokenRequest({ grant_type: "refresh_token" });

      await rejection(
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

      await rejection(
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

      await rejection(
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

      await rejection(
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

      expect(newToken.accessToken !== "old-access").toBe(true);
      expect(newToken.client.id).toBe(testClient.id);
      expect(newToken.user?.id).toBe(testUser.id);
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

      expect(newToken.scope?.toString()).toBe("read write");
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

      expect(newToken.scope?.toString()).toBe("read write");
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

      await rejection(
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

      expect(newToken.scope?.toString()).toBe("read write");
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
      expect(oldRefresh).toBe(undefined);
    });

    it("without rotate, claims through revokeRotated when implemented, never revoke", async () => {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new RotationAwareTokenService({
        clientService,
        userService,
      });
      await userService.add(testUser, "password");
      await clientService.add(testClient, "secret", testUser.id);
      const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
        resolve: () => ({
          clientService,
          tokenService: twoStep(tokenService),
        }),
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

      expect(tokenService.rotatedCalls).toBe(1);
      expect(tokenService.revokeCalls).toBe(0);
      expect(await tokenService.getRefreshToken("refresh-rotated")).toBe(
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
      expect(savedToken?.accessToken).toBe(newToken.accessToken);
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

      expect(typeof newToken.accessToken).toBe("string");
      expect(newToken.accessToken !== "old-access").toBe(true);
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

      expect(newToken.accessToken !== "old-access").toBe(true);
      expect(newToken.refreshToken).toBe("existing-refresh-token");
      expect(newToken.refreshTokenExpiresAt?.getTime()).toBe(
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

      expect(newToken.refreshToken).toBe("no-expire-refresh");
      expect(newToken.refreshTokenExpiresAt).toBe(undefined);
    });
  });

  describe("atomic rotation", () => {
    async function seed(
      userService: MemoryUserService<TestUser>,
      clientService: MemoryClientService<TestClient, TestUser>,
    ) {
      await userService.add(testUser, "password");
      await clientService.add(testClient, "secret", testUser.id);
      const client = (await clientService.get("client-1"))!;
      const parent: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: crypto.randomUUID(),
        accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
        refreshToken: crypto.randomUUID(),
        refreshTokenExpiresAt: new Date(Date.now() + 86_400_000),
        client,
        user: testUser,
        familyId: crypto.randomUUID(),
      };
      return { client, parent };
    }

    async function countingGrant() {
      const userService = new MemoryUserService<TestUser>();
      const clientService = new MemoryClientService<TestClient, TestUser>(
        userService,
      );
      const tokenService = new CountingTokenService({
        clientService,
        userService,
      });
      const { client, parent } = await seed(userService, clientService);
      await tokenService.save(parent);
      tokenService.calls = [];
      const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
        resolve: () => ({ clientService, tokenService }),
      });
      return { grant, tokenService, client, parent };
    }

    it("rotates through rotate when the store implements it, never a claim and a save", async () => {
      const { grant, tokenService, client, parent } = await countingGrant();

      const rotated = await exchangeToken(
        grant,
        refreshRequest(parent.refreshToken),
        client,
      );

      expect(tokenService.calls).toStrictEqual(["rotate"]);
      expect(rotated.familyId).toBe(parent.familyId);
      expect(
        (await tokenService.getRefreshToken(rotated.refreshToken))?.familyId,
      ).toBe(parent.familyId);
      expect(await tokenService.getRefreshToken(parent.refreshToken)).toBe(
        undefined,
      );
    });

    it("answers invalid_grant when rotate refuses the claim", async () => {
      const { grant, tokenService, client, parent } = await countingGrant();
      tokenService.refuseRotation = true;

      await rejection(
        () => exchangeToken(grant, refreshRequest(parent.refreshToken), client),
        InvalidGrantError,
        "refresh_token was already consumed",
      );
      expect(tokenService.calls).toStrictEqual(["rotate"]);
    });

    it("without rotate, a replay between the claim and the save is taken for theft and signs the person out", async () => {
      const userService = new MemoryUserService<TestUser>();
      const clientService = new MemoryClientService<TestClient, TestUser>(
        userService,
      );
      const tokenService = new MemoryTokenService<
        TestClient,
        TestUser,
        BasicScope
      >({ clientService, userService });
      const { client, parent } = await seed(userService, clientService);
      await tokenService.save(parent);
      const claimed = Promise.withResolvers<void>();
      const resume = Promise.withResolvers<void>();
      const reuseEvents: string[] = [];
      const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
        resolve: () => ({
          clientService,
          tokenService: twoStep(tokenService, async () => {
            claimed.resolve();
            await resume.promise;
          }),
        }),
        onTokenReuse: (event) => {
          reuseEvents.push(event.familyId);
        },
      });

      const refreshing = exchangeToken(
        grant,
        refreshRequest(parent.refreshToken),
        client,
      );
      await claimed.promise;
      await rejection(
        () => exchangeToken(grant, refreshRequest(parent.refreshToken), client),
        InvalidGrantError,
      );
      resume.resolve();
      const successor = await refreshing;

      expect(
        reuseEvents,
        "the documented two-step gap: a replay there finds no live successor",
      ).toStrictEqual([parent.familyId]);
      expect(
        await tokenService.getRefreshToken(successor.refreshToken),
        "the store keeps the revoked family revoked, so the refresh that " +
          "claimed the parent receives a dead successor",
      ).toBe(undefined);
      expect(await tokenService.getToken(successor.accessToken)).toBe(
        undefined,
      );
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
      expect(rotated.familyId).toBe(original.familyId);

      const stored = await tokenService.getRefreshToken(rotated.refreshToken);
      expect(stored?.familyId).toBe(original.familyId);
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

      await rejection(
        () =>
          exchangeToken(grant, refreshRequest(original.refreshToken), client),
        InvalidGrantError,
      );
      expect(reuseEvents.length).toBe(1);
      expect(reuseEvents[0].familyId).toBe(original.familyId);
      expect(reuseEvents[0].familyRevoked).toBe(true);

      expect(await tokenService.getRefreshToken(rotated.refreshToken)).toBe(
        undefined,
      );
      await rejection(
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

      const error = await rejection(
        () =>
          exchangeToken(grant, refreshRequest(original.refreshToken), client),
        InvalidGrantError,
      );
      expect(error.status).toBe(400);
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
        generateAccessToken:
          tokenService.generateAccessToken.bind(tokenService),
        generateRefreshToken:
          tokenService.generateRefreshToken.bind(tokenService),
        accessTokenExpiresAt:
          tokenService.accessTokenExpiresAt.bind(tokenService),
        refreshTokenExpiresAt:
          tokenService.refreshTokenExpiresAt.bind(tokenService),
        getToken: tokenService.getToken.bind(tokenService),
        getRefreshToken: tokenService.getRefreshToken.bind(tokenService),
        save: tokenService.save.bind(tokenService),
        revoke: tokenService.revoke.bind(tokenService),
        revokeCode: tokenService.revokeCode.bind(tokenService),
      } as typeof tokenService;
      const bareGrant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>(
        {
          resolve: () => ({ clientService, tokenService: bare }),
        },
      );

      await rejection(
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

  describe("replay grace", () => {
    async function graceGrant(replayGraceSeconds?: number) {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new MemoryTokenService<
        TestClient,
        TestUser,
        BasicScope
      >({ clientService, userService });
      await userService.add(testUser, "password");
      await clientService.add(testClient, "secret", testUser.id);
      const reuseEvents: string[] = [];
      const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
        resolve: () => ({ clientService, tokenService }),
        onTokenReuse: (event) => {
          reuseEvents.push(event.familyId);
        },
        ...(replayGraceSeconds === undefined ? {} : { replayGraceSeconds }),
      });
      const client = (await clientService.get("client-1"))!;
      const original: RefreshToken<TestClient, TestUser, BasicScope> = {
        accessToken: crypto.randomUUID(),
        accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
        refreshToken: crypto.randomUUID(),
        refreshTokenExpiresAt: new Date(Date.now() + 86_400_000),
        client,
        user: testUser,
        familyId: crypto.randomUUID(),
      };
      await tokenService.save(original);
      const rotated = await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      );
      return { grant, tokenService, client, original, rotated, reuseEvents };
    }

    it("answers invalid_grant without revoking the family for a replay inside the window", async () => {
      const { grant, tokenService, client, original, rotated, reuseEvents } =
        await graceGrant(30);

      await rejection(
        () =>
          exchangeToken(grant, refreshRequest(original.refreshToken), client),
        InvalidGrantError,
      );

      expect(reuseEvents).toStrictEqual([]);
      expect(
        await tokenService.getRefreshToken(rotated.refreshToken),
        "the successor must survive a replay inside the grace",
      ).not.toBe(undefined);
      const next = await exchangeToken(
        grant,
        refreshRequest(rotated.refreshToken),
        client,
      );
      expect(next.familyId).toBe(original.familyId);
    });

    it("revokes the family as before once the window has passed", async () => {
      using time = new FakeTime();
      const { grant, tokenService, client, original, rotated, reuseEvents } =
        await graceGrant(30);
      time.tick(30_001);

      await rejection(
        () =>
          exchangeToken(grant, refreshRequest(original.refreshToken), client),
        InvalidGrantError,
      );

      expect(reuseEvents).toStrictEqual([original.familyId]);
      expect(await tokenService.getRefreshToken(rotated.refreshToken)).toBe(
        undefined,
      );
    });

    it("treats a replay inside the window as reuse when no successor is live", async () => {
      const { grant, tokenService, client, original, rotated, reuseEvents } =
        await graceGrant(30);
      await tokenService.revoke(rotated);

      await rejection(
        () =>
          exchangeToken(grant, refreshRequest(original.refreshToken), client),
        InvalidGrantError,
      );

      expect(reuseEvents).toStrictEqual([original.familyId]);
    });

    it("treats a token revoked other than by rotation as reuse inside the window", async () => {
      const { grant, tokenService, client, rotated, reuseEvents } =
        await graceGrant(30);
      const sibling: RefreshToken<TestClient, TestUser, BasicScope> = {
        ...rotated,
        accessToken: crypto.randomUUID(),
        refreshToken: crypto.randomUUID(),
      };
      await tokenService.save(sibling);
      await tokenService.revoke(sibling);

      await rejection(
        () =>
          exchangeToken(grant, refreshRequest(sibling.refreshToken), client),
        InvalidGrantError,
      );

      expect(reuseEvents).toStrictEqual([rotated.familyId]);
    });

    it("is off by default, so a replay right after rotation revokes the family", async () => {
      const { grant, tokenService, client, original, rotated, reuseEvents } =
        await graceGrant();

      await rejection(
        () =>
          exchangeToken(grant, refreshRequest(original.refreshToken), client),
        InvalidGrantError,
      );

      expect(reuseEvents).toStrictEqual([original.familyId]);
      expect(await tokenService.getRefreshToken(rotated.refreshToken)).toBe(
        undefined,
      );
    });

    it("keeps the family of a thief who rotated first when the client replays inside the window", async () => {
      const { grant, tokenService, client, rotated, reuseEvents } =
        await graceGrant(30);
      const stolen = rotated.refreshToken;
      const thiefToken = await exchangeToken(
        grant,
        refreshRequest(stolen),
        client,
      );

      await rejection(
        () => exchangeToken(grant, refreshRequest(stolen), client),
        InvalidGrantError,
      );

      expect(reuseEvents).toStrictEqual([]);
      const thiefNext = await exchangeToken(
        grant,
        refreshRequest(thiefToken.refreshToken),
        client,
      );
      expect(thiefNext.familyId).toBe(rotated.familyId);
      expect(
        await tokenService.getRefreshToken(thiefNext.refreshToken),
      ).not.toBe(undefined);
    });

    it("refuses a grace that is not a non-negative number of seconds", () => {
      for (const replayGraceSeconds of [-1, Number.NaN, Infinity]) {
        expect(
          () =>
            new RefreshTokenGrant({
              resolve: () => {
                throw new Error("unused");
              },
              replayGraceSeconds,
            }),
        ).toThrow(RangeError);
      }
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
      const TokenService =
        options.rotates === false ? NoRotateTokenService : MemoryTokenService;
      const tokenService = new TokenService<TestClient, TestUser, BasicScope>({
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

      const rotated = (await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      )) as RefreshToken<TestClient, TestUser, BasicScope>;

      expect(rotated.refreshTokenExpiresAt?.getTime()).toBe(
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

      const rotated = (await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      )) as RefreshToken<TestClient, TestUser, BasicScope>;

      expect(rotated.refreshTokenExpiresAt?.getTime()).toBe(
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

      await rejection(
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
        current = (await exchangeToken(
          grant,
          refreshRequest(current.refreshToken),
          client,
        )) as RefreshToken<TestClient, TestUser, BasicScope>;
        expect(current.familyCreatedAt?.getTime()).toBe(START.getTime());
      }

      expect(current.refreshTokenExpiresAt?.getTime()).toBe(
        START.getTime() + 30 * DAY,
      );

      time.tick(6 * DAY);
      await rejection(
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

      const rotated = (await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      )) as RefreshToken<TestClient, TestUser, BasicScope>;

      expect(rotated.refreshTokenExpiresAt?.getTime()).toBe(
        START.getTime() + 7 * DAY,
      );
    });

    it("leaves a record without a family anchor uncapped", async () => {
      using _time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 30 * 24 * 60 * 60,
      });
      const original = await seedFamily(tokenService, client, undefined);

      const rotated = (await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      )) as RefreshToken<TestClient, TestUser, BasicScope>;

      expect(rotated.refreshTokenExpiresAt?.getTime()).toBe(
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

      expect(
        rotated.accessTokenExpiresAt?.getTime(),
        "an access token minted just under the ceiling must not outlive it",
      ).toBe(familyCreatedAt.getTime() + 30 * DAY);
    });

    it("clamps a new family's access token when the cap is shorter than the access lifetime", async () => {
      using _time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 600,
      });

      const issued = (await grant.generateToken(
        client,
        testUser,
        undefined,
        tokenService,
      )) as RefreshToken<TestClient, TestUser, BasicScope>;

      expect(issued.accessTokenExpiresAt?.getTime()).toBe(
        START.getTime() + 600_000,
      );
      expect(issued.refreshTokenExpiresAt?.getTime()).toBe(
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

      const next = (await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      )) as RefreshToken<TestClient, TestUser, BasicScope>;

      expect(next.refreshToken).toBe(original.refreshToken);
      expect(next.refreshTokenExpiresAt?.getTime()).toBe(
        familyCreatedAt.getTime() + 30 * DAY,
      );
      expect(next.accessTokenExpiresAt?.getTime()).toBe(
        familyCreatedAt.getTime() + 30 * DAY,
      );
    });

    it("anchors an anchorless record's rotation, capping the family from there", async () => {
      using time = new FakeTime(START);
      const { grant, client, tokenService } = await createCappedGrant({
        refreshTokenMaxLifetime: 30 * 24 * 60 * 60,
      });
      const original = await seedFamily(tokenService, client, undefined);

      const rotated = (await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      )) as RefreshToken<TestClient, TestUser, BasicScope>;

      expect(rotated.familyCreatedAt?.getTime()).toBe(START.getTime());
      const stored = await tokenService.getRefreshToken(rotated.refreshToken);
      expect(stored?.familyCreatedAt?.getTime()).toBe(START.getTime());

      time.tick(31 * DAY);
      await rejection(
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

      const rotated = (await exchangeToken(
        grant,
        refreshRequest(original.refreshToken),
        client,
      )) as RefreshToken<TestClient, TestUser, BasicScope>;

      expect(rotated.refreshTokenExpiresAt?.getTime()).toBe(
        START.getTime() + 5 * DAY,
      );
    });
  });
});
