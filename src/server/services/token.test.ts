import { describe, expect, it } from "vitest";
import { thrown } from "../../_test_assert.ts";
import type { RefreshToken, Token } from "../../models/token.ts";
import type { BasicScope } from "../../models/scope.ts";
import type { TestClient, TestUser } from "../../testing/_test_fixtures.ts";
import {
  AbstractTokenService,
  type AbstractTokenServiceOptions,
} from "./token.ts";

class StubTokenService extends AbstractTokenService<
  TestClient,
  TestUser,
  BasicScope
> {
  getToken(): Promise<Token<TestClient, TestUser, BasicScope> | undefined> {
    return Promise.resolve(undefined);
  }
  getRefreshToken(): Promise<
    RefreshToken<TestClient, TestUser, BasicScope> | undefined
  > {
    return Promise.resolve(undefined);
  }
  save(
    token: RefreshToken<TestClient, TestUser, BasicScope>,
  ): Promise<RefreshToken<TestClient, TestUser, BasicScope>>;
  save(
    token: Token<TestClient, TestUser, BasicScope>,
  ): Promise<Token<TestClient, TestUser, BasicScope>>;
  save(
    token:
      | Token<TestClient, TestUser, BasicScope>
      | RefreshToken<TestClient, TestUser, BasicScope>,
  ): Promise<
    | Token<TestClient, TestUser, BasicScope>
    | RefreshToken<TestClient, TestUser, BasicScope>
  > {
    return Promise.resolve(token);
  }
  revoke(): Promise<boolean> {
    return Promise.resolve(true);
  }
  revokeCode(): Promise<boolean> {
    return Promise.resolve(true);
  }
}

const testClient: TestClient = { id: "client-1" };
const testUser: TestUser = { id: "user-1", username: "testuser" };

function createService(
  options?: AbstractTokenServiceOptions<TestClient, TestUser>,
): StubTokenService {
  return new StubTokenService(options);
}

describe("AbstractTokenService", () => {
  describe("refreshTokenMaxLifetime", () => {
    it("rejects a sliding lifetime longer than the absolute cap", () => {
      thrown(
        () =>
          createService({
            refreshTokenLifetime: 1209600,
            refreshTokenMaxLifetime: 86400,
          }),
        TypeError,
        "refreshTokenLifetime must not exceed refreshTokenMaxLifetime",
      );
    });

    it("rejects the default sliding lifetime against a shorter cap", () => {
      thrown(
        () => createService({ refreshTokenMaxLifetime: 86400 }),
        TypeError,
      );
    });

    it("accepts a sliding lifetime equal to the cap", () => {
      const service = createService({
        refreshTokenLifetime: 86400,
        refreshTokenMaxLifetime: 86400,
      });
      expect(service.refreshTokenMaxLifetime).toBe(86400);
    });

    it("is unset by default", () => {
      expect(createService().refreshTokenMaxLifetime).toBe(undefined);
    });
  });

  describe("refreshTokenFamilyExpiresAt", () => {
    it("caps the family at its anchor plus the maximum lifetime", async () => {
      const service = createService({
        refreshTokenLifetime: 86400,
        refreshTokenMaxLifetime: 2592000,
      });
      const familyCreatedAt = new Date("2026-01-01T00:00:00.000Z");

      const expiresAt = await service.refreshTokenFamilyExpiresAt(
        testClient,
        testUser,
        familyCreatedAt,
      );

      expect(expiresAt?.getTime()).toBe(
        familyCreatedAt.getTime() + 2592000 * 1000,
      );
    });

    it("leaves the family uncapped when no maximum is configured", async () => {
      const service = createService();

      expect(
        await service.refreshTokenFamilyExpiresAt(
          testClient,
          testUser,
          new Date(),
        ),
      ).toBe(undefined);
    });
  });
});
