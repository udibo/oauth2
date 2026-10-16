import { assert, describe, expect, it } from "vitest";
import { rejection } from "../_test_assert.ts";
import { PasswordIdentityService } from "../identity/password.ts";
import type { RefreshToken } from "../models/token.ts";
import type { TestClient, TestUser } from "./_test_fixtures.ts";
import {
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
} from "./services.ts";

describe("MemoryUserService credential accessors", () => {
  const user = { id: "u1", username: "alice" };

  it("findByUsername resolves the user without a password check", async () => {
    const service = new MemoryUserService();
    await service.add(user, "hunter2hunter2");

    expect((await service.findByUsername("alice"))?.id).toStrictEqual("u1");
    expect(await service.findByUsername("ghost")).toStrictEqual(undefined);
  });

  it("getCredential returns a credential verifiable by the identity hasher", async () => {
    const service = new MemoryUserService();
    await service.add(user, "hunter2hunter2");

    const credential = await service.getCredential("u1");
    assert.exists(credential);
    const passwords = new PasswordIdentityService();
    expect(await passwords.verify("hunter2hunter2", credential)).toStrictEqual(
      true,
    );
    expect(await service.getCredential("ghost")).toStrictEqual(undefined);
  });

  it("setCredential replaces the stored credential", async () => {
    const service = new MemoryUserService();
    await service.add(user, "old-password-1");

    const passwords = new PasswordIdentityService();
    await service.setCredential("u1", await passwords.hash("new-password-1"));

    expect(
      await service.getAuthenticated("alice", "old-password-1"),
    ).toStrictEqual(undefined);
    expect(
      (await service.getAuthenticated("alice", "new-password-1"))?.id,
    ).toStrictEqual("u1");
  });

  it("setCredential throws for an unknown user", async () => {
    const service = new MemoryUserService();
    const passwords = new PasswordIdentityService();
    await rejection(
      async () => service.setCredential("ghost", await passwords.hash("x")),
      Error,
      "does not exist",
    );
  });
});

describe("MemoryTokenService.isWithinReplayGrace", () => {
  async function tokenStore() {
    const userService = new MemoryUserService<TestUser>();
    const clientService = new MemoryClientService<TestClient, TestUser>(
      userService,
    );
    const tokenService = new MemoryTokenService<TestClient, TestUser>({
      clientService,
      userService,
    });
    const user: TestUser = { id: "u1", username: "alice" };
    const client: TestClient = { id: "client-1" };
    await userService.add(user, "hunter2hunter2");
    await clientService.add(client);
    const token: RefreshToken<TestClient, TestUser> = {
      accessToken: crypto.randomUUID(),
      accessTokenExpiresAt: new Date(Date.now() + 60_000),
      refreshToken: crypto.randomUUID(),
      refreshTokenExpiresAt: new Date(Date.now() + 600_000),
      familyId: crypto.randomUUID(),
      client,
      user,
    };
    await tokenService.save(token);
    return { tokenService, token };
  }

  it("answers from the rotation time it recorded, not the one on the record passed in", async () => {
    const { tokenService, token } = await tokenStore();
    await tokenService.revoke(token);

    expect(
      await tokenService.isWithinReplayGrace(
        { ...token, rotatedAt: new Date() },
        60,
      ),
      "a token revoked other than by rotation is never inside the grace",
    ).toBe(false);
  });

  it("answers false for a refresh token it holds no tombstone for", async () => {
    const { tokenService, token } = await tokenStore();

    expect(
      await tokenService.isWithinReplayGrace(
        { ...token, rotatedAt: new Date() },
        60,
      ),
    ).toBe(false);
  });
});
