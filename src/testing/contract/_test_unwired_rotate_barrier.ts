import type { TestClient, TestUser } from "../_test_fixtures.ts";
import type { BasicScope } from "../../models/scope.ts";
import type { RefreshToken } from "../../models/token.ts";
import { MemoryClientService, MemoryUserService } from "../services.ts";
import { LockingTokenService } from "./_test_locking_token_service.ts";
import { runTokenRotationContractTests } from "./token-rotation.ts";

type TestRefreshToken = RefreshToken<TestClient, TestUser, BasicScope>;

const digest = (value: string): Promise<ArrayBuffer> =>
  crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));

class UnwiredGapTokenService extends LockingTokenService<TestClient, TestUser> {
  override async rotate(
    current: TestRefreshToken,
    next: TestRefreshToken,
  ): Promise<TestRefreshToken | undefined> {
    const successor = { ...next };
    await digest(successor.refreshToken);
    if (!(await this.revokeRotated(current))) return undefined;
    await digest(successor.accessToken);
    return await this.save(successor);
  }
}

runTokenRotationContractTests<TestClient, TestUser>({
  describeName:
    "a store that awaits between its claim and its insert, takes no family lock, and leaves the barrier unwired",
  makeServices: (barriers) => {
    const userService = new MemoryUserService<TestUser>();
    const clientService = new MemoryClientService<TestClient, TestUser>(
      userService,
    );
    const tokenService = new UnwiredGapTokenService(barriers);
    return { userService, clientService, tokenService };
  },
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(client),
});
