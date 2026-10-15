import type { TestClient, TestUser } from "../_test_fixtures.ts";
import { MemoryClientService, MemoryUserService } from "../services.ts";
import { LockingTokenService } from "./_test_locking_token_service.ts";
import { runTokenRotationContractTests } from "./token-rotation.ts";

runTokenRotationContractTests<TestClient, TestUser>({
  describeName:
    "a store that awaits between its claim and its insert satisfies the rotation contract when held there",
  rotateAwaitsBarrier: true,
  makeServices: (barriers) => {
    const userService = new MemoryUserService<TestUser>();
    const clientService = new MemoryClientService<TestClient, TestUser>(
      userService,
    );
    const tokenService = new LockingTokenService<TestClient, TestUser>(
      barriers,
    );
    return { userService, clientService, tokenService };
  },
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(client),
});
