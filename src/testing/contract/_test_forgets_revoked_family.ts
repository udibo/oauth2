import type { TestClient, TestUser } from "../_test_fixtures.ts";
import { MemoryClientService, MemoryUserService } from "../services.ts";
import { LockingTokenService } from "./_test_locking_token_service.ts";
import { runTokenServiceContractTests } from "./token.ts";

/**
 * A store that serializes `revokeFamily` on a family lock instead of recording
 * the revoked family, with `rotate` removed, so the refresh grant would claim
 * and save in two calls.
 */
function forgetsRevokedFamily(): LockingTokenService<TestClient, TestUser> {
  return new Proxy(
    new LockingTokenService<TestClient, TestUser>({
      afterClaim: () => Promise.resolve(),
    }),
    {
      get(target, prop) {
        if (prop === "rotate") return undefined;
        const value = Reflect.get(target, prop, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    },
  );
}

runTokenServiceContractTests<TestClient, TestUser>({
  describeName:
    "a store without rotate whose revokeFamily keeps no record of the revoked family",
  makeServices: () => {
    const userService = new MemoryUserService<TestUser>();
    const clientService = new MemoryClientService<TestClient, TestUser>(
      userService,
    );
    return { userService, clientService, tokenService: forgetsRevokedFamily() };
  },
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(client),
});
