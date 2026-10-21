import type { AuthorizationCode } from "../../models/authorization-code.ts";
import type { BasicScope } from "../../models/scope.ts";
import type { Token } from "../../models/token.ts";
import type { TestClient, TestUser } from "../_test_fixtures.ts";
import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
} from "../services.ts";
import { runCodeExchangeContractTests } from "./code-exchange.ts";

type TestToken = Token<TestClient, TestUser, BasicScope>;

class UnboundTokenService extends MemoryTokenService<TestClient, TestUser> {
  override revokeCode(code: string, client?: TestClient): Promise<boolean> {
    return super.revokeCode(code, client);
  }
}

function makeServices() {
  const userService = new MemoryUserService<TestUser>();
  const clientService = new MemoryClientService<TestClient, TestUser>(
    userService,
  );
  const authorizationCodeService = new MemoryAuthorizationCodeService<
    TestClient,
    TestUser
  >({ clientService, userService });
  const memory = new UnboundTokenService({
    clientService,
    userService,
    authorizationCodeService,
  });
  const exchangeCode = memory.exchangeCode!;
  const tokenService = new Proxy(memory, {
    get(target, prop) {
      if (prop === "exchangeCode") {
        return async (
          authorizationCode: AuthorizationCode<TestClient, TestUser>,
          token: TestToken,
        ) =>
          exchangeCode(authorizationCode, {
            ...token,
            codeVerifierHash: undefined,
          });
      }
      const value = Reflect.get(target, prop, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return {
    userService,
    clientService,
    authorizationCodeService,
    tokenService,
  };
}

const addUser = (
  service: unknown,
  user: TestUser,
  password: string,
): Promise<void> =>
  (service as MemoryUserService<TestUser>).add(user, password);
const addClient = (service: unknown, client: TestClient): Promise<void> =>
  (service as MemoryClientService<TestClient, TestUser>).add(client);

runCodeExchangeContractTests<TestClient, TestUser>({
  describeName: "a paired store that drops the verifier",
  exchangeAwaitsBarrier: false,
  makeServices,
  addUser,
  addClient,
});

runCodeExchangeContractTests<TestClient, TestUser>({
  describeName: "a paired store that drops the verifier, opted out",
  exchangeAwaitsBarrier: false,
  revokeCodeChecksVerifier: false,
  makeServices,
  addUser,
  addClient,
});
