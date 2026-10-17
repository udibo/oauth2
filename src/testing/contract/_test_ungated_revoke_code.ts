import type { TestClient, TestUser } from "../_test_fixtures.ts";
import {
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
} from "../services.ts";
import { runTokenServiceContractTests } from "./token.ts";

class UngatedTokenService extends MemoryTokenService<TestClient, TestUser> {
  override revokeCode(code: string): Promise<boolean> {
    return super.revokeCode(code);
  }
}

function makeServices(): {
  userService: MemoryUserService<TestUser>;
  clientService: MemoryClientService<TestClient, TestUser>;
  tokenService: UngatedTokenService;
} {
  const userService = new MemoryUserService<TestUser>();
  const clientService = new MemoryClientService<TestClient, TestUser>(
    userService,
  );
  const tokenService = new UngatedTokenService({ clientService, userService });
  return { userService, clientService, tokenService };
}

const addUser = (
  service: unknown,
  user: TestUser,
  password: string,
): Promise<void> =>
  (service as MemoryUserService<TestUser>).add(user, password);
const addClient = (
  service: unknown,
  client: TestClient,
  secret?: string,
  ownerUserId?: string,
): Promise<void> =>
  (service as MemoryClientService<TestClient, TestUser>).add(
    client,
    secret,
    ownerUserId,
  );

runTokenServiceContractTests<TestClient, TestUser>({
  describeName: "a token service whose revokeCode ignores the client",
  makeServices,
  addUser,
  addClient,
});

runTokenServiceContractTests<TestClient, TestUser>({
  describeName:
    "a token service whose revokeCode ignores the client, opted out",
  revokeCodeChecksClient: false,
  makeServices,
  addUser,
  addClient,
});
