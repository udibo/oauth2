import type { TestClient, TestUser } from "../_test_fixtures.ts";
import type { MemoryClientService, MemoryUserService } from "../services.ts";
import { lockingCodeExchangeServices } from "./_test_locking_code_exchange.ts";
import { runCodeExchangeContractTests } from "./code-exchange.ts";

const addUser = (
  service: unknown,
  user: TestUser,
  password: string,
): Promise<void> =>
  (service as MemoryUserService<TestUser>).add(user, password);
const addClient = (service: unknown, client: TestClient): Promise<void> =>
  (service as MemoryClientService<TestClient, TestUser>).add(client);

runCodeExchangeContractTests<TestClient, TestUser>({
  describeName:
    "a store that awaits between its claim and its insert, takes no code lock, and leaves the barrier unwired",
  makeServices: (barriers) =>
    lockingCodeExchangeServices(barriers, {
      awaitsBarrier: false,
      locksCodes: false,
    }),
  addUser,
  addClient,
});

runCodeExchangeContractTests<TestClient, TestUser>({
  describeName:
    "a store whose claim is visible before its insert and that takes no code lock",
  makeServices: (barriers) =>
    lockingCodeExchangeServices(barriers, { locksCodes: false }),
  addUser,
  addClient,
});
