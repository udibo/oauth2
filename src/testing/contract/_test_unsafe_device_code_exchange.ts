import type { TestClient, TestUser } from "../_test_fixtures.ts";
import type { MemoryClientService, MemoryUserService } from "../services.ts";
import { lockingDeviceCodeExchangeServices } from "./_test_locking_device_code_exchange.ts";
import { runDeviceCodeExchangeContractTests } from "./device-code-exchange.ts";

runDeviceCodeExchangeContractTests<TestClient, TestUser>({
  describeName: "a store that saves the token and then revokes, with no lock",
  makeServices: (barriers) =>
    lockingDeviceCodeExchangeServices(barriers, { locksDeviceCodes: false }),
  addUser: (service, user, password) =>
    (service as MemoryUserService<TestUser>).add(user, password),
  addClient: (service, client) =>
    (service as MemoryClientService<TestClient, TestUser>).add(client),
  exchangeAwaitsBarrier: false,
});
