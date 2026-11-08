import { describe, expect, it } from "vitest";
import type { BasicScope } from "../../models/scope.ts";
import type { TestClient, TestUser } from "../_test_fixtures.ts";
import {
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  MemoryTokenService,
  MemoryUserService,
} from "../services.ts";
import { runSuiteInChild } from "./_test_child.ts";
import { lockingDeviceCodeExchangeServices } from "./_test_locking_device_code_exchange.ts";
import { runDeviceCodeExchangeContractTests } from "./device-code-exchange.ts";

const addUser = (
  service: unknown,
  user: TestUser,
  password: string,
): Promise<void> =>
  (service as MemoryUserService<TestUser>).add(user, password);
const addClient = (service: unknown, client: TestClient): Promise<void> =>
  (service as MemoryClientService<TestClient, TestUser>).add(client);

runDeviceCodeExchangeContractTests<TestClient, TestUser>({
  describeName:
    "MemoryTokenService paired with its device store satisfies the device code exchange contract",
  makeServices: () => {
    const userService = new MemoryUserService<TestUser>();
    const clientService = new MemoryClientService<TestClient, TestUser>(
      userService,
    );
    const deviceAuthorizationService = new MemoryDeviceAuthorizationService<
      TestClient,
      TestUser,
      BasicScope
    >({ clientService, userService });
    const tokenService = new MemoryTokenService<TestClient, TestUser>({
      clientService,
      userService,
      deviceAuthorizationService,
    });
    return {
      userService,
      clientService,
      deviceAuthorizationService,
      tokenService,
    };
  },
  addUser,
  addClient,
  exchangeAwaitsBarrier: false,
});

runDeviceCodeExchangeContractTests<TestClient, TestUser>({
  describeName:
    "a store that awaits between its claim and its insert satisfies the device code exchange contract when held there",
  makeServices: (barriers) => lockingDeviceCodeExchangeServices(barriers),
  addUser,
  addClient,
});

describe("runDeviceCodeExchangeContractTests against a save-then-revoke store", () => {
  it("fails the store whose losing exchanges each persist a token", async () => {
    const run = await runSuiteInChild(
      "src/testing/contract/_test_unsafe_device_code_exchange.ts",
    );
    const suite = "a store that saves the token and then revokes, with no lock";

    expect(
      run.exitCode,
      `the suite must fail this store:\n${run.output}`,
    ).not.toBe(0);
    expect(
      run.tests
        .filter(
          (test) => test.status === "failed" && test.fullName.startsWith(suite),
        )
        .map((test) => test.fullName.slice(suite.length + 1)),
    ).toStrictEqual([
      "persists exactly one token for 8 concurrent exchanges of one device code",
    ]);
  });
});
