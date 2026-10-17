import { describe, expect, it } from "vitest";
import type { TestClient, TestUser } from "../_test_fixtures.ts";
import type { MemoryClientService, MemoryUserService } from "../services.ts";
import { runSuiteInChild } from "./_test_child.ts";
import { lockingCodeExchangeServices } from "./_test_locking_code_exchange.ts";
import { runCodeExchangeContractTests } from "./code-exchange.ts";

runCodeExchangeContractTests<TestClient, TestUser>({
  describeName:
    "a store that awaits between its claim and its insert satisfies the code exchange contract when held there",
  makeServices: (barriers) => lockingCodeExchangeServices(barriers),
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(client),
});

describe("runCodeExchangeContractTests with default options", () => {
  it("fails the stores that leave a replay a gap to land in", async () => {
    const run = await runSuiteInChild(
      "src/testing/contract/_test_unsafe_code_exchange.ts",
    );
    const failed = (suite: string) =>
      run.tests
        .filter(
          (test) => test.status === "failed" && test.fullName.startsWith(suite),
        )
        .map((test) => test.fullName.slice(suite.length + 1));
    const unwired =
      "a store that awaits between its claim and its insert, takes no code lock, and leaves the barrier unwired";
    const unlocked =
      "a store whose claim is visible before its insert and that takes no code lock";

    expect(
      run.exitCode,
      `the suite must fail these stores:\n${run.output}`,
    ).not.toBe(0);
    expect(failed(unwired).toSorted()).toStrictEqual(
      [
        "does not hold an exchange of another code behind a held one",
        "leaves no live token when the code is replayed through the grant while its exchange is in flight",
        "refuses a second exchange that starts while the first is held after its claim",
        "rolls the claim back when the insert fails after it",
      ].toSorted(),
    );
    for (const test of run.tests.filter(
      (test) => test.status === "failed" && test.fullName.startsWith(unwired),
    )) {
      expect(test.failureMessages.join("\n")).toContain(
        "exchangeCode settled without awaiting barriers.afterClaim",
      );
    }
    expect(failed(unlocked).toSorted()).toStrictEqual(
      [
        "leaves no live token when the code is replayed through the grant while its exchange is in flight",
        "rolls the claim back when the insert fails after it",
      ].toSorted(),
    );
    expect(
      run.tests.filter((test) => test.status === "skipped"),
      "a held case must fail, never skip, when the store is not opted out",
    ).toStrictEqual([]);
  });
});
