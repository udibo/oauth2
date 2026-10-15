import { describe, expect, it } from "vitest";
import { runSuiteInChild } from "./_test_child.ts";
import type { TestClient, TestUser } from "../_test_fixtures.ts";
import { MemoryClientService, MemoryUserService } from "../services.ts";
import { LockingTokenService } from "./_test_locking_token_service.ts";
import { runTokenRotationContractTests } from "./token-rotation.ts";

runTokenRotationContractTests<TestClient, TestUser>({
  describeName:
    "a store that awaits between its claim and its insert satisfies the rotation contract when held there",
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

describe("runTokenRotationContractTests with default options", () => {
  it("fails every held case for a store whose rotate never reaches the barrier", async () => {
    const run = await runSuiteInChild(
      "src/testing/contract/_test_unwired_rotate_barrier.ts",
    );
    const failed = run.tests.filter((test) => test.status === "failed");
    const held = [
      "leaves no live member when the family is revoked while a rotation is in flight",
      "refuses a second rotation that starts while the first is held after its claim",
      "answers a replay that arrives while a rotation is held after its claim with invalid_grant, without revoking the family",
      "does not hold a rotation in another family behind a held one",
      "rolls the claim back when the insert fails after it",
    ];

    expect(
      run.exitCode,
      `the suite must fail this store:\n${run.output}`,
    ).not.toBe(0);
    expect(
      failed.map((test) => held.find((name) => test.fullName.endsWith(name))),
    ).toStrictEqual(held);
    for (const test of failed) {
      expect(test.failureMessages.join("\n")).toContain(
        "rotate settled without awaiting barriers.afterClaim",
      );
    }
    expect(
      run.tests.filter((test) => test.status === "skipped"),
      "a held case must fail, never skip, when the store is not opted out",
    ).toStrictEqual([]);
  });
});
