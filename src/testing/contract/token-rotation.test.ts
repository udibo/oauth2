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

let serial = 0;
runTokenRotationContractTests<TestClient, TestUser>({
  describeName:
    "a store with fam_<n> family ids satisfies the rotation contract with makeFamilyId",
  makeServices: (barriers) => {
    const userService = new MemoryUserService<TestUser>();
    const clientService = new MemoryClientService<TestClient, TestUser>(
      userService,
    );
    const tokenService = new LockingTokenService<TestClient, TestUser>(
      barriers,
      { familyIdFormat: /^fam_[0-9]+$/ },
    );
    return { userService, clientService, tokenService };
  },
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(client),
  makeFamilyId: () => `fam_${++serial}`,
});

describe("runTokenRotationContractTests with makeFamilyId", () => {
  it("fails a fam_<n> store whose rotate takes no family lock", async () => {
    const run = await runSuiteInChild(
      "src/testing/contract/_test_serial_family_rotation.ts",
    );
    const failed = run.tests.filter((test) => test.status === "failed");
    const unlocked = [
      "leaves no live member when the family is revoked while a rotation is in flight",
      "answers a replay that arrives while a rotation is held after its claim with invalid_grant, without revoking the family",
      "leaves the parent live and persists nothing when the successor cannot be persisted",
      "rolls the claim back when the insert fails after it",
    ];

    expect(
      run.exitCode,
      `the suite must fail this store:\n${run.output}`,
    ).not.toBe(0);
    expect(
      failed.map((test) =>
        unlocked.find((name) => test.fullName.endsWith(name)),
      ),
    ).toStrictEqual(unlocked);
    expect(failed[0].failureMessages.join("\n")).toContain(
      "revokeFamily must wait for a rotation holding the family",
    );
    expect(
      failed.flatMap((test) => test.failureMessages).join("\n"),
      "every failure must come from the store's behavior, not its family ids",
    ).not.toContain("invalid input syntax for family id");
  });
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
