import { describe, expect, it } from "vitest";
import type { TestClient, TestUser } from "../_test_fixtures.ts";
import type { BasicScope } from "../../models/scope.ts";
import type { RefreshToken } from "../../models/token.ts";
import {
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
} from "../services.ts";
import { runSuiteInChild } from "./_test_child.ts";
import { runTokenServiceContractTests } from "./token.ts";

const FORGETS_REVOKED_FAMILY =
  "a store without rotate whose revokeFamily keeps no record of the revoked family";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SERIAL_FAMILY = /^fam_[0-9]+$/;

type TestRefreshToken = RefreshToken<TestClient, TestUser, BasicScope>;

/**
 * Wraps the memory store in the checks a typed database column and a fixed
 * scope vocabulary would apply: an argument outside them throws or is refused.
 */
function typedStore(
  tokenService: MemoryTokenService<TestClient, TestUser>,
  familyId: RegExp,
  scopes: readonly string[],
): MemoryTokenService<TestClient, TestUser> {
  const checkFamily = (value: string | undefined): void => {
    if (value !== undefined && !familyId.test(value)) {
      throw new TypeError(`invalid input syntax for family id: "${value}"`);
    }
  };
  const typed: Partial<MemoryTokenService<TestClient, TestUser>> = {
    acceptedScope: (client, user, scope) =>
      scope && ![...scope].every((value) => scopes.includes(value))
        ? Promise.resolve(false)
        : tokenService.acceptedScope(client, user, scope),
    save: ((token: TestRefreshToken) => {
      checkFamily(token.familyId);
      return tokenService.save(token);
    }) as MemoryTokenService<TestClient, TestUser>["save"],
    rotate: (current, next) => {
      checkFamily(current.familyId);
      checkFamily(next.familyId);
      return tokenService.rotate(current, next);
    },
    revokeFamily: (id) => {
      checkFamily(id);
      return tokenService.revokeFamily(id);
    },
    hasLiveRefreshToken: (id) => {
      checkFamily(id);
      return tokenService.hasLiveRefreshToken(id);
    },
  };
  return new Proxy(tokenService, {
    get(target, prop) {
      if (Object.hasOwn(typed, prop)) {
        return typed[prop as keyof typeof typed];
      }
      const value = Reflect.get(target, prop, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function typedServices(familyId: RegExp, scopes: readonly string[]) {
  const userService = new MemoryUserService<TestUser>();
  const clientService = new MemoryClientService<TestClient, TestUser>(
    userService,
  );
  const tokenService = typedStore(
    new MemoryTokenService<TestClient, TestUser>({
      clientService,
      userService,
    }),
    familyId,
    scopes,
  );
  return { userService, clientService, tokenService };
}

runTokenServiceContractTests<TestClient, TestUser>({
  describeName:
    "a store with uuid family ids and a fixed scope vocabulary satisfies the contract",
  makeServices: () => typedServices(UUID, ["openid", "profile"]),
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(client),
  supportedScope: "openid",
});

let serial = 0;
runTokenServiceContractTests<TestClient, TestUser>({
  describeName:
    "a store with its own family id format satisfies the contract with makeFamilyId",
  makeServices: () => typedServices(SERIAL_FAMILY, ["read"]),
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(client),
  makeFamilyId: () => `fam_${++serial}`,
});

describe("runTokenServiceContractTests", () => {
  it("fails a store without rotate whose revokeFamily does not keep the family revoked", async () => {
    const run = await runSuiteInChild(
      "src/testing/contract/_test_forgets_revoked_family.ts",
    );
    const failed = run.tests.filter((test) => test.status === "failed");

    expect(
      run.exitCode,
      `the suite must fail this store:\n${run.output}`,
    ).not.toBe(0);
    expect(failed.map((test) => test.fullName)).toStrictEqual([
      `${FORGETS_REVOKED_FAMILY} refresh-token rotation family keeps a revoked family revoked: a successor saved after revokeFamily is not live`,
      `${FORGETS_REVOKED_FAMILY} refresh-token rotation family keeps a replayed code's family revoked: a successor saved after revokeCode is not live`,
    ]);
    expect(failed[0].failureMessages.join("\n")).toContain(
      "a successor saved after its family was revoked must be stored already revoked",
    );
    expect(failed[1].failureMessages.join("\n")).toContain(
      "a successor saved after its code was replayed must be stored already revoked",
    );
  });
});

describe("runTokenServiceContractTests revokeCode client check", () => {
  it("fails a store whose revokeCode ignores the client by default, and registers an ignored case when it opts out", async () => {
    const run = await runSuiteInChild(
      "src/testing/contract/_test_ungated_revoke_code.ts",
    );
    const ungated = "a token service whose revokeCode ignores the client ";
    const optedOut =
      "a token service whose revokeCode ignores the client, opted out ";
    const inSuite = (suite: string, status: string): string[] =>
      run.tests
        .filter(
          (test) => test.status === status && test.fullName.startsWith(suite),
        )
        .map((test) => test.fullName.slice(suite.length).trim())
        .toSorted();

    expect(
      run.exitCode,
      `the suite must fail this store:\n${run.output}`,
    ).not.toBe(0);
    expect(inSuite(ungated, "failed")).toStrictEqual(
      [
        "revokeCode revokes for the client the code's tokens were issued to, after another client was refused",
        "revokeCode revokes nothing for a client other than the one the code's tokens were issued to",
        "revokeCode revokes nothing in a rotated family for a client other than the one the code's tokens were issued to",
      ].toSorted(),
    );
    expect(inSuite(optedOut, "failed")).toStrictEqual([]);
    expect(inSuite(optedOut, "skipped")).toContain(
      "revokeCode revokeCode ignores the presenting client — any client that presents a spent code revokes its tokens (revokeCodeChecksClient: false)",
    );
  });
});
