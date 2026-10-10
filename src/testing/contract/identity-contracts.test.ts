import { describe, expect, it } from "vitest";
import { runSuiteInChild } from "./_test_child.ts";
import {
  runIdentityUserStoreContractTests,
  runListableSessionServiceContractTests,
  runRevocableSessionServiceContractTests,
} from "./mod.ts";
import {
  sessionFixture,
  userFixture,
} from "./_test_identity_contract_fixtures.ts";

runIdentityUserStoreContractTests({
  makeFixture: () => userFixture(),
  replaceCredential: true,
  emailVerification: true,
  legacyCredentials: true,
});
runIdentityUserStoreContractTests({
  describeName: "IdentityUserStore without optional capabilities",
  makeFixture: () => {
    const fixture = userFixture();
    delete fixture.store.replaceCredential;
    delete fixture.store.markEmailVerified;
    delete fixture.store.getLegacyCredential;
    delete fixture.store.clearLegacyCredential;
    return fixture;
  },
});
runRevocableSessionServiceContractTests({
  makeFixture: () => sessionFixture(),
});
runListableSessionServiceContractTests({ makeFixture: () => sessionFixture() });

describe("identity contracts reject faulty stores", () => {
  const cases = [
    [
      "cas-stale",
      "read after a lost compare-and-set must see the committed credential",
    ],
    ["cas-missing", "replaceCredential capability is required"],
    ["cas-params", "compares credential values, including every parameter"],
    ["cas-race", "exactly one concurrent replacement may win"],
    ["email-guard", "a token for an old email must not verify the new email"],
    ["legacy-clear", "clears the selected imported credential"],
    ["revoke-owner", "revokes all of the selected user's sessions immediately"],
    [
      "revoke-advisory",
      "revokes all of the selected user's sessions immediately",
    ],
    ["list-ended", "lists must exclude foreign and ended sessions"],
    ["list-order", "lists must exclude foreign and ended sessions"],
    [
      "list-secret",
      "session summaries must not expose secret/hash or token material",
    ],
  ];
  for (const [fault, expected] of cases) {
    it(fault, async () => {
      const run = await runSuiteInChild(
        "src/testing/contract/_test_identity_contract_faults.ts",
        { IDENTITY_CONTRACT_FAULT: fault },
      );
      const failures = run.tests
        .filter((test) => test.status === "failed")
        .flatMap((test) => [test.fullName, ...test.failureMessages])
        .join("\n");
      expect(
        run.exitCode,
        `faulty store unexpectedly passed: ${fault}\n${run.output}`,
      ).not.toBe(0);
      expect(
        failures,
        `must fail the intended contract, not setup: ${run.output}`,
      ).toContain(expected);
    });
  }
});
