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
  resetCredential: true,
});
runIdentityUserStoreContractTests({
  describeName: "IdentityUserStore resetCredential without imported hashes",
  makeFixture: () => userFixture(),
  resetCredential: true,
});
runIdentityUserStoreContractTests({
  describeName: "IdentityUserStore without optional capabilities",
  makeFixture: () => {
    const fixture = userFixture();
    delete fixture.store.replaceCredential;
    delete fixture.store.markEmailVerified;
    delete fixture.store.getLegacyCredential;
    delete fixture.store.clearLegacyCredential;
    delete fixture.store.resetCredential;
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
    ["reset-missing", "resetCredential capability is required"],
    ["reset-sessions", "resetCredential revokes every session of the user"],
    ["reset-not-atomic", "a failed reset must leave the credential unchanged"],
    ["reset-sessions-early", "a failed reset must leave the sessions live"],
    [
      "reset-legacy-early",
      "a failed reset must leave the imported hash in place",
    ],
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
