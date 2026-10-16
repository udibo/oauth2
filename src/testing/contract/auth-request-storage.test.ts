import { describe, expect, it } from "vitest";
import { runSuiteInChild } from "./_test_child.ts";

describe("runAuthRequestStorageContractTests round trip", () => {
  it("fails a store that keeps only the record fields it knows", async () => {
    const run = await runSuiteInChild(
      "src/testing/contract/_test_drops_recorded_controls.ts",
    );
    const failed = run.tests
      .filter((test) => test.status === "failed")
      .map((test) => test.fullName)
      .sort();

    expect(
      run.exitCode,
      `the suite must fail this store:\n${run.output}`,
    ).not.toBe(0);
    expect(failed).toStrictEqual(
      [
        "a store that keeps only the fields it knows set / get / delete / clear returns a recorded maxAge of null as null, not as an absent field",
        "a store that keeps only the fields it knows set / get / delete / clear round-trips every field of a stored record",
        "a store that keeps only the fields it knows take hands one record to exactly one of 8 concurrent takes",
        "a store that keeps only the fields it knows take returns the record and removes it",
      ].sort(),
    );
  });
});

describe('runAuthRequestStorageContractTests with clear: "scoped"', () => {
  it("fails a store whose clear() removes another user's in-progress record", async () => {
    const run = await runSuiteInChild(
      "src/testing/contract/_test_scoped_clear_wipes_live.ts",
    );
    const failed = run.tests.filter((test) => test.status === "failed");

    expect(
      run.exitCode,
      `the suite must fail this store:\n${run.output}`,
    ).not.toBe(0);
    expect(failed).toHaveLength(1);
    expect(failed.map((test) => test.fullName).join("\n")).toContain(
      'leaves every in-progress record in place (clear: "scoped")',
    );
    expect(failed.flatMap((test) => test.failureMessages).join("\n")).toContain(
      "clear() on a shared store must not cancel another user's sign-in",
    );
    expect(
      run.tests.some((test) => test.fullName.includes("clears every record")),
      "scoped mode must not also require clear() to remove everything",
    ).toBe(false);
  });
});
