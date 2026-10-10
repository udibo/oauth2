import { describe, expect, it } from "vitest";
import { runSuiteInChild } from "./_test_child.ts";

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
