import {
  assertFalse,
  assertMatch,
  assertNotEquals,
  assertStringIncludes,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";

const decoder = new TextDecoder();

describe('runAuthRequestStorageContractTests with clear: "scoped"', () => {
  it("fails a store whose clear() removes another user's in-progress record", async () => {
    const { code, stdout, stderr } = await new Deno.Command(Deno.execPath(), {
      args: [
        "test",
        "--quiet",
        "--no-prompt",
        "--no-check",
        "--allow-read",
        "--allow-env",
        "_test_scoped_clear_wipes_live.ts",
      ],
      cwd: import.meta.dirname,
      stdout: "piped",
      stderr: "piped",
      env: { NO_COLOR: "1" },
    }).output();
    const output = decoder.decode(stdout) + decoder.decode(stderr);

    assertNotEquals(code, 0, `the suite must fail this store:\n${output}`);
    assertStringIncludes(
      output,
      "clear() on a shared store must not cancel another user's sign-in",
    );
    assertStringIncludes(
      output,
      'leaves every in-progress record in place (clear: "scoped") =>',
    );
    assertMatch(output, /\| 0 passed \(\d+ steps\) \| 1 failed \(2 steps\)/);
    assertFalse(
      output.includes("clears every record"),
      "scoped mode must not also require clear() to remove everything",
    );
  });
});
