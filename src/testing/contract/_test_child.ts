import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const VITEST = fileURLToPath(
  new URL("../../../node_modules/vitest/vitest.mjs", import.meta.url),
);
const CONFIG = fileURLToPath(
  new URL("./_test_child.config.ts", import.meta.url),
);

/** One test of a suite run in a child process. */
export interface ChildTestResult {
  fullName: string;
  status: string;
  failureMessages: string[];
}

/** What a suite run in a child process reported. */
export interface ChildSuiteRun {
  exitCode: number | null;
  tests: ChildTestResult[];
  output: string;
}

/**
 * Runs the suite in `file` (a path relative to the repository root) in its own
 * Vitest process, so a suite meant to fail cannot fail the parent run.
 */
export async function runSuiteInChild(
  file: string,
  env: Record<string, string> = {},
): Promise<ChildSuiteRun> {
  const childEnv = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith("VITEST")),
  );
  const outDir = await mkdtemp(join(tmpdir(), "oauth2-child-"));
  const reportFile = join(outDir, "report.json");
  try {
    const { exitCode, output } = await new Promise<{
      exitCode: number | null;
      output: string;
    }>((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [
          VITEST,
          "run",
          "--config",
          CONFIG,
          "--reporter=json",
          `--outputFile=${reportFile}`,
        ],
        {
          cwd: ROOT,
          env: {
            ...childEnv,
            ...env,
            CONTRACT_CHILD_FILE: file,
            NO_COLOR: "1",
          },
          stdio: ["ignore", "pipe", "pipe"],
          signal: AbortSignal.timeout(60_000),
        },
      );
      let output = "";
      child.stdout.on("data", (chunk) => (output += chunk));
      child.stderr.on("data", (chunk) => (output += chunk));
      child.once("error", reject);
      child.once("close", (exitCode) => resolve({ exitCode, output }));
    });
    const report = JSON.parse(await readFile(reportFile, "utf8")) as {
      testResults: { assertionResults: ChildTestResult[] }[];
    };
    return {
      exitCode,
      tests: report.testResults.flatMap((result) => result.assertionResults),
      output,
    };
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
}
