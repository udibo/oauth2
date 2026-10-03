import { assertEquals, assertExists, assertRejects } from "@std/assert";
import { pathToFileURL } from "node:url";
import { verifyRelease } from "./verify-release.ts";

Deno.test("first release guard rejects wrong versions until 0.1.0 exists in history", async () => {
  const path = await Deno.makeTempDir({ prefix: "oauth2 release history " });
  const root = pathToFileURL(`${path}/`);
  async function git(...args: string[]): Promise<void> {
    const result = await new Deno.Command("git", {
      args: [
        "-c",
        "user.name=Release test",
        "-c",
        "user.email=release-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        `core.hooksPath=${path}/hooks`,
        ...args,
      ],
      cwd: root,
      stdout: "piped",
      stderr: "piped",
    }).output();
    assertEquals(result.success, true, new TextDecoder().decode(result.stderr));
  }
  try {
    await assertRejects(
      () => verifyRelease("0.1.0", root),
      Error,
      "Cannot inspect release history",
    );
    await git("init");
    await git("commit", "--allow-empty", "-m", "test baseline");
    await git("tag", "0.0.0");
    await verifyRelease("0.1.0", root);
    for (const version of ["0.0.1", "0.2.0", "1.0.0"]) {
      await assertRejects(
        () => verifyRelease(version, root),
        Error,
        "First release must be 0.1.0",
      );
    }
    await git("tag", "0.1.0");
    await verifyRelease("0.1.1", root);
    await verifyRelease("0.2.0", root);
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("release guard checks only unpublished commit references", async (t) => {
  const cases = [
    {
      name: "rejects a private issue footer",
      message: "fix: synthetic change\n\nCloses udibo/udibo#405",
      rejected: true,
    },
    {
      name: "rejects a private repository URL regardless of case",
      message:
        "fix: synthetic change\n\nRefs HTTPS://GITHUB.COM/UDIBO/UDIBO/issues/405",
      rejected: true,
    },
    {
      name: "rejects a private repository root URL",
      message: "fix: synthetic change\n\nSee https://github.com/udibo/udibo",
      rejected: true,
    },
    {
      name: "rejects a quoted private repository URL",
      message: 'fix: synthetic change\n\nSee "https://github.com/udibo/udibo"',
      rejected: true,
    },
    {
      name: "permits references to the public package",
      message:
        "fix: synthetic change\n\nCloses udibo/oauth2#24\n\nSee https://github.com/udibo/oauth2/issues/24",
      rejected: false,
    },
    {
      name: "permits a different repository with a shared name prefix",
      message:
        "fix: synthetic change\n\nSee https://github.com/udibo/udibo-docs/issues/405",
      rejected: false,
    },
    {
      name: "permits a different owner with a shared name suffix",
      message: "fix: synthetic change\n\nCloses not-udibo/udibo#405",
      rejected: false,
    },
    {
      name: "permits a different host with a shared name suffix",
      message:
        "fix: synthetic change\n\nSee https://not-github.com/udibo/udibo/issues/405",
      rejected: false,
    },
    {
      name: "does not recheck references in an already released commit",
      baseline: "fix: published change\n\nCloses udibo/udibo#405",
      message: "fix: synthetic change\n\nCloses #24",
      rejected: false,
    },
    {
      name: "checks all commits when there is no previous release",
      message: "fix: synthetic change\n\nCloses udibo/udibo#405",
      firstRelease: true,
      rejected: true,
    },
    {
      name: "refuses a Git option as the previous release head",
      message: "fix: synthetic change",
      previousGitHead: "--all",
      expectedError: "Last release Git head must be a full commit hash",
      rejected: true,
    },
    {
      name: "fails closed when the previous release head cannot be read",
      message: "fix: synthetic change",
      previousGitHead: "0".repeat(40),
      expectedError: "Cannot inspect unreleased commits",
      rejected: true,
    },
    {
      name: "refuses private references in the proposed squash title",
      message: "fix: synthetic public change",
      prTitle: "fix: synthetic change for udibo/udibo#405",
      rejected: true,
    },
    {
      name: "refuses private references in the proposed squash body",
      message: "fix: synthetic public change",
      prTitle: "fix: synthetic public change",
      prBody: "Closes https://github.com/udibo/udibo/issues/405",
      rejected: true,
    },
    {
      name:
        "permits public PR text without imposing the first-release version rule",
      message: "fix: synthetic public change",
      prTitle: "fix: synthetic public change",
      prBody: "Closes #24",
      rejected: false,
      noReleaseTag: true,
    },
    {
      name:
        "does not recheck historical private references during PR admission",
      baseline: "fix: published change\n\nCloses udibo/udibo#405",
      message: "fix: synthetic public change",
      prTitle: "fix: synthetic public change",
      prBody: "Closes #24",
      rejected: false,
    },
    {
      name: "refuses private branch commits during PR admission",
      message: "fix: synthetic change\n\nCloses udibo/udibo#405",
      prTitle: "fix: synthetic public change",
      rejected: true,
    },
    {
      name: "fails closed when PR admission has no base head",
      message: "fix: synthetic public change",
      prTitle: "fix: synthetic public change",
      firstRelease: true,
      rejected: true,
      expectedError: "Pull request base Git head is required",
    },
  ];
  for (const testCase of cases) {
    await t.step(testCase.name, async () => {
      const path = await Deno.makeTempDir({
        prefix: "oauth2 release privacy ",
      });
      const root = pathToFileURL(`${path}/`);
      async function git(...args: string[]): Promise<string> {
        const result = await new Deno.Command("git", {
          args: [
            "-c",
            "user.name=Release test",
            "-c",
            "user.email=release-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            `core.hooksPath=${path}/hooks`,
            ...args,
          ],
          cwd: root,
          stdout: "piped",
          stderr: "piped",
        }).output();
        assertEquals(
          result.success,
          true,
          new TextDecoder().decode(result.stderr),
        );
        return new TextDecoder().decode(result.stdout).trim();
      }
      try {
        await git("init");
        await git(
          "commit",
          "--allow-empty",
          "-m",
          testCase.baseline ?? "test: synthetic release baseline",
        );
        const previousGitHead = testCase.previousGitHead ??
          (testCase.firstRelease ? undefined : await git("rev-parse", "HEAD"));
        if (!testCase.firstRelease && !testCase.noReleaseTag) {
          await git("tag", "0.1.0");
        }
        await git("commit", "--allow-empty", "-m", testCase.message);
        const run = async () => {
          if (testCase.prTitle === undefined) {
            await verifyRelease("0.1.0", root, previousGitHead);
            return;
          }
          await Deno.mkdir(new URL("scripts/", root));
          const script = new URL("scripts/verify-release.ts", root);
          await Deno.copyFile(
            new URL("./verify-release.ts", import.meta.url),
            script,
          );
          const result = await new Deno.Command(Deno.execPath(), {
            args: [
              "run",
              "--no-config",
              "--no-lock",
              "--allow-run=git",
              "--allow-read",
              "--allow-env=RELEASE_REFERENCE_BASE,RELEASE_REFERENCE_PR_TITLE,RELEASE_REFERENCE_PR_BODY",
              script.href,
              "--references-only",
            ],
            cwd: root,
            env: {
              RELEASE_REFERENCE_BASE: previousGitHead ?? "",
              RELEASE_REFERENCE_PR_TITLE: testCase.prTitle,
              RELEASE_REFERENCE_PR_BODY: testCase.prBody ?? "",
            },
            stdout: "piped",
            stderr: "piped",
          }).output();
          if (!result.success) {
            throw new Error(new TextDecoder().decode(result.stderr));
          }
        };
        if (testCase.rejected) {
          await assertRejects(
            run,
            Error,
            testCase.expectedError ??
              "Release input references a private repository",
          );
        } else {
          await run();
        }
      } finally {
        await Deno.remove(root, { recursive: true });
      }
    });
  }
});

Deno.test("release configuration supplies the previous release head to the pre-publication guard", async () => {
  const config = JSON.parse(
    await Deno.readTextFile(new URL("../.releaserc.json", import.meta.url)),
  ) as { plugins: (string | [string, Record<string, unknown>])[] };
  const guard = config.plugins.find((plugin) =>
    Array.isArray(plugin) && plugin[0] === "@semantic-release/exec" &&
    typeof plugin[1].verifyReleaseCmd === "string"
  );
  assertExists(guard);
  assertEquals(Array.isArray(guard), true);
  const [, options] = guard as [string, Record<string, unknown>];
  assertEquals(
    options.verifyReleaseCmd,
    "deno run --allow-run=git --allow-read scripts/verify-release.ts ${nextRelease.version} ${lastRelease.gitHead || ''}",
  );
});
