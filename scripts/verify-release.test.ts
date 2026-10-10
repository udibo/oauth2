import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { createTree, type TestTree } from "./_test_tree.ts";
import {
  verifyRelease,
  verifyReleaseDependencies,
  verifyReleaseReferences,
} from "./verify-release.ts";

let tree: TestTree | undefined;
afterEach(() => tree?.dispose());

function git(root: string, ...args: string[]): string {
  return execFileSync(
    "git",
    [
      "-c",
      "user.name=Release test",
      "-c",
      "user.email=release-test@example.invalid",
      "-c",
      "commit.gpgsign=false",
      "-c",
      `core.hooksPath=${join(root, "hooks")}`,
      ...args,
    ],
    { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
}

const PRIVATE_MESSAGE = "fix: synthetic change\n\nCloses udibo/udibo#405";

interface Case {
  name: string;
  message: string;
  baseline?: string;
  firstRelease?: boolean;
  previousGitHead?: string;
  proposed?: string;
  rejected: boolean;
  expectedError?: string;
}

const cases: Case[] = [
  {
    name: "rejects a private issue footer",
    message: PRIVATE_MESSAGE,
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
    message: PRIVATE_MESSAGE,
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
    proposed: "fix: synthetic change for udibo/udibo#405",
    rejected: true,
  },
  {
    name: "refuses private references in the proposed squash body",
    message: "fix: synthetic public change",
    proposed:
      "fix: synthetic public change\nCloses https://github.com/udibo/udibo/issues/405",
    rejected: true,
  },
  {
    name: "permits public PR text",
    message: "fix: synthetic public change",
    proposed: "fix: synthetic public change\nCloses #24",
    rejected: false,
  },
  {
    name: "does not recheck historical private references during PR admission",
    baseline: PRIVATE_MESSAGE,
    message: "fix: synthetic public change",
    proposed: "fix: synthetic public change\nCloses #24",
    rejected: false,
  },
  {
    name: "refuses private branch commits during PR admission",
    message: PRIVATE_MESSAGE,
    proposed: "fix: synthetic public change",
    rejected: true,
  },
];

describe("verifyReleaseReferences", () => {
  for (const testCase of cases) {
    it(testCase.name, () => {
      tree = createTree("oauth2 release privacy ");
      const root = tree.root;
      git(root, "init");
      git(
        root,
        "commit",
        "--allow-empty",
        "-m",
        testCase.baseline ?? "test: synthetic release baseline",
      );
      const previousGitHead =
        testCase.previousGitHead ??
        (testCase.firstRelease ? undefined : git(root, "rev-parse", "HEAD"));
      git(root, "commit", "--allow-empty", "-m", testCase.message);
      const run = (): void =>
        verifyReleaseReferences(root, previousGitHead, testCase.proposed);
      if (testCase.rejected) {
        expect(run).toThrow(
          testCase.expectedError ??
            "Release input references a private repository",
        );
      } else {
        expect(run).not.toThrow();
      }
    });
  }

  it("fails closed outside a Git repository", () => {
    tree = createTree();
    expect(() => verifyReleaseReferences(tree!.root)).toThrow(
      "Cannot inspect unreleased commits",
    );
  });
});

describe("the --references-only entry point", () => {
  const script = fileURLToPath(new URL("./verify-release.ts", import.meta.url));

  function run(
    root: string,
    env: Record<string, string>,
  ): ReturnType<typeof spawnSync> {
    return spawnSync(process.execPath, [script, "--references-only"], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, ...env },
    });
  }

  it("refuses a pull request with no base head", () => {
    tree = createTree();
    git(tree.root, "init");
    git(tree.root, "commit", "--allow-empty", "-m", "fix: synthetic change");
    const result = run(tree.root, { RELEASE_REFERENCE_BASE: "" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Pull request base Git head is required");
  });
});

describe("verifyReleaseDependencies", () => {
  function release(files: Record<string, string>): () => void {
    tree = createTree();
    for (const [path, content] of Object.entries(files)) {
      tree.write(path, content);
    }
    return () => verifyReleaseDependencies(tree!.root);
  }
  const manifest = (dependencies: Record<string, string>): string =>
    JSON.stringify({ name: "x", dependencies });

  it("permits dependencies that resolve through npm", () => {
    expect(
      release({
        "package.json": manifest({ "@udibo/http-error": "^0.12.0" }),
        ".npmrc": "node-linker=hoisted\n",
      }),
    ).not.toThrow();
  });

  it("refuses a dependency aliased to the @jsr scope", () => {
    expect(
      release({
        "package.json": manifest({
          "@udibo/http-error": "npm:@jsr/udibo__http-error@^0.11.1",
        }),
      }),
    ).toThrow(
      /dependencies resolve through JSR: @udibo\/http-error@npm:@jsr\/udibo__http-error@\^0\.11\.1/,
    );
  });

  it("refuses a jsr: specifier", () => {
    expect(
      release({
        "package.json": manifest({ "@udibo/http-error": "jsr:^0.11.1" }),
      }),
    ).toThrow("resolve through JSR");
  });

  it("refuses an .npmrc that routes the @jsr scope", () => {
    expect(
      release({
        "package.json": manifest({}),
        ".npmrc": "@jsr:registry=https://npm.jsr.io\n",
      }),
    ).toThrow(".npmrc routes the @jsr scope");
  });

  it("names the pre-release step that fixes it", () => {
    expect(
      release({
        "package.json": manifest({ a: "npm:@jsr/a__b@1.0.0" }),
      }),
    ).toThrow("PUBLISHING.md");
  });
});

describe("verifyRelease", () => {
  it("checks references and dependencies together", () => {
    tree = createTree();
    tree.write(
      "package.json",
      JSON.stringify({ dependencies: { a: "npm:@jsr/a__b@1.0.0" } }),
    );
    git(tree.root, "init");
    git(tree.root, "commit", "--allow-empty", "-m", "fix: synthetic change");
    expect(() => verifyRelease(tree!.root)).toThrow("resolve through JSR");
  });
});

describe("release configuration", () => {
  const config = JSON.parse(
    readFileSync(new URL("../.releaserc.json", import.meta.url), "utf8"),
  ) as { plugins: (string | [string, Record<string, unknown>])[] };

  it("supplies the previous release head to the pre-publication guard", () => {
    const guard = config.plugins.find(
      (plugin) =>
        Array.isArray(plugin) &&
        plugin[0] === "@semantic-release/exec" &&
        typeof plugin[1].verifyReleaseCmd === "string",
    ) as [string, Record<string, unknown>] | undefined;
    expect(guard?.[1].verifyReleaseCmd).toBe(
      "node scripts/verify-release.ts ${lastRelease.gitHead || ''}",
    );
  });
});
