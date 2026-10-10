/**
 * Pre-publication guards. `pnpm exec semantic-release` runs them from the
 * `verifyReleaseCmd` in `.releaserc.json`, before notes are generated, files
 * are prepared, or anything is pushed or published; pull-request CI runs the
 * references guard alone.
 *
 * - Unreleased commits must not reference the private application repository.
 * - A runtime dependency must not resolve through JSR, and `.npmrc` must not
 *   route the `@jsr` scope, because the npm package would then fail to install
 *   for anyone without that registry configured (see PUBLISHING.md).
 *
 * @module
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isMain } from "./_main.ts";

const DEFAULT_ROOT = resolve(fileURLToPath(new URL("../", import.meta.url)));
const PRIVATE_REFERENCE =
  /(?<![a-z0-9_.-])(?:udibo\/udibo#\d+\b|(?:https?:\/\/)?(?:www\.)?github\.com\/udibo\/udibo(?:\.git)?(?![a-z0-9_.-]))/i;
const DEPENDENCY_FIELDS = [
  "dependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;

/**
 * Refuses a commit range, and optional proposed squash text, that references a
 * private repository. Checks every commit when `previousGitHead` is omitted.
 */
export function verifyReleaseReferences(
  root: string = DEFAULT_ROOT,
  previousGitHead?: string,
  proposedMessage = "",
): void {
  if (
    previousGitHead &&
    !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(previousGitHead)
  ) {
    throw new Error("Last release Git head must be a full commit hash");
  }
  let commits: string;
  try {
    commits = execFileSync(
      "git",
      [
        "log",
        "--format=%B",
        previousGitHead ? `${previousGitHead}..HEAD` : "HEAD",
        "--",
      ],
      { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch {
    throw new Error("Cannot inspect unreleased commits");
  }
  if (PRIVATE_REFERENCE.test(`${commits}\n${proposedMessage}`)) {
    throw new Error(
      "Release input references a private repository. Remove those references before merging or publishing.",
    );
  }
}

/**
 * Refuses a release while a runtime dependency resolves through JSR or
 * `.npmrc` routes the `@jsr` scope to the JSR npm registry.
 */
export function verifyReleaseDependencies(root: string = DEFAULT_ROOT): void {
  const manifest = JSON.parse(
    readFileSync(resolve(root, "package.json"), "utf8"),
  ) as Record<string, Record<string, string> | undefined>;
  const viaJsr: string[] = [];
  for (const field of DEPENDENCY_FIELDS) {
    for (const [name, spec] of Object.entries(manifest[field] ?? {})) {
      if (/^jsr:|@jsr\//.test(spec) || name.startsWith("@jsr/")) {
        viaJsr.push(`${name}@${spec}`);
      }
    }
  }
  const npmrc = resolve(root, ".npmrc");
  const routesJsr =
    existsSync(npmrc) &&
    /^\s*@jsr:registry\s*=/m.test(readFileSync(npmrc, "utf8"));
  if (viaJsr.length > 0 || routesJsr) {
    const reasons = [
      ...(viaJsr.length > 0
        ? [`dependencies resolve through JSR: ${viaJsr.join(", ")}`]
        : []),
      ...(routesJsr ? [".npmrc routes the @jsr scope to npm.jsr.io"] : []),
    ];
    throw new Error(
      `Refusing to release: ${reasons.join("; ")}. Switch them to npm versions first (PUBLISHING.md, "Before the first npm release").`,
    );
  }
}

/** Runs every guard `semantic-release` needs before it publishes. */
export function verifyRelease(
  root: string = DEFAULT_ROOT,
  previousGitHead?: string,
): void {
  verifyReleaseReferences(root, previousGitHead);
  verifyReleaseDependencies(root);
}

function main(args: string[]): void {
  if (args[0] === "--dependencies-only") {
    verifyReleaseDependencies();
    return;
  }
  if (args[0] === "--references-only") {
    const base = process.env.RELEASE_REFERENCE_BASE;
    if (!base) throw new Error("Pull request base Git head is required");
    verifyReleaseReferences(
      undefined,
      base,
      [
        process.env.RELEASE_REFERENCE_PR_TITLE ?? "",
        process.env.RELEASE_REFERENCE_PR_BODY ?? "",
      ].join("\n"),
    );
    return;
  }
  verifyRelease(undefined, args[0] || undefined);
}

if (isMain(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  }
}
