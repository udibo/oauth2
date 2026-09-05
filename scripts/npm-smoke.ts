/**
 * Proves the built npm artifact from Node, the way an adopter would consume
 * it. Run `deno task npm:build` first; then this script:
 *
 * 1. asserts the artifact's export map is exactly the JSR export map minus
 *    the Deno-only subpaths, and that its version matches `src/deno.json`;
 * 2. asserts every runtime dependency of the artifact is pinned in
 *    `npm-smoke-consumer/package.json` at a version satisfying the
 *    artifact's range, so the committed `package-lock.json` is the only
 *    source of registry code CI ever executes;
 * 3. asserts `npm-smoke-consumer/mod.tsx` statically imports every subpath
 *    the smoke must prove (the export map minus the `/testing` rows the
 *    README leaves unverified on Node), so type-check coverage cannot
 *    silently shrink;
 * 4. installs the frozen registry dependencies with `npm ci`, packs the
 *    artifact with `npm pack`, and installs the local tarball offline —
 *    every npm invocation with lifecycle scripts disabled;
 * 5. type-checks the consumer with its own `tsc` under NodeNext resolution;
 * 6. runs `npm-smoke-consumer/main.mjs` under Node, which imports every one
 *    of those subpaths at runtime and probes a known export from each.
 *
 * Nothing here publishes anywhere, and nothing here resolves a floating
 * version from the registry: `npm ci` installs exactly the committed
 * lockfile, and the tarball install runs `--offline` so an unpinned
 * dependency fails loudly instead of fetching fresh code onto the runner.
 *
 * Usage: `deno task npm:smoke`
 */
import { parse, parseRange, satisfies } from "@std/semver";
import { fileURLToPath } from "node:url";

import { DENO_ONLY_EXPORTS } from "./build-npm.ts";

/** Mirrors `UNVERIFIED_ON_NODE` in `npm-smoke-consumer/main.mjs`. */
export const UNVERIFIED_ON_NODE: readonly string[] = [
  "./testing",
  "./testing/contract",
];

/**
 * Env for every npm spawn: no lifecycle script runs on this machine, in any
 * directory, whatever the local npm configuration says.
 */
export const NPM_SPAWN_ENV: Readonly<Record<string, string>> = {
  npm_config_ignore_scripts: "true",
};

/** `npm ci` — installs exactly the committed lockfile, nothing floating. */
export const FROZEN_INSTALL_ARGS: readonly string[] = [
  "ci",
  "--no-audit",
  "--no-fund",
];

/**
 * Installs the locally packed tarball on top of the frozen tree.
 * `--offline` turns any attempt to resolve a dependency from the registry —
 * an artifact dependency missing from the consumer's pins — into a hard
 * failure instead of a silent lockfile-less fetch.
 */
export function tarballInstallArgs(tarball: string): string[] {
  return [
    "install",
    "--no-save",
    "--no-audit",
    "--no-fund",
    "--ignore-scripts",
    "--offline",
    tarball,
  ];
}

const packageDir = fileURLToPath(new URL("../", import.meta.url));
const consumerDir = `${packageDir}npm-smoke-consumer`;

function fail(message: string): never {
  console.error(`npm smoke: ${message}`);
  Deno.exit(1);
}

async function run(
  command: string,
  args: readonly string[],
  cwd: string,
): Promise<void> {
  const { code } = await new Deno.Command(command, {
    args: [...args],
    cwd,
    env: { ...NPM_SPAWN_ENV },
    stdout: "inherit",
    stderr: "inherit",
  }).output();
  if (code !== 0) {
    fail(`\`${command} ${args.join(" ")}\` exited with ${code}`);
  }
}

async function readJson(path: string): Promise<Record<string, unknown>> {
  return JSON.parse(await Deno.readTextFile(path));
}

function assertArtifactDepsFrozen(
  artifactDeps: Record<string, string>,
  consumerDevDeps: Record<string, string>,
): void {
  for (const [name, range] of Object.entries(artifactDeps)) {
    const pinned = consumerDevDeps[name];
    if (pinned === undefined) {
      fail(
        `the artifact depends on ${name}@${range} but ` +
          `npm-smoke-consumer/package.json does not pin it — add an exact ` +
          `devDependency and regenerate package-lock.json ` +
          `(cd npm-smoke-consumer && npm install --no-audit --no-fund)`,
      );
    }
    if (!satisfies(parse(pinned), parseRange(range))) {
      fail(
        `${name}@${pinned} pinned in npm-smoke-consumer does not satisfy ` +
          `the artifact's range ${range} — update the pin and regenerate ` +
          `package-lock.json`,
      );
    }
  }
}

async function main(): Promise<void> {
  const srcConfig = await readJson(`${packageDir}src/deno.json`);
  const artifactConfig = await readJson(`${packageDir}npm/package.json`).catch(
    () => fail("npm/package.json not found — run `deno task npm:build` first"),
  );
  const consumerConfig = await readJson(`${consumerDir}/package.json`);

  const expectedExports = Object.keys(
    srcConfig.exports as Record<string, string>,
  ).filter((subpath) => !DENO_ONLY_EXPORTS.includes(subpath));
  const actualExports = Object.keys(
    artifactConfig.exports as Record<string, string>,
  );
  const missing = expectedExports.filter((s) => !actualExports.includes(s));
  const extra = actualExports.filter((s) => !expectedExports.includes(s));
  if (missing.length > 0 || extra.length > 0) {
    fail(
      `artifact export map drifted from src/deno.json — ` +
        `missing: [${missing.join(", ")}], unexpected: [${extra.join(", ")}]`,
    );
  }
  if (artifactConfig.version !== srcConfig.version) {
    fail(
      `artifact version ${artifactConfig.version} does not match ` +
        `src/deno.json version ${srcConfig.version} — rebuild with ` +
        "`deno task npm:build`",
    );
  }

  assertArtifactDepsFrozen(
    (artifactConfig.dependencies ?? {}) as Record<string, string>,
    (consumerConfig.devDependencies ?? {}) as Record<string, string>,
  );

  const typeCheckedSubpaths = expectedExports.filter(
    (subpath) => !UNVERIFIED_ON_NODE.includes(subpath),
  );
  const consumerSource = await Deno.readTextFile(`${consumerDir}/mod.tsx`);
  const unimported = typeCheckedSubpaths.filter(
    (subpath) => !consumerSource.includes(`"@udibo/oauth2${subpath.slice(1)}"`),
  );
  if (unimported.length > 0) {
    fail(
      `npm-smoke-consumer/mod.tsx does not import [${
        unimported.join(", ")
      }] — ` +
        `every Node-supported subpath must be type-checked, or added to the ` +
        `README runtime table's unverified rows and UNVERIFIED_ON_NODE`,
    );
  }

  await run("npm", FROZEN_INSTALL_ARGS, consumerDir);

  const packOutput = await new Deno.Command("npm", {
    args: ["pack", "--pack-destination", consumerDir],
    cwd: `${packageDir}npm`,
    env: { ...NPM_SPAWN_ENV },
    stdout: "piped",
    stderr: "inherit",
  }).output();
  if (packOutput.code !== 0) fail("`npm pack` failed");
  const tarball = new TextDecoder().decode(packOutput.stdout).trim()
    .split("\n").at(-1);
  if (!tarball?.endsWith(".tgz")) {
    fail(`npm pack printed no tarball: ${tarball}`);
  }

  await run("npm", tarballInstallArgs(`./${tarball}`), consumerDir);
  await run(
    "node",
    ["node_modules/typescript/bin/tsc", "-p", "."],
    consumerDir,
  );
  await run("node", ["main.mjs"], consumerDir);

  console.log(
    `npm smoke: ${typeCheckedSubpaths.length} subpaths type-checked and ` +
      `imported from the ${tarball} artifact`,
  );
}

if (import.meta.main) await main();
