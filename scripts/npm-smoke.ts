/**
 * Consumes the packed npm artifact the way an adopter would: packs the
 * package, installs the tarball into an empty project with the peer
 * dependencies pinned to the versions this repository tests with,
 * type-checks a consumer that imports every subpath under NodeNext
 * resolution, and imports every subpath on Node.
 *
 * Run `pnpm build` first, then `pnpm smoke`. With `--release` the consumer is
 * given no JSR registry, so the install itself fails when a runtime dependency
 * can only come from JSR, and the run also fails when one resolves through JSR
 * at all, which a published package must not do.
 * Set `QUICKSTART_BROWSER=1` on Node 24+ with Playwright Chromium installed
 * to exercise the quickstart's first sign-in and sign-out from this consumer.
 *
 * The pinned consumer needs npm 11.6.0 or later: earlier npm crashes resolving
 * it whenever the Vitest pin trails Vitest's newest release
 * (https://github.com/npm/cli/issues/9787). With `--install-only` the consumer
 * pins nothing, so any npm can run it: it installs the tarball, checks its
 * contents and runs the `udibo-oauth2` command, without the type check and
 * imports, which need the peers.
 */
import { execFileSync, spawn } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { isMain } from "./_main.ts";
import { SKILL_FILE } from "./skill-version.ts";

interface PackageManifest {
  name: string;
  version: string;
  exports: Record<string, unknown>;
  bin?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

const packageDir = fileURLToPath(new URL("../", import.meta.url));
const smokeDir = join(packageDir, "scripts", "npm-smoke");
const tscPath = join(packageDir, "node_modules", "typescript", "bin", "tsc");
const isWindows = process.platform === "win32";
const releaseMode = process.argv.includes("--release");
const installOnly = process.argv.includes("--install-only");
const PINNED_CONSUMER_MIN_NPM = [11, 6, 0] as const;
const CONSUMER_PINS = [
  "@hono/node-server",
  "hono",
  "react",
  "react-dom",
  "@types/react",
  "@types/react-dom",
  "@types/node",
  "typescript",
  "vitest",
];

function fail(message: string): never {
  console.error(`npm smoke: ${message}`);
  process.exit(1);
}

/**
 * Why `npmVersion` cannot install the pinned consumer, or `undefined` when it
 * can. npm before 11.6.0 lacks the `#loadPeerSet` fix (npm/cli#8448).
 */
export function pinnedConsumerNpmProblem(
  npmVersion: string,
): string | undefined {
  const parts = /^(\d+)\.(\d+)\.(\d+)/.exec(npmVersion.trim());
  if (!parts) return `cannot read the npm version from "${npmVersion}"`;
  const actual = parts.slice(1, 4).map(Number);
  for (const [index, minimum] of PINNED_CONSUMER_MIN_NPM.entries()) {
    if (actual[index]! > minimum) return undefined;
    if (actual[index]! < minimum) {
      return `npm ${npmVersion.trim()} cannot resolve the pinned consumer: npm before ${PINNED_CONSUMER_MIN_NPM.join(".")} crashes in #loadPeerSet whenever the Vitest pin trails Vitest's newest release (https://github.com/npm/cli/issues/9787). Use npm ${PINNED_CONSUMER_MIN_NPM.join(".")} or later, or pass --install-only`;
    }
  }
  return undefined;
}

function run(
  command: string,
  args: string[],
  cwd: string,
  stderr: "inherit" | "pipe" = "inherit",
): string {
  return execFileSync(command, args, {
    cwd,
    encoding: "utf8",
    shell: isWindows && command !== process.execPath,
    stdio: ["ignore", "pipe", stderr],
    env: { ...process.env, npm_config_ignore_scripts: "true" },
  });
}

function readManifest(path: string): PackageManifest {
  return JSON.parse(readFileSync(path, "utf8")) as PackageManifest;
}

function exactVersions(
  dependencies: Record<string, string>,
): Record<string, string> {
  const pinned: Record<string, string> = {};
  for (const name of CONSUMER_PINS) {
    const range = dependencies[name];
    if (range === undefined) fail(`package.json does not declare ${name}`);
    const installed = readManifest(
      join(packageDir, "node_modules", name, "package.json"),
    );
    pinned[name] = installed.version;
  }
  return pinned;
}

/**
 * Packs the exact `@udibo/*` runtime dependencies this checkout resolved, so
 * the age-gated consumer install can use them: the release-age policy exempts
 * the scope's own packages, which `npm install --before` cannot express.
 */
function ownDependencyTarballs(
  dependencies: Record<string, string>,
  destination: string,
): string[] {
  return Object.keys(dependencies)
    .filter((name) => name.startsWith("@udibo/"))
    .map((name) => {
      const { version } = readManifest(
        join(packageDir, "node_modules", name, "package.json"),
      );
      const file = run(
        "npm",
        ["pack", `${name}@${version}`, "--pack-destination", destination],
        destination,
        "pipe",
      )
        .trim()
        .split("\n")
        .at(-1)!;
      return join(destination, file);
    });
}

const BIN_NAME = "udibo-oauth2";

function npx(args: string[], cwd: string): string {
  return run("npx", ["--no-install", BIN_NAME, ...args], cwd, "pipe");
}

function checkBin(consumerDir: string, listing: string[]): void {
  const installed = readManifest(
    join(consumerDir, "node_modules", "@udibo", "oauth2", "package.json"),
  );
  const target = installed.bin?.[BIN_NAME];
  if (!target || !listing.includes(target.replace(/^\.\//, ""))) {
    fail(`bin ${BIN_NAME} points at ${target}, which is not in the tarball`);
  }
  const help = npx(["--help"], consumerDir);
  if (!help.includes("oidc keygen") || !help.includes("idp dev")) {
    fail(`${BIN_NAME} --help did not list its commands: ${help}`);
  }
  const jwk = JSON.parse(npx(["oidc", "keygen"], consumerDir)) as {
    kty?: string;
    d?: string;
  };
  if (jwk.kty !== "EC" || !jwk.d)
    fail(`${BIN_NAME} oidc keygen printed no key`);
}

async function checkIdpDev(consumerDir: string): Promise<void> {
  const entry = join(
    consumerDir,
    "node_modules",
    "@udibo",
    "oauth2",
    "dist",
    "cli",
    "bin.js",
  );
  writeFileSync(
    join(consumerDir, "idp.json"),
    JSON.stringify({
      port: 0,
      scopesSupported: ["openid", "skill-smoke"],
      users: [{ username: "reader@example.test", password: "local-fixture" }],
    }),
  );
  const child = spawn(
    process.execPath,
    [entry, "idp", "dev", "--config", "idp.json"],
    {
      cwd: consumerDir,
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
  const exited = new Promise<void>((resolve) => child.once("close", resolve));
  try {
    const url = await new Promise<string>((resolve, reject) => {
      let output = "";
      child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
        output += chunk;
        const match = output.match(/Listening on (http:\/\/\S+)/);
        if (match) resolve(match[1]!);
      });
      child.once("error", reject);
      child.once("close", () => reject(new Error(`exited early:\n${output}`)));
    });
    const response = await fetch(`${url}/.well-known/openid-configuration`);
    if (!response.ok)
      throw new Error(`idp dev answered discovery with ${response.status}`);
    const metadata = (await response.json()) as {
      issuer?: string;
      scopes_supported?: string[];
    };
    if (
      metadata.issuer !== url ||
      !metadata.scopes_supported?.includes("skill-smoke")
    ) {
      throw new Error(
        "discovery did not describe the locally configured issuer and scopes",
      );
    }
  } finally {
    child.kill("SIGTERM");
    await exited;
  }
}

async function main(): Promise<void> {
  const manifest = readManifest(join(packageDir, "package.json"));
  if (releaseMode) {
    const viaJsr = Object.entries(manifest.dependencies ?? {}).filter(
      ([, spec]) => spec.includes("jsr"),
    );
    if (viaJsr.length > 0) {
      fail(
        `the package depends on JSR-resolved packages: ${viaJsr
          .map(([name, spec]) => `${name}@${spec}`)
          .join(", ")}; see PUBLISHING.md, "Before the first npm release"`,
      );
    }
  }
  const npmVersion = run("npm", ["--version"], packageDir, "pipe").trim();
  if (!installOnly) {
    const problem = pinnedConsumerNpmProblem(npmVersion);
    if (problem) fail(problem);
  }
  const workDir = mkdtempSync(join(tmpdir(), "oauth2-smoke-"));
  try {
    const packDir = join(workDir, "pack");
    const consumerDir = join(workDir, "consumer");
    mkdirSync(packDir);
    mkdirSync(consumerDir);

    run("pnpm", ["pack", "--pack-destination", packDir], packageDir);
    const tarballs = readdirSync(packDir).filter((name) =>
      name.endsWith(".tgz"),
    );
    if (tarballs.length !== 1) {
      fail(`expected one tarball, found ${tarballs.length}`);
    }
    const tarball = join(packDir, tarballs[0]!);

    const appDir = join(consumerDir, "app");
    mkdirSync(appDir);
    writeFileSync(
      join(appDir, "package.json"),
      JSON.stringify({
        name: "oauth2-smoke-app",
        private: true,
        dependencies: { "@udibo/oauth2": pathToFileURL(tarball).href },
        scripts: { "auth:dev": "udibo-oauth2 idp dev --config idp.json" },
      }),
    );
    writeFileSync(
      join(consumerDir, "package.json"),
      JSON.stringify({
        name: "oauth2-smoke-consumer",
        private: true,
        workspaces: ["app"],
        type: "module",
        dependencies: installOnly
          ? {}
          : exactVersions({
              ...manifest.dependencies,
              ...manifest.devDependencies,
            }),
      }),
    );
    if (!releaseMode) {
      writeFileSync(
        join(consumerDir, ".npmrc"),
        "@jsr:registry=https://npm.jsr.io\n",
      );
    }
    run(
      "npm",
      [
        "install",
        "--no-audit",
        "--no-fund",
        "--ignore-scripts",
        "--before",
        new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
        ...ownDependencyTarballs(manifest.dependencies ?? {}, packDir),
        tarball,
      ],
      consumerDir,
    );

    const installedDir = join(consumerDir, "node_modules", "@udibo", "oauth2");
    const installed = readManifest(join(installedDir, "package.json"));
    const listing = readdirSync(installedDir, { recursive: true })
      .map(String)
      .map((entry) => entry.replaceAll("\\", "/"));
    for (const required of [
      "README.md",
      "LICENSE",
      "package.json",
      SKILL_FILE,
    ]) {
      if (!listing.includes(required)) {
        fail(`the tarball is missing ${required}`);
      }
    }
    const packedSkill = readFileSync(join(installedDir, SKILL_FILE), "utf8");
    if (
      !packedSkill.split("\n").includes(`  version: "${installed.version}"`)
    ) {
      fail(
        "the packaged skill version differs from the installed package version",
      );
    }
    const unexpected = listing.filter(
      (entry) =>
        entry.includes(".test.") ||
        entry.includes("_test_") ||
        entry.startsWith("src/"),
    );
    if (unexpected.length > 0) {
      fail(`the tarball contains ${unexpected.join(", ")}`);
    }

    const subpaths = Object.keys(manifest.exports).filter(
      (subpath) => subpath !== "./package.json",
    );
    const consumerSource = readFileSync(join(smokeDir, "consumer.tsx"), "utf8");
    const unimported = subpaths.filter(
      (subpath) =>
        !consumerSource.includes(`"${manifest.name}${subpath.slice(1)}"`),
    );
    if (unimported.length > 0) {
      fail(
        `scripts/npm-smoke/consumer.tsx does not import [${unimported.join(", ")}]`,
      );
    }
    for (const subpath of subpaths) {
      const target = installed.exports[subpath] as
        | { types: string; default: string }
        | undefined;
      for (const file of [target?.types, target?.default]) {
        if (!file || !listing.includes(file.replace(/^\.\//, ""))) {
          fail(
            `export ${subpath} points at ${file}, which is not in the tarball`,
          );
        }
      }
    }

    checkBin(consumerDir, listing);
    const workspaceHelp = run(
      "npm",
      ["run", "auth:dev", "--", "--help"],
      appDir,
      "pipe",
    );
    if (!workspaceHelp.includes("Run a local identity provider")) {
      fail("the workspace's auth:dev script did not resolve the installed CLI");
    }
    await checkIdpDev(consumerDir);

    const nonNpm = Object.entries(installed.dependencies ?? {}).filter(
      ([, spec]) => spec.includes("jsr"),
    );
    if (nonNpm.length > 0) {
      const names = nonNpm.map(([name, spec]) => `${name}@${spec}`).join(", ");
      if (releaseMode) {
        fail(`the package depends on JSR-resolved packages: ${names}`);
      }
      console.warn(
        `npm smoke: WARNING dependencies resolve through JSR (${names}); publish only after switching them to npm versions`,
      );
    }

    if (installOnly) {
      console.log(
        `npm smoke: ${tarballs[0]} installed with npm ${npmVersion} and ran its command on Node ${process.version}`,
      );
      return;
    }

    copyFileSync(
      join(smokeDir, "consumer.tsx"),
      join(consumerDir, "consumer.tsx"),
    );
    copyFileSync(join(smokeDir, "main.mjs"), join(consumerDir, "main.mjs"));
    writeFileSync(
      join(consumerDir, "tsconfig.json"),
      JSON.stringify({
        compilerOptions: {
          target: "ES2022",
          lib: ["ESNext", "DOM", "DOM.Iterable"],
          module: "NodeNext",
          moduleResolution: "NodeNext",
          types: ["node"],
          jsx: "react-jsx",
          strict: true,
          noEmit: true,
          skipLibCheck: false,
        },
        include: ["consumer.tsx"],
      }),
    );
    run(process.execPath, [tscPath, "-p", "."], consumerDir);

    if (process.env.QUICKSTART_BROWSER === "1") {
      const { checkHostedQuickstart } = await import("./quickstart-browser.ts");
      await checkHostedQuickstart(consumerDir);
      console.log(
        "npm smoke: hosted quickstart passed first sign-in and sign-out from both entry points",
      );
    }

    const output = run(process.execPath, ["main.mjs"], consumerDir);
    if (!output.includes("imported")) fail(`unexpected output: ${output}`);
    console.log(
      `npm smoke: ${tarballs[0]} type-checked ${subpaths.length} subpaths and ran on Node ${process.version}`,
    );
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

if (isMain(import.meta.url)) await main();
