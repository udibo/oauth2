/**
 * Consumes the packed npm artifact the way an adopter would: packs the
 * package, installs the tarball into an empty project with the peer
 * dependencies pinned to the versions this repository tests with,
 * type-checks a consumer that imports every subpath under NodeNext
 * resolution, and imports every subpath on Node.
 *
 * Run `pnpm build` first, then `pnpm smoke`. With `--release` the run also
 * fails when a runtime dependency resolves through JSR instead of npm, which
 * a published package must not do.
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
import { fileURLToPath } from "node:url";

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
const CONSUMER_PINS = [
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
  devDependencies: Record<string, string>,
): Record<string, string> {
  const pinned: Record<string, string> = {};
  for (const name of CONSUMER_PINS) {
    const range = devDependencies[name];
    if (range === undefined) fail(`devDependencies does not pin ${name}`);
    const installed = readManifest(
      join(packageDir, "node_modules", name, "package.json"),
    );
    pinned[name] = installed.version;
  }
  return pinned;
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
  const child = spawn(process.execPath, [entry, "idp", "dev", "--port", "0"], {
    cwd: consumerDir,
    stdio: ["ignore", "pipe", "ignore"],
  });
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
      fail(`idp dev answered discovery with ${response.status}`);
  } finally {
    child.kill("SIGTERM");
    await exited;
  }
}

async function main(): Promise<void> {
  const manifest = readManifest(join(packageDir, "package.json"));
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

    writeFileSync(
      join(consumerDir, "package.json"),
      JSON.stringify({
        name: "oauth2-smoke-consumer",
        private: true,
        type: "module",
        dependencies: exactVersions(manifest.devDependencies ?? {}),
      }),
    );
    writeFileSync(
      join(consumerDir, ".npmrc"),
      "@jsr:registry=https://npm.jsr.io\n",
    );
    run(
      "npm",
      [
        "install",
        "--no-audit",
        "--no-fund",
        "--ignore-scripts",
        "--before",
        new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
        tarball,
      ],
      consumerDir,
    );

    const installedDir = join(consumerDir, "node_modules", "@udibo", "oauth2");
    const installed = readManifest(join(installedDir, "package.json"));
    const listing = readdirSync(installedDir, { recursive: true })
      .map(String)
      .map((entry) => entry.replaceAll("\\", "/"));
    for (const required of ["README.md", "LICENSE", "package.json"]) {
      if (!listing.includes(required)) {
        fail(`the tarball is missing ${required}`);
      }
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

    const output = run(process.execPath, ["main.mjs"], consumerDir);
    if (!output.includes("imported")) fail(`unexpected output: ${output}`);
    console.log(
      `npm smoke: ${tarballs[0]} type-checked ${subpaths.length} subpaths and ran on Node ${process.version}`,
    );
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

await main();
