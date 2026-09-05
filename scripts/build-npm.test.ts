import { assert, assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  DENO_ONLY_EXPORTS,
  npmEntryPoints,
  npmInstallHardening,
} from "./build-npm.ts";
import {
  FROZEN_INSTALL_ARGS,
  NPM_SPAWN_ENV,
  tarballInstallArgs,
  UNVERIFIED_ON_NODE,
} from "./npm-smoke.ts";

const packageDir = new URL("../", import.meta.url);
const srcExports = (JSON.parse(
  Deno.readTextFileSync(new URL("src/deno.json", packageDir)),
) as { exports: Record<string, string> }).exports;

describe("npm artifact entry points", () => {
  it("carries every JSR subpath except the Deno-only ones, same names", () => {
    const names = npmEntryPoints(srcExports, "src").map((entry) => entry.name);
    assertEquals(
      names,
      Object.keys(srcExports).filter(
        (subpath) => !DENO_ONLY_EXPORTS.includes(subpath),
      ),
    );
  });

  it("maps each entry point to its JSR target inside src/", () => {
    for (const { name, path } of npmEntryPoints(srcExports, "src")) {
      assertEquals(path, `src/${srcExports[name].replace(/^\.\//, "")}`);
    }
  });

  it("excludes only subpaths that still exist in the JSR export map", () => {
    for (const subpath of DENO_ONLY_EXPORTS) {
      assert(
        subpath in srcExports,
        `${subpath} is in DENO_ONLY_EXPORTS but no longer in src/deno.json ` +
          `exports; delete the stale exclusion`,
      );
    }
  });
});

describe("npm smoke coverage sets", () => {
  it("keeps the unverified-on-Node rows in step between the smoke halves", () => {
    const runtimeHalf = Deno.readTextFileSync(
      new URL("npm-smoke-consumer/main.mjs", packageDir),
    );
    const match = runtimeHalf.match(
      /export const UNVERIFIED_ON_NODE = (\[[^\]]*\])/,
    );
    assert(match, "main.mjs no longer declares UNVERIFIED_ON_NODE");
    assertEquals(JSON.parse(match[1].replace(/'/g, '"')), UNVERIFIED_ON_NODE);
  });

  it("leaves no subpath both excluded from the artifact and unverified", () => {
    assertEquals(
      UNVERIFIED_ON_NODE.filter((s) => DENO_ONLY_EXPORTS.includes(s)),
      [],
    );
  });

  it("marks only artifact subpaths as unverified", () => {
    for (const subpath of UNVERIFIED_ON_NODE) {
      assert(
        subpath in srcExports,
        `${subpath} is in UNVERIFIED_ON_NODE but not in src/deno.json exports`,
      );
    }
  });
});

describe("npm supply-chain freeze", () => {
  const consumerDir = new URL("npm-smoke-consumer/", packageDir);
  const consumerConfig = JSON.parse(
    Deno.readTextFileSync(new URL("package.json", consumerDir)),
  ) as { devDependencies: Record<string, string> };

  it("commits a lockfile that pins every registry dependency exactly", () => {
    const lock = JSON.parse(
      Deno.readTextFileSync(new URL("package-lock.json", consumerDir)),
    ) as { packages: Record<string, { version?: string }> };
    for (
      const [name, version] of Object.entries(consumerConfig.devDependencies)
    ) {
      assert(
        /^\d+\.\d+\.\d+$/.test(version),
        `${name}@${version} in npm-smoke-consumer/package.json is not an ` +
          `exact version — the lockfile can only freeze exact pins`,
      );
      assertEquals(
        lock.packages[`node_modules/${name}`]?.version,
        version,
        `${name} is pinned at ${version} but package-lock.json disagrees — ` +
          `regenerate it (cd npm-smoke-consumer && npm install)`,
      );
    }
  });

  it("does not gitignore the lockfile that freezes CI's registry code", () => {
    const gitignore = Deno.readTextFileSync(new URL(".gitignore", consumerDir));
    assert(!gitignore.includes("package-lock.json"));
  });

  it("disables lifecycle scripts for every npm invocation", () => {
    const npmrc = Deno.readTextFileSync(new URL(".npmrc", consumerDir));
    assert(npmrc.includes("ignore-scripts=true"));
    assertEquals(NPM_SPAWN_ENV.npm_config_ignore_scripts, "true");
    assertEquals(npmInstallHardening().npm_config_ignore_scripts, "true");
    assert(tarballInstallArgs("./x.tgz").includes("--ignore-scripts"));
  });

  it("installs registry dependencies only from the frozen lockfile", () => {
    assertEquals(FROZEN_INSTALL_ARGS[0], "ci");
  });

  it("installs the tarball offline, so an unpinned dependency fails loudly", () => {
    const args = tarballInstallArgs("./x.tgz");
    assert(args.includes("--offline"));
    assert(args.includes("--no-save"));
    assertEquals(args.at(-1), "./x.tgz");
  });

  it("ports minimumDependencyAge to dnt's internal npm install", () => {
    const now = new Date("2026-08-29T12:00:00.000Z");
    assertEquals(
      npmInstallHardening(now).npm_config_before,
      "2026-08-26T12:00:00.000Z",
    );
  });
});

describe("README runtime table", () => {
  const readme = Deno.readTextFileSync(new URL("README.md", packageDir));
  const runtimeSection = readme.split(/## Runtime support\r?\n/)[1]?.split(
    "\n## ",
  )[0];
  assert(runtimeSection, "the runtime-support section was not found");
  const rows = runtimeSection.split("\n")
    .filter((line) => line.startsWith("| "))
    .slice(2)
    .map((line) => {
      const cells = line.split("|").map((cell) => cell.trim());
      const subpaths = [...cells[1].matchAll(/`(\/[^`]+)`/g)]
        .map((match) => `.${match[1]}`);
      return { subpaths, deno: cells[2], node: cells[3] };
    });
  assert(rows.length >= 4, "the runtime-support table was not found");

  it("keeps the unverified row identical to UNVERIFIED_ON_NODE", () => {
    const unverified = rows.filter((row) => row.node === "Not verified");
    assertEquals(unverified.length, 1);
    assertEquals(unverified[0].subpaths, [...UNVERIFIED_ON_NODE]);
  });

  it("keeps the Deno-only row identical to DENO_ONLY_EXPORTS", () => {
    const denoOnly = rows.filter((row) => row.deno === "Deno only");
    assertEquals(denoOnly.length, 1);
    assertEquals(denoOnly[0].subpaths, [...DENO_ONLY_EXPORTS]);
    assertEquals(denoOnly[0].node, "Not supported");
  });

  it("limits other Node claims to the import and type smoke coverage", () => {
    for (const row of rows) {
      if (
        row.node === "Not verified" || row.deno === "Deno only"
      ) continue;
      assertEquals(
        row.node,
        "Import/type smoke-tested",
        "Node support must match the verified compatibility boundary",
      );
    }
  });
});
