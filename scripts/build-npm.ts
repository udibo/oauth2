/**
 * Builds the `@udibo/oauth2` npm artifact from `src/` with dnt
 * (`@deno/dnt`), into `npm/`.
 *
 * The artifact mirrors the JSR package: same name, same version (read from
 * `src/deno.json`, or overridden by the first CLI argument so the release
 * pipeline can stamp the version it is about to publish), and the same
 * subpath exports minus `./cli` — the one entrypoint the README's runtime
 * table marks Deno-only (`Deno.serve` has no Node shim).
 *
 * Nothing here publishes anywhere. CI runs this task and then
 * `scripts/npm-smoke.ts`, which installs the packed tarball into
 * `npm-smoke-consumer/` and proves the Node claims in the README's runtime
 * table.
 *
 * Usage: `deno task npm:build [version]`
 */
import { build, emptyDir } from "@deno/dnt";
import { fileURLToPath } from "node:url";

/**
 * Subpaths of the JSR package deliberately left out of the npm artifact.
 * `./cli` is a Deno-only development tool (`Deno.serve`, `Deno.args`) with a
 * documented `deno run jsr:@udibo/oauth2/cli` invocation; shimming it would
 * add `@deno/shim-deno` as a runtime dependency for every consumer and still
 * fail at `Deno.serve`, which the shim does not implement.
 */
export const DENO_ONLY_EXPORTS: readonly string[] = ["./cli"];

/**
 * npm configuration injected (as `npm_config_*` env) into dnt's internal
 * `npm install`, which resolves the artifact's type-check dependencies with
 * no lockfile: lifecycle scripts never run, and `before` ports the root
 * `minimumDependencyAge: P3D` policy to npm — a version published within the
 * last three days does not resolve here.
 */
export function npmInstallHardening(
  now: Date = new Date(),
): Record<string, string> {
  const threeDaysMs = 3 * 24 * 60 * 60 * 1000;
  return {
    npm_config_ignore_scripts: "true",
    npm_config_before: new Date(now.getTime() - threeDaysMs).toISOString(),
  };
}

interface SrcConfig {
  name: string;
  version: string;
  description: string;
  license: string;
  exports: Record<string, string>;
}

/**
 * Derives dnt entry points from the JSR export map so the npm artifact can
 * never drift from `src/deno.json`: every subpath except {@linkcode DENO_ONLY_EXPORTS}
 * is carried over under the same name.
 */
export function npmEntryPoints(
  exports: Record<string, string>,
  srcDir: string,
): { name: string; path: string }[] {
  return Object.entries(exports)
    .filter(([subpath]) => !DENO_ONLY_EXPORTS.includes(subpath))
    .map(([name, target]) => ({
      name,
      path: `${srcDir}/${target.replace(/^\.\//, "")}`,
    }));
}

async function main(): Promise<void> {
  const packageDir = fileURLToPath(new URL("../", import.meta.url));
  const srcConfig = JSON.parse(
    await Deno.readTextFile(`${packageDir}src/deno.json`),
  ) as SrcConfig;
  const version = Deno.args[0] ?? srcConfig.version;
  const outDir = `${packageDir}npm`;

  for (const [key, value] of Object.entries(npmInstallHardening())) {
    Deno.env.set(key, value);
  }

  await emptyDir(outDir);

  await build({
    entryPoints: npmEntryPoints(srcConfig.exports, `${packageDir}src`),
    outDir,
    configFile: `${packageDir}src/deno.json`,
    shims: {},
    test: false,
    scriptModule: false,
    declaration: "inline",
    skipSourceOutput: true,
    compilerOptions: {
      target: "ES2022",
      lib: ["ESNext", "DOM", "DOM.Iterable"],
      skipLibCheck: false,
      jsx: "react-jsx",
      jsxImportSource: "react",
    },
    filterDiagnostic(diagnostic): boolean {
      if (diagnostic.code === 5089) return false;
      const file = diagnostic.file?.fileName ?? "";
      return !file.includes("/deps/jsr.io/@std/testing/");
    },
    package: {
      name: srcConfig.name,
      version,
      description: srcConfig.description,
      license: srcConfig.license,
      repository: {
        type: "git",
        url: "git+https://github.com/udibo/oauth2.git",
      },
      bugs: { url: "https://github.com/udibo/oauth2/issues" },
      publishConfig: { access: "public" },
    },
    async postBuild(): Promise<void> {
      for (const file of ["README.md", "LICENSE", "SECURITY.md"]) {
        await Deno.copyFile(`${packageDir}${file}`, `${outDir}/${file}`);
      }
    },
  });
}

if (import.meta.main) await main();
