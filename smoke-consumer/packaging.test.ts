/**
 * The packaging invariants a bad publish would violate.
 *
 * A JSR version is immutable, and the release pipeline has no rehearsal: these
 * assertions are the rehearsal. They read the same files the release reads —
 * `src/deno.json`, `.releaserc.json`, the example import maps and the release
 * workflow — and one of them runs the real `deno publish --dry-run` and asserts
 * on the payload it prints.
 *
 * @module
 */

import { assert, assertEquals, assertFalse } from "@std/assert";
import { beforeAll, describe, it } from "@std/testing/bdd";
import { parse as parseYaml } from "@std/yaml";

const packageDir = new URL("../", import.meta.url);

interface WorkflowStep {
  name?: string;
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
  env?: Record<string, string>;
}

interface WorkflowJob {
  needs?: string[];
  if?: string;
  permissions?: Record<string, string>;
  steps: WorkflowStep[];
}

interface Workflow {
  jobs: Record<string, WorkflowJob>;
}

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(Deno.readTextFileSync(new URL(path, packageDir)));
}

function readText(path: string): string {
  return Deno.readTextFileSync(new URL(path, packageDir));
}

function srcFilesImporting(dependency: string): string[] {
  const escaped = dependency.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const needle = new RegExp(
    `(?:\\bfrom|\\bimport)\\s*\\(?\\s*["']${escaped}(?:/[^"']*)?["']`,
  );
  const hits: string[] = [];
  const walk = (dir: URL, prefix: string): void => {
    for (const entry of Deno.readDirSync(dir)) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory) {
        walk(new URL(`${entry.name}/`, dir), rel);
      } else if (
        /\.tsx?$/.test(entry.name) &&
        needle.test(Deno.readTextFileSync(new URL(entry.name, dir)))
      ) {
        hits.push(rel);
      }
    }
  };
  walk(new URL("src/", packageDir), "");
  return hits;
}

function isDroppedByPublishExclude(file: string): boolean {
  return /\.test\.tsx?$/.test(file) || file.includes("_test_");
}

const packageConfig = readJson("src/deno.json");
const exports = packageConfig.exports as Record<string, string>;
const imports = packageConfig.imports as Record<string, string>;

const EXAMPLES = [
  "examples/hono/app-with-own-auth",
  "examples/hono/app-with-external-auth",
  "examples/hono/api-service",
  "examples/juniper/app-with-own-auth",
  "examples/juniper/app-with-external-auth",
];

const TEMPLATES = ["templates/juniper", "templates/react-router"];

const DEV_ONLY_DEPENDENCIES = [
  "@udibo/juniper",
  "@testing-library/react",
  "axe-core",
  "react-dom",
];

describe("published payload", () => {
  let published: string[];

  beforeAll(async () => {
    const command = new Deno.Command(Deno.execPath(), {
      args: ["task", "check:publish"],
      cwd: packageDir,
      stdout: "piped",
      stderr: "piped",
    });
    const { code, stdout, stderr } = await command.output();
    const output = new TextDecoder().decode(stdout) +
      new TextDecoder().decode(stderr);
    assertEquals(code, 0, `deno publish --dry-run failed:\n${output}`);
    published = [...output.replaceAll("\\", "/").matchAll(/\/src\/(.+?) \(/g)]
      .map((match) => match[1]);
    assert(published.length > 0, `no file list in:\n${output}`);
  });

  it("ships the README, license and linked documentation", () => {
    for (
      const file of [
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "llms.txt",
        "llms-full.txt",
        "docs/known-limitations.md",
      ]
    ) {
      assert(
        published.includes(file),
        `${file} missing from staged release payload`,
      );
    }
  });

  it("carries no test source", () => {
    const tests = published.filter((file) =>
      /\.test\.tsx?$/.test(file) || file.includes("_test_")
    );
    assertEquals(tests, []);
  });

  it("carries every module the export map promises", () => {
    for (const target of Object.values(exports)) {
      const file = target.replace(/^\.\//, "");
      assert(
        published.includes(file),
        `${file} is an entrypoint but was excluded from the payload`,
      );
    }
  });

  it("carries the testing entrypoints that only look like test files", () => {
    for (
      const file of [
        "testing/mod.ts",
        "testing/services.ts",
        "testing/server.ts",
        "testing/contract/mod.ts",
        "adapters/hono/bff/testing.ts",
        "react/testing.tsx",
      ]
    ) {
      assert(published.includes(file), `${file} was excluded from the payload`);
    }
  });
});

interface DocSymbol {
  name: string;
}

interface DocNode {
  symbols?: DocSymbol[];
}

interface DocOutput {
  nodes: Record<string, DocNode>;
}

/**
 * The complete `@udibo/oauth2/crypto` surface. The entrypoint is for callers
 * sealing their own cookies and minting their own tokens; anything the package
 * only needs internally belongs in an `_`-prefixed module instead.
 */
const CRYPTO_SURFACE = [
  "base64urlDecode",
  "base64urlEncode",
  "deriveAesKey",
  "deriveSealKey",
  "randomToken",
  "seal",
  "sealJson",
  "sha256Hash",
  "timingSafeEqualString",
  "toArrayBuffer",
  "unseal",
  "unsealJson",
];

/**
 * The symbols two entrypoints carry on purpose, each with the pair it belongs
 * to. `./server` is the half `./server/authorization` shares with
 * `./server/resource`; `./client` and `./server` share the error contract one
 * throws and the other catches; one discovery cache serves both the client and
 * the external identity flows. Any other name with two homes renders as two
 * JSR pages for one symbol, and a reader cannot tell which is canonical.
 */
const SHARED_BY_DESIGN: Record<string, readonly string[]> = {
  Authorization: ["./client", "./server"],
  authorizationFromClaims: ["./client", "./server"],
  checkRedirectUriPattern: ["./server", "./server/authorization"],
  DEFAULT_DISCOVERY_CACHE_MAX_ENTRIES: ["./client", "./identity/external"],
  DEFAULT_DISCOVERY_TTL_MS: ["./client", "./identity/external"],
  DiscoveryCache: ["./client", "./identity/external"],
  DiscoveryCacheEntry: ["./client", "./identity/external"],
  isOAuth2Error: ["./client", "./server"],
  isRedirectUriPattern: ["./server", "./server/authorization"],
  IsPublicSuffix: ["./server", "./server/authorization"],
  matchRedirectUri: ["./server", "./server/authorization"],
  MemoryDiscoveryCache: ["./client", "./identity/external"],
  MemoryDiscoveryCacheOptions: ["./client", "./identity/external"],
  OAuth2Error: ["./client", "./server"],
  OrganizationContext: ["./client", "./server"],
  RedirectUriPatternRule: ["./server", "./server/authorization"],
  RedirectUriPatternViolation: ["./server", "./server/authorization"],
};

describe("public surface naming", () => {
  let surface: Map<string, string[]>;

  beforeAll(async () => {
    const srcDir = new URL("src/", packageDir);
    const command = new Deno.Command(Deno.execPath(), {
      args: ["doc", "--json", ...Object.values(exports)],
      cwd: srcDir,
      stdout: "piped",
      stderr: "piped",
    });
    const { code, stdout, stderr } = await command.output();
    assertEquals(
      code,
      0,
      `deno doc --json failed:\n${new TextDecoder().decode(stderr)}`,
    );
    const doc: DocOutput = JSON.parse(new TextDecoder().decode(stdout));
    surface = new Map();
    for (const [file, node] of Object.entries(doc.nodes)) {
      const path = `./${file.split("/src/")[1]}`;
      const names = (node.symbols ?? []).map((symbol) => symbol.name);
      surface.set(path, [...new Set(names)].sort());
    }
    assert(surface.size > 0, "deno doc --json produced no entrypoints");
  });

  function exported(): string[] {
    return [...new Set([...surface.values()].flat())].sort();
  }

  function forEntrypoint(subpath: string): string[] {
    const target = exports[subpath];
    const names = surface.get(target);
    assert(names, `${subpath} resolved to no documented module`);
    return names;
  }

  it("spells the protocol OAuth2, never Oauth2", () => {
    assertEquals(exported().filter((name) => /^Oauth2/.test(name)), []);
  });

  it("names a call-time option bag *Options, never *Config", () => {
    assertEquals(exported().filter((name) => name.endsWith("Config")), []);
  });

  function entrypointsByName(): Map<string, string[]> {
    const homes = new Map<string, string[]>();
    for (const subpath of Object.keys(exports)) {
      for (const name of forEntrypoint(subpath)) {
        homes.set(name, [...(homes.get(name) ?? []), subpath].sort());
      }
    }
    return homes;
  }

  it("gives every symbol one entrypoint, unless the pair is deliberate", () => {
    const offenders = [...entrypointsByName()]
      .filter(([name, subpaths]) =>
        subpaths.length > 1 &&
        [...(SHARED_BY_DESIGN[name] ?? [])].sort().join() !== subpaths.join()
      )
      .map(([name, subpaths]) => `${name} (${subpaths.join(", ")})`)
      .sort();
    assertEquals(
      offenders,
      [],
      "each of these renders as two JSR pages for one symbol; drop the " +
        "re-export from the entrypoint a caller would not look in first, or " +
        "add the pair to SHARED_BY_DESIGN with the reason",
    );
  });

  it("lists nothing in SHARED_BY_DESIGN that has stopped being shared", () => {
    const homes = entrypointsByName();
    const stale = Object.keys(SHARED_BY_DESIGN)
      .filter((name) => (homes.get(name)?.length ?? 0) < 2)
      .sort();
    assertEquals(
      stale,
      [],
      "these symbols now have one home; delete their SHARED_BY_DESIGN entries",
    );
  });

  it("keeps ./crypto to the helpers a caller reaches for", () => {
    assertEquals(forEntrypoint("./crypto"), CRYPTO_SURFACE);
  });
});

describe("published dependency set", () => {
  it("keeps its dev-only dependencies out of the published payload", () => {
    const exclude =
      (packageConfig.publish as { exclude?: string[] } | undefined)?.exclude ??
        [];
    assert(
      exclude.some((glob) => glob.includes(".test.")) &&
        exclude.some((glob) => glob.includes("_test_")),
      "publish.exclude must drop the test files that import the dev-only deps",
    );
    for (const dependency of DEV_ONLY_DEPENDENCIES) {
      for (const importer of srcFilesImporting(dependency)) {
        assert(
          isDroppedByPublishExclude(importer),
          `${dependency} is imported by ${importer}, which publish.exclude ` +
            `does not drop, so JSR would publish it as a dependency. A ` +
            `dev-only dependency's only importers must be test files.`,
        );
      }
    }
  });

  it("pins the published React range, so widening it is a deliberate edit", () => {
    assertEquals(
      imports.react,
      "npm:react@^19.0.0",
      "a caret range over every 19.x is what lets an app dedupe to one React; " +
        "narrowing or widening it is how an app ends up with two copies",
    );
  });

  it("pins the published Hono range, so widening it is a deliberate edit", () => {
    assertEquals(
      imports.hono,
      "npm:hono@^4.7.0",
      "the floor is the oldest Hono the adapters' type imports resolve " +
        "against — `hono/utils/http-status`'s ContentfulStatusCode arrived in " +
        "4.6.15 — and nothing in this suite compiles against that floor, so " +
        "type-check the adapters against it before widening the range",
    );
  });

  it("keeps the assertion libraries the testing entrypoints import at runtime", () => {
    assert("@std/assert" in imports);
    assert("@std/testing" in imports);
  });
});

describe("example and template import maps", () => {
  it("declare @udibo/oauth2 so a copied directory resolves outside the workspace", () => {
    for (const directory of [...EXAMPLES, ...TEMPLATES]) {
      const config = readJson(`${directory}/deno.json`);
      const map = config.imports as Record<string, string>;
      assert(
        map["@udibo/oauth2"]?.startsWith("jsr:@udibo/oauth2@"),
        `${directory}/deno.json does not declare @udibo/oauth2`,
      );
    }
  });
});

describe("release configuration", () => {
  const releaseConfig = readJson(".releaserc.json");
  const plugins = releaseConfig.plugins as unknown[];

  function pluginOptions(name: string): Record<string, unknown> {
    for (const plugin of plugins) {
      if (Array.isArray(plugin) && plugin[0] === name) {
        return plugin[1] as Record<string, unknown>;
      }
    }
    throw new Error(`${name} is not configured`);
  }

  it("treats a breaking change as a minor while the package is 0.x", () => {
    const rules = pluginOptions("@semantic-release/commit-analyzer")
      .releaseRules as { breaking?: boolean; release: string }[];
    const breaking = rules.find((rule) => rule.breaking);
    assertEquals(breaking?.release, "minor");
  });

  it("type-checks the package before spending an immutable version", () => {
    const jsr = pluginOptions("@sebbo2002/semantic-release-jsr");
    const args = (jsr.publishArgs ?? []) as string[];
    assertFalse(args.includes("--no-check"));
  });

  it("prepares the exact release version before publishing", () => {
    const prepare = pluginOptions("@semantic-release/exec")
      .prepareCmd as string;
    assert(
      prepare.includes("deno task release:prepare ${nextRelease.version}"),
    );
    const assets = pluginOptions("@semantic-release/git").assets as string[];
    for (const directory of [...EXAMPLES, ...TEMPLATES]) {
      assert(assets.includes(`${directory}/deno.json`));
    }
  });

  it("does not require npm credentials to publish to JSR", () => {
    assertFalse(
      plugins.some((plugin) =>
        Array.isArray(plugin) && plugin[0] === "@semantic-release/npm"
      ),
    );
  });
});

describe("release workflow", () => {
  const workflow = parseYaml(
    readText(".github/workflows/ci-cd.yml"),
  ) as Workflow;
  const release = workflow.jobs["release-oauth2-package"];

  it("exists, so something actually publishes the package", () => {
    assert(release);
  });

  it("stays skipped until the release gate variable is set", () => {
    const condition = release.if ?? "";
    assert(condition.includes("vars.OAUTH2_RELEASE_ENABLED == 'true'"));
    assert(condition.includes("github.ref == 'refs/heads/main'"));
    assert(condition.includes("github.event_name == 'push'"));
  });

  it("runs only after the package's own checks and tests pass", () => {
    assertEquals(release.needs, ["oauth2-package"]);
  });

  it("mints an OIDC token instead of storing a JSR credential", () => {
    assertEquals(release.permissions, {
      "contents": "write",
      "id-token": "write",
      issues: "write",
      "pull-requests": "write",
    });
  });

  it("reads the whole history semantic-release derives the version from", () => {
    const checkout = release.steps.find((step) =>
      step.uses?.startsWith("actions/checkout@")
    );
    assertEquals(checkout?.with?.["fetch-depth"], 0);
  });

  it("prints the computed version before the step that publishes it", () => {
    const dryRun = release.steps.findIndex((step) =>
      step.run?.includes("semantic-release --dry-run")
    );
    const publish = release.steps.findIndex((step) =>
      /semantic-release$/.test(step.run?.trim() ?? "")
    );
    assert(dryRun !== -1, "no dry run step");
    assert(publish !== -1, "no publish step");
    assert(dryRun < publish, "the dry run must come first");
  });

  it("pins every npx package to an exact version", () => {
    const npxSteps = release.steps.filter((step) => step.run?.includes("npx"));
    assertEquals(npxSteps.length, 2);
    for (const step of npxSteps) {
      const run = step.run ?? "";
      for (const match of run.matchAll(/--package (\S+)/g)) {
        const spec = match[1];
        assert(
          /@\d+\.\d+\.\d+$/.test(spec),
          `${spec} is not pinned to an exact version`,
        );
      }
      assert(run.includes("@sebbo2002/semantic-release-jsr@3.2.1"));
    }
  });

  it("carries every configured release plugin in both npx package sets", () => {
    const releaseConfig = readJson(".releaserc.json");
    const configured = (releaseConfig.plugins as unknown[])
      .map((plugin) => (Array.isArray(plugin) ? plugin[0] : plugin) as string)
      .filter((name) =>
        name !== "@semantic-release/commit-analyzer" &&
        name !== "@semantic-release/release-notes-generator"
      );
    const npxSteps = release.steps.filter((step) => step.run?.includes("npx"));
    for (const step of npxSteps) {
      for (const name of configured) {
        assert(
          step.run?.includes(`--package ${name}@`),
          `${name} is configured in .releaserc.json but not pinned in the ` +
            `npx package set, so npx would resolve a floating version while ` +
            `id-token: write is active`,
        );
      }
    }
  });

  it("builds and Node-smokes the npm artifact in the gating job", () => {
    const steps = workflow.jobs["oauth2-package"].steps;
    for (const task of ["deno task npm:build", "deno task npm:smoke"]) {
      const step = steps.find((s) => s.run?.includes(task));
      assert(
        step,
        `oauth2-package never runs \`${task}\`, so the npm artifact and its ` +
          `Node smoke would go unexercised until the release job`,
      );
      assertEquals(
        step.env?.npm_config_ignore_scripts,
        "true",
        `the \`${task}\` step lets npm lifecycle scripts run on the ` +
          `self-hosted runner — set npm_config_ignore_scripts: "true"`,
      );
    }
  });

  it("takes no shared dependency cache into the job that holds id-token", () => {
    const setupDeno = release.steps.find((step) =>
      step.uses?.startsWith("denoland/setup-deno@")
    );
    assertEquals(setupDeno?.with?.cache, false);
  });

  it("runs semantic-release on Node, not Deno", () => {
    assert(
      release.steps.some((step) =>
        step.uses?.startsWith("actions/setup-node@")
      ),
    );
  });

  it("verifies the package publishes before the release job can run", () => {
    const steps = workflow.jobs["oauth2-package"].steps;
    assert(steps.some((step) => step.run?.includes("check:publish")));
  });
});
