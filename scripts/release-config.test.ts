import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";
import { describe, expect, it } from "vitest";

interface Step {
  name?: string;
  uses?: string;
  run?: string;
  if?: string;
  env?: Record<string, string>;
  with?: Record<string, unknown>;
  "continue-on-error"?: boolean;
}
interface Job {
  needs?: string[];
  if?: string;
  permissions?: Record<string, string>;
  steps: Step[];
}
interface Workflow {
  on: { pull_request: { types: string[] } };
  jobs: Record<string, Job>;
}

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (path: string): string => readFileSync(join(root, path), "utf8");
const workflowText = read(".github/workflows/ci-cd.yml");
const workflow = parse(workflowText) as Workflow;
const release = workflow.jobs.release!;

const releaseConfig = JSON.parse(read(".releaserc.json")) as {
  repositoryUrl?: string;
  plugins: (string | [string, Record<string, unknown>])[];
};
const pluginNames = releaseConfig.plugins.map((plugin) =>
  typeof plugin === "string" ? plugin : plugin[0],
);

function pluginOptions(name: string): Record<string, unknown> {
  for (const plugin of releaseConfig.plugins) {
    if (Array.isArray(plugin) && plugin[0] === name) return plugin[1];
  }
  throw new Error(`${name} is not configured`);
}

const manifest = JSON.parse(read("package.json")) as {
  devDependencies: Record<string, string>;
};

describe("release configuration", () => {
  it("treats a breaking change as a minor while the package is 0.x", () => {
    const rules = pluginOptions("@semantic-release/commit-analyzer")
      .releaseRules as { breaking?: boolean; release: string }[];
    expect(rules.find((rule) => rule.breaking)?.release).toBe("minor");
  });

  it("reads a ! in the commit header as a breaking change", () => {
    for (const name of [
      "@semantic-release/commit-analyzer",
      "@semantic-release/release-notes-generator",
    ]) {
      expect(pluginOptions(name).preset, name).toBe("conventionalcommits");
    }
  });

  it("type-checks the package before spending an immutable version", () => {
    expect(pluginNames).toContain("@sebbo2002/semantic-release-jsr");
    expect(JSON.stringify(releaseConfig)).not.toContain("--no-check");
  });

  it("publishes the repository root, which holds the built dist/", () => {
    expect(pluginNames).toContain("@semantic-release/npm");
    expect(JSON.stringify(releaseConfig)).not.toContain("pkgRoot");
  });

  it("commits the version files semantic-release rewrites, and no Deno file", () => {
    const assets = pluginOptions("@semantic-release/git").assets as string[];
    expect(assets).toEqual(["CHANGELOG.md", "package.json", "jsr.json"]);
  });

  it("verifies the release before any file is prepared or published", () => {
    expect(pluginNames.indexOf("@semantic-release/exec")).toBeLessThan(
      pluginNames.indexOf("@semantic-release/npm"),
    );
    expect(pluginOptions("@semantic-release/exec")).toHaveProperty(
      "verifyReleaseCmd",
    );
  });

  it("pins every release plugin and its preset to an exact devDependency", () => {
    const needed = [
      "semantic-release",
      "conventional-changelog-conventionalcommits",
      ...pluginNames.filter(
        (name) =>
          name !== "@semantic-release/commit-analyzer" &&
          name !== "@semantic-release/release-notes-generator",
      ),
    ];
    for (const name of needed) {
      expect(manifest.devDependencies[name], name).toMatch(/^\d+\.\d+\.\d+$/);
    }
  });
});

describe("release workflow", () => {
  it("stays skipped until the release gate variable is set", () => {
    const condition = release.if ?? "";
    expect(condition).toContain("vars.OAUTH2_RELEASE_ENABLED == 'true'");
    expect(condition).toContain("github.ref == 'refs/heads/main'");
    expect(condition).toContain("github.event_name == 'push'");
  });

  it("runs only after every other job passes", () => {
    const others = Object.keys(workflow.jobs).filter(
      (name) => name !== "release",
    );
    expect([...(release.needs ?? [])].sort()).toEqual(others.sort());
    expect(release.if ?? "").not.toMatch(
      /\b(?:always|cancelled|failure|success)\s*\(/i,
    );
  });

  it("requires a real browser test verdict without skipped or allowed failures", () => {
    const browser = workflow.jobs["react-browser"]!;
    expect(browser.if).toBeUndefined();
    const run = browser.steps.find(
      (step) => step.run?.trim() === "pnpm test:browser",
    );
    expect(run).toBeDefined();
    const install = browser.steps.findIndex((step) =>
      step.run?.includes("playwright install --with-deps chromium"),
    );
    expect(install).toBeGreaterThan(-1);
    expect(install).toBeLessThan(browser.steps.indexOf(run!));
    for (const step of browser.steps) {
      expect(step.if).toBeUndefined();
      expect(step["continue-on-error"] ?? false).toBe(false);
    }
  });

  it("mints an OIDC token instead of storing a registry credential", () => {
    expect(release.permissions).toEqual({
      contents: "write",
      "id-token": "write",
      issues: "write",
      "pull-requests": "write",
    });
    expect(workflowText).not.toMatch(/^\s*NPM_TOKEN:/m);
    expect(workflowText).not.toMatch(/NODE_AUTH_TOKEN/);
  });

  it("reads the whole history semantic-release derives the version from", () => {
    const checkout = release.steps.find((step) =>
      step.uses?.startsWith("actions/checkout@"),
    );
    expect(checkout?.with?.["fetch-depth"]).toBe(0);
  });

  it("pushes the release commit with the deploy key that bypasses branch protection", () => {
    const checkout = release.steps.find((step) =>
      step.uses?.startsWith("actions/checkout@"),
    );
    expect(checkout?.with?.["ssh-key"]).toBe("${{ secrets.DEPLOY_KEY }}");
  });

  it("pushes over the deploy key's SSH remote, not package.json's https URL", () => {
    expect(releaseConfig.repositoryUrl).toBe("git@github.com:udibo/oauth2.git");
  });

  it("checks branch commits and proposed squash text before PR admission", () => {
    const steps = workflow.jobs.test!.steps;
    const checkout = steps.find((step) =>
      step.uses?.startsWith("actions/checkout@"),
    );
    expect(checkout?.with?.["fetch-depth"]).toBe(0);
    const guard = steps.find((step) => step.run?.includes("--references-only"));
    expect(guard?.if).toContain("github.event_name == 'pull_request'");
    expect(guard?.env).toEqual({
      RELEASE_REFERENCE_BASE: "${{ github.event.pull_request.base.sha }}",
      RELEASE_REFERENCE_PR_TITLE: "${{ github.event.pull_request.title }}",
      RELEASE_REFERENCE_PR_BODY: "${{ github.event.pull_request.body }}",
    });
    expect(workflow.on.pull_request.types).toContain("edited");
  });

  it("refuses a JSR-resolved dependency before building or publishing anything", () => {
    const guard = release.steps.findIndex((step) =>
      step.run?.includes("verify-release.ts --dependencies-only"),
    );
    const build = release.steps.findIndex(
      (step) => step.run?.trim() === "pnpm build",
    );
    const smoke = release.steps.findIndex((step) =>
      step.run?.includes("npm-smoke.ts --release"),
    );
    const dryRun = release.steps.findIndex((step) =>
      step.run?.includes("semantic-release --dry-run"),
    );
    expect(guard).toBeGreaterThan(-1);
    expect(guard).toBeLessThan(build);
    expect(smoke).toBeGreaterThan(build);
    expect(smoke).toBeLessThan(dryRun);
  });

  it("prints the computed version before the step that publishes it", () => {
    const dryRun = release.steps.findIndex((step) =>
      step.run?.includes("semantic-release --dry-run"),
    );
    const publish = release.steps.findIndex((step) =>
      (step.run?.trim() ?? "").endsWith("semantic-release"),
    );
    expect(dryRun).toBeGreaterThan(-1);
    expect(publish).toBeGreaterThan(dryRun);
  });

  it("builds the package before semantic-release verifies npm auth", () => {
    const build = release.steps.findIndex(
      (step) => step.run?.trim() === "pnpm build",
    );
    const dryRun = release.steps.findIndex((step) =>
      step.run?.includes("semantic-release --dry-run"),
    );
    expect(build).toBeGreaterThan(-1);
    expect(build).toBeLessThan(dryRun);
  });

  it("never leaves npm authentication to setup-node's placeholder token", () => {
    const configuresRegistry = release.steps.some(
      (step) =>
        step.uses?.startsWith("actions/setup-node@") &&
        step.with?.["registry-url"] !== undefined,
    );
    expect(configuresRegistry).toBe(false);
  });

  it("runs an npm new enough for trusted publishing", () => {
    expect(
      release.steps.some((step) => step.run?.includes("npm install -g npm@")),
    ).toBe(true);
  });

  it("gives both semantic-release invocations the same credentials", () => {
    const runs = release.steps.filter((step) =>
      /semantic-release( --dry-run)?$/.test(step.run?.trim() ?? ""),
    );
    expect(runs).toHaveLength(2);
    const [dryRun, publish] = runs.map((step) =>
      Object.keys(step.env ?? {}).sort(),
    );
    expect(dryRun).toEqual(publish);
    expect(dryRun).toContain("GITHUB_TOKEN");
  });

  it("takes no shared dependency cache into the job that holds id-token", () => {
    for (const step of release.steps) {
      expect(step.with?.cache, step.name).toBeUndefined();
    }
  });

  it("installs from the lockfile only", () => {
    for (const job of Object.values(workflow.jobs)) {
      for (const step of job.steps) {
        if (step.run?.includes("pnpm install")) {
          expect(step.run).toContain("--frozen-lockfile");
        }
      }
    }
  });

  it("builds and Node-smokes the npm package in a gating job", () => {
    const steps = workflow.jobs.package!.steps;
    for (const task of ["pnpm build", "pnpm smoke", "pnpm jsr:dry-run"]) {
      expect(
        steps.some((step) => step.run?.trim() === task),
        task,
      ).toBe(true);
    }
  });

  it("runs the matrix on Node 22, 24 and 26 and on Windows and macOS", () => {
    const include = (
      workflow.jobs.test as unknown as {
        strategy: { matrix: { include: { os: string; node: number }[] } };
      }
    ).strategy.matrix.include;
    const ubuntu = include.filter((entry) => entry.os === "ubuntu-latest");
    expect(ubuntu.map((entry) => entry.node).sort((a, b) => a - b)).toEqual([
      22, 24, 26,
    ]);
    expect(include.map((entry) => entry.os)).toEqual(
      expect.arrayContaining(["windows-latest", "macos-latest"]),
    );
  });
});

describe("every workflow", () => {
  const dir = join(root, ".github", "workflows");
  const files = readdirSync(dir).filter((name) => name.endsWith(".yml"));

  it("pins each action to a full commit SHA", () => {
    const unpinned: string[] = [];
    for (const file of files) {
      const text = readFileSync(join(dir, file), "utf8");
      for (const match of text.matchAll(/^\s*(?:-\s+)?uses:\s*(\S+)/gm)) {
        if (!/@[0-9a-f]{40}$/.test(match[1]!))
          unpinned.push(`${file}: ${match[1]}`);
      }
    }
    expect(unpinned).toEqual([]);
  });

  it("does not use Deno", () => {
    for (const file of files) {
      expect(readFileSync(join(dir, file), "utf8"), file).not.toMatch(/deno/i);
    }
  });
});
