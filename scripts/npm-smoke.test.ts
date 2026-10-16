import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";
import { describe, expect, it } from "vitest";

import { pinnedConsumerNpmProblem } from "./npm-smoke.ts";

interface Step {
  name?: string;
  run?: string;
  if?: string;
}
interface Workflow {
  jobs: Record<
    string,
    { strategy?: { matrix?: { node?: number[] } }; steps: Step[] }
  >;
}

const root = fileURLToPath(new URL("../", import.meta.url));
const workflow = parse(
  readFileSync(join(root, ".github/workflows/ci-cd.yml"), "utf8"),
) as Workflow;
const packageJob = workflow.jobs.package!;

function stepsOnNode(node: number): Step[] {
  return packageJob.steps.filter(
    (step) => step.if === undefined || step.if === `matrix.node == ${node}`,
  );
}

function indexOfRun(steps: Step[], pattern: RegExp): number {
  return steps.findIndex((step) => pattern.test(step.run ?? ""));
}

describe("pinnedConsumerNpmProblem", () => {
  it("rejects npm 10, which crashes in #loadPeerSet on a trailing Vitest pin", () => {
    expect(pinnedConsumerNpmProblem("10.9.9")).toContain(
      "https://github.com/npm/cli/issues/9787",
    );
  });

  it("rejects the last npm 11 release before the fix", () => {
    expect(pinnedConsumerNpmProblem("11.5.0")).toContain("before 11.6.0");
  });

  it("accepts the first fixed npm and anything later", () => {
    expect(pinnedConsumerNpmProblem("11.6.0")).toBeUndefined();
    expect(pinnedConsumerNpmProblem("11.21.0\n")).toBeUndefined();
    expect(pinnedConsumerNpmProblem("12.0.0")).toBeUndefined();
  });

  it("rejects output it cannot read as a version", () => {
    expect(pinnedConsumerNpmProblem("not a version")).toContain(
      'cannot read the npm version from "not a version"',
    );
  });
});

describe("the package smoke job", () => {
  it("installs the tarball with Node 22's bundled npm before replacing it", () => {
    const steps = stepsOnNode(22);
    const bundled = indexOfRun(steps, /npm-smoke\.ts --install-only$/);
    const upgrade = indexOfRun(steps, /^npm install -g npm@/);
    const pinned = indexOfRun(steps, /^pnpm smoke$/);
    expect(bundled).toBeGreaterThan(-1);
    expect(upgrade).toBeGreaterThan(bundled);
    expect(pinned).toBeGreaterThan(upgrade);
  });

  it("upgrades Node 22 to an exact npm that can resolve the pinned consumer", () => {
    const upgrade = stepsOnNode(22).find((step) =>
      step.run?.startsWith("npm install -g npm@"),
    );
    const version = /npm@(\d+\.\d+\.\d+)$/.exec(upgrade?.run ?? "")?.[1];
    expect(version).toBeDefined();
    expect(pinnedConsumerNpmProblem(version!)).toBeUndefined();
  });

  it("runs the pinned consumer with the bundled npm on every newer Node", () => {
    const newer = (packageJob.strategy?.matrix?.node ?? []).filter(
      (node) => node > 22,
    );
    expect(newer.length).toBeGreaterThan(0);
    for (const node of newer) {
      const steps = stepsOnNode(node);
      expect(indexOfRun(steps, /^npm install -g npm@/)).toBe(-1);
      expect(indexOfRun(steps, /^pnpm smoke$/)).toBeGreaterThan(-1);
    }
  });
});
