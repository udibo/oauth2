import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import { parse } from "yaml";

import { SKILL_FILE, skillAtVersion } from "./skill-version.ts";

const root = new URL("../", import.meta.url);
const skill = readFileSync(new URL(SKILL_FILE, root), "utf8");
const manifest = JSON.parse(
  readFileSync(new URL("package.json", root), "utf8"),
) as {
  version: string;
  bin: Record<string, string>;
  exports: Record<string, { types?: string }>;
};

function checkPins(source: string, version: string): void {
  const frontmatter = parse(source.split("---\n")[1]!) as {
    name: string;
    metadata: { version: string; targets: string };
  };
  expect(frontmatter.name).toBe("udibo-oauth2");
  expect(frontmatter.metadata).toMatchObject({
    version,
    targets: `@udibo/oauth2@${version}`,
  });
  expect(source).toContain(
    `npm install --save-exact @udibo/oauth2@${version}\n`,
  );
  const guides = [
    ...source.matchAll(
      /https:\/\/github\.com\/udibo\/oauth2\/blob\/([^/]+)\/(docs\/[^)\s]+)/g,
    ),
  ];
  expect(guides.length).toBeGreaterThan(0);
  for (const [, tag, path] of guides) {
    expect(tag).toBe(version);
    expect(existsSync(fileURLToPath(new URL(path!, root)))).toBe(true);
  }
}

describe("the package skill", () => {
  it("uses the package version, exported integration types and the installed CLI", () => {
    checkPins(skill, manifest.version);
    const subpaths = [...skill.matchAll(/`@udibo\/oauth2\/(.+?)`/g)].map(
      ([, subpath]) => `./${subpath}`,
    );
    expect(subpaths).toContain("./hono/resource-server");
    for (const subpath of subpaths)
      expect(manifest.exports[subpath]?.types).toBeDefined();
    expect(manifest.bin["udibo-oauth2"]).toBeDefined();
    expect(skill).toContain(
      '"auth:dev": "udibo-oauth2 idp dev --config idp.json"',
    );
    expect(skill).toContain("\n```sh\nnpm run auth:dev\n```\n");
  });

  it("updates the complete skill for a release and can safely repeat preparation", () => {
    const release = "1.2.3";
    const next = skillAtVersion(skill, release);
    checkPins(next, release);
    expect(skillAtVersion(next, release)).toBe(next);
    expect(() => skillAtVersion(skill, "")).toThrow(
      "Expected a package release version",
    );
  });
});
