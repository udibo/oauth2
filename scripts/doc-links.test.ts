import { afterEach, describe, expect, it } from "vitest";

import { createTree, type TestTree } from "./_test_tree.ts";
import { anchors, findProblems } from "./doc-links.ts";

let tree: TestTree | undefined;
afterEach(() => tree?.dispose());

function problemsFor(files: Record<string, string>): string[] {
  tree = createTree();
  for (const [path, content] of Object.entries(files)) {
    tree.write(path, content);
  }
  return findProblems(tree.root);
}

describe("anchors", () => {
  it("slugs headings the way GitHub does and numbers duplicates", () => {
    expect([
      ...anchors("# Title\n## Two words\n## Two words\n### `code` & more\n"),
    ]).toEqual(["title", "two-words", "two-words-1", "code--more"]);
  });

  it("ignores headings inside code fences", () => {
    expect([...anchors("```sh\n# not a heading\n```\n# Real\n")]).toEqual([
      "real",
    ]);
  });

  it("accepts explicit anchor elements", () => {
    expect(anchors('<a id="custom"></a>\n').has("custom")).toBe(true);
  });
});

describe("findProblems", () => {
  it("accepts links to existing files and headings", () => {
    expect(
      problemsFor({
        "README.md":
          "# Intro\n[guide](docs/guide.md#setup)\n[out](https://jsr.io)\n[here](#intro)\n",
        "docs/guide.md": "# Guide\n## Setup\n[back](../README.md)\n",
      }),
    ).toEqual([]);
  });

  it("reports a link to a file that does not exist", () => {
    expect(problemsFor({ "README.md": "[gone](docs/gone.md)\n" })).toEqual([
      "README.md: missing file docs/gone.md",
    ]);
  });

  it("reports a link to a heading that does not exist", () => {
    expect(
      problemsFor({
        "README.md": "[x](docs/guide.md#missing)\n",
        "docs/guide.md": "# Guide\n",
      }),
    ).toEqual(["README.md: missing heading docs/guide.md#missing"]);
  });

  it("resolves links relative to the document that holds them", () => {
    expect(
      problemsFor({
        "docs/guides/a.md": "[b](../b.md)\n[c](c.md)\n",
        "docs/b.md": "# B\n",
        "docs/guides/c.md": "# C\n",
      }),
    ).toEqual([]);
  });

  it("reports a reference to the private application repository", () => {
    expect(
      problemsFor({
        "README.md": "see https://github.com/udibo/udibo/issues/1\n",
      }),
    ).toEqual(["README.md: private reference github.com/udibo/udibo"]);
  });

  it("reports frontmatter and a changelog section in a guide", () => {
    expect(
      problemsFor({
        "docs/guide.md": "---\ntitle: x\n---\n# Guide\n## Changelog\n",
      }),
    ).toEqual([
      "docs/guide.md: internal document frontmatter",
      "docs/guide.md: per-document changelog",
    ]);
  });

  it("checks examples and templates READMEs too", () => {
    expect(
      problemsFor({ "examples/hono/x/README.md": "[gone](nope.md)\n" }),
    ).toEqual(["examples/hono/x/README.md: missing file nope.md"]);
  });
});
