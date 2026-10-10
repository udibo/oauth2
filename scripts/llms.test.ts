import { afterEach, describe, expect, it } from "vitest";

import { createTree, type TestTree } from "./_test_tree.ts";
import { findProblems, render } from "./llms.ts";

const INDEX = [
  "# Package",
  "",
  "Summary.",
  "",
  "## Docs",
  "",
  "- [Guide](docs/guide.md): the guide",
  "- [Setup](docs/guide.md#setup): section link, same page",
  "- [Example](examples/hono/a/README.md): an example",
  "",
  "## Optional",
  "",
  "- [Site](https://example.com)",
  "",
].join("\n");

let tree: TestTree | undefined;
afterEach(() => tree?.dispose());

function fixture(overrides: Record<string, string> = {}): TestTree {
  tree = createTree();
  const files: Record<string, string> = {
    "llms.txt": INDEX,
    "README.md": "[guide](docs/guide.md)\n",
    "docs/guide.md": "# Guide\n[sibling](other.md)\n## Setup\n",
    "examples/hono/a/README.md": "# A\n[parent](../../../docs/guide.md)\n",
    ...overrides,
  };
  for (const [path, content] of Object.entries(files)) {
    tree.write(path, content);
  }
  return tree;
}

function writeFull(t: TestTree): void {
  t.write("llms-full.txt", render(t.root, INDEX));
}

describe("render", () => {
  it("concatenates the pages in index order, once each, with absolute links", () => {
    const t = fixture();
    const full = render(t.root, INDEX);
    expect(full.match(/llms-full:source=/g)).toHaveLength(3);
    expect(full.indexOf("source=docs/guide.md")).toBeLessThan(
      full.indexOf("source=examples/hono/a/README.md"),
    );
    expect(full).toContain(
      "[sibling](https://github.com/udibo/oauth2/blob/main/docs/other.md)",
    );
    expect(full).toContain(
      "[parent](https://github.com/udibo/oauth2/blob/main/docs/guide.md)",
    );
  });

  it("stops the header at the Docs section", () => {
    const t = fixture();
    expect(render(t.root, INDEX)).not.toContain("## Optional");
  });
});

describe("findProblems", () => {
  it("passes when the corpus is indexed and llms-full.txt is current", () => {
    const t = fixture();
    writeFull(t);
    expect(findProblems(t.root)).toEqual([]);
  });

  it("reports a page the index does not link", () => {
    const t = fixture({ "docs/orphan.md": "# Orphan\n" });
    writeFull(t);
    expect(findProblems(t.root)).toEqual([
      "not linked from llms.txt: docs/orphan.md",
    ]);
  });

  it("reports a stale llms-full.txt", () => {
    const t = fixture();
    writeFull(t);
    t.write("docs/guide.md", "# Guide changed\n## Setup\n");
    expect(findProblems(t.root)).toEqual([
      "llms-full.txt is stale; run `pnpm llms:generate`",
    ]);
  });

  it("reports a missing llms-full.txt", () => {
    const t = fixture();
    expect(findProblems(t.root)).toEqual([
      "llms-full.txt is missing; run `pnpm llms:generate`",
    ]);
  });

  it("reports a dead link in the README", () => {
    const t = fixture({ "README.md": "[gone](docs/gone.md)\n" });
    writeFull(t);
    expect(findProblems(t.root)).toEqual([
      "dead link in README.md: docs/gone.md",
    ]);
  });
});
