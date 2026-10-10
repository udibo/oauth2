import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { createTree, type TestTree } from "./_test_tree.ts";
import {
  apiReferenceFiles,
  entrypoints,
  exportedNames,
  publicSymbols,
} from "./_exports.ts";

const repoRoot = resolve(fileURLToPath(new URL("../", import.meta.url)));

let tree: TestTree | undefined;
afterEach(() => tree?.dispose());

function namesOf(files: Record<string, string>, entry: string): string[] {
  tree = createTree();
  for (const [path, content] of Object.entries(files)) {
    tree.write(path, content);
  }
  return [...exportedNames(resolve(tree.root, entry)).keys()].sort();
}

describe("exportedNames", () => {
  it("lists declarations of every exported kind", () => {
    expect(
      namesOf(
        {
          "a.ts": [
            "export function f() {}",
            "export async function g() {}",
            "export const h = 1;",
            "export class C {}",
            "export abstract class D {}",
            "export interface I {}",
            "export type T = string;",
            "export enum E {}",
            "const hidden = 1;",
          ].join("\n"),
        },
        "a.ts",
      ),
    ).toEqual(["C", "D", "E", "I", "T", "f", "g", "h"]);
  });

  it("follows a named re-export, a rename, and type-only specifiers", () => {
    tree = createTree();
    tree.write("impl.ts", "export const a = 1;\nexport interface B {}\n");
    tree.write(
      "mod.ts",
      'export {\n  a as renamed,\n  type B,\n} from "./impl.ts";\n',
    );
    const names = exportedNames(resolve(tree.root, "mod.ts"));
    expect([...names.keys()].sort()).toEqual(["B", "renamed"]);
    expect(names.get("renamed")).toBe(resolve(tree.root, "impl.ts"));
  });

  it("follows a star export and keeps the declaring file", () => {
    tree = createTree();
    tree.write("impl.ts", "export const a = 1;\n");
    tree.write("mod.ts", 'export * from "./impl.ts";\nexport const own = 2;\n');
    const names = exportedNames(resolve(tree.root, "mod.ts"));
    expect(names.get("a")).toBe(resolve(tree.root, "impl.ts"));
    expect(names.get("own")).toBe(resolve(tree.root, "mod.ts"));
  });

  it("resolves a local export of an imported binding to the file that declares it", () => {
    tree = createTree();
    tree.write("impl.ts", "export const a = 1;\n");
    tree.write("mod.ts", 'import { a } from "./impl.ts";\nexport { a };\n');
    expect(exportedNames(resolve(tree.root, "mod.ts")).get("a")).toBe(
      resolve(tree.root, "impl.ts"),
    );
  });

  it("finds a symbol reachable through two star exports", () => {
    expect(
      namesOf(
        {
          "shared.ts": "export const shared = 1;\n",
          "left.ts": 'export * from "./shared.ts";\n',
          "right.ts": 'export * from "./shared.ts";\n',
          "mod.ts": 'export * from "./left.ts";\nexport * from "./right.ts";\n',
        },
        "mod.ts",
      ),
    ).toEqual(["shared"]);
  });

  it("stops at an import cycle", () => {
    expect(
      namesOf(
        {
          "a.ts": 'export * from "./b.ts";\nexport const a = 1;\n',
          "b.ts": 'export * from "./a.ts";\nexport const b = 1;\n',
        },
        "a.ts",
      ),
    ).toEqual(["a", "b"]);
  });

  it("omits names re-exported from another package", () => {
    expect(
      namesOf(
        { "mod.ts": 'export { HttpError } from "@udibo/http-error";\n' },
        "mod.ts",
      ),
    ).toEqual([]);
  });
});

describe("the package's public surface", () => {
  it("includes everything each entrypoint exports at runtime", async () => {
    const missing: string[] = [];
    for (const [subpath, path] of Object.entries(entrypoints(repoRoot))) {
      const file = resolve(repoRoot, path);
      const names = exportedNames(file);
      const runtime = Object.keys(await import(/* @vite-ignore */ file));
      for (const name of runtime) {
        if (!names.has(name)) missing.push(`${subpath}: ${name}`);
      }
    }
    expect(missing).toEqual([]);
  });

  it("maps every symbol to the specifier a consumer imports it from", () => {
    const symbols = publicSymbols(repoRoot);
    expect(symbols).toContainEqual({
      name: "randomToken",
      file: "utils/crypto.ts",
      specifier: "@udibo/oauth2/crypto",
    });
  });

  it("lists the entrypoint files and the files declaring their symbols, without tests", () => {
    const files = apiReferenceFiles(repoRoot, publicSymbols(repoRoot));
    expect(files).toContain("server/mod.ts");
    expect(files).toContain("utils/crypto.ts");
    expect(files.filter((file) => file.includes(".test."))).toEqual([]);
  });
});
