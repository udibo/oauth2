import { describe, expect, it } from "vitest";

import { findUndocumented } from "./doc-lint.ts";

const exported = (...names: string[]): ReadonlySet<string> => new Set(names);

describe("findUndocumented", () => {
  it("accepts a documented exported symbol", () => {
    expect(
      findUndocumented(
        "a.ts",
        "/** Does a thing. */\nexport function f(): void {}\n",
        exported("f"),
      ),
    ).toEqual([]);
  });

  it("reports an exported symbol with no JSDoc", () => {
    expect(
      findUndocumented("a.ts", "export function f(): void {}\n", exported("f")),
    ).toEqual([{ file: "a.ts", line: 1, name: "f" }]);
  });

  it("does not count a blank line between the comment and the declaration", () => {
    expect(
      findUndocumented(
        "a.ts",
        "/** Does a thing. */\n\nexport const f = 1;\n",
        exported("f"),
      ),
    ).toEqual([{ file: "a.ts", line: 3, name: "f" }]);
  });

  it("does not count a line comment as documentation", () => {
    expect(
      findUndocumented(
        "a.ts",
        "// does a thing\nexport const f = 1;\n",
        exported("f"),
      ),
    ).toEqual([{ file: "a.ts", line: 2, name: "f" }]);
  });

  it("reads through a directive comment between the JSDoc and the declaration", () => {
    expect(
      findUndocumented(
        "a.ts",
        "/** Does a thing. */\n// oxlint-disable-next-line no-explicit-any\nexport const f = 1;\n",
        exported("f"),
      ),
    ).toEqual([]);
  });

  it("ignores exports that no entrypoint publishes", () => {
    expect(
      findUndocumented("a.ts", "export const internal = 1;\n", exported("f")),
    ).toEqual([]);
  });

  it("judges an overloaded function by its first signature", () => {
    expect(
      findUndocumented(
        "a.ts",
        [
          "/** First. */",
          "export function f(a: string): void;",
          "export function f(a: number): void;",
          "export function f(a: string | number): void {}",
        ].join("\n"),
        exported("f"),
      ),
    ).toEqual([]);
  });

  it("reports an undocumented interface property", () => {
    expect(
      findUndocumented(
        "a.ts",
        [
          "/** Shape. */",
          "export interface Shape {",
          "  /** Documented. */",
          "  a: string;",
          "  b: string;",
          "}",
        ].join("\n"),
        exported("Shape"),
      ),
    ).toEqual([{ file: "a.ts", line: 5, name: "Shape.b" }]);
  });

  it("reports an undocumented public class method but not a private member", () => {
    expect(
      findUndocumented(
        "a.ts",
        [
          "/** A class. */",
          "export class Box {",
          "  private secret = 1;",
          "  #hidden = 2;",
          "  open(): void {}",
          "}",
        ].join("\n"),
        exported("Box"),
      ),
    ).toEqual([{ file: "a.ts", line: 5, name: "Box.open" }]);
  });

  it("does not look inside a method body or a multi-line member type", () => {
    expect(
      findUndocumented(
        "a.ts",
        [
          "/** A class. */",
          "export class Box {",
          "  /** Opens. */",
          "  open(",
          "    flag: boolean,",
          "  ): void {",
          "    const inner = 1;",
          "  }",
          "}",
        ].join("\n"),
        exported("Box"),
      ),
    ).toEqual([]);
  });

  it("reports an undocumented property of an object type alias", () => {
    expect(
      findUndocumented(
        "a.ts",
        [
          "/** Options. */",
          "export type Options = {",
          "  a: string;",
          "};",
        ].join("\n"),
        exported("Options"),
      ),
    ).toEqual([{ file: "a.ts", line: 3, name: "Options.a" }]);
  });

  it("does not require JSDoc on the construct signature of a constructor type", () => {
    expect(
      findUndocumented(
        "a.ts",
        [
          "/** A constructor type. */",
          "export type Ctor = {",
          "  new (value: string): Thing;",
          "  prototype: Thing;",
          "};",
        ].join("\n"),
        exported("Ctor"),
      ),
    ).toEqual([]);
  });
});
