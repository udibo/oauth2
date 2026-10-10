/**
 * Documentation gate: every symbol an entrypoint in `jsr.json` exports needs a
 * JSDoc comment, and so does every public member of an exported interface,
 * class, or object type. JSR renders "no documentation available" for what is
 * missing, which is what adopters read first.
 *
 * Type visibility (a public signature naming an unexported type) is not
 * checked here: `tsc` reports it under `declaration` and
 * `isolatedDeclarations`, and `pnpm check` runs `tsc`.
 *
 * @module
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { apiReferenceFiles, entrypoints, publicSymbols } from "./_exports.ts";
import { isMain } from "./_main.ts";

/** A declaration that has no JSDoc comment. */
export interface UndocumentedDeclaration {
  /** `src/`-relative path of the file that declares it. */
  file: string;
  /** 1-based line of the declaration. */
  line: number;
  /** Exported name, or `Owner.member` for a member. */
  name: string;
}

const DECLARATION =
  /^export\s+(?:declare\s+)?(?:abstract\s+)?(?:async\s+)?(?:function\*?|const|let|var|class|interface|type|enum|namespace)\s+([A-Za-z_$][\w$]*)/;
const MEMBER_MODIFIERS =
  /^(?:(?:public|static|readonly|abstract|override|async|declare|get|set)\s+)*/;

function isDocumented(lines: string[], index: number): boolean {
  for (let at = index - 1; at >= 0; at--) {
    const text = lines[at]!.trim();
    if (text.startsWith("//") || text.startsWith("@")) continue;
    return text.endsWith("*/");
  }
  return false;
}

function memberName(text: string): string | null {
  if (/^(?:\/\*|\*|\/\/|[})\]|>@])/.test(text)) return null;
  if (/^(?:private|protected)\b/.test(text) || text.startsWith("#")) {
    return null;
  }
  const rest = text.replace(MEMBER_MODIFIERS, "");
  if (rest.startsWith("[")) return rest.slice(1, rest.indexOf(":")).trim();
  if (rest.startsWith("#")) return null;
  return /^[A-Za-z_$][\w$]*|^["'][^"']+["']/.exec(rest)?.[0] ?? null;
}

function bodyStart(lines: string[], from: number): number {
  for (let at = from; at < lines.length; at++) {
    const text = lines[at]!.trimEnd();
    if (text.endsWith("{")) return at;
    if (at > from && /^\S/.test(lines[at]!)) return -1;
    if (text.endsWith(";") && !text.endsWith("{")) return -1;
  }
  return -1;
}

/**
 * Lists the exported declarations of `source` that lack a JSDoc comment,
 * limited to `exported` names, together with the public members of the
 * exported interfaces, classes, and object types. A repeated overload is
 * judged by its first signature.
 */
export function findUndocumented(
  file: string,
  source: string,
  exported: ReadonlySet<string>,
): UndocumentedDeclaration[] {
  const lines = source.split("\n");
  const found: UndocumentedDeclaration[] = [];
  const declared = new Set<string>();
  for (let index = 0; index < lines.length; index++) {
    const match = DECLARATION.exec(lines[index]!);
    if (!match) continue;
    const name = match[1]!;
    if (!exported.has(name) || declared.has(name)) continue;
    declared.add(name);
    if (!isDocumented(lines, index)) {
      found.push({ file, line: index + 1, name });
    }
    const head = lines[index]!;
    const kind = /\b(class|interface|type)\b/.exec(head)?.[1];
    if (kind !== "class" && kind !== "interface" && kind !== "type") continue;
    const open = bodyStart(lines, index);
    if (open === -1) continue;
    if (kind === "type" && !/=\s*\{$/.test(lines[open]!.trimEnd())) continue;
    const members = new Set<string>();
    let close = open + 1;
    while (close < lines.length && !lines[close]!.startsWith("}")) close++;
    const body = lines.slice(open + 1, close);
    if (kind === "type" && body.some((text) => /^ {2}new\s*[<(]/.test(text))) {
      continue;
    }
    for (let at = open + 1; at < close; at++) {
      if (!/^ {2}\S/.test(lines[at]!)) continue;
      const memberLabel = memberName(lines[at]!.trim());
      if (memberLabel === null || members.has(memberLabel)) continue;
      members.add(memberLabel);
      if (!isDocumented(lines, at)) {
        found.push({ file, line: at + 1, name: `${name}.${memberLabel}` });
      }
    }
  }
  return found;
}

function main(): number {
  const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
  const symbols = publicSymbols(root);
  const files = apiReferenceFiles(root, symbols);
  const findings: UndocumentedDeclaration[] = [];
  for (const file of files) {
    const names = new Set(
      symbols.filter((symbol) => symbol.file === file).map((s) => s.name),
    );
    const source = readFileSync(resolve(root, "src", file), "utf8");
    findings.push(...findUndocumented(file, source, names));
  }
  if (findings.length > 0) {
    console.error(
      findings
        .map(({ file, line, name }) => `src/${file}:${line} ${name}`)
        .join("\n"),
    );
    console.error(
      `\ndoc-lint: ${findings.length} undocumented declaration(s). ` +
        "Every exported symbol and public member needs contract-level JSDoc.",
    );
    return 1;
  }
  const entrypointCount = Object.keys(entrypoints(root)).length;
  console.log(`doc-lint: ${entrypointCount} entrypoints clean.`);
  return 0;
}

if (isMain(import.meta.url)) {
  process.exit(main());
}
