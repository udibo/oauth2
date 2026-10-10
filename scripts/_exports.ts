/**
 * Finds the public surface of the package from its source: which entrypoints
 * `jsr.json` publishes and which symbol each one exports, following
 * `export { } from` and `export * from` to the file that declares the symbol.
 * `doc-check` and `doc-lint` share it so both judge the same set of symbols.
 *
 * The scan reads declarations rather than running the compiler, which holds
 * because the source is formatted by `oxfmt` and exports its symbols with
 * explicit `export` statements. `_exports.test.ts` compares the result with
 * what each entrypoint exports at runtime.
 *
 * @module
 */
import { readFileSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";

/** A public symbol and the entrypoint specifier a consumer imports it from. */
export interface PublicSymbol {
  /** Exported name. */
  name: string;
  /** Path of the file that declares it, relative to `src/`, with `/` separators. */
  file: string;
  /** Specifier to import it from, e.g. `@udibo/oauth2/server`. */
  specifier: string;
}

const DECLARATION =
  /^export\s+(?:declare\s+)?(?:abstract\s+)?(?:async\s+)?(?:function\*?|const|let|var|class|interface|type|enum|namespace)\s+([A-Za-z_$][\w$]*)/gm;
const NAMED_EXPORT =
  /^export\s+(?:type\s+)?\{([^}]*)\}(?:\s*from\s*["']([^"']+)["'])?/gm;
const STAR_EXPORT =
  /^export\s+\*(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*from\s*["']([^"']+)["']/gm;
const NAMED_IMPORT =
  /^import\s+(?:type\s+)?\{([^}]*)\}\s*from\s*["']([^"']+)["']/gm;

function posix(path: string): string {
  return path.split(sep).join("/");
}

function bindings(list: string): { local: string; exported: string }[] {
  return list
    .split(",")
    .map((part) => part.replace(/\/\/.*$/gm, "").trim())
    .filter((part) => part !== "")
    .map((part) => {
      const [local, exported = local] = part
        .replace(/^type\s+/, "")
        .split(/\s+as\s+/);
      return { local: local!.trim(), exported: exported.trim() };
    });
}

function relativeTarget(from: string, specifier: string): string | null {
  return specifier.startsWith(".") ? resolve(dirname(from), specifier) : null;
}

/**
 * Maps every name `file` exports to the absolute path of the file that
 * declares it. `seen` holds the files being resolved, which breaks import cycles. Names re-exported from a package outside `src/` are omitted.
 */
export function exportedNames(
  file: string,
  seen: Set<string> = new Set(),
): Map<string, string> {
  const names = new Map<string, string>();
  if (seen.has(file)) return names;
  seen.add(file);
  const text = readFileSync(file, "utf8");

  for (const match of text.matchAll(DECLARATION)) {
    names.set(match[1]!, file);
  }

  const imported = new Map<string, { target: string; name: string }>();
  for (const match of text.matchAll(NAMED_IMPORT)) {
    const target = relativeTarget(file, match[2]!);
    if (!target) continue;
    for (const { local, exported } of bindings(match[1]!)) {
      imported.set(exported, { target, name: local });
    }
  }

  for (const match of text.matchAll(NAMED_EXPORT)) {
    const from = match[2];
    const target = from ? relativeTarget(file, from) : null;
    if (from && !target) continue;
    for (const { local, exported } of bindings(match[1]!)) {
      if (target) {
        const origin = exportedNames(target, seen).get(local);
        if (origin) names.set(exported, origin);
        continue;
      }
      const viaImport = imported.get(local);
      if (viaImport) {
        const origin = exportedNames(viaImport.target, seen).get(
          viaImport.name,
        );
        if (origin) names.set(exported, origin);
      } else {
        names.set(exported, file);
      }
    }
  }

  for (const match of text.matchAll(STAR_EXPORT)) {
    const target = relativeTarget(file, match[2]!);
    if (!target) continue;
    if (match[1]) {
      names.set(match[1], file);
      continue;
    }
    for (const [name, origin] of exportedNames(target, seen)) {
      if (!names.has(name)) names.set(name, origin);
    }
  }
  seen.delete(file);
  return names;
}

/** The `jsr.json` export map: subpath (`./server`) to source path (`./src/server/mod.ts`). */
export function entrypoints(root: string): Record<string, string> {
  const config = JSON.parse(
    readFileSync(resolve(root, "jsr.json"), "utf8"),
  ) as {
    exports: Record<string, string>;
  };
  return config.exports;
}

/** Every symbol every entrypoint exports, with the specifier a consumer imports it from. */
export function publicSymbols(root: string): PublicSymbol[] {
  const srcDir = resolve(root, "src");
  const symbols: PublicSymbol[] = [];
  for (const [subpath, path] of Object.entries(entrypoints(root))) {
    const specifier = `@udibo/oauth2${subpath.slice(1)}`;
    for (const [name, declaredIn] of exportedNames(resolve(root, path))) {
      symbols.push({
        name,
        file: posix(relative(srcDir, declaredIn)),
        specifier,
      });
    }
  }
  return symbols;
}

/**
 * The files that make up the API reference: every entrypoint plus every file
 * declaring a symbol one exports, as `src/`-relative paths, tests excluded.
 */
export function apiReferenceFiles(
  root: string,
  symbols: PublicSymbol[],
): string[] {
  const srcDir = resolve(root, "src");
  const files = Object.values(entrypoints(root)).map((path) =>
    posix(relative(srcDir, resolve(root, path))),
  );
  return [...new Set([...files, ...symbols.map((symbol) => symbol.file)])]
    .filter((file) => !/\.test\.tsx?$/.test(file))
    .sort();
}
