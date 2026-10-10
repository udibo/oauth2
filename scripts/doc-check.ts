/**
 * Documentation gate: type-checks the code in the docs.
 *
 * Two sources feed one `tsc` run, so a snippet that no longer compiles
 * against the package fails CI the same way a broken source file does:
 *
 * - Every fenced `ts` / `tsx` block in `README.md` and `docs/**\/*.md`. These
 *   are whole programs and are held to the compiler's full strictness.
 * - Every `@example` block on the JSDoc of a file that is part of the API
 *   reference — the entrypoints in `src/deno.json` and the files whose symbols
 *   they export. This is what JSR renders, and it is the first code most
 *   adopters copy.
 *
 * An `@example` is a fragment rather than a program: it names the symbol it
 * documents without importing it, it leans on bindings the surrounding prose
 * supplies (`app`, `db`, a service the reader already has), and it is often the
 * inside of a handler, ending in a `return`. So each one is compiled with an
 * import prelude that pulls the package symbols it names from the entrypoint a
 * consumer would import them from, and the diagnostics that only say "this is a
 * fragment" — a bare `return`, a third-party module only the reader's app
 * installs — are tolerated. Everything else — an unresolvable path, a renamed
 * export, a wrong argument, a property that is not on the type — fails.
 *
 * An undeclared binding is the exception that used to swallow the rest: a free
 * `server` makes `server.authenticate(c)` an error type, so the call it
 * demonstrates is never checked at all, which is how an `@example` calling a
 * `Request` parameter with a Hono context shipped past a green gate. An example
 * therefore binds what it uses — `declare const server: ResourceServer<…>` —
 * and a free identifier fails. {@link UNDECLARED_BINDING_BASELINE} carries the
 * files whose examples predate the rule; the list only shrinks, and an entry
 * that has stopped being needed fails too.
 *
 * Blocks that are deliberately not checkable — interface shapes quoted for
 * reading, single option lines, pseudo-code over an app's own modules — opt out
 * with an `ignore` word in the info string (` ```ts ignore `), which is also
 * what makes the opt-outs countable and reviewable.
 *
 * The opt-outs are capped: exceeding `--ignore-budget` (default
 * {@linkcode DEFAULT_IGNORE_BUDGET}) fails the run, so the count can only
 * ratchet down. Lower the budget when a snippet stops needing its opt-out.
 *
 * @module
 */

import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  apiReferenceFiles,
  entrypoints,
  type PublicSymbol,
  publicSymbols,
} from "./_exports.ts";
import { isMain } from "./_main.ts";

export type { PublicSymbol };

/**
 * The number of `ignore`-marked snippets the package may carry today, across
 * both markdown fences and JSDoc `@example` blocks. Ratchet it down as opt-outs
 * are removed.
 */
export const DEFAULT_IGNORE_BUDGET = 13;

/** Where a snippet came from, which decides how strictly it is judged. */
export type SnippetOrigin = "markdown" | "jsdoc";

/** One checkable code block lifted out of the documentation. */
export interface Snippet {
  /** Package-relative path of the file the block was written in. */
  source: string;
  /** 1-based line of the opening fence, for the failure message. */
  fence: number;
  /** Fence language, which becomes the generated file's extension. */
  lang: "ts" | "tsx";
  /** The block's contents, with JSDoc comment markers already stripped. */
  code: string;
  /** Which of the two extractors produced it. */
  origin: SnippetOrigin;
}

/** Checkable blocks found in one file, plus how many opted out with `ignore`. */
export interface Extraction {
  /** Blocks to compile. */
  snippets: Snippet[];
  /** How many blocks carried an `ignore` word in the info string. */
  ignored: number;
}

const FENCE = /^\s*```(.*)$/;

function langOf(info: string[]): "ts" | "tsx" | null {
  return info[0] === "ts" || info[0] === "tsx" ? info[0] : null;
}

/**
 * Lifts the fenced `ts`/`tsx` blocks out of a markdown document. Blocks whose
 * info string contains `ignore` are counted, not returned.
 */
export function extractMarkdownSnippets(
  source: string,
  markdown: string,
): Extraction {
  const lines = markdown.split("\n");
  const snippets: Snippet[] = [];
  let ignored = 0;
  let index = 0;
  while (index < lines.length) {
    const opening = FENCE.exec(lines[index]!);
    if (!opening) {
      index++;
      continue;
    }
    const info = opening[1]!.trim().split(/\s+/);
    const lang = langOf(info);
    const start = index + 1;
    let end = start;
    while (end < lines.length && !FENCE.test(lines[end]!)) end++;
    if (lang) {
      if (info.includes("ignore")) {
        ignored++;
      } else {
        snippets.push({
          source,
          fence: index + 1,
          lang,
          code: lines.slice(start, end).join("\n"),
          origin: "markdown",
        });
      }
    }
    index = end + 1;
  }
  return { snippets, ignored };
}

/**
 * Lifts the fenced `ts`/`tsx` blocks that sit under an `@example` tag out of a
 * TypeScript file's JSDoc, stripping the ` * ` prefixes. A block whose info
 * string contains `ignore` is counted, not returned; blocks under any other tag
 * are not examples and are skipped.
 */
export function extractJsDocExamples(source: string, code: string): Extraction {
  const lines = code.split("\n");
  const snippets: Snippet[] = [];
  let ignored = 0;
  let inDoc = false;
  let inExample = false;
  let info: string[] = [];
  let lang: "ts" | "tsx" | null = null;
  let open = false;
  let buffer: string[] = [];
  let fence = 0;
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!.trim();
    if (!inDoc) {
      if (line.startsWith("/**")) inDoc = true;
      else continue;
    }
    const body = line
      .replace(/^\/\*\*/, "")
      .replace(/^\*\/?/, "")
      .replace(/^ /, "");
    if (!open) {
      if (/^@example\b/.test(body)) inExample = true;
      else if (/^@\w+/.test(body)) inExample = false;
      const opening = inExample ? FENCE.exec(body) : null;
      if (opening) {
        info = opening[1]!.trim().split(/\s+/);
        lang = langOf(info);
        open = true;
        buffer = [];
        fence = index + 1;
      }
    } else if (FENCE.test(body)) {
      if (lang) {
        if (info.includes("ignore")) {
          ignored++;
        } else {
          snippets.push({
            source,
            fence,
            lang,
            code: buffer.join("\n"),
            origin: "jsdoc",
          });
        }
      }
      open = false;
    } else {
      buffer.push(body);
    }
    if (line.includes("*/")) {
      inDoc = false;
      inExample = false;
      open = false;
    }
  }
  return { snippets, ignored };
}

/**
 * Builds the `import` lines that put the package symbols a fragment names into
 * its scope, resolved through the entrypoints a consumer would import them
 * from. Symbols the fragment declares or already imports are left alone, and
 * the symbols declared in the fragment's own file win when two entrypoints
 * export the same name.
 */
export function importPreludeFor(
  snippet: Snippet,
  symbols: PublicSymbol[],
): string {
  const preferred = [
    ...symbols.filter((symbol) => symbol.file === snippet.source),
    ...symbols,
  ];
  const groups = new Map<string, string[]>();
  const taken = new Set<string>();
  for (const { name, specifier } of preferred) {
    if (taken.has(name)) continue;
    if (!new RegExp(`\\b${name}\\b`).test(snippet.code)) continue;
    const declaration = `\\b(?:const|let|var|function|class|interface|type|enum)\\s+${name}\\b`;
    if (new RegExp(declaration).test(snippet.code)) continue;
    if (new RegExp(`import[^;]*\\b${name}\\b[^;]*from`).test(snippet.code)) {
      continue;
    }
    taken.add(name);
    const names = groups.get(specifier) ?? [];
    names.push(name);
    groups.set(specifier, names);
  }
  return [...groups]
    .map(
      ([specifier, names]) =>
        `import { ${names.sort().join(", ")} } from "${specifier}";`,
    )
    .join("\n");
}

/**
 * The API-reference files whose `@example` blocks still lean on a binding the
 * prose supplies instead of declaring it. Their examples compile with the
 * offending call unchecked, so the list is debt: it may shrink, never grow, and
 * an entry whose file no longer needs it fails the gate.
 */
export const UNDECLARED_BINDING_BASELINE: ReadonlySet<string> = new Set([
  "adapters/hono/authorization-server.ts",
  "adapters/hono/bff/auth-request-store.ts",
  "adapters/hono/bff/bff.ts",
  "adapters/hono/bff/testing.ts",
  "adapters/hono/resource-server.ts",
  "client/discovery-cache.ts",
  "identity/captcha.ts",
  "identity/external/flow.ts",
  "identity/external/mod.ts",
  "identity/external/oauth2.ts",
  "identity/hibp.ts",
  "identity/identifier.ts",
  "identity/mfa/mod.ts",
  "identity/mfa/recovery-codes.ts",
  "identity/mfa/service.ts",
  "identity/mfa/totp.ts",
  "identity/migration.ts",
  "identity/otp.ts",
  "identity/rate-limit.ts",
  "identity/service.ts",
  "identity/session.ts",
  "identity/token-flow.ts",
  "react/components/class-names.tsx",
  "react/components/mfa-enrollment-form.tsx",
  "react/testing.tsx",
  "server/authorization-server.ts",
  "server/signing-keys.ts",
]);

const FRAGMENT_DIAGNOSTIC = /^TS(?:1108|2304|2552|7006|7031|18004):/;

const UNDECLARED_BINDING = /^TS(?:2304|2552|18004):/;

const CONSUMER_DEPENDENCY =
  /^TS2307: Cannot find module '(?![./]|@udibo\/oauth2)[^']+'/;

/**
 * Whether a `tsc` diagnostic (`TS2304: Cannot find name 'app'.`) is about an
 * `@example` naming a binding it never declared. Such a binding has an error
 * type, so every call made on it goes unchecked — the gate fails it outside
 * {@link UNDECLARED_BINDING_BASELINE}, even though it is fragment-shaped.
 */
export function isUndeclaredBinding(diagnostic: string): boolean {
  return UNDECLARED_BINDING.test(diagnostic);
}

/**
 * Whether a `tsc` diagnostic is only about an `@example` being a fragment
 * rather than a program — a binding the surrounding prose supplies, or a bare
 * `return` because the example quotes the inside of a handler. Everything else
 * is a real defect in the documented code. A prose-supplied binding is
 * fragment-shaped but only tolerated for the files in
 * {@link UNDECLARED_BINDING_BASELINE}; see {@link isUndeclaredBinding}.
 */
export function isFragmentDiagnostic(diagnostic: string): boolean {
  return FRAGMENT_DIAGNOSTIC.test(diagnostic);
}

/**
 * Whether a `tsc` diagnostic is only about a third-party module the reader's
 * own app installs, which the snippet sandbox deliberately does not carry. A
 * missing `@udibo/oauth2` subpath or a relative module is never this.
 */
export function isConsumerDependency(diagnostic: string): boolean {
  return CONSUMER_DEPENDENCY.test(diagnostic);
}

/**
 * The compiler configuration the snippets are checked under: the package's
 * own strict settings, with each `@udibo/oauth2` subpath mapped to the source
 * file `jsr.json` publishes for it, so a snippet resolves exactly what a
 * consumer would import.
 */
export function snippetTsconfig(
  exports: Record<string, string>,
): Record<string, unknown> {
  const paths: Record<string, string[]> = {};
  for (const [subpath, path] of Object.entries(exports)) {
    paths[`@udibo/oauth2${subpath.slice(1)}`] = [`../../${path.slice(2)}`];
  }
  return {
    extends: "../../tsconfig.json",
    compilerOptions: {
      noEmit: true,
      declaration: false,
      isolatedDeclarations: false,
      verbatimModuleSyntax: false,
      paths,
    },
    include: ["*.ts", "*.tsx"],
  };
}

/** One error line of `tsc --pretty false` output, with its continuation lines. */
export interface Diagnostic {
  /** Generated snippet file name the error is in, when it names one. */
  file: string | null;
  /** `TSnnnn: message`, followed by any continuation lines. */
  text: string;
}

/** Splits `tsc --pretty false` output into one diagnostic per error. */
export function parseDiagnostics(output: string): Diagnostic[] {
  const found: Diagnostic[] = [];
  for (const line of output.split(/\r?\n/)) {
    const match =
      /^(.*?)\((\d+),(\d+)\): error (TS\d+): (.*)$/.exec(line) ??
      /^error (TS\d+): (.*)$/.exec(line);
    if (match && match.length === 6) {
      const file =
        /doc-check[\\/]([\w.-]+\.tsx?)$/.exec(match[1]!)?.[1] ?? null;
      found.push({ file, text: `${match[4]}: ${match[5]}` });
    } else if (match) {
      found.push({ file: null, text: `${match[1]}: ${match[2]}` });
    } else if (found.length > 0 && /^\s/.test(line)) {
      found[found.length - 1]!.text += `\n${line}`;
    }
  }
  return found;
}

function fileNameFor(snippet: Snippet): string {
  const slug = snippet.source
    .replace(/\.tsx?$/, "")
    .replace(/\.md$/, "")
    .replaceAll(/[^a-zA-Z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase();
  const prefix = snippet.origin === "jsdoc" ? "src-" : "";
  return `${prefix}${slug}-line${snippet.fence}.${snippet.lang}`;
}

function markdownFiles(root: string): string[] {
  const found = ["README.md"];
  function walk(dir: string, prefix: string): void {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        walk(join(dir, entry.name), `${prefix}${entry.name}/`);
      } else if (entry.name.endsWith(".md")) {
        found.push(`${prefix}${entry.name}`);
      }
    }
  }
  walk(join(root, "docs"), "docs/");
  return found.sort();
}

function clean(outDir: string): void {
  rmSync(outDir, { recursive: true, force: true });
}

function main(args: string[]): number {
  const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
  const outDir = join(root, "scripts", "doc-check");
  const budgetArg = args
    .find((arg) => arg.startsWith("--ignore-budget="))
    ?.slice("--ignore-budget=".length);
  const budget =
    budgetArg === undefined ? DEFAULT_IGNORE_BUDGET : Number(budgetArg);

  clean(outDir);

  const sources = markdownFiles(root);
  const snippets: Snippet[] = [];
  let ignored = 0;
  for (const source of sources) {
    const extraction = extractMarkdownSnippets(
      source,
      readFileSync(join(root, source), "utf8"),
    );
    snippets.push(...extraction.snippets);
    ignored += extraction.ignored;
  }
  const markdownCount = snippets.length;

  const symbols = publicSymbols(root);
  const files = apiReferenceFiles(root, symbols);
  for (const file of files) {
    const extraction = extractJsDocExamples(
      file,
      readFileSync(join(root, "src", file), "utf8"),
    );
    snippets.push(...extraction.snippets);
    ignored += extraction.ignored;
  }
  const exampleCount = snippets.length - markdownCount;

  if (ignored > budget) {
    console.error(
      `doc-check: ${ignored} snippet(s) marked \`ignore\` exceeds the budget ` +
        `of ${budget}. An opt-out skips type-checking, so the count may only ` +
        `go down: compile the snippet, move it into an example, or raise the ` +
        `budget deliberately.`,
    );
    return 1;
  }

  if (snippets.length === 0) {
    console.log("doc-check: no checkable snippets found.");
    return 0;
  }

  mkdirSync(outDir, { recursive: true });
  writeFileSync(
    join(outDir, "tsconfig.json"),
    JSON.stringify(snippetTsconfig(entrypoints(root)), null, 2),
  );
  const written = new Map<string, Snippet>();
  for (const snippet of snippets) {
    const name = fileNameFor(snippet);
    const prelude =
      snippet.origin === "jsdoc" ? importPreludeFor(snippet, symbols) : "";
    writeFileSync(
      join(outDir, name),
      `// ${snippet.source}:${snippet.fence}\n${
        prelude ? `${prelude}\n` : ""
      }${snippet.code}\nexport {};\n`,
    );
    written.set(name, snippet);
  }

  const tsc = join(root, "node_modules", "typescript", "bin", "tsc");
  const result = spawnSync(
    process.execPath,
    [
      tsc,
      "-p",
      relative(root, join(outDir, "tsconfig.json")),
      "--pretty",
      "false",
    ],
    { cwd: root, encoding: "utf8" },
  );
  const raw = `${result.stdout}${result.stderr}`;
  const all = parseDiagnostics(raw);

  const baselineUsed = new Set<string>();
  let undeclared = 0;
  const failures = all.filter((diagnostic) => {
    const snippet = diagnostic.file ? written.get(diagnostic.file) : undefined;
    if (!snippet || snippet.origin !== "jsdoc") return true;
    if (isUndeclaredBinding(diagnostic.text)) {
      if (!UNDECLARED_BINDING_BASELINE.has(snippet.source)) {
        undeclared++;
        return true;
      }
      baselineUsed.add(snippet.source);
    }
    return (
      !isFragmentDiagnostic(diagnostic.text) &&
      !isConsumerDependency(diagnostic.text)
    );
  });
  const stale = [...UNDECLARED_BINDING_BASELINE]
    .filter((source) => !baselineUsed.has(source))
    .sort();
  const failureLines = failures.map((diagnostic) => {
    const snippet = diagnostic.file ? written.get(diagnostic.file) : undefined;
    const origin = snippet ? `${snippet.source}:${snippet.fence}: ` : "";
    return `${origin}${diagnostic.text}`;
  });
  clean(outDir);

  if (failures.length > 0) {
    console.error(failureLines.join("\n\n"));
    if (undeclared > 0) {
      console.error(
        `doc-check: ${undeclared} of these are bindings an \`@example\` ` +
          `names without declaring. A free binding has an error type, so the ` +
          `call it is demonstrating is never checked — declare it ` +
          `(\`declare const server: ResourceServer<Client, User>;\`) instead ` +
          `of leaning on the prose.`,
      );
    }
    console.error(
      `doc-check: ${failures.length} documented snippet(s) do not compile. ` +
        `Fix the snippet, move it into an example, or mark the block ` +
        `\`ts ignore\` when it is a fragment quoted for reading.`,
    );
    return 1;
  }
  if (stale.length > 0) {
    console.error(
      `doc-check: ${stale.length} file(s) no longer need their ` +
        `UNDECLARED_BINDING_BASELINE entry — the list only shrinks, so ` +
        `delete them from it:\n  ${stale.join("\n  ")}`,
    );
    return 1;
  }
  if (result.status !== 0 && all.length === 0) {
    console.error(raw);
    console.error("doc-check: `tsc` failed without diagnostics.");
    return 1;
  }

  console.log(
    `doc-check: ${markdownCount} markdown snippet(s) across ` +
      `${sources.length} file(s) and ${exampleCount} JSDoc \`@example\` ` +
      `block(s) across ${files.length} API-reference file(s) compile ` +
      `(${ignored} marked \`ignore\`, budget ${budget}; ` +
      `${UNDECLARED_BINDING_BASELINE.size} file(s) still lean on undeclared ` +
      `bindings).`,
  );
  return 0;
}

if (isMain(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
