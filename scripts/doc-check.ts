/**
 * Documentation gate: type-checks the code in the docs.
 *
 * Two sources feed one `deno check` run, so a snippet that no longer compiles
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

/**
 * The number of `ignore`-marked snippets the package may carry today, across
 * both markdown fences and JSDoc `@example` blocks. Ratchet it down as opt-outs
 * are removed.
 */
export const DEFAULT_IGNORE_BUDGET = 13;

const budgetArg = Deno.args
  .find((arg) => arg.startsWith("--ignore-budget="))
  ?.slice("--ignore-budget=".length);
const budget = budgetArg === undefined
  ? DEFAULT_IGNORE_BUDGET
  : Number(budgetArg);

const packageDir = new URL("../", import.meta.url);
const srcDir = new URL("src/", packageDir);
const outDir = new URL("doc-check/", new URL("scripts/", packageDir));

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

/** A public symbol and the entrypoint specifier a consumer imports it from. */
export interface PublicSymbol {
  /** Exported name. */
  name: string;
  /** `deno doc` declaration kind, which decides whether the import is a type. */
  kind: string;
  /** Package-relative path of the file that declares it. */
  file: string;
  /** Specifier to import it from, e.g. `@udibo/oauth2/server`. */
  specifier: string;
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
    const opening = FENCE.exec(lines[index]);
    if (!opening) {
      index++;
      continue;
    }
    const info = opening[1].trim().split(/\s+/);
    const lang = langOf(info);
    const start = index + 1;
    let end = start;
    while (end < lines.length && !FENCE.test(lines[end])) end++;
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
export function extractJsDocExamples(
  source: string,
  code: string,
): Extraction {
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
    const line = lines[index].trim();
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
        info = opening[1].trim().split(/\s+/);
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
  for (const { name, kind, specifier } of preferred) {
    if (taken.has(name)) continue;
    if (!new RegExp(`\\b${name}\\b`).test(snippet.code)) continue;
    const declaration =
      `\\b(?:const|let|var|function|class|interface|type|enum)\\s+${name}\\b`;
    if (new RegExp(declaration).test(snippet.code)) continue;
    if (new RegExp(`import[^;]*\\b${name}\\b[^;]*from`).test(snippet.code)) {
      continue;
    }
    taken.add(name);
    const names = groups.get(specifier) ?? [];
    const isType = kind === "interface" || kind === "typeAlias";
    names.push(isType ? `type ${name}` : name);
    groups.set(specifier, names);
  }
  return [...groups]
    .map(([specifier, names]) =>
      `import { ${names.sort().join(", ")} } from "${specifier}";`
    )
    .join("\n");
}

const FRAGMENT_DIAGNOSTIC = /^TS(?:1108|2304|2552|7006|7031|18004) \[ERROR\]/;

const UNDECLARED_BINDING = /^TS(?:2304|2552|18004) \[ERROR\]/;

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

/**
 * Whether a `deno check` diagnostic is about an `@example` naming a binding it
 * never declared. Such a binding has an error type, so every call made on it
 * goes unchecked — the gate fails it outside
 * {@link UNDECLARED_BINDING_BASELINE}, even though it is fragment-shaped.
 */
export function isUndeclaredBinding(diagnostic: string): boolean {
  return UNDECLARED_BINDING.test(diagnostic);
}

const CONSUMER_DEPENDENCY =
  /^TS2307 \[ERROR\]: Import "(?!@udibo\/oauth2)[^"]+" not a dependency and not in import map/;

/**
 * Whether a `deno check` diagnostic is only about an `@example` being a
 * fragment rather than a program — a binding the surrounding prose supplies, or
 * a bare `return` because the example quotes the inside of a handler.
 * Everything else is a real defect in the documented code. A prose-supplied
 * binding is fragment-shaped but only tolerated for the files in
 * {@link UNDECLARED_BINDING_BASELINE}; see {@link isUndeclaredBinding}.
 */
export function isFragmentDiagnostic(diagnostic: string): boolean {
  return FRAGMENT_DIAGNOSTIC.test(diagnostic);
}

/**
 * Whether a `deno check` diagnostic is only about a third-party module the
 * reader's own app installs, which the snippet sandbox deliberately does not
 * carry. A missing `@udibo/oauth2` subpath is never this.
 */
export function isConsumerDependency(diagnostic: string): boolean {
  return CONSUMER_DEPENDENCY.test(diagnostic);
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

async function markdownFiles(): Promise<string[]> {
  const found = ["README.md"];
  async function walk(dir: URL, prefix: string): Promise<void> {
    for await (const entry of Deno.readDir(dir)) {
      if (entry.isDirectory) {
        await walk(new URL(`${entry.name}/`, dir), `${prefix}${entry.name}/`);
      } else if (entry.name.endsWith(".md")) {
        found.push(`${prefix}${entry.name}`);
      }
    }
  }
  await walk(new URL("docs/", packageDir), "docs/");
  return found.sort();
}

async function publicSymbols(): Promise<PublicSymbol[]> {
  const config = JSON.parse(
    await Deno.readTextFile(new URL("deno.json", srcDir)),
  );
  const symbols: PublicSymbol[] = [];
  for (const [subpath, path] of Object.entries(config.exports)) {
    const specifier = `@udibo/oauth2${subpath.slice(1)}`;
    const { success, stdout } = await new Deno.Command(Deno.execPath(), {
      args: ["doc", "--json", path as string],
      cwd: srcDir,
      env: { NO_COLOR: "1" },
      stdout: "piped",
      stderr: "null",
    }).output();
    if (!success) {
      throw new Error(`doc-check: \`deno doc --json ${path}\` failed.`);
    }
    const doc = JSON.parse(new TextDecoder().decode(stdout));
    for (const node of Object.values(doc.nodes) as { symbols?: unknown[] }[]) {
      for (const symbol of node.symbols ?? []) {
        const { name, declarations } = symbol as {
          name: string;
          declarations?: { kind: string; location: { filename: string } }[];
        };
        const declaration = declarations?.[0];
        if (!declaration) continue;
        symbols.push({
          name,
          kind: declaration.kind,
          file: declaration.location.filename.replace(srcDir.href, ""),
          specifier,
        });
      }
    }
  }
  return symbols;
}

async function apiReferenceFiles(symbols: PublicSymbol[]): Promise<string[]> {
  const config = JSON.parse(
    await Deno.readTextFile(new URL("deno.json", srcDir)),
  );
  const entrypoints = Object.values(config.exports as Record<string, string>)
    .map((path) => path.replace(/^\.\//, ""));
  return [...new Set([...entrypoints, ...symbols.map((s) => s.file)])]
    .filter((file) => !/\.test\.tsx?$/.test(file))
    .sort();
}

async function clean(): Promise<void> {
  try {
    for await (const entry of Deno.readDir(outDir)) {
      if (entry.name.endsWith(".ts") || entry.name.endsWith(".tsx")) {
        await Deno.remove(new URL(entry.name, outDir));
      }
    }
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
}

function diagnostics(stderr: string): string[] {
  return stderr
    .split(/^(?=TS\d+ \[ERROR\]:)/m)
    .filter((block) => /^TS\d+ \[ERROR\]:/.test(block))
    .map((block) => block.trimEnd());
}

function locationOf(diagnostic: string): string | null {
  const matches = [...diagnostic.matchAll(/doc-check\/([\w.-]+\.tsx?)/g)];
  return matches.length > 0 ? matches[matches.length - 1][1] : null;
}

async function main(): Promise<void> {
  await clean();

  const sources = await markdownFiles();
  const snippets: Snippet[] = [];
  let ignored = 0;
  for (const source of sources) {
    const markdown = await Deno.readTextFile(new URL(source, packageDir));
    const extraction = extractMarkdownSnippets(source, markdown);
    snippets.push(...extraction.snippets);
    ignored += extraction.ignored;
  }
  const markdownCount = snippets.length;

  const symbols = await publicSymbols();
  const files = await apiReferenceFiles(symbols);
  for (const file of files) {
    const code = await Deno.readTextFile(new URL(file, srcDir));
    const extraction = extractJsDocExamples(file, code);
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
    Deno.exit(1);
  }

  if (snippets.length === 0) {
    console.log("doc-check: no checkable snippets found.");
    return;
  }

  const written: string[] = [];
  const fragments = new Map<string, Snippet>();
  for (const snippet of snippets) {
    const name = fileNameFor(snippet);
    const prelude = snippet.origin === "jsdoc"
      ? importPreludeFor(snippet, symbols)
      : "";
    await Deno.writeTextFile(
      new URL(name, outDir),
      `// ${snippet.source}:${snippet.fence}\n${
        prelude ? `${prelude}\n` : ""
      }${snippet.code}\n`,
    );
    written.push(`scripts/doc-check/${name}`);
    if (snippet.origin === "jsdoc") fragments.set(name, snippet);
  }

  const { success, stderr } = await new Deno.Command(Deno.execPath(), {
    args: ["check", ...written],
    cwd: packageDir,
    env: { NO_COLOR: "1" },
    stdout: "null",
    stderr: "piped",
  }).output();

  const raw = new TextDecoder().decode(stderr);
  const baselineUsed = new Set<string>();
  let undeclared = 0;
  const failures = diagnostics(raw).filter((diagnostic) => {
    const location = locationOf(diagnostic);
    const snippet = location ? fragments.get(location) : undefined;
    if (!snippet) return true;
    if (isUndeclaredBinding(diagnostic)) {
      if (!UNDECLARED_BINDING_BASELINE.has(snippet.source)) {
        undeclared++;
        return true;
      }
      baselineUsed.add(snippet.source);
    }
    return !isFragmentDiagnostic(diagnostic) &&
      !isConsumerDependency(diagnostic);
  });
  const stale = [...UNDECLARED_BINDING_BASELINE]
    .filter((source) => !baselineUsed.has(source))
    .sort();

  await clean();

  if (failures.length > 0) {
    console.error(failures.join("\n\n"));
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
    Deno.exit(1);
  }
  if (stale.length > 0) {
    console.error(
      `doc-check: ${stale.length} file(s) no longer need their ` +
        `UNDECLARED_BINDING_BASELINE entry — the list only shrinks, so ` +
        `delete them from it:\n  ${stale.join("\n  ")}`,
    );
    Deno.exit(1);
  }
  if (!success && diagnostics(raw).length === 0) {
    console.error(raw);
    console.error("doc-check: `deno check` failed without diagnostics.");
    Deno.exit(1);
  }

  console.log(
    `doc-check: ${markdownCount} markdown snippet(s) across ` +
      `${sources.length} file(s) and ${exampleCount} JSDoc \`@example\` ` +
      `block(s) across ${files.length} API-reference file(s) compile ` +
      `(${ignored} marked \`ignore\`, budget ${budget}; ` +
      `${UNDECLARED_BINDING_BASELINE.size} file(s) still lean on undeclared ` +
      `bindings).`,
  );
}

if (import.meta.main) await main();
