/**
 * Documentation gate: runs `deno doc --lint` over every entrypoint in
 * `src/deno.json` and fails on any error. The only tolerated diagnostic is a
 * `private-type-ref` from the Hono adapters referencing external framework
 * types (`Context`, `Hono`, `Handler`, `MiddlewareHandler`) that deno doc
 * cannot resolve as part of this package's documented graph. Any other
 * `private-type-ref`, and any failure the tolerated hits don't explain (such
 * as an unresolvable entrypoint), still fails the gate.
 *
 * @module
 */

const srcDir = new URL("../src/", import.meta.url);
const config = JSON.parse(
  await Deno.readTextFile(new URL("deno.json", srcDir)),
);
const entrypoints = Object.values(config.exports as Record<string, string>);

const { success, stderr } = await new Deno.Command(Deno.execPath(), {
  args: ["doc", "--lint", ...entrypoints],
  cwd: srcDir,
  env: { NO_COLOR: "1" },
  stdout: "null",
  stderr: "piped",
}).output();

if (success) {
  console.log(`doc-lint: ${entrypoints.length} entrypoints clean.`);
  Deno.exit(0);
}

const honoTypeRef =
  /references private type '(?:Context|Hono|Handler|MiddlewareHandler)'/;
function isToleratedHonoTypeRef(block: string): boolean {
  return block.startsWith("error[private-type-ref]") &&
    honoTypeRef.test(block) &&
    block.replaceAll("\\", "/").includes("adapters/hono/");
}

const raw = new TextDecoder().decode(stderr);
const errors = splitDiagnostics(raw);
const violations = errors.filter((block) => !isToleratedHonoTypeRef(block));

/**
 * Splits `deno doc --lint` stderr into one block per `error[...]` diagnostic.
 * deno doc separates diagnostics by a single newline, not a blank line, and its
 * blocks carry no trailing delimiter — so splitting on blank lines merges every
 * diagnostic into one blob. A merged blob that contains any tolerated Hono ref
 * would then mask a real leak sitting beside it, so each diagnostic must be
 * isolated before it is classified. The trailing `error: Found N ...` summary
 * is not a per-symbol diagnostic and is dropped.
 */
function splitDiagnostics(text: string): string[] {
  const blocks: string[] = [];
  let current: string[] | null = null;
  for (const line of text.split("\n")) {
    if (/^error\[/.test(line)) {
      if (current) blocks.push(current.join("\n").trim());
      current = [line];
    } else if (/^error: /.test(line)) {
      if (current) blocks.push(current.join("\n").trim());
      current = null;
    } else if (current) {
      current.push(line);
    }
  }
  if (current) blocks.push(current.join("\n").trim());
  return blocks;
}

if (violations.length > 0) {
  console.error(violations.join("\n\n"));
  console.error(
    `\ndoc-lint: ${violations.length} documentation error(s). ` +
      "Every exported symbol needs contract-level JSDoc.",
  );
  Deno.exit(1);
}
if (errors.length === 0) {
  console.error(raw);
  console.error("\ndoc-lint: `deno doc --lint` failed without lint output.");
  Deno.exit(1);
}
console.log(`doc-lint: ${entrypoints.length} entrypoints clean.`);
