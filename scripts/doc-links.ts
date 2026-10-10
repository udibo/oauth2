/**
 * Documentation gate: public documents carry no private references, no
 * internal frontmatter or per-document changelog, and every relative link
 * resolves to an existing file and, for Markdown targets, an existing heading.
 *
 * @module
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isMain } from "./_main.ts";

/** Strings that must not appear in a public document. */
export const FORBIDDEN: readonly string[] = [
  "github.com/udibo/udibo",
  "udibo/udibo#",
  "--cwd=packages/oauth2",
  "product/migration.md",
];

const ROOT_FILES = [
  "README.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "CHANGELOG.md",
  "PUBLISHING.md",
  "llms.txt",
  "llms-full.txt",
];

function collect(root: string, dir: string, found: string[]): void {
  const base = join(root, dir);
  if (!existsSync(base)) return;
  for (const entry of readdirSync(base, { withFileTypes: true })) {
    if (["node_modules", ".git", "build", "dist"].includes(entry.name)) {
      continue;
    }
    const path = `${dir}/${entry.name}`;
    if (entry.isDirectory()) collect(root, path, found);
    else if (entry.isFile() && path.endsWith(".md")) found.push(path);
  }
}

/** The public documents the gate covers, relative to `root` with `/` separators. */
export function publicDocuments(root: string): string[] {
  const files = ROOT_FILES.filter((file) => existsSync(join(root, file)));
  for (const dir of ["docs", "examples", "templates"]) {
    collect(root, dir, files);
  }
  return files;
}

/** The heading anchors a Markdown document defines, in GitHub's slug style. */
export function anchors(markdown: string): Set<string> {
  const result = new Set<string>();
  const duplicates = new Map<string, number>();
  let fenced = false;
  for (const line of markdown.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    if (fenced) continue;
    const heading = /^#{1,6}\s+(.+?)(?:\s+#+)?\s*$/.exec(line)?.[1];
    if (!heading) continue;
    const slug = heading
      .toLowerCase()
      .replace(/<[^>]*>/g, "")
      .replace(/[^\p{L}\p{N}\p{M}_\-\s]/gu, "")
      .replace(/\s/g, "-");
    const count = duplicates.get(slug) ?? 0;
    duplicates.set(slug, count + 1);
    result.add(count === 0 ? slug : `${slug}-${count}`);
  }
  for (const match of markdown.matchAll(
    /<(?:a|span)\s+(?:id|name)=["']([^"']+)["']/g,
  )) {
    result.add(match[1]!);
  }
  return result;
}

/** Lists every problem in the public documents under `root`. */
export function findProblems(root: string): string[] {
  const problems: string[] = [];
  const texts = new Map<string, string>();
  const read = (path: string): string => {
    if (!texts.has(path)) texts.set(path, readFileSync(path, "utf8"));
    return texts.get(path)!;
  };
  for (const file of publicDocuments(root)) {
    const sourcePath = resolve(root, file);
    const text = read(sourcePath);
    for (const pattern of FORBIDDEN) {
      if (text.includes(pattern)) {
        problems.push(`${file}: private reference ${pattern}`);
      }
    }
    if (file.startsWith("docs/")) {
      if (/^---\r?\n/.test(text)) {
        problems.push(`${file}: internal document frontmatter`);
      }
      if (/^## Changelog\s*$/m.test(text)) {
        problems.push(`${file}: per-document changelog`);
      }
    }
    for (const match of text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
      const target = match[1]!;
      if (/^[a-z]+:/i.test(target) || target.startsWith("//")) continue;
      const url = new URL(target, pathToFileURL(sourcePath));
      const fragment = decodeURIComponent(url.hash.slice(1));
      url.hash = "";
      url.search = "";
      const path = fileURLToPath(url);
      if (!existsSync(path)) {
        problems.push(`${file}: missing file ${target}`);
      } else if (
        fragment &&
        statSync(path).isFile() &&
        path.endsWith(".md") &&
        !anchors(read(path)).has(fragment)
      ) {
        problems.push(`${file}: missing heading ${target}`);
      }
    }
  }
  return problems;
}

function main(): number {
  const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
  const problems = findProblems(root);
  if (problems.length > 0) {
    console.error(problems.join("\n"));
    return 1;
  }
  console.log(
    `doc-links: ${publicDocuments(root).length} public documents, local files and headings verified.`,
  );
  return 0;
}

if (isMain(import.meta.url)) {
  process.exit(main());
}
