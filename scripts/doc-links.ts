/** Checks public documentation for private references, broken links, and internal document conventions. */
const packageDir = new URL("../", import.meta.url);
const FORBIDDEN = [
  "github.com/udibo/udibo",
  "udibo/udibo#",
  "--cwd=packages/oauth2",
  "product/migration.md",
];
const files = [
  "README.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "CHANGELOG.md",
  "PUBLISHING.md",
  "llms.txt",
  "llms-full.txt",
];

async function collect(dir: string): Promise<void> {
  for await (const entry of Deno.readDir(new URL(`${dir}/`, packageDir))) {
    if (["node_modules", ".git", "build"].includes(entry.name)) continue;
    const path = `${dir}/${entry.name}`;
    if (entry.isDirectory) await collect(path);
    else if (entry.isFile && path.endsWith(".md")) files.push(path);
  }
}
for (const dir of ["docs", "examples", "templates"]) await collect(dir);

function anchors(markdown: string): Set<string> {
  const result = new Set<string>();
  const duplicates = new Map<string, number>();
  let fenced = false;
  for (const line of markdown.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    if (fenced) continue;
    const heading = /^#{1,6}\s+(.+?)(?:\s+#+)?\s*$/.exec(line)?.[1];
    if (!heading) continue;
    const slug = heading.toLowerCase()
      .replace(/<[^>]*>/g, "")
      .replace(/[^\p{L}\p{N}\p{M}_\-\s]/gu, "")
      .replace(/\s/g, "-");
    const count = duplicates.get(slug) ?? 0;
    duplicates.set(slug, count + 1);
    result.add(count === 0 ? slug : `${slug}-${count}`);
  }
  for (
    const match of markdown.matchAll(
      /<(?:a|span)\s+(?:id|name)=["']([^"']+)["']/g,
    )
  ) {
    result.add(match[1]);
  }
  return result;
}

const problems: string[] = [];
const texts = new Map<string, string>();
async function read(url: URL): Promise<string> {
  const key = url.href;
  if (!texts.has(key)) texts.set(key, await Deno.readTextFile(url));
  return texts.get(key)!;
}
for (const file of files) {
  const source = new URL(file, packageDir);
  const text = await read(source);
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
    const target = match[1];
    if (/^[a-z]+:/i.test(target) || target.startsWith("//")) continue;
    const url = new URL(target, source);
    const fragment = decodeURIComponent(url.hash.slice(1));
    url.hash = "";
    try {
      const stat = await Deno.stat(url);
      if (fragment && stat.isFile && url.pathname.endsWith(".md")) {
        if (!anchors(await read(url)).has(fragment)) {
          problems.push(`${file}: missing heading ${target}`);
        }
      }
    } catch {
      problems.push(`${file}: missing file ${target}`);
    }
  }
}
if (problems.length) {
  console.error(problems.join("\n"));
  Deno.exit(1);
}
console.log(
  `doc-links: ${files.length} public documents, local files and headings verified.`,
);
