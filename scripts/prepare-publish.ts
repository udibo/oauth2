/** Stages the complete JSR payload without publishing it. */
const packageDir = new URL("../", import.meta.url);
const srcDir = new URL("src/", packageDir);
const documents = [
  "README.md",
  "LICENSE",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "llms.txt",
  "llms-full.txt",
];

async function copyDocument(
  source: URL,
  target: URL,
  root: URL,
): Promise<void> {
  if (!/\.(md|txt)$/.test(source.pathname)) {
    await Deno.copyFile(source, target);
    return;
  }
  const text = await Deno.readTextFile(source);
  const linked = text.replace(
    /(\[[^\]]*\]\()([^)]+)(\))/g,
    (match, prefix, path: string, suffix) => {
      if (/^[a-z]+:/i.test(path) || path.startsWith("#")) return match;
      const resolved = new URL(path, source);
      if (!resolved.href.startsWith(root.href)) return match;
      return `${prefix}https://github.com/udibo/oauth2/blob/main/${
        resolved.href.slice(root.href.length)
      }${suffix}`;
    },
  );
  await Deno.writeTextFile(target, linked);
}

async function copyTree(source: URL, target: URL, root: URL): Promise<void> {
  await Deno.mkdir(target, { recursive: true });
  for await (const entry of Deno.readDir(source)) {
    const name = encodeURIComponent(entry.name);
    if (entry.isDirectory) {
      await copyTree(
        new URL(`${name}/`, source),
        new URL(`${name}/`, target),
        root,
      );
    } else if (entry.isFile) {
      await copyDocument(new URL(name, source), new URL(name, target), root);
    }
  }
}

/** Copies consumer documentation into the publish root; repeated runs replace stale copies. */
export async function preparePublish(root: URL = packageDir): Promise<void> {
  const target = new URL("src/", root);
  for (const file of documents) {
    await copyDocument(new URL(file, root), new URL(file, target), root);
  }
  const docs = new URL("docs/", target);
  if (!docs.href.startsWith(target.href)) {
    throw new Error("Invalid publish directory");
  }
  try {
    await Deno.remove(docs, { recursive: true });
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  await copyTree(new URL("docs/", root), docs, root);
}

if (import.meta.main) {
  await preparePublish();
  console.log(`Prepared documentation in ${srcDir}`);
}
