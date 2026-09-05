import { parse } from "@std/semver";
import { preparePublish } from "./prepare-publish.ts";

/** Stamps the package and all example/template pins, then stages documentation. */
export async function prepareRelease(
  version: string,
  root = new URL("../", import.meta.url),
): Promise<void> {
  parse(version);
  const srcFile = new URL("src/deno.json", root);
  const src = JSON.parse(await Deno.readTextFile(srcFile));
  src.version = version;
  await Deno.writeTextFile(srcFile, JSON.stringify(src, null, 2) + "\n");
  const workspace = JSON.parse(
    await Deno.readTextFile(new URL("deno.json", root)),
  );
  for (const member of workspace.workspace as string[]) {
    if (
      !member.startsWith("./examples/") && !member.startsWith("./templates/")
    ) continue;
    const file = new URL(`${member}/deno.json`, root);
    const config = JSON.parse(await Deno.readTextFile(file));
    config.imports["@udibo/oauth2"] = `jsr:@udibo/oauth2@^${version}`;
    await Deno.writeTextFile(file, JSON.stringify(config, null, 2) + "\n");
  }
  await preparePublish(root);
}

if (import.meta.main) {
  const version = Deno.args[0];
  if (!version) throw new Error("Usage: deno task release:prepare <version>");
  await prepareRelease(version);
}
