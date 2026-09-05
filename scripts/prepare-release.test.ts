import { assertEquals, assertRejects } from "@std/assert";
import { pathToFileURL } from "node:url";
import { prepareRelease } from "./prepare-release.ts";

Deno.test("release staging works outside the monorepo in a path with spaces", async () => {
  const path = await Deno.makeTempDir({ prefix: "oauth2 standalone " });
  const root = pathToFileURL(`${path}/`);
  try {
    for (
      const dir of ["src/docs", "docs", "templates/sample", "examples/sample"]
    ) await Deno.mkdir(new URL(dir, root), { recursive: true });
    for (
      const name of [
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "llms.txt",
        "llms-full.txt",
      ]
    ) await Deno.writeTextFile(new URL(name, root), name);
    await Deno.writeTextFile(
      new URL("docs/guide.md", root),
      "[source](../src/mod.ts) [local](#local) [external](https://jsr.io)",
    );
    await Deno.writeTextFile(new URL("src/docs/stale.md", root), "stale");
    await Deno.writeTextFile(
      new URL("deno.json", root),
      JSON.stringify({
        workspace: ["./src", "./templates/sample", "./examples/sample"],
      }),
    );
    await Deno.writeTextFile(
      new URL("src/deno.json", root),
      JSON.stringify({ name: "@udibo/oauth2", version: "0.0.0" }),
    );
    for (const dir of ["templates/sample", "examples/sample"]) {
      await Deno.writeTextFile(
        new URL(`${dir}/deno.json`, root),
        JSON.stringify({
          imports: { "@udibo/oauth2": "jsr:@udibo/oauth2@^0.0.0" },
        }),
      );
    }
    await prepareRelease("0.1.0", root);
    await prepareRelease("0.1.0", root);
    assertEquals(
      JSON.parse(await Deno.readTextFile(new URL("src/deno.json", root)))
        .version,
      "0.1.0",
    );
    for (const dir of ["templates/sample", "examples/sample"]) {
      assertEquals(
        JSON.parse(await Deno.readTextFile(new URL(`${dir}/deno.json`, root)))
          .imports["@udibo/oauth2"],
        "jsr:@udibo/oauth2@^0.1.0",
      );
    }
    assertEquals(
      await Deno.readTextFile(new URL("src/README.md", root)),
      "README.md",
    );
    assertEquals(
      await Deno.readTextFile(new URL("src/docs/guide.md", root)),
      "[source](https://github.com/udibo/oauth2/blob/main/src/mod.ts) [local](#local) [external](https://jsr.io)",
    );
    await assertRejects(
      () => Deno.stat(new URL("src/docs/stale.md", root)),
      Deno.errors.NotFound,
    );
    await assertRejects(
      () => Deno.stat(new URL("src/docs/docs", root)),
      Deno.errors.NotFound,
    );
    await assertRejects(() => prepareRelease("invalid", root));
    assertEquals(
      JSON.parse(await Deno.readTextFile(new URL("src/deno.json", root)))
        .version,
      "0.1.0",
    );
  } finally {
    await Deno.remove(path, { recursive: true });
  }
});
