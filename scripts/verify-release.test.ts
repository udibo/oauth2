import { assertEquals, assertRejects } from "@std/assert";
import { pathToFileURL } from "node:url";
import { verifyRelease } from "./verify-release.ts";

Deno.test("first release guard rejects wrong versions until 0.1.0 exists in history", async () => {
  const path = await Deno.makeTempDir({ prefix: "oauth2 release history " });
  const root = pathToFileURL(`${path}/`);
  async function git(...args: string[]): Promise<void> {
    const result = await new Deno.Command("git", {
      args: [
        "-c",
        "user.name=Release test",
        "-c",
        "user.email=release-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        `core.hooksPath=${path}/hooks`,
        ...args,
      ],
      cwd: root,
      stdout: "piped",
      stderr: "piped",
    }).output();
    assertEquals(result.success, true, new TextDecoder().decode(result.stderr));
  }
  try {
    await assertRejects(
      () => verifyRelease("0.1.0", root),
      Error,
      "Cannot inspect release history",
    );
    await git("init");
    await git("commit", "--allow-empty", "-m", "test baseline");
    await git("tag", "0.0.0");
    await verifyRelease("0.1.0", root);
    for (const version of ["0.0.1", "0.2.0", "1.0.0"]) {
      await assertRejects(
        () => verifyRelease(version, root),
        Error,
        "First release must be 0.1.0",
      );
    }
    await git("tag", "0.1.0");
    await verifyRelease("0.1.1", root);
    await verifyRelease("0.2.0", root);
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});
