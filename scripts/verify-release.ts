/** Refuses an accidental 1.0.0 or patch release for the first public version. */
export async function verifyRelease(
  version: string,
  root = new URL("../", import.meta.url),
): Promise<void> {
  const result = await new Deno.Command("git", {
    args: ["tag", "--list", "0.1.0"],
    cwd: root,
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (!result.success) throw new Error("Cannot inspect release history");
  if (
    new TextDecoder().decode(result.stdout).trim() === "" && version !== "0.1.0"
  ) {
    throw new Error(
      `First release must be 0.1.0, got ${version}. Seed the 0.0.0 baseline and a feat commit before enabling publishing.`,
    );
  }
}

if (import.meta.main) {
  const version = Deno.args[0];
  if (!version) {
    throw new Error("Usage: deno run scripts/verify-release.ts <version>");
  }
  await verifyRelease(version);
}
