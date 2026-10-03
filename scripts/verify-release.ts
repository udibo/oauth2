/** Refuses an incorrect first version or private references in unreleased commits. */
export async function verifyRelease(
  version: string,
  root = new URL("../", import.meta.url),
  previousGitHead?: string,
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
  await verifyReleaseReferences(root, previousGitHead);
}

/** Checks the selected commit range and optional proposed squash text. */
export async function verifyReleaseReferences(
  root = new URL("../", import.meta.url),
  previousGitHead?: string,
  proposedMessage = "",
): Promise<void> {
  if (
    previousGitHead && !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(previousGitHead)
  ) {
    throw new Error("Last release Git head must be a full commit hash");
  }
  const commits = await new Deno.Command("git", {
    args: [
      "log",
      "--format=%B",
      previousGitHead ? `${previousGitHead}..HEAD` : "HEAD",
      "--",
    ],
    cwd: root,
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (!commits.success) throw new Error("Cannot inspect unreleased commits");
  const privateReference =
    /(?<![a-z0-9_.-])(?:udibo\/udibo#\d+\b|(?:https?:\/\/)?(?:www\.)?github\.com\/udibo\/udibo(?:\.git)?(?![a-z0-9_.-]))/i;
  if (
    privateReference.test(
      `${new TextDecoder().decode(commits.stdout)}\n${proposedMessage}`,
    )
  ) {
    throw new Error(
      "Release input references a private repository. Remove those references before merging or publishing.",
    );
  }
}

if (import.meta.main) {
  const version = Deno.args[0];
  if (version === "--references-only") {
    const base = Deno.env.get("RELEASE_REFERENCE_BASE");
    if (!base) throw new Error("Pull request base Git head is required");
    await verifyReleaseReferences(
      undefined,
      base,
      [
        Deno.env.get("RELEASE_REFERENCE_PR_TITLE") ?? "",
        Deno.env.get("RELEASE_REFERENCE_PR_BODY") ?? "",
      ].join("\n"),
    );
  } else if (!version) {
    throw new Error(
      "Usage: deno run scripts/verify-release.ts <version> [last-release-git-head]",
    );
  } else {
    await verifyRelease(version, undefined, Deno.args[1] || undefined);
  }
}
