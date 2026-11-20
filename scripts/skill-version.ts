import { readFileSync, writeFileSync } from "node:fs";

import { isMain } from "./_main.ts";

/** Package-relative path shared by release preparation and the packed consumer check. */
export const SKILL_FILE = "skills/udibo-oauth2/SKILL.md";

/** Update the skill's own version, exact npm pins and guide links for the release being packed. */
export function skillAtVersion(source: string, version: string): string {
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error("Expected a package release version");
  }
  const field = /^  version: "([^"]+)"$/m;
  const previous = source.match(field)?.[1];
  if (!previous) throw new Error("Missing skill version");
  return source
    .replace(field, `  version: "${version}"`)
    .replaceAll(`@udibo/oauth2@${previous}`, `@udibo/oauth2@${version}`)
    .replaceAll(
      `/udibo/oauth2/blob/${previous}/`,
      `/udibo/oauth2/blob/${version}/`,
    );
}

if (isMain(import.meta.url)) {
  const file = new URL(`../${SKILL_FILE}`, import.meta.url);
  writeFileSync(
    file,
    skillAtVersion(readFileSync(file, "utf8"), process.argv[2] ?? ""),
  );
}
