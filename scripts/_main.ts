import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * Whether the module at `metaUrl` (pass `import.meta.url`) is the script Node
 * was started with, so a script can export functions for tests and still run
 * when invoked directly. Resolves symlinks on both sides, which a checkout
 * under a linked directory needs.
 */
export function isMain(metaUrl: string): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(metaUrl));
  } catch {
    return false;
  }
}
