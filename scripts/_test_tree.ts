import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

/** A throwaway directory tree for script tests, removed by `dispose`. */
export interface TestTree {
  /** Absolute path of the tree's root. */
  root: string;
  /** Writes `content` at `path` under the root, creating parent directories. */
  write(path: string, content: string): void;
  /** Deletes the tree. */
  dispose(): void;
}

/** Creates a tree whose path contains a space, as a contributor's checkout may. */
export function createTree(prefix = "oauth2 script "): TestTree {
  const root = mkdtempSync(join(tmpdir(), prefix));
  return {
    root,
    write(path, content) {
      const target = join(root, path);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, content);
    },
    dispose() {
      rmSync(root, { recursive: true, force: true });
    },
  };
}
