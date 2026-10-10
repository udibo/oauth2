import { execFileSync } from "node:child_process";
import { globSync, statSync } from "node:fs";

const marker = "dist/server/mod.js";

function newestSourceTime(): number {
  return Math.max(
    0,
    ...globSync("src/**/*.{ts,tsx}", { exclude: ["**/*.test.*"] }).map(
      (file) => statSync(file).mtimeMs,
    ),
  );
}

function distTime(): number {
  try {
    return statSync(marker).mtimeMs;
  } catch {
    return 0;
  }
}

/**
 * The examples and templates import `@udibo/oauth2` through its package
 * exports, which point at `dist/`. Rebuilds it when it is missing or older
 * than the sources so a root `pnpm test` never runs them against stale output.
 */
export default function setup(): void {
  if (distTime() >= newestSourceTime()) return;
  execFileSync("pnpm", ["build"], { stdio: "inherit" });
}
