/**
 * Bundles the browser app (`client/main.tsx`) into `public/build/` with
 * esbuild, resolving imports through this project's `deno.json` via the Deno
 * esbuild plugin.
 *
 * Run through the tasks:
 *
 *   deno task build           # one-shot bundle (minified when APP_ENV=production)
 *   deno task build --watch   # rebuild on change
 *
 * @module
 */

import * as path from "@std/path";
import { denoPlugin } from "@deno/esbuild-plugin";
import * as esbuild from "esbuild";

import { isProduction } from "@/config.ts";

const projectRoot = path.dirname(path.fromFileUrl(import.meta.url));

const options: esbuild.BuildOptions = {
  plugins: [denoPlugin({ configPath: path.join(projectRoot, "deno.json") })],
  absWorkingDir: projectRoot,
  entryPoints: [path.join(projectRoot, "client", "main.tsx")],
  outdir: path.join(projectRoot, "public", "build"),
  bundle: true,
  platform: "browser",
  format: "esm",
  jsx: "automatic",
  jsxImportSource: "react",
  ...(isProduction ? { minify: true } : { jsxDev: true, sourcemap: "linked" }),
};

if (Deno.args.includes("--watch")) {
  const context = await esbuild.context(options);
  await context.watch();
  console.log("Watching for browser bundle changes...");
} else {
  await esbuild.build(options);
  await esbuild.stop();
  console.log("Browser bundle written to public/build");
}
