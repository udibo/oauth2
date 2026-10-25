/**
 * Stands in for `virtual:react-router/server-build` so `server/index.ts` can
 * run under Vitest without a Vite build. Every page request renders a plain
 * text body.
 *
 * @module
 */

import type { ServerBuild } from "react-router";

const build: ServerBuild = {
  entry: {
    module: {
      default: (_request, status) => new Response("page", { status }),
    },
  },
  routes: {
    root: { id: "root", path: "", module: { default: () => null } },
    page: {
      id: "page",
      parentId: "root",
      path: "*",
      module: { default: () => null },
    },
  },
  assets: {
    entry: { module: "/entry.client.js", imports: [] },
    routes: {},
    url: "/manifest.js",
    version: "test",
  },
  publicPath: "/",
  assetsBuildDirectory: "build/client",
  future: {},
  ssr: true,
  isSpaMode: false,
  prerender: [],
  routeDiscovery: { mode: "lazy", manifestPath: "/__manifest" },
};

export const {
  entry,
  routes,
  assets,
  publicPath,
  assetsBuildDirectory,
  future,
  ssr,
  isSpaMode,
  prerender,
  routeDiscovery,
} = build;
