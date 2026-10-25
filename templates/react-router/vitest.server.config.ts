import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

import { testEnv } from "./test/env.ts";

export default defineConfig({
  define: {
    "import.meta.env.REACT_ROUTER_HONO_SERVER_BUILD_DIRECTORY": '"build"',
    "import.meta.env.REACT_ROUTER_HONO_SERVER_ASSETS_DIR": '"assets"',
    "import.meta.env.REACT_ROUTER_HONO_SERVER_RUNTIME": '"node"',
    "import.meta.env.REACT_ROUTER_HONO_SERVER_BASENAME": '"/"',
    "import.meta.env.REACT_ROUTER_HONO_SERVER_VITE_BASE": '"/"',
  },
  resolve: {
    alias: {
      "virtual:react-router/server-build": fileURLToPath(
        new URL("./test/server-build.ts", import.meta.url),
      ),
    },
  },
  test: {
    name: "template-server",
    environment: "node",
    include: ["server/**/*.test.ts"],
    env: testEnv,
    server: { deps: { inline: ["react-router-hono-server"] } },
  },
});
