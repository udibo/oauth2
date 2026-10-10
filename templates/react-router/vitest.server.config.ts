import { defineConfig } from "vitest/config";

import { testEnv } from "./test/env.ts";

export default defineConfig({
  test: {
    name: "template-server",
    environment: "node",
    include: ["server/**/*.test.ts"],
    env: testEnv,
  },
});
