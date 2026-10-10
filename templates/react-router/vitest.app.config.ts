import { defineConfig } from "vitest/config";

import { testEnv } from "./test/env.ts";

export default defineConfig({
  test: {
    name: "template-app",
    environment: "jsdom",
    include: ["app/**/*.test.{ts,tsx}"],
    setupFiles: ["./test/setup.ts"],
    env: testEnv,
  },
});
