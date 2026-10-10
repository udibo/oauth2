import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: ["vitest.server.config.ts", "vitest.app.config.ts"],
  },
});
