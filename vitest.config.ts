import { defineConfig, type ViteUserConfig } from "vitest/config";

const config: ViteUserConfig = defineConfig({
  test: {
    testTimeout: 30_000,
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    exclude: ["src/cli/**", "src/adapters/**", "src/react/**", "node_modules"],
    coverage: {
      provider: "v8",
      reporter: ["text-summary", "lcov"],
      include: ["src/**/*.ts", "src/**/*.tsx"],
      exclude: ["**/*.test.ts", "**/*.test.tsx", "**/_test_*", "**/*.e2e.ts"],
    },
  },
});

export default config;
