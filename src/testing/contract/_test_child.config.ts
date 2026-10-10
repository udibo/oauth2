import { defineConfig, type ViteUserConfig } from "vitest/config";

const file = process.env.CONTRACT_CHILD_FILE;
if (!file) throw new Error("CONTRACT_CHILD_FILE names the suite to run");

const config: ViteUserConfig = defineConfig({
  test: { include: [file], coverage: { enabled: false } },
});

export default config;
