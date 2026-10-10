import {
  defineConfig,
  devices,
  type PlaywrightTestConfig,
} from "@playwright/test";

const config: PlaywrightTestConfig = defineConfig({
  testDir: "src",
  testMatch: "**/*.e2e.ts",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? "github" : "list",
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});

export default config;
