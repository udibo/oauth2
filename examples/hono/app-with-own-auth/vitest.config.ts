import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "example-app-with-own-auth",
    environment: "node",
    include: ["**/*.test.ts"],
    env: {
      PORT: "8001",
      PUBLIC_URL: "http://localhost:8001",
      API_SERVICE_ORIGIN: "http://localhost:8002",
      EXTERNAL_APP_ORIGIN: "http://localhost:8003",
    },
  },
});
