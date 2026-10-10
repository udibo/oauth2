import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "example-api-service",
    environment: "node",
    include: ["**/*.test.ts"],
    env: {
      PORT: "8002",
      PUBLIC_URL: "http://localhost:8002",
      AUTH_SERVER_URL: "http://localhost:8001",
      CLIENT_ID: "spa",
      CLIENT_SECRET: "spa-secret",
    },
  },
});
