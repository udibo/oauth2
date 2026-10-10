import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "example-app-with-external-auth",
    environment: "node",
    include: ["**/*.test.ts"],
    env: {
      PORT: "8003",
      PUBLIC_URL: "http://localhost:8003",
      IDP_BASE_URL: "http://localhost:8001",
      IDP_CLIENT_ID: "spa",
      IDP_CLIENT_SECRET: "spa-secret",
      API_SERVICE_URL: "http://localhost:8002/api",
    },
  },
});
