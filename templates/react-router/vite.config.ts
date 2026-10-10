import { reactRouter } from "@react-router/dev/vite";
import babel from "@rolldown/plugin-babel";
import tailwindcss from "@tailwindcss/vite";
import { reactCompilerPreset } from "@vitejs/plugin-react";
import { reactRouterHonoServer } from "react-router-hono-server/dev";
import { defineConfig } from "vite";

export default defineConfig({
  server: { port: 8000, strictPort: true },
  plugins: [
    tailwindcss(),
    reactRouterHonoServer({ serverEntryPoint: "./server/index.ts" }),
    reactRouter(),
    babel({ presets: [reactCompilerPreset()] }),
  ],
});
