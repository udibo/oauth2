/**
 * Example: a Hono app whose API routes require an OAuth2 bearer token.
 *
 * Mount layout (one sub-app per prefix — Hono best practice for larger
 * apps; see https://hono.dev/docs/guides/best-practices):
 *
 *   - `app.route("/", home)` — interactive walkthrough at `GET /`
 *     that drives every OAuth2 grant against the companion
 *     authorization server (port 8001) and tests the resulting tokens
 *     against this server's `/api/*` endpoints (`routes/home.ts`).
 *   - `app.route("/api", api)` — protected API endpoints
 *     (`routes/api.ts`). Each route demonstrates a different scope
 *     requirement on `resourceServer.protect()`:
 *       - `GET /api/public`  — no token required.
 *       - `GET /api/private` — any valid token.
 *       - `GET /api/write`   — token must carry `write` scope.
 *       - `GET /api/admin`   — token must carry `admin` scope.
 *   - `app.route("/dev", dev)` — dev-only redirect callback +
 *     token-endpoint proxy used by the homepage's in-browser runners
 *     (`routes/dev.ts`). Not part of how a real api-service pairs
 *     with an auth server; included so the example is self-contained.
 *
 * Run:
 *   Terminal 1: (in the app-with-own-auth example) deno task serve
 *   Terminal 2: deno task serve
 *
 * @module
 */

import { Hono } from "hono";

import type { HonoResourceServerVariables } from "@udibo/oauth2/hono/resource-server";
import { type ExampleClient, type ExampleUser } from "./oauth2/server.ts";
import home from "./routes/home.ts";
import api from "./routes/api.ts";
import dev from "./routes/dev.ts";

const app = new Hono<{
  Variables: HonoResourceServerVariables<ExampleClient, ExampleUser>;
}>();

app.route("/", home);
app.route("/api", api);
app.route("/dev", dev);

export default app;

if (import.meta.main) {
  console.log("Open http://localhost:8002/ for the endpoint walkthrough.");
  console.log("Make sure app-with-own-auth is running on port 8001.");
}
