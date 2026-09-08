/**
 * Root server middleware for the app. Mounted by Juniper at `/`.
 *
 * Kept intentionally thin — request logging only. The OAuth2 wiring
 * lives in the nested route groups: `routes/oauth2/` (the IDP),
 * `routes/auth/` (the BFF), and `routes/api/` (protected resources).
 *
 * @module
 */

import { Hono } from "hono";
import { requestLogger } from "@udibo/oauth2/hono/log";
import type { AppEnv } from "@udibo/juniper/server";

const app = new Hono<AppEnv>();

app.use(requestLogger());

export default app;
