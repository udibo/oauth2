/**
 * Root server middleware for the app. Mounted by Juniper at `/`.
 *
 * Kept intentionally thin — request logging only. The OAuth2 wiring
 * lives in the nested route groups: `routes/auth/` (the BFF) and
 * `routes/api/` (protected resources); login itself lives on the external
 * IDP, not in this app.
 *
 * @module
 */

import { Hono } from "hono";
import { logger } from "hono/logger";
import type { AppEnv } from "@udibo/juniper/server";

const app = new Hono<AppEnv>();

app.use(logger());

export default app;
