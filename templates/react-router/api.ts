/**
 * Your app's protected API, mounted at `/api/*`. Each route is guarded by
 * `bff.protect()`, which reads the session cookie, refreshes the access token
 * if it's near expiry, and validates it against the in-process resource
 * server — one inbound request, zero outbound.
 *
 * Add your real endpoints here; `resourceServer.getContext(c)` gives you the
 * validated user and client.
 *
 * @module
 */

import { Hono } from "hono";

import type { HonoResourceServerVariables } from "@udibo/oauth2/hono/resource-server";

import {
  type AppClient,
  type AppUser,
  bff,
  resourceServer,
} from "@/oauth2/server.ts";

const app = new Hono<{
  Variables: HonoResourceServerVariables<AppClient, AppUser>;
}>();

app.use("/me", bff.protect());
app.get("/me", (c) => {
  const { user } = resourceServer.getContext(c);
  return c.json({
    sub: user?.id,
    name: user?.name,
    email: user?.email,
    emailVerified: user?.emailVerified,
  });
});

export default app;
