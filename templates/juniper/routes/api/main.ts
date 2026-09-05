/**
 * Protected API endpoints, mounted at `/api/*`. `bff.protect()` reads the
 * session cookie, refreshes the access token if it's near expiry, and
 * validates it against the in-process resource server. Browser calls must
 * include the session cookie and an `x-csrf: 1` header.
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
    username: user?.username,
    name: user?.name,
  });
});

export default app;
