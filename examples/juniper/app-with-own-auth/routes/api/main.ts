/**
 * Protected API endpoints, mounted at `/api/*`. Each is guarded by
 * `bff.protect(scope?)`, which reads the session cookie, refreshes the
 * access token if it's near expiry, and validates it (and its scope)
 * against the in-process resource server — one inbound request, zero
 * outbound.
 *
 *   - `GET /api/me`    — any valid token.
 *   - `GET /api/write` — requires the `write` scope.
 *   - `GET /api/admin` — requires the `admin` scope (only `admin` has it).
 *
 * @module
 */

import { Hono } from "hono";

import type { HonoResourceServerVariables } from "@udibo/oauth2/hono/resource-server";

import {
  bff,
  type DemoClient,
  type DemoUser,
  resourceServer,
} from "@/oauth2/server.ts";

const app = new Hono<{
  Variables: HonoResourceServerVariables<DemoClient, DemoUser>;
}>();

app.use("/me", bff.protect());
app.get("/me", (c) => {
  const { client, user, scope } = resourceServer.getContext(c);
  return c.json({
    message: "Any valid token.",
    sub: user?.id,
    client: client.id,
    scope: scope?.toString(),
  });
});

app.use("/write", bff.protect("write"));
app.get("/write", (c) => {
  const { user, scope } = resourceServer.getContext(c);
  return c.json({
    message: "Required scope: write.",
    sub: user?.id,
    scope: scope?.toString(),
  });
});

app.use("/admin", bff.protect("admin"));
app.get("/admin", (c) => {
  const { user, scope } = resourceServer.getContext(c);
  return c.json({
    message: "Required scope: admin.",
    sub: user?.id,
    scope: scope?.toString(),
  });
});

export default app;
