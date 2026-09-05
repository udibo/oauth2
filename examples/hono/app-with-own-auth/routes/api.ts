/**
 * Demo protected API endpoints exercising the BFF + resource server.
 *
 * Mounted at `/api` by `main.ts`; the paths below are relative.
 * `bff.protect(scope?)` reads the session cookie, refreshes the access
 * token if it's near expiry, and authenticates against the configured
 * resource server in one middleware. The scope arg gates each route by
 * what's in the token — a token issued for `user` (scope `read write`)
 * gets 403 from `/admin`.
 *
 *   - `GET /me`    — any valid token.
 *   - `GET /write` — required scope: `write`.
 *   - `GET /admin` — required scope: `admin`.
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
} from "../oauth2/server.ts";

const app = new Hono<{
  Variables: HonoResourceServerVariables<DemoClient, DemoUser>;
}>();

app.use("/me", bff.protect());
app.get("/me", (c) => {
  const { client, user, scope } = resourceServer.getContext(c);
  return c.json({
    message: "Any valid token.",
    sub: (user as { id: string } | undefined)?.id,
    client: client.id,
    scope: scope?.toString(),
  });
});

app.use("/write", bff.protect("write"));
app.get("/write", (c) => {
  const { user, scope } = resourceServer.getContext(c);
  return c.json({
    message: "Required scope: write.",
    sub: (user as { id: string } | undefined)?.id,
    scope: scope?.toString(),
  });
});

app.use("/admin", bff.protect("admin"));
app.get("/admin", (c) => {
  const { user, scope } = resourceServer.getContext(c);
  return c.json({
    message: "Required scope: admin.",
    sub: (user as { id: string } | undefined)?.id,
    scope: scope?.toString(),
  });
});

export default app;
