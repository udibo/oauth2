/**
 * Demo API endpoints exercising `resourceServer.protect(scope?)`.
 *
 * Mounted at `/api` by `main.ts`; the paths below are relative. Each
 * route demonstrates a different scope requirement so a reader can see
 * how the same `protect()` middleware gates by what's in the token.
 *
 *   - `GET /public`  — no token required.
 *   - `GET /private` — any valid token.
 *   - `GET /write`   — token must carry `write` scope.
 *   - `GET /admin`   — token must carry `admin` scope.
 *
 * @module
 */

import { Hono } from "hono";

import type { HonoResourceServerVariables } from "@udibo/oauth2/hono/resource-server";

import {
  type ExampleClient,
  type ExampleUser,
  resourceServer,
} from "../oauth2/server.ts";

const app = new Hono<{
  Variables: HonoResourceServerVariables<ExampleClient, ExampleUser>;
}>();

app.get(
  "/public",
  (c) => c.json({ message: "Public endpoint — no token required." }),
);

app.use("/private", resourceServer.protect());
app.get("/private", (c) => {
  const { client, user, scope } = resourceServer.getContext(c);
  return c.json({
    message: "Protected endpoint — any valid token.",
    client: client.id,
    user: user?.id,
    scope: scope?.toString(),
  });
});

app.use("/write", resourceServer.protect("write"));
app.get("/write", (c) => {
  const { client, user, scope } = resourceServer.getContext(c);
  return c.json({
    message: "Write endpoint — required scope: write.",
    client: client.id,
    user: user?.id,
    scope: scope?.toString(),
  });
});

app.use("/admin", resourceServer.protect("admin"));
app.get("/admin", (c) => {
  const { client, user, scope } = resourceServer.getContext(c);
  return c.json({
    message: "Admin endpoint — required scope: admin.",
    client: client.id,
    user: user?.id,
    scope: scope?.toString(),
  });
});

export default app;
