/**
 * Protected API endpoints, mounted at `/api/*`. Each is guarded by
 * `bff.protect(scope?)`, which reads the session cookie, refreshes the
 * access token if it's near expiry, then validates it (and its scope) by
 * introspecting the external IDP via `IntrospectionTokenReader` — one
 * inbound request plus one outbound introspection call per request. (Cache
 * introspection results or validate JWTs locally in production to avoid the
 * round-trip.)
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
  type ExternalClient,
  type ExternalUser,
  resourceServer,
} from "@/oauth2/server.ts";

const app = new Hono<{
  Variables: HonoResourceServerVariables<ExternalClient, ExternalUser>;
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
