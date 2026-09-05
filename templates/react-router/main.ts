/**
 * The server: one Hono app that serves the SPA and runs the whole auth layer.
 *
 * Mount layout:
 *
 *   - `/oauth2/*`   — the embedded authorization server. Its authorize
 *     handler bounces signed-out users to the SPA's `/login` page with the
 *     in-flight authorize URL as `return_to`.
 *   - `/auth/*`     — the BFF's browser endpoints (`login`, `callback`,
 *     `logout`, `session`). Logout also ends the issuer session, so signing
 *     out signs you out completely.
 *   - `/identity/*` — sign-up / sign-in / password-reset / email-verify
 *     endpoints the SPA's forms post to. On success the handler opens the
 *     issuer session and redirects into `bff.loginContinuation`, which either
 *     resumes an in-flight authorize URL or starts a fresh BFF login.
 *   - `/api/*`      — your protected API (`api.ts`).
 *   - `/build/*`    — the esbuild browser bundle (`deno task build`).
 *   - everything else GET — the SPA shell, so React Router owns the URL space.
 *
 * @module
 */

import { Hono } from "hono";
import { csrf } from "hono/csrf";
import { serveStatic } from "hono/deno";

import { honoIdentityRoutes } from "@udibo/oauth2/hono/identity";

import api from "@/api.ts";
import { isProduction } from "@/config.ts";
import { identity } from "@/oauth2/identity.ts";
import { authServer, bff, getUser } from "@/oauth2/server.ts";
import { endSession, readSessionUserId, startSession } from "@/sessions.ts";

const shell = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="icon" href="data:," />
    <title>My App</title>
  </head>
  <body>
    <div id="root"></div>
    <script>globalThis.__DEMO_ACCOUNT__ = ${!isProduction};</script>
    <script type="module" src="/build/main.js"></script>
  </body>
</html>
`;

const app = new Hono();

app.route(
  "/oauth2",
  authServer.routes({
    authenticateUser: async (c) => {
      const userId = readSessionUserId(c);
      if (userId) {
        const user = await getUser(userId);
        if (user) return { user };
        endSession(c);
      }
      const url = new URL(c.req.url);
      const returnTo = `${url.pathname}${url.search}`;
      return c.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`);
    },
  }),
);

app.use("/auth/logout", async (c, next) => {
  await next();
  if (c.res.status < 400) endSession(c);
});
app.route("/auth", bff.routes());

app.use("/identity/*", csrf());
app.route(
  "/identity",
  honoIdentityRoutes(identity, {
    onAuthenticated: async (c, user, action) => {
      if (action === "signUp") {
        await identity.requestEmailVerification({
          userId: user.id,
          email: user.email,
        });
      }
      startSession(c, user.id);
      return c.redirect(bff.loginContinuation(c.req.query("return_to")));
    },
  }),
);

app.route("/api", api);

app.use("/build/*", serveStatic({ root: "./public" }));
app.get("/build/*", (c) => c.notFound());
app.get("*", (c) => c.html(shell));

export default app;
