/**
 * The auth layer as one Hono app: the embedded authorization server, the BFF,
 * the identity endpoints the forms post to, and your protected API. Kept apart
 * from `index.ts` so tests can drive it with `app.request()` without React
 * Router or a build.
 *
 *   - `/oauth2/*`   — the embedded authorization server. Its authorize
 *     handler bounces signed-out users to the `/login` page with the
 *     in-flight authorize URL as `return_to`.
 *   - `/auth/*`     — the BFF's browser endpoints (`login`, `callback`,
 *     `logout`, `session`). Logout also ends the issuer session, so signing
 *     out signs you out completely.
 *   - `/identity/*` — sign-up / sign-in / password-reset / email-verify
 *     endpoints the forms post to. On success the handler opens the issuer
 *     session and redirects into `bff.loginContinuation`, which either resumes
 *     an in-flight authorize URL or starts a fresh BFF login.
 *   - `/api/*`      — your protected API (`api.ts`).
 *
 * @module
 */

import { Hono } from "hono";
import { csrf } from "hono/csrf";

import { honoIdentityRoutes } from "@udibo/oauth2/hono/identity";

import api from "./api.ts";
import { identity } from "./oauth2/identity.ts";
import { authServer, bff, getUser } from "./oauth2/server.ts";
import { endSession, readSessionUserId, startSession } from "./sessions.ts";

const auth = new Hono();

auth.route(
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

auth.use("/auth/logout", async (c, next) => {
  await next();
  if (c.res.status < 400) endSession(c);
});
auth.route("/auth", bff.routes());

auth.use("/identity/*", csrf());
auth.route(
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

auth.route("/api", api);

export default auth;
