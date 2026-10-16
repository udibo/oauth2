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
import { satisfiesAuthenticationRequest } from "@udibo/oauth2/server";
import { safeReturnTo } from "@udibo/oauth2/url";

import api from "./api.ts";
import { identity } from "./oauth2/identity.ts";
import { authServer, bff, getUser } from "./oauth2/server.ts";
import { endSession, readSession, startSession } from "./sessions.ts";

const REAUTHENTICATION_WINDOW_SECONDS = 10 * 60;

const auth = new Hono();

auth.route(
  "/oauth2",
  authServer.routes({
    authenticateUser: async (c, authentication) => {
      const url = new URL(c.req.url);
      const returnTo = `${url.pathname}${url.search}`;
      const login = () =>
        c.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`);
      const session = readSession(c);
      if (!session) return login();
      const user = await getUser(session.userId);
      if (!user) {
        endSession(c);
        return login();
      }
      const result = {
        user,
        authenticationContext: { auth_time: session.authTime },
        reauthenticated:
          session.signedInFor === returnTo &&
          Math.floor(Date.now() / 1000) - session.authTime <=
            REAUTHENTICATION_WINDOW_SECONDS,
      };
      if (
        authentication &&
        !satisfiesAuthenticationRequest(authentication, result)
      ) {
        return login();
      }
      return result;
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
      const returnTo = safeReturnTo(c.req.query("return_to"));
      startSession(c, user.id, returnTo);
      return c.redirect(bff.loginContinuation(returnTo));
    },
  }),
);

auth.route("/api", api);

export default auth;
