/**
 * Identity-provider sign-out, mounted at `/logout`. Clears the `idp_session`
 * cookie — separate from the BFF's `/auth/logout`, which clears the OAuth2
 * token session. The app's sign-out button chains both:
 * `logout({ returnTo: "/logout" })` hits `/auth/logout`, which redirects
 * here, so one click ends both sessions.
 *
 * `return_to` is constrained to a same-origin path (`safeReturnTo`) so the
 * endpoint can't be used as an open redirect, and the navigation is rejected
 * unless it is same-origin (`isSameOrigin`) so it can't be used to force a
 * cross-site logout.
 *
 * @module
 */

import { Hono } from "hono";
import { safeReturnTo } from "@udibo/oauth2/url";

import { isSameOrigin } from "@/security.ts";
import { endSession } from "@/sessions.ts";

const app = new Hono();

app.get("/", (c) => {
  if (!isSameOrigin(c.req.raw)) return c.text("Cross-site request", 403);
  endSession(c);
  return c.redirect(safeReturnTo(c.req.query("return_to")));
});

export default app;
