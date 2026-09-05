/**
 * Identity-provider sign-out, mounted at `/logout`.
 *
 * This clears the **IDP** session (`idp_session`). It is separate from the
 * SPA's sign-out, which calls the BFF's `/auth/logout` to clear the
 * OAuth2 token session — mirroring real SSO, where leaving an app doesn't
 * end your identity-provider session. Clearing the IDP session lets the
 * demo sign in as a different user on the next authorize.
 *
 * `return_to` is honored but constrained to a same-origin path (the shared
 * `safeReturnTo` guard) so the endpoint can't be used as an open redirect.
 *
 * @module
 */

import { Hono } from "hono";
import { safeReturnTo } from "@udibo/oauth2/url";

import { endSession } from "@/sessions.ts";

const app = new Hono();

app.post("/", async (c) => {
  const form = await c.req.formData().catch(() => null);
  const returnTo = safeReturnTo(form?.get("return_to")?.toString());
  endSession(c);
  return c.redirect(returnTo);
});

app.get("/", (c) => {
  endSession(c);
  return c.redirect(safeReturnTo(c.req.query("return_to")));
});

export default app;
