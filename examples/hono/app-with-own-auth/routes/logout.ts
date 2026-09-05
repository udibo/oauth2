/**
 * Logout endpoint for the embedded IDP.
 *
 * Mounted at `/logout` by `main.ts`; the path below is relative.
 * `POST /` clears the IDP session cookie (and the server-side record),
 * so a subsequent `/oauth2/authorize` hits the login form again instead
 * of silently re-signing in the same user.
 *
 * Two callers, two responses:
 * - The SPA's "Sign out" button `fetch`es this with no body and ignores
 *   the response — it just needs the IDP session cleared, so it gets 204.
 * - The consent page's "Sign out & switch user" form POSTs a `return_to`
 *   so the browser lands back on the authorize URL to sign in as a
 *   different account; we redirect there.
 *
 * Distinct from `POST /auth/logout` (the BFF endpoint) — that one clears
 * the BFF's session and revokes the SPA's tokens, but doesn't touch the
 * IDP session. To swap demo users you call both; the SPA's Sign out
 * button does this in sequence.
 *
 * @module
 */

import { type Context, Hono } from "hono";

import { safeReturnTo } from "@udibo/oauth2/url";

import { endSession } from "../sessions.ts";

const app = new Hono();

app.post("/", async (c) => {
  endSession(c);
  const returnTo = safeReturnTo(await readReturnTo(c), "");
  if (returnTo) {
    return c.redirect(returnTo);
  }
  return c.body(null, 204);
});

export default app;

/**
 * Reads `return_to` from the query string or the form body, tolerating a
 * bodiless `fetch` POST (the SPA's Sign out button sends no body).
 */
async function readReturnTo(c: Context): Promise<string | undefined> {
  const fromQuery = c.req.query("return_to");
  if (fromQuery) return fromQuery;
  if (!(c.req.header("content-type") ?? "").includes("form")) return undefined;
  try {
    const value = (await c.req.formData()).get("return_to");
    return typeof value === "string" ? value : undefined;
  } catch {
    return undefined;
  }
}
