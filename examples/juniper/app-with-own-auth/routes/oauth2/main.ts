/**
 * The embedded authorization server's endpoints, mounted at `/oauth2/*`
 * (`/oauth2/authorize`, `/oauth2/token`, `/oauth2/revoke`,
 * `/oauth2/introspect`).
 *
 * `authenticateUser` resolves the IDP login session: with no session it
 * redirects to the login form, preserving the original authorize URL as
 * `return_to`. There's **no `handleConsent`** — the demo SPA is this IDP's own
 * first-party client, and with no handler the framework grants the (per-user
 * narrowed) scope without a prompt. An app serving untrusted third-party
 * clients would add a `handleConsent` here to prompt or deny — see the Hono
 * `app-with-own-auth` example for a full consent page.
 *
 * @module
 */

import { authServer, getUser } from "@/oauth2/server.ts";
import { readSessionUserId } from "@/sessions.ts";

export default authServer.routes({
  authenticateUser: async (c) => {
    const url = new URL(c.req.url);
    const returnTo = `${url.pathname}${url.search}`;
    const loginRedirect = () =>
      c.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`);

    const userId = readSessionUserId(c);
    if (!userId) return loginRedirect();
    const user = await getUser(userId);
    if (!user) return loginRedirect();
    return { user };
  },
});
