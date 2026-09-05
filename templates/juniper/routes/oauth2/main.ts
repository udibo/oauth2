/**
 * The embedded authorization server's endpoints, mounted at `/oauth2/*`
 * (`/oauth2/authorize`, `/oauth2/token`, `/oauth2/revoke`,
 * `/oauth2/introspect`).
 *
 * `authenticateUser` resolves the IDP login session: with no session it
 * redirects to the sign-in form, preserving the original authorize URL as
 * `return_to`. There is no `handleConsent` — this app is its own first-party
 * client, and with no handler the framework grants without a prompt. Add one
 * here if you ever serve untrusted third-party clients.
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
