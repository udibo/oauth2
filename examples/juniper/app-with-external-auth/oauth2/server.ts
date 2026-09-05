/**
 * Wires the OAuth2 pieces for the Juniper app-with-external-auth example.
 * Server-only — never imported by the React client bundle (that uses
 * `oauth2/browser-client.ts`).
 *
 * Unlike `app-with-own-auth`, this app does **not** run an authorization
 * server. It delegates login to a **separate** identity provider and wires:
 *
 * 1. **An OAuth2 client + Hono BFF** — confidential client talking to the
 *    external IDP over real HTTP (no `localAuthServerFetch`). The BFF owns
 *    the `oauth2_session` cookie and exposes the `/auth/*` endpoints.
 * 2. **A resource server** — validates bearer tokens via RFC 7662
 *    introspection against the IDP ({@link IntrospectionTokenReader}),
 *    projecting the response into the app's `User`/`Client` shape.
 *
 * The diff between this file and `app-with-own-auth/oauth2/server.ts` is
 * the literal self-hosted → external migration path: swap the embedded
 * authorization server + in-process token service for an
 * `IntrospectionTokenReader`, drop `localAuthServerFetch`, and point the
 * endpoints at the external IDP.
 *
 * **Local-dev pairing**: the IDP URLs default to the sibling
 * `examples/juniper/app-with-own-auth` on port 8004, so you can run that
 * in one terminal and this in another to exercise the full flow without a
 * real deployment. Swap `IDP_BASE_URL` + credentials in production.
 *
 * ## Production shortcuts
 *
 * This example trades production hardening for a one-command local run:
 *
 * - **The IDP URLs and the client secret are literals in this file** — the
 *   secret is the same committed `spa-secret` the paired IDP registers. Read
 *   both from the environment, and refuse to start without the secret.
 * - **The BFF cookie is `secure: false`** so it survives plain-`http://`
 *   localhost. Serve over HTTPS and set `secure: true`.
 * - **Every request costs a live introspection round-trip to the IDP**, with
 *   no caching and no failure budget. Decide what a deployed app does when
 *   the IDP is slow or down before you ship this shape.
 *
 * @module
 */

import { HonoBff } from "@udibo/oauth2/hono/bff";
import { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import { DirectClient } from "@udibo/oauth2/client";
import { IntrospectionTokenReader } from "@udibo/oauth2/server/resource";

/** Client identity projected from the IDP's introspection response. */
export interface ExternalClient {
  id: string;
}

/** User identity projected from the IDP's introspection response. */
export interface ExternalUser {
  id: string;
  username?: string;
}

/**
 * **Production swap point.** In a real deployment these come from env vars
 * and point at Udibo (or whichever IDP you registered with). The defaults
 * pair with `app-with-own-auth` running locally on port 8004.
 */
export const IDP_BASE_URL = "http://localhost:8004";
export const APP_BASE_URL = "http://localhost:8005";
export const IDP_CLIENT_ID = "spa";
export const IDP_CLIENT_SECRET = "spa-secret";

/** Exported so tests can stub `getToken` directly (no live IDP needed). */
export const tokenReader: IntrospectionTokenReader<
  ExternalClient,
  ExternalUser
> = new IntrospectionTokenReader<ExternalClient, ExternalUser>({
  introspectionEndpoint: `${IDP_BASE_URL}/oauth2/introspect`,
  clientId: IDP_CLIENT_ID,
  clientSecret: IDP_CLIENT_SECRET,
  getClient: (data) => ({ id: data.client_id ?? "" }),
  getUser: (data) =>
    data.sub ? { id: data.sub, username: data.username } : undefined,
});

const oauthClient = new DirectClient({
  clientId: IDP_CLIENT_ID,
  clientSecret: IDP_CLIENT_SECRET,
  redirectUri: `${APP_BASE_URL}/auth/callback`,
  endpoints: {
    authorization: `${IDP_BASE_URL}/oauth2/authorize`,
    token: `${IDP_BASE_URL}/oauth2/token`,
    revocation: `${IDP_BASE_URL}/oauth2/revoke`,
  },
});

export const resourceServer = new HonoResourceServer<
  ExternalClient,
  ExternalUser
>({
  resolve: () => ({ services: { tokenService: tokenReader } }),
  realm: "App with External Auth",
});

export const bff = new HonoBff({
  client: oauthClient,
  resourceServer,
  defaultReturnTo: "/",
  scope: "read write admin",
  resolveUser: async (tokens) => {
    const token = await tokenReader.getToken(tokens.accessToken);
    if (!token?.user) return null;
    return { sub: token.user.id, username: token.user.username };
  },
  cookie: { secure: false },
});
