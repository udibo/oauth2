/**
 * Wires the OAuth2 pieces for the app-with-external-auth example.
 *
 * Two things live here:
 *
 * 1. **An OAuth2 client + Hono BFF** — the BFF wraps the client in
 *    confidential mode, owns the session cookie, and exposes the
 *    `/auth/*` browser-facing endpoints. Unlike `app-with-own-auth/`,
 *    this client talks to a **separate** identity provider over real
 *    HTTP — there's no `localAuthServerFetch` here.
 * 2. **A resource server** — validates bearer tokens via RFC 7662
 *    introspection against the external IDP. The
 *    {@link IntrospectionTokenReader} authenticates with the IDP using
 *    `IDP_CLIENT_ID` / `IDP_CLIENT_SECRET` and projects the response
 *    into the app's `User` / `Client` shape.
 *
 * The diff between this file and `app-with-own-auth/oauth2/server.ts`
 * is the literal migration path between self-hosted IDP and external
 * IDP: swap `HonoAuthorizationServer` + the in-process token service
 * for `IntrospectionTokenReader`, swap `localAuthServerFetch(authServer)`
 * for real `fetch`, and point the endpoints at the external IDP.
 *
 * **Pairing for local dev**: by default the IDP URLs point at
 * `app-with-own-auth/` on port 8001, so you can `cd app-with-own-auth &&
 * deno task serve` in one terminal and `cd app-with-external-auth &&
 * deno task serve` in another to exercise the end-to-end flow without a
 * real Udibo deployment. Swap `IDP_BASE_URL` and the credentials in
 * production.
 *
 * @module
 */

import { HonoBff } from "@udibo/oauth2/hono/bff";
import { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import { DirectClient } from "@udibo/oauth2/client";
import { IntrospectionTokenReader } from "@udibo/oauth2/server/resource";

/**
 * Client identity returned by the IDP's introspection endpoint. Real
 * apps typically add their own fields (a `name`, a `kind`, etc.).
 */
export interface ExternalClient {
  id: string;
}

/**
 * User identity returned by the IDP's introspection endpoint. Real apps
 * fetch additional user fields from their own database keyed on
 * `data.sub`.
 */
export interface ExternalUser {
  id: string;
  username?: string;
}

/**
 * **Production swap point.** In a real deployment these come from
 * environment variables and point at Udibo (or whichever IDP you've
 * registered with). The defaults below pair the example with
 * `app-with-own-auth/` running locally on port 8001.
 */
export const IDP_BASE_URL = "http://localhost:8001";
export const APP_BASE_URL = "http://localhost:8003";
export const IDP_CLIENT_ID = "spa";
export const IDP_CLIENT_SECRET = "spa-secret";

/**
 * Base URL of a **separate** resource server, proxied through the BFF by
 * `main.ts`. Defaults to the `api-service/` example on port 8002, which
 * introspects against the same IDP, so the session's access token is valid
 * there too.
 */
export const API_SERVICE_URL = "http://localhost:8002/api";

/** Exported so tests can stub `getToken` directly. */
export const tokenReader = new IntrospectionTokenReader<
  ExternalClient,
  ExternalUser
>({
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
    return {
      sub: token.user.id,
      username: token.user.username,
    };
  },
  cookie: { secure: false },
});
