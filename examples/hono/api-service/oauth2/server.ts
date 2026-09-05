/**
 * OAuth2 resource server setup for the api-service example.
 *
 * `main.ts` imports {@linkcode resourceServer} and calls
 * `resourceServer.protect()` on the API routes that need a valid bearer
 * token. Everything else about the app is ordinary Hono.
 *
 * This example uses the library's built-in {@linkcode IntrospectionTokenReader}
 * (RFC 7662), which validates tokens by asking the authorization server
 * over HTTP. The reader is generic over the app's `Client` / `User` types
 * — the {@linkcode IntrospectionTokenReader} options' `getClient` and
 * `getUser` mappers project the introspection response into the shapes
 * this app actually uses. If your authorization server returns extension
 * fields (email, roles, tenant), claim them in `getUser` here.
 *
 * If your resource server shares a database with the authorization
 * server, replace the token reader with a direct `TokenReaderInterface`
 * implementation that queries that DB.
 *
 * Testing note: {@linkcode tokenReader} is exported as well so tests can
 * stub its `getToken` method directly. That keeps the override scoped to
 * a single object — no `globalThis.fetch` stub, no introspection wire
 * format to fake. See `../main.test.ts` for the pattern.
 *
 * @module
 */

import { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import { IntrospectionTokenReader } from "@udibo/oauth2/server/resource";

/** Client identity returned by the authorization server. */
export interface ExampleClient {
  id: string;
}

/** User identity returned by the authorization server. */
export interface ExampleUser {
  id: string;
  username?: string;
}

export const AUTH_SERVER_URL = "http://localhost:8001";
export const CLIENT_ID = "spa";
export const CLIENT_SECRET = "spa-secret";
export const REDIRECT_URI = "http://localhost:8002/dev/callback";
/**
 * Cookie the authorization-code demo stashes its PKCE `code_verifier` in
 * between `/` (which builds the authorize URL with the S256 challenge) and
 * `/dev/callback` (which reads it back to complete the token exchange). PKCE
 * is required by default under OAuth 2.1.
 */
export const PKCE_COOKIE = "demo_pkce_verifier";

/** Exposed so tests can stub `getToken` directly. */
export const tokenReader = new IntrospectionTokenReader<
  ExampleClient,
  ExampleUser
>({
  introspectionEndpoint: `${AUTH_SERVER_URL}/oauth2/introspect`,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  getClient: (data) => ({ id: data.client_id ?? "" }),
  getUser: (data) =>
    data.sub ? { id: data.sub, username: data.username } : undefined,
});

export const resourceServer = new HonoResourceServer<
  ExampleClient,
  ExampleUser
>({
  resolve: () => ({ services: { tokenService: tokenReader } }),
  realm: "Example API",
});
