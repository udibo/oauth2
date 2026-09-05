/**
 * Wires the OAuth2 server-side pieces for the Juniper app-with-own-auth
 * example into one process. This file is **server-only** — it is never
 * imported by the React client bundle (that uses
 * `oauth2/browser-client.ts`, which has no server dependencies).
 *
 * Three things live here:
 *
 * 1. **An authorization server** (the embedded IDP) — the same code path
 *    a real issuer runs, backed by `Memory*Service` so the example
 *    stands up without a database.
 * 2. **An OAuth2 client + Hono BFF** — the BFF wraps the client in
 *    confidential mode, owns the `oauth2_session` cookie, and exposes the
 *    `/auth/*` browser endpoints the React SPA talks to.
 * 3. **A resource server** — validates bearer tokens against the same
 *    in-process token service the auth server issues from, so a browser →
 *    API call costs one inbound request and zero outbound.
 *
 * The demo SPA is the IDP's own first-party client, so the authorize route
 * configures **no `handleConsent`** — with no handler the framework treats the
 * request as consented and grants without a prompt. (Self-hosted servers where
 * every client is first-party never need a consent handler; one is only there
 * to prompt for, or deny, untrusted third-party clients — see the Hono
 * `app-with-own-auth` example for a full consent page.) Per-user scope limits
 * are still enforced: {@link ScopedTokenService} narrows every issued token
 * down to the signed-in user's `maxScope`, so a token minted for the regular
 * `user` is rejected (403) by the `admin`-scoped endpoint.
 *
 * ## Production shortcuts
 *
 * This example trades production hardening for a one-command local run. Each
 * of these is a deliberate shortcut, not a pattern to copy:
 *
 * - **The client secret is the literal `spa-secret`, committed here.** Read it
 *   from the environment instead, and refuse to start when it is missing.
 * - **The BFF cookie is `secure: false`** so it survives plain-`http://`
 *   localhost. Serve over HTTPS and set `secure: true`.
 * - **Both demo users share the password `password`**, seeded unconditionally.
 *   A deployed app seeds no accounts.
 * - **Every store is an in-memory `Memory*Service`**, so all state — users,
 *   clients, tokens, codes — dies with the process. Replace them with
 *   database-backed implementations of the same interfaces; the conformance
 *   tests in `@udibo/oauth2/testing/contract` verify yours.
 * - **Sign-in calls {@link authenticateCredentials} directly**, with no rate
 *   limiting, no lockout, and no timing equalization — an unknown username
 *   answers measurably faster than a known one with a wrong password, which
 *   is a username-enumeration oracle. Route credentials through
 *   `IdentityService.signIn` (`@udibo/oauth2/identity`) instead: it throttles
 *   before the lookup and hashes on every failure branch. The
 *   `templates/juniper` starter shows that wiring.
 *
 * @module
 */

import { HonoAuthorizationServer } from "@udibo/oauth2/hono/authorization-server";
import { HonoBff } from "@udibo/oauth2/hono/bff";
import { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import { DirectClient } from "@udibo/oauth2/client";
import { BasicScope } from "@udibo/oauth2/server";
import {
  AuthorizationCodeGrant,
  ClientCredentialsGrant,
  localAuthServerFetch,
  RefreshTokenGrant,
} from "@udibo/oauth2/server/authorization";
import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
} from "@udibo/oauth2/testing";

/** A demo user, with the scope set they're allowed to be granted. */
export interface DemoUser {
  id: string;
  username: string;
  name: string;
  /**
   * Space-delimited scope tokens this user may be granted. Every issued
   * token is narrowed to this set (see {@link ScopedTokenService}), so
   * `user` (no `admin`) gets a 403 from the admin-scoped endpoint.
   */
  maxScope: string;
}

/**
 * A demo OAuth2 client. The framework only reads `id`, `grants`, and
 * `redirectUris` (the `ClientInterface` surface); `name` is an app-defined
 * field carried along for the app's own use — bring whatever shape you like.
 */
export interface DemoClient {
  id: string;
  grants: string[];
  redirectUris: string[];
  name: string;
}

/** Issuer (and listening origin in `deno task serve`). */
export const ISSUER = "http://localhost:8004";

export const ADMIN_USER: DemoUser = {
  id: "user-admin",
  username: "admin",
  name: "Admin User",
  maxScope: "read write admin",
};
export const STANDARD_USER: DemoUser = {
  id: "user-1",
  username: "user",
  name: "Demo User",
  maxScope: "read write",
};

export const DEMO_CLIENT: DemoClient = {
  id: "spa",
  grants: ["authorization_code", "refresh_token"],
  redirectUris: [
    `${ISSUER}/auth/callback`,
    "http://localhost:8005/auth/callback",
  ],
  name: "Example SPA",
};
export const DEMO_CLIENT_SECRET = "spa-secret";

/**
 * Token service that caps every issued token at the signed-in user's
 * `maxScope`. RFC 6749 §3.3 lets the authorization server grant a subset
 * of the requested scope; this is where a real server would consult
 * per-user roles/permissions. With no consent handler configured the framework
 * grants without a prompt, so this narrowing is the only thing standing between
 * `user` and the admin-scoped endpoint.
 */
class ScopedTokenService extends MemoryTokenService<DemoClient, DemoUser> {
  override acceptedScope(
    _client: DemoClient,
    user: DemoUser,
    scope?: BasicScope | null,
  ): Promise<BasicScope | null | undefined | false> {
    if (!scope) return Promise.resolve(scope);
    const narrowed = BasicScope.intersection(scope.toString(), user.maxScope);
    return Promise.resolve(narrowed.size > 0 ? narrowed : false);
  }
}

const userService = new MemoryUserService<DemoUser>();
const clientService = new MemoryClientService<DemoClient, DemoUser>(
  userService,
);
/** Exported so tests can mint tokens the resource server will accept. */
export const tokenService = new ScopedTokenService({
  clientService,
  userService,
});
const authorizationCodeService = new MemoryAuthorizationCodeService<
  DemoClient,
  DemoUser
>({ clientService, userService });

await userService.add(ADMIN_USER, "password");
await userService.add(STANDARD_USER, "password");
await clientService.add(DEMO_CLIENT, DEMO_CLIENT_SECRET);

/** Authenticates IDP login credentials (used by `routes/login.ts`). */
export function authenticateCredentials(
  username: string,
  password: string,
): Promise<DemoUser | undefined> {
  return userService.getAuthenticated(username, password);
}

/** Looks up a user by id (used by the authorize handler). */
export function getUser(id: string): Promise<DemoUser | undefined> {
  return userService.get(id);
}

/** The embedded authorization server (the IDP). */
export const authServer = new HonoAuthorizationServer<DemoClient, DemoUser>({
  resolve: () => ({
    services: { clientService, tokenService },
    issuer: ISSUER,
    tokenEndpoint: `${ISSUER}/oauth2/token`,
    authorizationEndpoint: `${ISSUER}/oauth2/authorize`,
    revocationEndpoint: `${ISSUER}/oauth2/revoke`,
    introspectionEndpoint: `${ISSUER}/oauth2/introspect`,
  }),
  grants: {
    authorization_code: new AuthorizationCodeGrant<DemoClient, DemoUser>({
      resolve: () => ({
        clientService,
        tokenService,
        authorizationCodeService,
      }),
      allowRefreshToken: true,
    }),
    client_credentials: new ClientCredentialsGrant<DemoClient, DemoUser>({
      resolve: () => ({ clientService, tokenService }),
    }),
    refresh_token: new RefreshTokenGrant<DemoClient, DemoUser>({
      resolve: () => ({ clientService, tokenService }),
    }),
  },
  scopesSupported: ["read", "write", "admin"],
});

const oauthClient = new DirectClient({
  clientId: DEMO_CLIENT.id,
  clientSecret: DEMO_CLIENT_SECRET,
  redirectUri: `${ISSUER}/auth/callback`,
  endpoints: {
    authorization: `${ISSUER}/oauth2/authorize`,
    token: `${ISSUER}/oauth2/token`,
    revocation: `${ISSUER}/oauth2/revoke`,
  },
  fetch: localAuthServerFetch(authServer),
});

/**
 * Resource server sharing the auth server's token service, so bearer
 * tokens validate in-process without an introspection round-trip. Passed
 * to the BFF as its `resourceServer` so `bff.protect()` is the only
 * middleware a protected route needs.
 */
export const resourceServer = new HonoResourceServer<DemoClient, DemoUser>({
  resolve: () => ({ services: { tokenService } }),
});

/** The Backend-For-Frontend the React SPA authenticates through. */
export const bff = new HonoBff({
  client: oauthClient,
  resourceServer,
  defaultReturnTo: "/",
  scope: "read write admin",
  resolveUser: async (tokens) => {
    const token = await tokenService.getToken(tokens.accessToken);
    if (!token?.user) return null;
    return {
      sub: token.user.id,
      username: token.user.username,
      name: token.user.name,
    };
  },
  cookie: { secure: false },
});
