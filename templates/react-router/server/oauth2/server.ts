/**
 * Server-side OAuth2 wiring — never imported by the browser bundle (that uses
 * `app/oauth2/browser-client.ts`).
 *
 * Three pieces run in this one process:
 *
 * 1. **An authorization server** (the embedded issuer) — backed by
 *    `Memory*Service` stores so the starter stands up without a database.
 * 2. **An OAuth2 client + Hono BFF** — the BFF holds the tokens in a
 *    server-side session behind an HttpOnly cookie and exposes the `/auth/*`
 *    endpoints the browser talks to. The browser never sees a token.
 * 3. **A resource server** — validates bearer tokens against the same
 *    in-process token service, so a browser → API call costs one inbound
 *    request and zero outbound.
 *
 * The app is this issuer's own first-party client, so no consent handler is
 * configured — the framework grants without a prompt.
 *
 * Going to production: replace the `Memory*Service` stores with DB-backed
 * implementations (the contract tests in `@udibo/oauth2/testing/contract`
 * verify conformance) and set `OAUTH2_CLIENT_SECRET` (see `config.ts`).
 *
 * @module
 */

import { HonoAuthorizationServer } from "@udibo/oauth2/hono/authorization-server";
import { HonoBff } from "@udibo/oauth2/hono/bff";
import { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import { DirectClient } from "@udibo/oauth2/client";
import {
  AuthorizationCodeGrant,
  localAuthServerFetch,
  RefreshTokenGrant,
} from "@udibo/oauth2/server/authorization";
import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
} from "@udibo/oauth2/testing";

import { config } from "../config.ts";

/**
 * Your app's user. `username` is the sign-in identifier (the email address);
 * `MemoryUserService` indexes on it. Extend with whatever fields you need.
 */
export interface AppUser {
  id: string;
  username: string;
  name: string;
  email: string;
  emailVerified: boolean;
}

/** Your app's OAuth2 client record (`id`/`grants`/`redirectUris` is the full surface the framework reads). */
export interface AppClient {
  id: string;
  grants: string[];
  redirectUris: string[];
}

/**
 * Demo account seeded in every non-production environment so the app runs with
 * zero signup: `demo@example.com` / `password`. Remove it (and this export)
 * once you have real account storage.
 */
export const DEMO_USER: AppUser = {
  id: "user-demo",
  username: "demo@example.com",
  name: "Demo User",
  email: "demo@example.com",
  emailVerified: true,
};
export const DEMO_PASSWORD = "password";

/** The app's own first-party client registration. */
export const APP_CLIENT: AppClient = {
  id: "web",
  grants: ["authorization_code", "refresh_token"],
  redirectUris: [`${config.origin}/auth/callback`],
};
const APP_CLIENT_SECRET = config.clientSecret;

export const userService = new MemoryUserService<AppUser>();
const clientService = new MemoryClientService<AppClient, AppUser>(userService);
const tokenService = new MemoryTokenService<AppClient, AppUser>({
  clientService,
  userService,
});
const authorizationCodeService = new MemoryAuthorizationCodeService<
  AppClient,
  AppUser
>({ clientService, userService });

if (!config.isProduction) {
  await userService.add(DEMO_USER, DEMO_PASSWORD);
}
await clientService.add(APP_CLIENT, APP_CLIENT_SECRET);

/** Looks up a user by id (used by the authorize handler in `main.ts`). */
export function getUser(id: string): Promise<AppUser | undefined> {
  return userService.get(id);
}

/** The embedded authorization server, mounted at `/oauth2/*`. */
export const authServer = new HonoAuthorizationServer<AppClient, AppUser>({
  resolve: () => ({
    services: { clientService, tokenService },
    issuer: config.origin,
    tokenEndpoint: `${config.origin}/oauth2/token`,
    authorizationEndpoint: `${config.origin}/oauth2/authorize`,
    revocationEndpoint: `${config.origin}/oauth2/revoke`,
    introspectionEndpoint: `${config.origin}/oauth2/introspect`,
  }),
  grants: {
    authorization_code: new AuthorizationCodeGrant<AppClient, AppUser>({
      resolve: () => ({
        clientService,
        tokenService,
        authorizationCodeService,
      }),
      allowRefreshToken: true,
    }),
    refresh_token: new RefreshTokenGrant<AppClient, AppUser>({
      resolve: () => ({ clientService, tokenService }),
    }),
  },
});

const oauthClient = new DirectClient({
  clientId: APP_CLIENT.id,
  clientSecret: APP_CLIENT_SECRET,
  redirectUri: `${config.origin}/auth/callback`,
  endpoints: {
    authorization: `${config.origin}/oauth2/authorize`,
    token: `${config.origin}/oauth2/token`,
    revocation: `${config.origin}/oauth2/revoke`,
  },
  fetch: localAuthServerFetch(authServer),
});

/**
 * Resource server sharing the auth server's token service, so bearer tokens
 * validate in-process. Passed to the BFF so `bff.protect()` is the only
 * middleware a protected route needs.
 */
export const resourceServer = new HonoResourceServer<AppClient, AppUser>({
  resolve: () => ({ services: { tokenService } }),
});

/** The Backend-For-Frontend the browser authenticates through (`/auth/*`). */
export const bff = new HonoBff({
  client: oauthClient,
  resourceServer,
  defaultReturnTo: "/dashboard",
  resolveUser: async (tokens) => {
    const token = await tokenService.getToken(tokens.accessToken);
    if (!token?.user) return null;
    return {
      sub: token.user.id,
      name: token.user.name,
      email: token.user.email,
      emailVerified: token.user.emailVerified,
    };
  },
  sessionMaxAgeMs: 14 * 24 * 60 * 60 * 1000,
  cookie: { secure: config.secureCookies },
});
