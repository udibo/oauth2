/**
 * Server-side OAuth2 wiring for your app: an embedded authorization server
 * (your app's own identity provider), the BFF the React app signs in through,
 * and a resource server that validates bearer tokens — one process, zero
 * external services. Storage is in-memory (`Memory*Service`), so everything
 * works locally and in CI without a database or a cloud account; swap those
 * services for implementations backed by your database when you're ready.
 *
 * This module is server-only — never import it from client code. The browser
 * uses `oauth2/browser-client.ts` instead.
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
import {
  type PasswordHasherLike,
  PasswordIdentityService,
} from "@udibo/oauth2/identity";

/** A user account. Extend with whatever fields your app needs. */
export interface AppUser {
  id: string;
  username: string;
  name: string;
}

/** The app's own OAuth2 client registration. */
export interface AppClient {
  id: string;
  grants: string[];
  redirectUris: string[];
}

/** The origin the app is served from; doubles as the OAuth2 issuer. */
export const ISSUER: string = Deno.env.get("APP_ORIGIN") ??
  "http://localhost:8000";

const isProduction = Deno.env.get("APP_ENV") === "production";

function resolveClientSecret(): string {
  const secret = Deno.env.get("OAUTH2_CLIENT_SECRET");
  if (secret) return secret;
  if (isProduction) {
    throw new Error(
      "OAUTH2_CLIENT_SECRET must be set when APP_ENV=production — the " +
        "development fallback is public in the template source.",
    );
  }
  return "dev-only-secret";
}

const CLIENT_SECRET = resolveClientSecret();

const APP_CLIENT: AppClient = {
  id: "app",
  grants: ["authorization_code", "refresh_token"],
  redirectUris: [`${ISSUER}/auth/callback`],
};

/**
 * Demo account seeded in every non-production environment so the app runs
 * with zero signup: `demo` / `password`. Remove it (and this export) once you
 * have real account storage.
 */
export const DEMO_USER: AppUser = {
  id: "demo-user",
  username: "demo",
  name: "Demo User",
};

/**
 * The password hasher shared by the user store and the identity flows
 * (`oauth2/identity.ts`). One instance, so every credential in the app is
 * hashed at the same work factor and no sign-in path is measurably cheaper
 * than another. Swap it for an argon2/scrypt {@link PasswordHasherLike} and
 * both halves follow.
 */
export const passwords: PasswordHasherLike = new PasswordIdentityService();

/** The app's user store. `oauth2/identity.ts` drives the own-auth flows over it. */
export const userService: MemoryUserService<AppUser> = new MemoryUserService<
  AppUser
>({ passwords });
const clientService = new MemoryClientService<AppClient, AppUser>(userService);
const tokenService = new MemoryTokenService<AppClient, AppUser>({
  clientService,
  userService,
});
const authorizationCodeService = new MemoryAuthorizationCodeService<
  AppClient,
  AppUser
>({ clientService, userService });

await clientService.add(APP_CLIENT, CLIENT_SECRET);
if (!isProduction) {
  await userService.add(DEMO_USER, "password");
}

/** Looks up a user by id; used by the authorize handler. */
export function getUser(id: string): Promise<AppUser | undefined> {
  return userService.get(id);
}

/** The embedded authorization server, mounted at `/oauth2/*`. */
export const authServer: HonoAuthorizationServer<AppClient, AppUser> =
  new HonoAuthorizationServer({
    resolve: () => ({
      services: { clientService, tokenService },
      issuer: ISSUER,
      tokenEndpoint: `${ISSUER}/oauth2/token`,
      authorizationEndpoint: `${ISSUER}/oauth2/authorize`,
      revocationEndpoint: `${ISSUER}/oauth2/revoke`,
      introspectionEndpoint: `${ISSUER}/oauth2/introspect`,
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
  clientSecret: CLIENT_SECRET,
  redirectUri: `${ISSUER}/auth/callback`,
  endpoints: {
    authorization: `${ISSUER}/oauth2/authorize`,
    token: `${ISSUER}/oauth2/token`,
    revocation: `${ISSUER}/oauth2/revoke`,
  },
  fetch: localAuthServerFetch(authServer),
});

/**
 * Resource server sharing the auth server's token service, so bearer tokens
 * validate in-process. Use `resourceServer.getContext(c)` inside routes
 * guarded by `bff.protect()`.
 */
export const resourceServer: HonoResourceServer<AppClient, AppUser> =
  new HonoResourceServer({ resolve: () => ({ services: { tokenService } }) });

/**
 * The Backend-For-Frontend the React app authenticates through. The browser
 * never holds a token — it gets an HttpOnly session cookie, and credentialed
 * fetches must send an `x-csrf: 1` header.
 */
export const bff: HonoBff = new HonoBff({
  client: oauthClient,
  resourceServer,
  defaultReturnTo: "/",
  resolveUser: async (tokens) => {
    const token = await tokenService.getToken(tokens.accessToken);
    if (!token?.user) return null;
    return {
      sub: token.user.id,
      username: token.user.username,
      name: token.user.name,
    };
  },
  sessionMaxAgeMs: 14 * 24 * 60 * 60 * 1000,
  cookie: { secure: isProduction },
});
