/**
 * Wires the OAuth2 pieces for the app-with-own-auth example into one Hono process.
 *
 * Three things live here:
 *
 * 1. **An authorization server** — the same code path a real issuer
 *    runs, just backed by `Memory*Service` so the example stands up
 *    without a database.
 * 2. **An OAuth2 client + Hono BFF** — the BFF wraps the client in
 *    confidential mode, owns the session cookie, and exposes the
 *    `/auth/*` browser-facing endpoints.
 * 3. **A resource server** — validates bearer tokens against the same
 *    in-process token service the auth server uses, so a browser → API
 *    call costs one inbound request and zero outbound (the BFF's
 *    `attachToken` middleware sets the `Authorization` header in-process,
 *    and refreshes route through `localAuthServerFetch` rather than
 *    opening a socket).
 *
 * Two seeded users (`admin` and `user`) carry different scope-grant
 * caps so the demo can show one user accessing endpoints the other
 * can't.
 *
 * @module
 */

import { HonoAuthorizationServer } from "@udibo/oauth2/hono/authorization-server";
import { HonoBff } from "@udibo/oauth2/hono/bff";
import { HonoResourceServer } from "@udibo/oauth2/hono/resource-server";
import { DirectClient } from "@udibo/oauth2/client";
import {
  AuthorizationCodeGrant,
  ClientCredentialsGrant,
  DeviceAuthorizationGrant,
  localAuthServerFetch,
  RefreshTokenGrant,
} from "@udibo/oauth2/server/authorization";
import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  MemoryTokenService,
  MemoryUserService,
} from "@udibo/oauth2/testing";

export interface DemoUser {
  id: string;
  username: string;
  name: string;
  /**
   * Space-delimited scope tokens this user is allowed to grant during
   * OAuth2 consent. The consent handler narrows the requested scope
   * down to this — so an `admin`-only API rejects a token issued for
   * the regular `user`.
   */
  maxScope: string;
  /** Recovery/verification address; the identity flows key off it. */
  email?: string;
  /** Set by the verify-email flow (`oauth2/identity.ts`). */
  emailVerified?: boolean;
}

export interface DemoClient {
  id: string;
  grants: string[];
  redirectUris: string[];
  name: string;
}

const issuer = "http://localhost:8001";

export const ADMIN_USER: DemoUser = {
  id: "user-admin",
  username: "admin",
  name: "Admin User",
  maxScope: "read write admin",
  email: "admin@example.com",
  emailVerified: true,
};
export const STANDARD_USER: DemoUser = {
  id: "user-1",
  username: "user",
  name: "Demo User",
  maxScope: "read write",
  email: "user@example.com",
  emailVerified: true,
};
export const DEMO_CLIENT: DemoClient = {
  id: "spa",
  grants: [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
  ],
  redirectUris: [
    `${issuer}/auth/callback`,
    "http://localhost:8002/dev/callback",
    "http://localhost:8003/auth/callback",
  ],
  name: "Example SPA",
};
export const DEMO_CLIENT_SECRET = "spa-secret";

export const userService = new MemoryUserService<DemoUser>();
const clientService = new MemoryClientService<DemoClient, DemoUser>(
  userService,
);
const tokenService = new MemoryTokenService<DemoClient, DemoUser>({
  clientService,
  userService,
});
const authorizationCodeService = new MemoryAuthorizationCodeService<
  DemoClient,
  DemoUser
>({ clientService, userService });
export const deviceService = new MemoryDeviceAuthorizationService<
  DemoClient,
  DemoUser
>({ clientService, userService });

await userService.add(ADMIN_USER, "password");
await userService.add(STANDARD_USER, "password");
await clientService.add(DEMO_CLIENT, DEMO_CLIENT_SECRET);

export const authServer = new HonoAuthorizationServer<DemoClient, DemoUser>({
  resolve: () => ({
    services: { clientService, tokenService },
    issuer,
    tokenEndpoint: `${issuer}/oauth2/token`,
    authorizationEndpoint: `${issuer}/oauth2/authorize`,
    revocationEndpoint: `${issuer}/oauth2/revoke`,
    introspectionEndpoint: `${issuer}/oauth2/introspect`,
    deviceAuthorizationEndpoint: `${issuer}/oauth2/device_authorization`,
    verificationUri: `${issuer}/device`,
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
    "urn:ietf:params:oauth:grant-type:device_code":
      new DeviceAuthorizationGrant<DemoClient, DemoUser>({
        resolve: () => ({
          clientService,
          tokenService,
          deviceAuthorizationService: deviceService,
        }),
        allowRefreshToken: true,
      }),
  },
  scopesSupported: ["read", "write", "admin"],
});

const oauthClient = new DirectClient({
  clientId: DEMO_CLIENT.id,
  clientSecret: DEMO_CLIENT_SECRET,
  redirectUri: `${issuer}/auth/callback`,
  endpoints: {
    authorization: `${issuer}/oauth2/authorize`,
    token: `${issuer}/oauth2/token`,
    revocation: `${issuer}/oauth2/revoke`,
  },
  fetch: localAuthServerFetch(authServer),
});

export const resourceServer = new HonoResourceServer<DemoClient, DemoUser>({
  resolve: () => ({ services: { tokenService } }),
});

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
  csrf: false,
});
