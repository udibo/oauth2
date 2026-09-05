/**
 * One-shot factory that wires the {@link MemoryUserService},
 * {@link MemoryClientService}, {@link MemoryTokenService},
 * {@link MemoryAuthorizationCodeService}, and
 * {@link MemoryDeviceAuthorizationService} into a real
 * {@link AuthorizationServer}, seeds it from the supplied users / clients,
 * and returns a harness whose `fetch` you pass to a `DirectClient`
 * constructor's `fetch` option for tests that need an end-to-end OAuth2
 * protocol surface.
 *
 * The point of this factory is that **the test exercises the same
 * code paths as production**. There is no parallel mock implementation of
 * the OAuth2 wire protocol — the responses come from the real
 * {@link AuthorizationServer}, just dispatched in-process via
 * {@link localAuthServerFetch} instead of over a socket.
 *
 * Construct the test app's `DirectClient` (or `HonoBff` whose underlying
 * client you control) with `fetch: oauth.fetch`. We deliberately do
 * **not** recommend `stub(globalThis, "fetch", oauth.fetch)` — a global
 * stub silently captures every outbound request the app makes, not just
 * the OAuth2 ones, and that's a common source of mysterious test
 * cross-talk in consumer projects.
 *
 * @example
 * ```ts
 * import { DirectClient } from "@udibo/oauth2/client";
 * import { createMemoryAuthorizationServer } from "@udibo/oauth2/testing";
 *
 * Deno.test("client credentials grant", async () => {
 *   const oauth = await createMemoryAuthorizationServer({
 *     issuer: "http://localhost",
 *     clients: [{
 *       client: { id: "m2m", grants: ["client_credentials"] },
 *       secret: "s",
 *     }],
 *   });
 *   const client = new DirectClient({
 *     clientId: "m2m",
 *     clientSecret: "s",
 *     endpoints: { token: "http://localhost/oauth2/token" },
 *     fetch: oauth.fetch,
 *   });
 *   const tokens = await client.getClientCredentialsToken();
 *   // ...assert against the real token response.
 * });
 * ```
 *
 * @module
 */

import type { ClientInterface } from "../models/client.ts";
import type {
  AbstractScope,
  BasicScope,
  ScopeConstructor,
} from "../models/scope.ts";
import {
  AuthorizationServer,
  localAuthServerFetch,
} from "../server/authorization-server.ts";
import type {
  AuthenticateUserFn,
  AuthorizationServerOptions,
  HandleConsentFn,
} from "../server/authorization-server.ts";
import { AuthorizationCodeGrant } from "../server/grants/authorization-code.ts";
import { ClientCredentialsGrant } from "../server/grants/client-credentials.ts";
import { DeviceAuthorizationGrant } from "../server/grants/device-authorization.ts";
import { PasswordGrant } from "../server/grants/password.ts";
import { RefreshTokenGrant } from "../server/grants/refresh-token.ts";

import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  MemoryTokenService,
  MemoryUserService,
  type MemoryUserShape,
} from "./services.ts";

/** Which OAuth2 grants the memory authorization server enables. */
export interface MemoryAuthorizationServerGrants {
  /**
   * Authorization code grant. Default `true`. PKCE is required (OAuth 2.1) and
   * this factory exposes no opt-out: a hand-rolled authorize URL must carry
   * `code_challenge`, and the token exchange the matching `code_verifier`.
   */
  authorization_code?: boolean;
  /** Client credentials grant (M2M). Default `true`. */
  client_credentials?: boolean;
  /** Refresh token grant. Default `true`. */
  refresh_token?: boolean;
  /** Resource owner password credentials grant. Default `false` (legacy / discouraged). */
  password?: boolean;
  /** Device authorization grant (RFC 8628). Default `true`. */
  device_code?: boolean;
}

/** Seed entry for a user. */
export interface MemoryAuthorizationServerUserSeed<U extends MemoryUserShape> {
  /** The user record to seed into the memory user service. */
  user: U;
  /** Plaintext password registered for the user; used by the password grant and login. */
  password: string;
}

/** Seed entry for a registered OAuth2 client. */
export interface MemoryAuthorizationServerClientSeed<
  C extends ClientInterface,
> {
  /** The client record to register with the memory client service. */
  client: C;
  /** Omit for a public client; supply for a confidential client. */
  secret?: string;
  /**
   * User returned by `clientService.getUser(client)` (client-credentials
   * grant). Omit it to seed a client whose machine token carries no user.
   */
  ownerUserId?: string;
}

/** Options for {@link createMemoryAuthorizationServer}. */
export interface CreateMemoryAuthorizationServerOptions<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> {
  /** Issuer identifier. Defaults to `"http://localhost"`. */
  issuer?: string;
  /**
   * Endpoint URLs. Each defaults to `${issuer}${defaultPath}`. Setting any
   * to `null` removes it from the advertised metadata. (Note: this only
   * affects the metadata document — {@link localAuthServerFetch} never
   * dispatches the `authorization` endpoint regardless; drive that leg with
   * the harness's {@link MemoryAuthorizationServerHarness.authorize} helper.)
   */
  endpoints?: {
    token?: string | null;
    authorization?: string | null;
    revocation?: string | null;
    introspection?: string | null;
    deviceAuthorization?: string | null;
  };
  /**
   * URL users visit to enter their device code (RFC 8628). Defaults to
   * `${issuer}/device`. Required by the device-authorization endpoint, so the
   * default keeps the device flow drivable through {@link fetch}.
   */
  verificationUri?: string;
  /** Scope vocabulary advertised in metadata. */
  scopesSupported?: string[];
  /** Custom scope constructor. Defaults to {@link BasicScope}. */
  Scope?: ScopeConstructor<S>;
  /** Realm reported on `WWW-Authenticate` headers. */
  realm?: string;
  /** Which grants to enable. */
  grants?: MemoryAuthorizationServerGrants;
  /** Users to seed before the server is returned. */
  users?: ReadonlyArray<MemoryAuthorizationServerUserSeed<U>>;
  /** Clients to seed before the server is returned. */
  clients?: ReadonlyArray<MemoryAuthorizationServerClientSeed<C>>;
}

/** Harness returned by {@link createMemoryAuthorizationServer}. */
export interface MemoryAuthorizationServerHarness<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> {
  /** The composed authorization server. Use it directly when you want full control. */
  server: AuthorizationServer<C, U, S>;
  /** The Memory* services, exposed for fixture seeding mid-test. */
  services: {
    userService: MemoryUserService<U>;
    clientService: MemoryClientService<C, U>;
    tokenService: MemoryTokenService<C, U, S>;
    authorizationCodeService: MemoryAuthorizationCodeService<C, U, S>;
    deviceAuthorizationService: MemoryDeviceAuthorizationService<C, U, S>;
  };
  /**
   * `fetch`-compatible function that dispatches OAuth2 requests directly
   * into {@link server} without a socket. Pass this as the `fetch` option
   * to a `DirectClient` (or to `HonoBff`'s underlying client) under test
   * so outbound OAuth2 traffic is rerouted in-process — there is no need
   * to stub `globalThis.fetch`, which would also intercept unrelated
   * outbound requests the app may issue.
   */
  fetch: typeof fetch;
  /**
   * Drives the browser-facing authorization leg (`GET /authorize`)
   * in-process and returns the resulting `Response` (a 302 redirect carrying
   * the `code` on success). This can't go through {@link fetch} because the
   * authorize endpoint needs an `authenticateUser`/`handleConsent` callback.
   *
   * With no options it authenticates as the first seeded user. Pass `user`
   * to authenticate as a specific user, or `authenticateUser`/`handleConsent`
   * for full control. Read the `code` from the returned response's `Location`
   * header, then exchange it with a `DirectClient` wired to {@link fetch}.
   *
   * @example
   * ```ts
   * import type { ClientInterface } from "@udibo/oauth2/server";
   * import type {
   *   MemoryAuthorizationServerHarness,
   *   MemoryUserShape,
   * } from "@udibo/oauth2/testing";
   *
   * declare const oauth: MemoryAuthorizationServerHarness<
   *   ClientInterface,
   *   MemoryUserShape
   * >;
   * declare const beginUrl: string;
   *
   * const res = await oauth.authorize(beginUrl);
   * const code = new URL(res.headers.get("Location")!).searchParams
   *   .get("code")!;
   * ```
   */
  authorize(
    url: string | URL,
    options?: {
      authenticateUser?: AuthenticateUserFn<U>;
      handleConsent?: HandleConsentFn<C, S>;
      user?: U;
    },
  ): Promise<Response>;
  /**
   * Adds a user and, when no user has been seeded yet, makes it the one
   * {@linkcode authorize} authenticates as by default. Adding through
   * {@linkcode services}.userService instead skips that.
   */
  addUser(user: U, password: string): Promise<void>;
  /** Convenience wrapper around `services.clientService.add`. */
  addClient(
    client: C,
    secret?: string,
    ownerUserId?: string,
  ): Promise<void>;
}

const DEFAULT_PATHS = {
  token: "/oauth2/token",
  authorization: "/oauth2/authorize",
  revocation: "/oauth2/revoke",
  introspection: "/oauth2/introspect",
  deviceAuthorization: "/oauth2/device_authorization",
} as const;

const DEFAULT_GRANTS: Required<MemoryAuthorizationServerGrants> = {
  authorization_code: true,
  client_credentials: true,
  refresh_token: true,
  password: false,
  device_code: true,
};

/**
 * Returns a {@link MemoryAuthorizationServerHarness} ready to drop into a
 * test. See the module-level example for usage.
 */
export async function createMemoryAuthorizationServer<
  C extends ClientInterface = ClientInterface,
  U extends MemoryUserShape = MemoryUserShape,
  S extends AbstractScope = BasicScope,
>(
  options: CreateMemoryAuthorizationServerOptions<C, U, S> = {},
): Promise<MemoryAuthorizationServerHarness<C, U, S>> {
  const issuer = options.issuer ?? "http://localhost";
  const enabledGrants = { ...DEFAULT_GRANTS, ...options.grants };

  const userService = new MemoryUserService<U>();
  const clientService = new MemoryClientService<C, U>(userService);
  const tokenService = new MemoryTokenService<C, U, S>({
    clientService,
    userService,
  });
  const authorizationCodeService = new MemoryAuthorizationCodeService<C, U, S>({
    clientService,
    userService,
  });
  const deviceAuthorizationService = new MemoryDeviceAuthorizationService<
    C,
    U,
    S
  >({ clientService, userService });

  const grants: AuthorizationServerOptions<C, U, S>["grants"] = {};
  if (enabledGrants.authorization_code) {
    grants.authorization_code = new AuthorizationCodeGrant<C, U, S>({
      resolve: () => ({
        clientService,
        tokenService,
        authorizationCodeService,
      }),
      Scope: options.Scope,
      allowRefreshToken: enabledGrants.refresh_token,
    });
  }
  if (enabledGrants.client_credentials) {
    grants.client_credentials = new ClientCredentialsGrant<C, U, S>({
      resolve: () => ({ clientService, tokenService }),
      Scope: options.Scope,
    });
  }
  if (enabledGrants.refresh_token) {
    grants.refresh_token = new RefreshTokenGrant<C, U, S>({
      resolve: () => ({ clientService, tokenService }),
      Scope: options.Scope,
    });
  }
  if (enabledGrants.password) {
    grants.password = new PasswordGrant<C, U, S>({
      resolve: () => ({ clientService, tokenService, userService }),
      Scope: options.Scope,
    });
  }
  if (enabledGrants.device_code) {
    grants["urn:ietf:params:oauth:grant-type:device_code"] =
      new DeviceAuthorizationGrant<C, U, S>({
        resolve: () => ({
          clientService,
          tokenService,
          deviceAuthorizationService,
        }),
        Scope: options.Scope,
        allowRefreshToken: enabledGrants.refresh_token,
      });
  }

  const endpointOverrides = options.endpoints ?? {};
  const endpoint = (
    name: keyof typeof DEFAULT_PATHS,
  ): string | undefined => {
    const override = endpointOverrides[name];
    if (override === null) return undefined;
    if (override !== undefined) return override;
    return `${issuer}${DEFAULT_PATHS[name]}`;
  };

  const verificationUri = options.verificationUri ?? `${issuer}/device`;
  const server = new AuthorizationServer<C, U, S>({
    resolve: () => ({
      services: { clientService, tokenService },
      issuer,
      tokenEndpoint: endpoint("token"),
      authorizationEndpoint: endpoint("authorization"),
      revocationEndpoint: endpoint("revocation"),
      introspectionEndpoint: endpoint("introspection"),
      deviceAuthorizationEndpoint: endpoint("deviceAuthorization"),
      verificationUri,
    }),
    grants,
    scopesSupported: options.scopesSupported,
    Scope: options.Scope,
    realm: options.realm,
  });

  let defaultUser: U | undefined;
  for (const seed of options.users ?? []) {
    await userService.add(seed.user, seed.password);
    defaultUser ??= seed.user;
  }
  for (const seed of options.clients ?? []) {
    await clientService.add(seed.client, seed.secret, seed.ownerUserId);
  }

  return {
    server,
    services: {
      userService,
      clientService,
      tokenService,
      authorizationCodeService,
      deviceAuthorizationService,
    },
    fetch: localAuthServerFetch(server),
    authorize: (url, authorizeOptions = {}) => {
      const authenticateUser: AuthenticateUserFn<U> =
        authorizeOptions.authenticateUser ??
          (() => {
            const user = authorizeOptions.user ?? defaultUser;
            if (!user) {
              return Promise.reject(
                new Error(
                  "authorize() has no user to authenticate as: seed a user, " +
                    "or pass `user`/`authenticateUser`",
                ),
              );
            }
            return Promise.resolve({ user });
          });
      return server.handleAuthorizeRequest(
        new Request(String(url)),
        authenticateUser,
        authorizeOptions.handleConsent,
      );
    },
    addUser: async (user, password) => {
      await userService.add(user, password);
      defaultUser ??= user;
    },
    addClient: (client, secret, ownerUserId) =>
      clientService.add(client, secret, ownerUserId),
  };
}
