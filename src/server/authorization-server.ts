/**
 * Authorization Server implementation for issuing OAuth2 tokens.
 *
 * Implements the OAuth 2.0 Authorization Framework (RFC 6749) with support for:
 * - Token endpoint (RFC 6749 Section 3.2)
 * - Authorization endpoint (RFC 6749 Section 3.1)
 * - Token revocation (RFC 7009)
 * - Token introspection (RFC 7662)
 * - Server metadata (RFC 8414)
 * - Device authorization (RFC 8628)
 *
 * **Configuration.** A single instance serves every tenant/origin. The only
 * configuration seam is `resolve(request)`, which returns the services the
 * server's own endpoints need (`{ clientService, tokenService }`) plus the
 * issuer/endpoints. Each grant resolves its own services independently. For a
 * single-tenant server, `resolve` is a constant function (create the services
 * once, outside it, and return them every time).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749
 * @module
 */

import type { AuthorizeParameters } from "../models/authorization-code.ts";
import type { ClientInterface } from "../models/client.ts";
import type {
  IntrospectionResponse,
  RefreshToken,
  Token,
  TokenResponse,
} from "../models/token.ts";
import type {
  AuthorizationServerMetadata,
  DeviceAuthorizationResponse,
} from "../models/responses.ts";
import type { AbstractScope, BasicScope } from "../models/scope.ts";
import {
  AccessDeniedError,
  InvalidRequestError,
  InvalidTokenError,
  isOAuth2Error,
  OAuth2Error,
  ServerError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
} from "../errors.ts";
import {
  authenticateClientCredentials,
  extractClientCredentials,
} from "./client-authentication.ts";
import type { IsPublicSuffix } from "./redirect-uri.ts";
import { isRedirectUriPattern, matchRedirectUri } from "./redirect-uri.ts";
import type { DispatchableGrant } from "./grants/grant.ts";
import { AuthorizationCodeGrant } from "./grants/authorization-code.ts";
import { DeviceAuthorizationGrant } from "./grants/device-authorization.ts";
import type { ClientServiceInterface } from "./services/client.ts";
import type { TokenServiceInterface } from "./services/token.ts";
import {
  ResourceServer,
  type ResourceServerOptions,
  type ResourceServerServices,
} from "./resource-server.ts";
import {
  defaultSubjectOf,
  type SigningKeyProvider,
  signJwt,
  verifyJwt,
} from "./signing-keys.ts";
import { validateCodeChallenge } from "../utils/pkce.ts";

/** The logout request's parameters, after `id_token_hint` has been read. */
interface EndSessionParameters {
  clientId: string | null;
  subject: string | null;
  postLogoutRedirectUri: string | null;
  state: string | null;
  logoutHint: string | null;
}

/** What {@link AuthorizationServer.handleEndSessionRequest} tells the app. */
export interface EndSessionContext<Client extends ClientInterface> {
  /** The logout request itself. */
  request: Request;
  /**
   * The relying party the logout names — from a signature-valid
   * `id_token_hint`'s audience, or from `client_id`. Null when the request
   * named none, or named one this server does not know.
   */
  client: Client | null;
  /**
   * The `sub` of a signature-valid `id_token_hint`. Null when the request sent
   * no hint, or one that did not verify — so a session lookup keyed on it must
   * handle "no subject", which is the ordinary case for a client that never
   * requested `openid`.
   */
  subject: string | null;
  /**
   * The RP's `logout_hint`, verbatim. **Unvalidated and unauthenticated** —
   * OIDC defines it as a hint about which user to log out and nothing checks
   * it, so treat it as a suggestion for a chooser UI, never as an identifier
   * to end a session by.
   */
  logoutHint: string | null;
}

/** What an app's {@link EndSessionFn} may ask the server to do afterwards. */
export interface EndSessionResult {
  /**
   * Headers to merge into the response — the session-clearing `Set-Cookie`,
   * typically. The server owns `Location`; anything else is yours.
   */
  headers?: HeadersInit;
  /**
   * Where to send the browser when the request named no **authorized**
   * `post_logout_redirect_uri` — your own "you are signed out" page. Not
   * validated: it comes from your code, not from the request. Omit it and such
   * a logout answers 204.
   */
  fallback?: string;
}

/**
 * Ends the app's session for an RP-initiated logout. Called for every logout
 * request that reaches the endpoint, including ones whose parameters do not
 * check out — refusing to end a session because a *redirect* was unauthorized
 * would leave the person signed in, which is the opposite of what they asked
 * for.
 */
export type EndSessionFn<Client extends ClientInterface> = (
  context: EndSessionContext<Client>,
) => EndSessionResult | void | Promise<EndSessionResult | void>;

/** Grants configuration for the authorization server. */
export interface AuthorizationServerGrants<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> {
  /** Maps an OAuth2 `grant_type` value to the grant that handles it. */
  [grantType: string]: DispatchableGrant<Client, User, S>;
}

/**
 * Services the authorization server's OWN endpoints need: client lookup/auth
 * (token, revocation, introspection, device-authorization) and token storage
 * (plus the inherited bearer-token validation). Grant-specific services
 * (authorization-code, user, device) live on the grants, not here.
 */
export interface AuthorizationServerServices<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> extends ResourceServerServices<Client, User, S> {
  /** Looks up and authenticates clients for the AS endpoints. */
  clientService: ClientServiceInterface<Client, User>;
  /** The full token service (read + write) the AS endpoints need. */
  tokenService: TokenServiceInterface<Client, User, S>;
}

/**
 * Per-request context resolved by an {@link AuthorizationServer}.
 *
 * `services` is the server's own services for this request. The issuer and
 * endpoint fields drive the RFC 8414 metadata and the in-process
 * {@link localAuthServerFetch} routing; any endpoint omitted defaults to
 * `${issuer}${path}` (e.g. `${issuer}/token`), so a server whose endpoints sit
 * at the issuer root needs only `issuer`.
 */
export interface AuthorizationServerContext<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> {
  /** The server's own services for this request. */
  services: AuthorizationServerServices<Client, User, S>;
  /** The issuer identifier URL for this request. */
  issuer?: string;
  /** URL of the authorization endpoint. Defaults to `${issuer}/authorize`. */
  authorizationEndpoint?: string;
  /** URL of the token endpoint. Defaults to `${issuer}/token`. */
  tokenEndpoint?: string;
  /** URL of the token revocation endpoint (RFC 7009). Defaults to `${issuer}/revoke`. */
  revocationEndpoint?: string;
  /** URL of the token introspection endpoint (RFC 7662). Defaults to `${issuer}/introspect`. */
  introspectionEndpoint?: string;
  /** URL of the device authorization endpoint (RFC 8628). Defaults to `${issuer}/device_authorization`. */
  deviceAuthorizationEndpoint?: string;
  /**
   * URL where users verify device codes (RFC 8628 Section 3.2). Unlike the
   * `*Endpoint` fields it has no issuer-derived default: the device
   * authorization endpoint answers 500 `server_error` until it is set.
   */
  verificationUri?: string;
  /** URL of the JWKS endpoint. Defaults to `${issuer}/jwks`. */
  jwksEndpoint?: string;
  /** URL of the OIDC UserInfo endpoint. Defaults to `${issuer}/userinfo`. */
  userinfoEndpoint?: string;
  /**
   * URL of the OIDC RP-Initiated Logout end-session endpoint. Defaults to
   * `${issuer}/end_session`.
   */
  endSessionEndpoint?: string;
}

/**
 * Options for configuring the authorization server.
 */
export interface AuthorizationServerOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> extends Omit<ResourceServerOptions<Client, User, S>, "resolve"> {
  /**
   * Resolves the per-request context — the server's own services plus the
   * issuer/endpoints. This is the only services seam: for a single-tenant
   * server it is a constant function returning the same context every time.
   */
  resolve: (
    request: Request,
  ) =>
    | AuthorizationServerContext<Client, User, S>
    | Promise<AuthorizationServerContext<Client, User, S>>;
  /** Grants the server supports, keyed by `grant_type` (each key must equal `grant.grantType`). */
  grants: AuthorizationServerGrants<Client, User, S>;
  /** Scopes supported by this server (advertised in RFC 8414 metadata). */
  scopesSupported?: string[];
  /**
   * OIDC issuance keys. Configuring this turns the OIDC provider surface on:
   * the token endpoint mints an `id_token` for user-bound grants with the
   * `openid` scope, and the JWKS/UserInfo endpoints and
   * `openid-configuration` metadata go live. In multi-instance deploys load
   * one persisted key on every instance (see `signing-keys.ts`).
   */
  signingKeys?: SigningKeyProvider;
  /**
   * Refuses to construct a server that would run with OIDC issuance off. Set
   * it on any deployment that issues `id_token`s: without `signingKeys` an
   * instance still boots and serves plain OAuth2 while answering 404 from the
   * OIDC surface, so a rollout that dropped the key presents as "some relying
   * parties broke" instead of a failed deploy.
   *
   * It asserts that a {@linkcode SigningKeyProvider} is wired, not that the
   * provider can produce a key. For a true fail-to-start, load the key before
   * constructing the server (`await importSigningKeyJwk(...)` into a
   * `StaticSigningKeyProvider`) so an unreadable key throws on the same boot
   * path.
   *
   * @default false
   */
  requireOidc?: boolean;
  /**
   * Ends the app's session for an OIDC RP-Initiated Logout. Configuring it is
   * what turns the end-session endpoint on: without it the endpoint answers
   * 404 **and** `end_session_endpoint` stays out of the discovery document, so
   * metadata never advertises a logout the server cannot perform.
   */
  endSession?: EndSessionFn<Client>;
  /**
   * Maps a user to the id_token/UserInfo `sub` claim. Defaults to the user's
   * `id` property; override when your subject identifier differs.
   */
  subjectOf?: (user: User) => string;
  /**
   * Extra OIDC claims for the id_token and UserInfo response (e.g. `name`,
   * `email` when the scope allows). Merged under the protocol claims — `sub`
   * (from `subjectOf`) and the id_token's `iss`/`aud`/`iat`/`exp`/`nonce`
   * always win.
   */
  userClaims?: (
    user: User,
    scope?: S | null,
  ) => Promise<Record<string, unknown>> | Record<string, unknown>;
  /**
   * Extension fields for an **active** introspection response (RFC 7662
   * permits them), so a resource server validating by introspection sees the
   * same authorization claims a JWT access token carries — feed it the same
   * computation `userClaims` uses and the two validation strategies stay in
   * field-level parity. Called with the introspected token; the RFC 7662
   * protocol fields (`active`, `scope`, `client_id`, `token_type`, `exp`,
   * `iss`, `sub`, `username`) always win over anything it returns.
   */
  introspectionClaims?: (
    token: Token<Client, User, S>,
  ) => Promise<Record<string, unknown>> | Record<string, unknown>;
  /**
   * Decides whether the domain under a wildcard redirect URI is a public
   * suffix, which is what bounds a wildcard registration to one registrant's
   * namespace. Import `isPublicSuffix` from
   * `@udibo/oauth2/server/public-suffix` to use the bundled list.
   *
   * Leaving it unset makes every wildcard registration inert — the authorize
   * endpoint will not match one — which is the right setting for a server that
   * only ever registers literal redirect URIs, and keeps the list out of the
   * bundle.
   */
  isPublicSuffix?: IsPublicSuffix;
}

/**
 * Function to authenticate the user during authorization.
 *
 * Return one of:
 *
 * - `{ user, authorizedScope? }` — user is authenticated; the authorize flow
 *   continues. `authorizedScope` declares scopes the user has already
 *   pre-authorized for this client; anything in the requested scope not
 *   covered by it triggers consent. **Omitting `authorizedScope` means
 *   "nothing pre-authorized"** — so any requested scope needs consent: the
 *   framework calls `handleConsent` when one is configured, and otherwise
 *   treats the request as consented and grants the accepted scope. To
 *   pre-authorize everything, return the requested scope as `authorizedScope`.
 * - `null` — explicit denial. The framework redirects the browser to
 *   `redirect_uri` with `error=access_denied`. Use this for "the user said
 *   no", not for "the user isn't signed in yet."
 * - A `Response` — short-circuits the rest of the authorize flow and is
 *   returned to the browser as-is. Use this to redirect to a login page,
 *   render an interstitial, etc.
 */
export type AuthenticateUserFn<User> = (
  request: Request,
) => Promise<
  { user: User; authorizedScope?: AbstractScope } | Response | null
>;

/**
 * Function to handle user consent during authorization.
 *
 * Called when the requested scope is not already covered by the user's
 * pre-authorized scope. Return one of:
 *
 * - `{ approved: true, scope? }` — consent granted. `scope` optionally
 *   narrows the granted scope (RFC 6749 §3.3 allows partial grants).
 * - `{ approved: false }` — consent denied. The framework redirects to
 *   `redirect_uri` with `error=access_denied`.
 * - A `Response` — short-circuits the rest of the authorize flow and is
 *   returned to the browser as-is. Use this to render a consent page that
 *   later resubmits to the authorize endpoint with the user's decision.
 */
export type HandleConsentFn<
  Client extends ClientInterface,
  S extends AbstractScope,
> = (
  client: Client,
  requestedScope: S | undefined,
  user: unknown,
) => Promise<{ approved: boolean; scope?: S } | Response>;

/** Resolved endpoint URLs for a request (issuer-derived unless overridden). */
export interface ResolvedEndpoints {
  /** Authorization endpoint URL, if resolved. */
  authorization?: string;
  /** Token endpoint URL, if resolved. */
  token?: string;
  /** Token revocation endpoint URL, if resolved. */
  revocation?: string;
  /** Token introspection endpoint URL, if resolved. */
  introspection?: string;
  /** Device authorization endpoint URL, if resolved. */
  deviceAuthorization?: string;
  /** JWKS endpoint URL, if resolved. */
  jwks?: string;
  /** OIDC UserInfo endpoint URL, if resolved. */
  userinfo?: string;
  /** OIDC RP-Initiated Logout end-session endpoint URL, if resolved. */
  endSession?: string;
}

type AdvertisedEndpointKey = keyof ResolvedEndpoints;

type EndpointOption = Extract<
  keyof AuthorizationServerContext<ClientInterface, unknown, AbstractScope>,
  `${string}Endpoint`
>;

type DiscoveryEndpointKey = "metadata" | "oidcMetadata";

interface EndpointDefinition {
  path: string;
  methods: readonly string[];
}

interface AdvertisedEndpointDefinition extends EndpointDefinition {
  option: EndpointOption;
  metadata: keyof AuthorizationServerMetadata;
  oidc: boolean;
}

const ENDPOINTS = {
  authorization: {
    option: "authorizationEndpoint",
    path: "/authorize",
    metadata: "authorization_endpoint",
    methods: ["GET"],
    oidc: false,
  },
  token: {
    option: "tokenEndpoint",
    path: "/token",
    metadata: "token_endpoint",
    methods: ["POST"],
    oidc: false,
  },
  revocation: {
    option: "revocationEndpoint",
    path: "/revoke",
    metadata: "revocation_endpoint",
    methods: ["POST"],
    oidc: false,
  },
  introspection: {
    option: "introspectionEndpoint",
    path: "/introspect",
    metadata: "introspection_endpoint",
    methods: ["POST"],
    oidc: false,
  },
  deviceAuthorization: {
    option: "deviceAuthorizationEndpoint",
    path: "/device_authorization",
    metadata: "device_authorization_endpoint",
    methods: ["POST"],
    oidc: false,
  },
  jwks: {
    option: "jwksEndpoint",
    path: "/jwks",
    metadata: "jwks_uri",
    methods: ["GET"],
    oidc: true,
  },
  userinfo: {
    option: "userinfoEndpoint",
    path: "/userinfo",
    metadata: "userinfo_endpoint",
    methods: ["GET", "POST"],
    oidc: true,
  },
  endSession: {
    option: "endSessionEndpoint",
    path: "/end_session",
    metadata: "end_session_endpoint",
    methods: ["GET", "POST"],
    oidc: true,
  },
  metadata: {
    path: "/.well-known/oauth-authorization-server",
    methods: ["GET"],
  },
  oidcMetadata: {
    path: "/.well-known/openid-configuration",
    methods: ["GET"],
  },
} satisfies
  & Record<AdvertisedEndpointKey, AdvertisedEndpointDefinition>
  & Record<DiscoveryEndpointKey, EndpointDefinition>;

/**
 * Every endpoint the authorization server serves, by name — the seven it
 * advertises in its metadata (the {@link ResolvedEndpoints} keys) plus
 * `metadata` and `oidcMetadata`, the two discovery documents that are served
 * but never advertised. Index {@link ENDPOINT_PATHS} and
 * {@link ENDPOINT_METHODS} with it to enumerate the whole surface.
 */
export type EndpointKey =
  | "authorization"
  | "token"
  | "revocation"
  | "introspection"
  | "deviceAuthorization"
  | "jwks"
  | "userinfo"
  | "endSession"
  | "metadata"
  | "oidcMetadata";

type EndpointKeysInSync = EndpointKey extends keyof typeof ENDPOINTS
  ? keyof typeof ENDPOINTS extends EndpointKey ? true
  : never
  : never;
const _endpointKeysInSync: EndpointKeysInSync = true;

type EndpointEntry = {
  [K in EndpointKey]: readonly [K, typeof ENDPOINTS[K]];
}[EndpointKey];

type AdvertisedEndpointEntry = {
  [K in AdvertisedEndpointKey]: readonly [K, typeof ENDPOINTS[K]];
}[AdvertisedEndpointKey];

const ENDPOINT_ENTRIES = Object.entries(ENDPOINTS) as EndpointEntry[];

const ADVERTISED_ENTRIES = ENDPOINT_ENTRIES.filter(
  (entry): entry is AdvertisedEndpointEntry => "metadata" in entry[1],
);

const DEVICE_AUTHORIZATION_GRANT_TYPE =
  "urn:ietf:params:oauth:grant-type:device_code";

const AUTHORIZATION_CODE_GRANT_TYPE = "authorization_code";

/**
 * The path each endpoint is served from when the request context supplies only
 * an `issuer` (so the endpoint URL is `${issuer}${path}`). Mount handlers at
 * these paths — as the Hono adapter's `routes()` does — to match what the
 * server advertises in its RFC 8414 metadata.
 *
 * Covers the whole served surface: the seven endpoints the server advertises,
 * plus the two discovery documents (`metadata` for RFC 8414,
 * `oidcMetadata` for OIDC Discovery) that are served but never advertised.
 * Pair it with {@link ENDPOINT_METHODS} to enumerate path *and* verbs.
 *
 * @example Mount every endpoint yourself
 * ```ts
 * for (const key of Object.keys(ENDPOINT_PATHS) as (keyof typeof ENDPOINT_PATHS)[]) {
 *   app.on([...ENDPOINT_METHODS[key]], ENDPOINT_PATHS[key], handlerFor(key));
 * }
 * ```
 */
export const ENDPOINT_PATHS: Readonly<Record<EndpointKey, string>> = Object
  .fromEntries(
    ENDPOINT_ENTRIES.map(([key, { path }]) => [key, path]),
  ) as Record<EndpointKey, string>;

/**
 * The HTTP methods each endpoint in {@link ENDPOINT_PATHS} answers — `POST` for
 * the token-style endpoints, `GET` for authorize/JWKS/discovery, both for
 * UserInfo. Read it instead of re-deriving verbs per endpoint, so a hand-rolled
 * mount answers exactly what the built-in `routes()` does.
 *
 * @example
 * ```ts
 * app.on([...ENDPOINT_METHODS.userinfo], ENDPOINT_PATHS.userinfo, handler);
 * ```
 */
export const ENDPOINT_METHODS: Readonly<
  Record<EndpointKey, readonly string[]>
> = Object.fromEntries(
  ENDPOINT_ENTRIES.map(([key, { methods }]) => [key, methods]),
) as Record<EndpointKey, string[]>;

/** Where an authorize failure is reported once a redirect URI is verified. */
interface AuthorizeRedirectTarget {
  url: URL | null;
}

/** A token value resolved to its record and the kind it was found as. */
interface ResolvedToken<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> {
  tokenType: "access_token" | "refresh_token";
  token: Token<Client, User, S> | RefreshToken<Client, User, S>;
}

function isAuthorizationCodeGrant<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  grant: DispatchableGrant<Client, User, S>,
): grant is AuthorizationCodeGrant<Client, User, S> {
  return grant instanceof AuthorizationCodeGrant;
}

function isDeviceAuthorizationGrant<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  grant: DispatchableGrant<Client, User, S>,
): grant is DeviceAuthorizationGrant<Client, User, S> {
  return grant instanceof DeviceAuthorizationGrant;
}

/**
 * Authorization Server for issuing OAuth2 tokens.
 *
 * Handles OAuth2 endpoints including:
 * - Token endpoint (POST /token)
 * - Authorization endpoint (GET /authorize)
 * - Revocation endpoint (POST /revoke) - RFC 7009
 * - Introspection endpoint (POST /introspect) - RFC 7662
 * - Device authorization endpoint (POST /device_authorization) - RFC 8628
 * - Metadata endpoint (GET /.well-known/oauth-authorization-server) - RFC 8414
 *
 * Framework-agnostic: each `handle*Request` method takes a web `Request` and
 * returns a `Response`, so an adapter routes its endpoints to them. Extends
 * {@linkcode ResourceServer}, so the same instance also validates bearer
 * tokens. A single instance serves every tenant/origin via the `resolve`
 * callback in {@linkcode AuthorizationServerOptions}.
 *
 * The handlers throw {@linkcode HttpError} subclasses on failure (e.g.
 * {@linkcode InvalidRequestError}, {@linkcode InvalidClientError},
 * {@linkcode UnsupportedGrantTypeError}) and convert them to RFC 6749 §5.2
 * error responses unless `throwOnError` is set.
 *
 * @template Client The client entity type.
 * @template User The resource-owner entity type.
 * @template S The scope type used across grants and metadata.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749
 *
 * @example
 * ```ts
 * const server = new AuthorizationServer({
 *   resolve: () => ({ services, issuer: "https://auth.example.com" }),
 *   grants: { authorization_code: authCodeGrant, refresh_token: refreshGrant },
 * });
 *
 * app.post("/token", (c) => server.handleTokenRequest(c.req.raw));
 * ```
 */
export class AuthorizationServer<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> extends ResourceServer<Client, User, S> {
  /** Grants the server supports, keyed by `grant_type`. */
  grants: AuthorizationServerGrants<Client, User, S>;
  /** Scopes advertised in RFC 8414 metadata, if configured. */
  scopesSupported?: string[];
  /** OIDC signing keys; the OIDC surface is active when set. */
  signingKeys?: SigningKeyProvider;
  #endSession?: EndSessionFn<Client>;
  #isPublicSuffix?: IsPublicSuffix;
  #subjectOf: (user: User) => string;
  #userClaims?: (
    user: User,
    scope?: S | null,
  ) => Promise<Record<string, unknown>> | Record<string, unknown>;
  #introspectionClaims?: (
    token: Token<Client, User, S>,
  ) => Promise<Record<string, unknown>> | Record<string, unknown>;
  /** Resolves the per-request {@link AuthorizationServerContext}. */
  #resolve: (
    request: Request,
  ) =>
    | AuthorizationServerContext<Client, User, S>
    | Promise<AuthorizationServerContext<Client, User, S>>;

  /**
   * Creates an authorization server from the given
   * {@linkcode AuthorizationServerOptions}.
   *
   * @throws {Error} If any grant's map key does not equal its `grantType`.
   * @throws {Error} If `requireOidc` is set without `signingKeys`.
   */
  constructor(options: AuthorizationServerOptions<Client, User, S>) {
    super({
      resolve: options.resolve,
      Scope: options.Scope,
      realm: options.realm,
      errorFormat: options.errorFormat,
      throwOnError: options.throwOnError,
    });
    this.#resolve = options.resolve;
    this.grants = { ...options.grants };
    for (const [grantType, grant] of Object.entries(this.grants)) {
      if (grant.grantType !== grantType) {
        throw new Error(
          `grant registered under key "${grantType}" has grantType ` +
            `"${grant.grantType}"; the map key must equal grant.grantType`,
        );
      }
    }
    this.scopesSupported = options.scopesSupported;
    this.signingKeys = options.signingKeys;
    this.#endSession = options.endSession;
    if (options.requireOidc && !this.signingKeys) {
      throw new Error(
        "requireOidc is set but no signingKeys provider was configured, so " +
          "OIDC issuance is off: this instance would mint no id_token and " +
          "answer 404 from /.well-known/openid-configuration, /jwks, and " +
          "/userinfo. Load the signing key (importSigningKeyJwk) and pass it " +
          "as the signingKeys option, or unset requireOidc if this server is " +
          "plain OAuth2.",
      );
    }
    this.#isPublicSuffix = options.isPublicSuffix;
    this.#subjectOf = options.subjectOf ?? defaultSubjectOf;
    this.#userClaims = options.userClaims;
    this.#introspectionClaims = options.introspectionClaims;
  }

  /**
   * Whether this instance will actually serve the OIDC surface: `true` once
   * `signingKeys` is set, which is what gates `id_token` issuance and the
   * `/jwks`, `/userinfo`, and `openid-configuration` endpoints (they answer
   * 404 while it is `false`).
   *
   * Read it in a readiness probe to keep an instance that booted without its
   * signing key out of the load balancer instead of letting it 404 relying
   * parties. It reports the provider this server configured — not that the
   * provider can produce a key, which surfaces on first use — and it tracks
   * the `signingKeys` field, so it is meaningful from construction onward and
   * follows any later reassignment.
   */
  get oidcEnabled(): boolean {
    return this.signingKeys !== undefined;
  }

  /** Resolves the per-request {@link AuthorizationServerContext}. */
  async authorizationContext(
    request: Request,
  ): Promise<AuthorizationServerContext<Client, User, S>> {
    return await this.#resolve(request);
  }

  /** Resolves the endpoint URLs for a request (issuer-derived unless set). */
  #resolvedEndpoints(
    context: AuthorizationServerContext<Client, User, S>,
  ): ResolvedEndpoints {
    const { issuer } = context;
    const endpoints: ResolvedEndpoints = {};
    for (const [key, { option, path }] of ADVERTISED_ENTRIES) {
      endpoints[key] = context[option] ??
        (issuer ? `${issuer}${path}` : undefined);
    }
    return endpoints;
  }

  /** The resolved endpoint URLs for a request. Used by {@link localAuthServerFetch}. */
  async resolveEndpoints(request: Request): Promise<ResolvedEndpoints> {
    return this.#resolvedEndpoints(await this.authorizationContext(request));
  }

  /**
   * Converts a token to a bearer token response body.
   */
  bearerToken(
    token: Token<Client, User, S>,
    services: AuthorizationServerServices<Client, User, S>,
  ): TokenResponse {
    const bearerToken: TokenResponse = {
      token_type: "Bearer",
      access_token: token.accessToken,
    };

    const { tokenService } = services;
    if (token.accessTokenExpiresAt) {
      bearerToken.expires_in = Math.round(
        (token.accessTokenExpiresAt.getTime() - Date.now()) / 1000,
      );
    } else if (tokenService) {
      bearerToken.expires_in = tokenService.accessTokenLifetime;
    }

    if ("refreshToken" in token && token.refreshToken) {
      bearerToken.refresh_token = token.refreshToken as string;
    }

    if (token.scope) {
      bearerToken.scope = token.scope.toString();
    }

    return bearerToken;
  }

  /**
   * Creates a token response. When the issuing `grant` is passed, an id_token
   * is only minted for grants that represent an end-user authentication
   * (`grant.issuesIdToken !== false`).
   */
  async createTokenResponse(
    token: Token<Client, User, S>,
    context: AuthorizationServerContext<Client, User, S>,
    grant?: DispatchableGrant<Client, User, S>,
  ): Promise<Response> {
    const body = this.bearerToken(token, context.services);
    if (grant?.issuesIdToken !== false) {
      const idToken = await this.mintIdToken(token, context);
      if (idToken) body.id_token = idToken;
    }
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: {
        "Content-Type": "application/json;charset=UTF-8",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
      },
    });
  }

  /**
   * Applies `Cache-Control: no-store` and `Pragma: no-cache` headers to an
   * error per RFC 6749 Section 5.2. The headers land on both the rethrown
   * error (when {@link throwOnError} is true) and the generated response.
   */
  private addCacheHeaders(error: OAuth2Error): void {
    error.headers.set("Cache-Control", "no-store");
    error.headers.set("Pragma", "no-cache");
  }

  /**
   * Error-prepare callback for the endpoints that authenticate the client
   * (token, revocation, introspection, device authorization). Attaches the
   * RFC 6749 Section 5.2 cache headers, and — when client authentication was
   * attempted via the `Authorization` header and failed with a 401 — the
   * matching `WWW-Authenticate: Basic` challenge that RFC 6749 Section 5.2
   * requires.
   */
  private prepareClientAuthError(
    request: Request,
  ): (error: OAuth2Error) => void {
    return (error) => {
      this.addCacheHeaders(error);
      if (error.status === 401 && request.headers.get("authorization")) {
        error.headers.set("WWW-Authenticate", `Basic realm="${this.realm}"`);
      }
    };
  }

  /**
   * Rejects a client that is not registered for a grant type
   * (RFC 6749 Section 5.2 `unauthorized_client`).
   */
  #assertGrantAuthorized(client: Client, grantType: string): void {
    if (!client.grants?.includes(grantType)) {
      throw new UnauthorizedClientError(
        `client is not authorized to use the ${grantType} grant type`,
      );
    }
  }

  /** The grant a token request's `grant_type` dispatches to. */
  #grantFromBody(body: FormData): DispatchableGrant<Client, User, S> {
    const grantType = body.get("grant_type");
    if (typeof grantType !== "string") {
      throw new InvalidRequestError("grant_type parameter required");
    }
    const grant = this.grants[grantType];
    if (!grant) {
      throw new UnsupportedGrantTypeError("invalid grant_type");
    }
    return grant;
  }

  async #beginClientAuthenticatedRequest<
    G extends DispatchableGrant<Client, User, S> | undefined = undefined,
  >(
    request: Request,
    options: {
      grantFromBody?: (body: FormData) => G;
      requiredGrantType?: string;
    } = {},
  ): Promise<{
    context: AuthorizationServerContext<Client, User, S>;
    body: FormData;
    client: Client;
    grant: G;
  }> {
    if (request.method !== "POST") {
      throw new InvalidRequestError("method must be POST");
    }

    const contentType = request.headers.get("content-type");
    if (!contentType?.includes("application/x-www-form-urlencoded")) {
      throw new InvalidRequestError(
        "content-type header must be application/x-www-form-urlencoded",
      );
    }

    const context = await this.authorizationContext(request);

    const body = await request.clone().formData().catch(() => {
      throw new InvalidRequestError(
        "body must be application/x-www-form-urlencoded",
      );
    });

    const grant = options.grantFromBody?.(body) as G;
    const client = grant
      ? await grant.getAuthenticatedClient(request, body)
      : await this.authenticateClient(request, body, context.services);

    const grantType = grant?.grantType ?? options.requiredGrantType;
    if (grantType) this.#assertGrantAuthorized(client, grantType);

    return { context, body, client, grant };
  }

  /**
   * Handles a token request (POST /token).
   * Supports multiple grant types based on the configured grants.
   *
   * A malformed request — wrong method, a content-type other than
   * `application/x-www-form-urlencoded`, or an unsupported grant — is a 400
   * `invalid_request`.
   */
  async handleTokenRequest(request: Request): Promise<Response> {
    try {
      const { context, body, client, grant } = await this
        .#beginClientAuthenticatedRequest(request, {
          grantFromBody: (body) => this.#grantFromBody(body),
        });

      const token = await grant.token(request, client, body);

      return await this.createTokenResponse(token, context, grant);
    } catch (error) {
      return this.handleError(error, this.prepareClientAuthError(request));
    }
  }

  /**
   * Mint an OIDC id_token for a user-bound token whose scope includes
   * `openid`, or `undefined` when the OIDC surface is off (no signing keys),
   * the token has no user, the scope lacks `openid`, or no issuer resolved.
   */
  async mintIdToken(
    token: Token<Client, User, S>,
    context: AuthorizationServerContext<Client, User, S>,
  ): Promise<string | undefined> {
    if (!this.signingKeys || !token.user || !context.issuer) return undefined;
    if (!token.scope?.has("openid")) return undefined;

    const key = await this.signingKeys.getSigningKey();
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      ...(await this.#oidcClaims(token.user, token.scope)),
      iss: context.issuer,
      aud: token.client.id,
      iat: now,
      exp: now + 3600,
    };
    if (token.nonce) claims.nonce = token.nonce;
    return await signJwt(key, claims);
  }

  /** OIDC claims released for a user: `userClaims` under the winning `sub`. */
  async #oidcClaims(
    user: User,
    scope?: S | null,
  ): Promise<Record<string, unknown>> {
    return {
      ...(await this.#userClaims?.(user, scope) ?? {}),
      sub: this.#subjectOf(user),
    };
  }

  /**
   * Handles an OIDC discovery request (GET /.well-known/openid-configuration):
   * the RFC 8414 metadata document including the OIDC fields. 404 when OIDC
   * issuance is off (no signing keys), so relying parties fail fast instead of
   * reading a document missing its REQUIRED OIDC members.
   */
  async handleOidcMetadataRequest(request: Request): Promise<Response> {
    if (!this.signingKeys) {
      return this.handleError(
        new OAuth2Error(404, "OIDC issuance is not enabled", {
          extensions: { error: "not_found" },
        }),
      );
    }
    return await this.handleMetadataRequest(request);
  }

  /**
   * Handles a JWKS request (GET /jwks): the public signing keys id_tokens and
   * JWT access tokens verify against. 404 when OIDC issuance is off.
   */
  async handleJwksRequest(_request: Request): Promise<Response> {
    if (!this.signingKeys) {
      return this.handleError(
        new OAuth2Error(404, "OIDC issuance is not enabled", {
          extensions: { error: "not_found" },
        }),
      );
    }
    try {
      const jwks = await this.signingKeys.getPublicJwks();
      return new Response(JSON.stringify(jwks), {
        status: 200,
        headers: {
          "Content-Type": "application/json;charset=UTF-8",
          "Cache-Control": "public, max-age=300",
        },
      });
    } catch (error) {
      return this.handleError(error);
    }
  }

  /**
   * Handles an OIDC UserInfo request (GET/POST /userinfo): validates the
   * bearer token (which must carry the `openid` scope and a user) and returns
   * `sub` plus any configured `userClaims`.
   *
   * Failures follow RFC 6750 Section 3.1, which OIDC Core Section 5.3.3 defers
   * to: a missing, malformed, or expired token is a 401 (`invalid_token`,
   * omitted from the challenge when no credentials were presented at all),
   * while a **valid** token that simply lacks the `openid` scope is a 403
   * `insufficient_scope` whose challenge names `scope="openid"`. The
   * distinction matters to relying parties — a 401 tells an RP its credential
   * is bad, so answering one for a scope problem sends it to refresh a token
   * that will fail again the same way.
   */
  async handleUserInfoRequest(request: Request): Promise<Response> {
    try {
      const { user, scope } = await this.authenticate(request);
      this.assertScope(scope, "openid");
      if (!user) {
        throw new InvalidTokenError("access token has no resource owner");
      }
      const claims = await this.#oidcClaims(user, scope);
      return new Response(JSON.stringify(claims), {
        status: 200,
        headers: {
          "Content-Type": "application/json;charset=UTF-8",
          "Cache-Control": "no-store",
        },
      });
    } catch (error) {
      return this.handleAuthError(error);
    }
  }

  /**
   * Handles an OIDC RP-Initiated Logout request (GET/POST /end_session).
   *
   * The server does not know what a session **is** — that is the app's — so
   * `endSession` does the ending and this method does the protocol around it:
   * identifying the relying party, authorizing the return trip, and shaping
   * the response. `endSession` is always called, even when nothing else about
   * the request checks out, because a logout that refuses to log anyone out is
   * the worst possible failure mode for this endpoint.
   *
   * **Authorizing `post_logout_redirect_uri` is the whole security surface.**
   * It is matched by **exact string** against the resolved client's
   * {@link ClientInterface.postLogoutRedirectUris} — no patterns, no prefixes,
   * unlike the authorization endpoint's redirect matching. A logout redirect
   * carries no code to steal, but an unvalidated one is an open redirect on the
   * IDP's own domain, which is a phishing primitive: the victim really did just
   * come from your login page. When no client resolves, or the URI is not
   * registered, the browser is **not** sent there — it goes to `fallback` if
   * the app supplied one, or gets a bare 204.
   *
   * `id_token_hint` is verified against the signing keys but its expiry is
   * ignored: by the time anyone logs out the id_token naming their session has
   * usually expired, and it is a hint, not authority. `client_id` is accepted
   * as the fallback identifier the spec allows. `state` rides along only to a
   * URI that passed authorization.
   *
   * Wire the app's session teardown through the `endSession` **constructor
   * option**; this method answers 404 without it, and the discovery document
   * omits `end_session_endpoint` to match.
   *
   * @example
   * ```ts
   * const server = new AuthorizationServer({
   *   resolve,
   *   grants,
   *   signingKeys,
   *   endSession: async ({ subject }) => {
   *     if (subject) await sessions.deleteByUserId(subject);
   *     return { headers: { "Set-Cookie": clearSessionCookie() }, fallback: "/" };
   *   },
   * });
   * app.all("/end_session", (c) => server.handleEndSessionRequest(c.req.raw));
   * ```
   */
  async handleEndSessionRequest(request: Request): Promise<Response> {
    const endSession = this.#endSession;
    if (!endSession) return new Response(null, { status: 404 });
    try {
      const params = await this.#endSessionParameters(request);
      const client = await this.#resolveEndSessionClient(request, params);
      const result = await endSession({
        request,
        client,
        subject: params.subject,
        logoutHint: params.logoutHint,
      }) ?? {};

      const headers = new Headers(result.headers);
      const authorized = this.#postLogoutRedirect(client, params);
      const target = authorized ?? result.fallback;
      if (!target) return new Response(null, { status: 204, headers });
      headers.set("Location", target);
      return new Response(null, { status: 302, headers });
    } catch (error) {
      return this.handleError(error);
    }
  }

  /**
   * The logout parameters, from the query string on GET and the form body on
   * POST — RP-Initiated Logout §2 permits both. A verified `id_token_hint`
   * contributes the subject and the audience; an unverifiable one contributes
   * nothing rather than refusing the logout.
   */
  async #endSessionParameters(request: Request): Promise<EndSessionParameters> {
    const url = new URL(request.url);
    const params = request.method === "POST"
      ? new URLSearchParams(await request.text())
      : url.searchParams;
    const idTokenHint = params.get("id_token_hint");
    const hint = idTokenHint ? await this.#readIdTokenHint(idTokenHint) : null;
    return {
      clientId: params.get("client_id") ?? hint?.audience ?? null,
      subject: hint?.subject ?? null,
      postLogoutRedirectUri: params.get("post_logout_redirect_uri") ?? null,
      state: params.get("state") ?? null,
      logoutHint: params.get("logout_hint") ?? null,
    };
  }

  /** The subject and audience of a signature-valid `id_token_hint`, if any. */
  async #readIdTokenHint(
    idTokenHint: string,
  ): Promise<{ subject: string | null; audience: string | null } | null> {
    const key = await this.signingKeys?.getSigningKey();
    if (!key) return null;
    const payload = await verifyJwt(idTokenHint, key.publicJwk, {
      ignoreExpiration: true,
    });
    if (!payload) return null;
    const aud = payload.aud;
    const audience = typeof aud === "string"
      ? aud
      : Array.isArray(aud) && typeof aud[0] === "string"
      ? aud[0]
      : null;
    return {
      subject: typeof payload.sub === "string" ? payload.sub : null,
      audience,
    };
  }

  /** The client the logout names, or null when it named none we can find. */
  async #resolveEndSessionClient(
    request: Request,
    params: EndSessionParameters,
  ): Promise<Client | null> {
    if (!params.clientId) return null;
    const { services } = await this.authorizationContext(request);
    try {
      return await services.clientService.get(params.clientId) ?? null;
    } catch {
      return null;
    }
  }

  /**
   * The `post_logout_redirect_uri` to honor, with `state` appended — or
   * undefined when the request named none, named no resolvable client, or
   * named a URI that client did not register.
   */
  #postLogoutRedirect(
    client: Client | null,
    params: EndSessionParameters,
  ): string | undefined {
    const requested = params.postLogoutRedirectUri;
    if (!requested || !client) return undefined;
    const registered = client.postLogoutRedirectUris ?? [];
    if (!registered.includes(requested)) return undefined;
    if (!params.state) return requested;
    const url = new URL(requested);
    url.searchParams.set("state", params.state);
    return url.toString();
  }

  /**
   * Parses authorization request parameters from the query string.
   *
   * The authorization endpoint is GET-only (RFC 6749 Section 3.1 requires GET
   * and only permits POST), so parameters are read from `url.searchParams`.
   */
  parseAuthorizeParameters(request: Request): AuthorizeParameters {
    const url = new URL(request.url);
    const params = url.searchParams;

    return {
      responseType: params.get("response_type") ?? undefined,
      clientId: params.get("client_id") ?? undefined,
      redirectUri: params.get("redirect_uri") ?? undefined,
      state: params.get("state") ?? undefined,
      scope: params.get("scope") ?? undefined,
      challenge: params.get("code_challenge") ?? undefined,
      challengeMethod: params.get("code_challenge_method") ?? undefined,
      nonce: params.get("nonce") ?? undefined,
    };
  }

  /**
   * Handles an authorization request (GET /authorize).
   * Used for the authorization code flow.
   *
   * Once the request has named a redirect URI the client registered, failures
   * are reported to that URI as an RFC 6749 Section 4.1.2.1 error redirect;
   * before that they are error responses from this endpoint, since there is no
   * verified place to send the user back to.
   *
   * Requires a grant extending {@linkcode AuthorizationCodeGrant} registered
   * under `authorization_code`; without one the endpoint answers 500
   * `server_error` (or rethrows, with `throwOnError`).
   *
   * @param request The incoming request
   * @param authenticateUser Function to authenticate the user
   * @param handleConsent Optional function to handle user consent
   * @returns A Response (redirect to client or error page)
   */
  async handleAuthorizeRequest(
    request: Request,
    authenticateUser: AuthenticateUserFn<User>,
    handleConsent?: HandleConsentFn<Client, S>,
  ): Promise<Response> {
    const target: AuthorizeRedirectTarget = { url: null };
    try {
      return await this.#authorize(
        request,
        target,
        authenticateUser,
        handleConsent,
      );
    } catch (error) {
      return this.#authorizeErrorResponse(error, target.url);
    }
  }

  /**
   * The authorize flow proper, recording the redirect target on `target` as
   * soon as one is verified so {@link handleAuthorizeRequest} can report later
   * failures to the client.
   */
  async #authorize(
    request: Request,
    target: AuthorizeRedirectTarget,
    authenticateUser: AuthenticateUserFn<User>,
    handleConsent?: HandleConsentFn<Client, S>,
  ): Promise<Response> {
    const params = this.parseAuthorizeParameters(request);
    const grant = this.#authorizationCodeGrant();
    const { services } = await this.authorizationContext(request);
    const client = await this.#resolveAuthorizeClient(
      grant,
      params.clientId,
      services,
    );

    const redirectUrl = this.#resolveRedirectTarget(client, params.redirectUri);
    target.url = redirectUrl;

    if (!params.state) {
      throw new InvalidRequestError("state required");
    }
    redirectUrl.searchParams.set("state", params.state);

    this.#validateResponseType(params.responseType);
    const requestedScope = grant.parseScope(params.scope);
    this.#validateChallenge(grant, params);

    const authResult = await authenticateUser(request);
    if (authResult instanceof Response) return authResult;
    if (!authResult) {
      throw new AccessDeniedError("authentication required");
    }
    const { user, authorizedScope } = authResult;

    if (grant.requirePKCE && !params.challenge) {
      throw new InvalidRequestError(
        "code_challenge required (PKCE is required for this grant)",
      );
    }

    const consented = await this.#resolveScopeAndConsent({
      grant,
      client,
      user,
      requestedScope,
      authorizedScope,
      services,
      handleConsent,
    });
    if (consented instanceof Response) return consented;

    const authorizationCode = await grant.generateAuthorizationCode({
      client,
      user,
      scope: consented.scope,
      redirectUri: params.redirectUri ?? null,
      challenge: params.challenge ?? null,
      challengeMethod: params.challengeMethod ?? null,
      nonce: params.nonce ?? null,
    }, request);

    redirectUrl.searchParams.set("code", authorizationCode.code);
    return Response.redirect(redirectUrl.toString(), 302);
  }

  /**
   * Reports an authorize failure: an RFC 6749 Section 4.1.2.1 error redirect
   * once a verified `redirectUrl` exists, otherwise a plain error response.
   */
  #authorizeErrorResponse(error: unknown, redirectUrl: URL | null): Response {
    if (!redirectUrl || !(error instanceof Error) || !isOAuth2Error(error)) {
      return this.handleError(error);
    }

    const { searchParams } = redirectUrl;
    searchParams.set("error", error.extensions.error ?? "server_error");
    // Use exposedMessage, never raw error.message, so 5xx server_error detail isn't leaked into the redirect.
    const description = error.extensions.error_description ??
      error.exposedMessage;
    if (description) {
      searchParams.set("error_description", description);
    }
    const errorUri = error.extensions.error_uri ?? error.type;
    if (errorUri) {
      searchParams.set("error_uri", errorUri);
    }
    return Response.redirect(redirectUrl.toString(), 302);
  }

  #authorizationCodeGrant(): AuthorizationCodeGrant<Client, User, S> {
    const grant = this.grants[AUTHORIZATION_CODE_GRANT_TYPE];
    if (!grant) {
      throw new ServerError("missing authorization code grant");
    }
    if (!isAuthorizationCodeGrant<Client, User, S>(grant)) {
      throw new ServerError(
        `the grant registered as "${AUTHORIZATION_CODE_GRANT_TYPE}" ` +
          `(${grant.constructor.name}) cannot serve the authorization ` +
          `endpoint: it must extend AuthorizationCodeGrant`,
      );
    }
    return grant;
  }

  #deviceAuthorizationGrant(): DeviceAuthorizationGrant<Client, User, S> {
    const grant = this.grants[DEVICE_AUTHORIZATION_GRANT_TYPE];
    if (!grant) {
      throw new ServerError("device authorization grant not configured");
    }
    if (!isDeviceAuthorizationGrant<Client, User, S>(grant)) {
      throw new ServerError(
        `the grant registered as "${DEVICE_AUTHORIZATION_GRANT_TYPE}" ` +
          `(${grant.constructor.name}) cannot serve the device authorization ` +
          `endpoint: it must extend DeviceAuthorizationGrant`,
      );
    }
    return grant;
  }

  /**
   * The client the authorize request names, once it is registered for the
   * authorization code grant.
   */
  async #resolveAuthorizeClient(
    grant: AuthorizationCodeGrant<Client, User, S>,
    clientId: string | undefined,
    services: AuthorizationServerServices<Client, User, S>,
  ): Promise<Client> {
    if (!clientId) {
      throw new InvalidRequestError("client_id parameter required");
    }
    const client = await grant.getClient(clientId, services.clientService);
    this.#assertGrantAuthorized(client, AUTHORIZATION_CODE_GRANT_TYPE);
    return client;
  }

  /**
   * The URL the browser is sent back to: the requested `redirect_uri` once it
   * matches a registration, or the client's first literal registration when the
   * request omitted one.
   */
  #resolveRedirectTarget(client: Client, redirectUri?: string): URL {
    if (!client.redirectUris?.length) {
      throw new UnauthorizedClientError("no authorized redirect_uri");
    }
    if (
      redirectUri &&
      !matchRedirectUri(client.redirectUris, redirectUri, this.#isPublicSuffix)
    ) {
      throw new UnauthorizedClientError("redirect_uri not authorized");
    }

    const defaultRedirectUri = client.redirectUris.find(
      (uri) => !isRedirectUriPattern(uri),
    );
    if (!redirectUri && !defaultRedirectUri) {
      throw new InvalidRequestError(
        "redirect_uri required when every registered redirect_uri is a pattern",
      );
    }

    return new URL(redirectUri ?? defaultRedirectUri!);
  }

  /** Rejects any `response_type` other than the `code` this endpoint issues. */
  #validateResponseType(responseType?: string): void {
    if (!responseType) {
      throw new InvalidRequestError("response_type required");
    }
    // RFC 6749 §4.1.2.1: unsupported response_type is unsupported_response_type, not invalid_request.
    if (responseType !== "code") {
      throw new UnsupportedResponseTypeError("response_type not supported");
    }
  }

  /**
   * Rejects PKCE parameters the grant cannot honor (RFC 7636 Section 4.3), and
   * a `code_challenge` malformed for a method whose shape Section 4.2 fixes.
   */
  #validateChallenge(
    grant: AuthorizationCodeGrant<Client, User, S>,
    params: AuthorizeParameters,
  ): void {
    const { challenge, challengeMethod } = params;
    if (challengeMethod && !challenge) {
      throw new InvalidRequestError(
        "code_challenge required when code_challenge_method is set",
      );
    }
    if (challenge && !grant.validateChallengeMethod(challengeMethod)) {
      throw new InvalidRequestError("unsupported code_challenge_method");
    }
    if (challenge && !validateCodeChallenge(challenge, challengeMethod)) {
      throw new InvalidRequestError(
        "code_challenge must be 43-128 characters using [A-Z] / [a-z] / [0-9] / - / . / _ / ~",
      );
    }
  }

  /**
   * The scope the authorization code will carry: the requested scope narrowed
   * by the token service, then by consent when the user has not already
   * pre-authorized it. A `Response` short-circuits the flow (a consent page).
   */
  async #resolveScopeAndConsent(options: {
    grant: AuthorizationCodeGrant<Client, User, S>;
    client: Client;
    user: User;
    requestedScope: S | undefined;
    authorizedScope: AbstractScope | undefined;
    services: AuthorizationServerServices<Client, User, S>;
    handleConsent?: HandleConsentFn<Client, S>;
  }): Promise<{ scope: S | undefined } | Response> {
    const {
      grant,
      client,
      user,
      requestedScope,
      authorizedScope,
      services,
      handleConsent,
    } = options;

    const acceptedScope = await grant.acceptedScope(
      client,
      user,
      requestedScope,
      services.tokenService,
    );
    let scope = acceptedScope ?? undefined;

    const needsConsent = scope !== undefined &&
      !(authorizedScope && authorizedScope.has(scope));
    if (needsConsent && handleConsent) {
      const consent = await handleConsent(client, scope, user);
      if (consent instanceof Response) return consent;
      if (!consent.approved) {
        throw new AccessDeniedError("user denied consent");
      }
      if (consent.scope) scope = consent.scope;
    }

    return { scope };
  }

  /**
   * Authenticates a client from the credentials the request presents: Basic
   * authentication (RFC 6749 Section 2.3.1) or the `client_id`/`client_secret`
   * of `body`, the form body the endpoint already parsed. The grants
   * authenticate through the same implementation, so a request that fails here
   * fails identically at the token endpoint.
   *
   * @throws {InvalidClientError} If client authentication fails
   */
  async authenticateClient(
    request: Request,
    body: FormData,
    services: AuthorizationServerServices<Client, User, S>,
  ): Promise<Client> {
    return await authenticateClientCredentials(
      extractClientCredentials(request, body),
      services.clientService,
    );
  }

  /**
   * Handles a token revocation request (POST /revoke).
   *
   * Per RFC 7009, requires client authentication and accepts:
   * - token: The token to revoke (required)
   * - token_type_hint: Hint about token type (optional)
   *
   * **A client can only revoke its own tokens.** RFC 7009 Section 2.1 requires
   * the server to verify that the presented token was issued to the
   * authenticated client; without that check any client that has observed a
   * token value — a resource server it called, a shared browser, a log — could
   * end another application's live sessions at will. A token belonging to a
   * different client is left alone.
   *
   * Always returns 200 OK, even if the token was invalid, already revoked, or
   * issued to another client: RFC 7009 Section 2.2 requires that answer so the
   * endpoint cannot be used as an oracle for whether a token value is live or
   * whose it is. That covers the token only: a malformed request — wrong
   * method, a content-type other than `application/x-www-form-urlencoded`, or
   * no `token` parameter — is a 400 `invalid_request`, as on the token
   * endpoint.
   *
   * `token_type_hint` orders the lookup rather than restricting it, so a client
   * that mislabels its token still gets it revoked.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc7009
   */
  async handleRevocationRequest(request: Request): Promise<Response> {
    try {
      const { context, body, client } = await this
        .#beginClientAuthenticatedRequest(request);

      const token = body.get("token");
      if (typeof token !== "string") {
        throw new InvalidRequestError("token parameter required");
      }

      const tokenTypeHint = body.get("token_type_hint");
      const hint = typeof tokenTypeHint === "string" ? tokenTypeHint : null;

      const { tokenService } = context.services;
      const resolved = await this.#resolveToken(tokenService, token, hint);
      if (
        resolved &&
        resolved.token.client.id.toString() === client.id.toString()
      ) {
        await tokenService.revoke(token, resolved.tokenType);
      }

      return new Response(null, { status: 200 });
    } catch (error) {
      return this.handleError(error, this.prepareClientAuthError(request));
    }
  }

  async #resolveToken(
    tokenService: TokenServiceInterface<Client, User, S>,
    value: string,
    hint: string | null,
  ): Promise<ResolvedToken<Client, User, S> | undefined> {
    const refreshFirst = hint === "refresh_token";

    if (refreshFirst) {
      const refreshToken = await tokenService.getRefreshToken(value);
      if (refreshToken) {
        return { tokenType: "refresh_token", token: refreshToken };
      }
    }

    const token = await tokenService.getToken(value);
    if (token) return { tokenType: "access_token", token };

    if (refreshFirst) return undefined;

    const refreshToken = await tokenService.getRefreshToken(value);
    return refreshToken
      ? { tokenType: "refresh_token", token: refreshToken }
      : undefined;
  }

  #introspectedExpiry(
    resolved: ResolvedToken<Client, User, S>,
  ): Date | undefined {
    return resolved.tokenType === "refresh_token"
      ? (resolved.token as RefreshToken<Client, User, S>).refreshTokenExpiresAt
      : resolved.token.accessTokenExpiresAt;
  }

  /**
   * Handles a token introspection request (POST /introspect).
   *
   * Per RFC 7662, requires client authentication and returns information
   * about the token including whether it is active.
   *
   * Both access tokens and refresh tokens introspect. `token_type_hint` orders
   * the lookup rather than restricting it (RFC 7662 Section 2.1 requires the
   * other kind to be tried when the hinted lookup misses), so a mislabelled
   * token still resolves. An active access token carries
   * `token_type: "Bearer"`; a refresh token carries no `token_type`, since
   * that field describes how an access token is presented, and its `exp` is
   * the refresh token's own expiry.
   *
   * A token with no user — the client acting as its own resource owner, as
   * the client credentials grant issues — carries no `sub` and no `username`;
   * `client_id` identifies the machine. `sub` is optional in RFC 7662, and
   * leaving it absent keeps `sub` an unambiguous "there is a resource owner"
   * signal rather than overloading `client_id` into the subject namespace
   * (RFC 9700 §4.15.1).
   *
   * A wrong method, or a content type other than
   * `application/x-www-form-urlencoded`, is a 400 `invalid_request`, as on the
   * token endpoint.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc7662
   */
  async handleIntrospectionRequest(request: Request): Promise<Response> {
    try {
      const { context, body } = await this.#beginClientAuthenticatedRequest(
        request,
      );

      const tokenValue = body.get("token");
      if (typeof tokenValue !== "string") {
        throw new InvalidRequestError("token parameter required");
      }

      const tokenTypeHint = body.get("token_type_hint");
      const hint = typeof tokenTypeHint === "string" ? tokenTypeHint : null;

      const { tokenService } = context.services;

      let response: IntrospectionResponse;

      const resolved = await this.#resolveToken(
        tokenService,
        tokenValue,
        hint,
      );
      const expiresAt = resolved && this.#introspectedExpiry(resolved);

      if (!resolved || (expiresAt && expiresAt < new Date())) {
        response = { active: false };
      } else {
        const { token, tokenType } = resolved;

        response = {
          active: true,
          client_id: token.client.id,
        };

        if (tokenType === "access_token") {
          response.token_type = "Bearer";
        }

        if (token.scope) {
          response.scope = token.scope.toString();
        }

        if (expiresAt) {
          response.exp = Math.floor(expiresAt.getTime() / 1000);
        }

        if (context.issuer) {
          response.iss = context.issuer;
        }

        const user = token.user as
          | { id?: string; username?: string }
          | undefined;
        if (user?.id) {
          response.sub = user.id;
        }
        if (user?.username) {
          response.username = user.username;
        }

        if (this.#introspectionClaims) {
          response = {
            ...await this.#introspectionClaims(token),
            ...response,
          };
        }
      }

      return new Response(JSON.stringify(response), {
        status: 200,
        headers: {
          "Content-Type": "application/json;charset=UTF-8",
          "Cache-Control": "no-store",
          "Pragma": "no-cache",
        },
      });
    } catch (error) {
      return this.handleError(error, this.prepareClientAuthError(request));
    }
  }

  /**
   * Gets OAuth2 server metadata (RFC 8414).
   *
   * Returns metadata about this authorization server including supported
   * grant types, endpoints, and capabilities.
   *
   * `code_challenge_methods_supported` is derived from the registered
   * authorization code grant's own `challengeMethods`, so a server that
   * registers an extra method (or drops `S256`) advertises what it will
   * actually accept. It is omitted entirely when no authorization code grant
   * is registered, since PKCE has nothing to apply to.
   *
   * `token_endpoint_auth_methods_supported` always includes `none`, the
   * RFC 7591 method for a client with no secret. The token endpoint accepts it
   * on every deployment and for every grant — a request carrying only
   * `client_id` reaches `ClientServiceInterface.getAuthenticated` with no
   * secret, which that interface's contract requires to resolve a public
   * client — and there is no option that turns it off, so it is not
   * conditional on anything a caller configures. Which clients may use it is
   * decided per client, by whether the client has a secret; discovery
   * describes the endpoint, not the client population.
   *
   * @throws {ServerError} If the resolved context has no `issuer` — RFC 8414
   * makes it REQUIRED and it is the field clients validate against.
   * @see https://datatracker.ietf.org/doc/html/rfc8414#section-2
   * @see https://datatracker.ietf.org/doc/html/rfc7591#section-2
   */
  getMetadata(
    context: AuthorizationServerContext<Client, User, S>,
  ): AuthorizationServerMetadata {
    const grants = Object.keys(this.grants);
    const hasAuthCodeGrant = grants.includes("authorization_code");

    if (!context.issuer) {
      throw new ServerError(
        "issuer must be configured to serve authorization server metadata " +
          "(RFC 8414)",
      );
    }

    const endpoints = this.#resolvedEndpoints(context);

    const metadata: AuthorizationServerMetadata = {
      issuer: context.issuer,
    };

    this.#advertiseEndpoints(metadata, endpoints, false);

    metadata.grant_types_supported = grants;
    metadata.token_endpoint_auth_methods_supported = [
      "client_secret_basic",
      "client_secret_post",
      "none",
    ];
    const challengeMethods = this.#supportedChallengeMethods();
    if (challengeMethods.length) {
      metadata.code_challenge_methods_supported = challengeMethods;
    }
    metadata.response_types_supported = hasAuthCodeGrant ? ["code"] : [];

    if (this.scopesSupported) {
      metadata.scopes_supported = this.scopesSupported;
    }

    if (this.signingKeys) {
      this.#advertiseEndpoints(metadata, endpoints, true);
      metadata.id_token_signing_alg_values_supported = ["ES256"];
      metadata.subject_types_supported = ["public"];
    }

    return metadata;
  }

  #supportedChallengeMethods(): string[] {
    const grant = this.grants[AUTHORIZATION_CODE_GRANT_TYPE];
    if (!grant || !isAuthorizationCodeGrant<Client, User, S>(grant)) return [];
    const { challengeMethods } = grant;
    return Object.keys(challengeMethods).filter(
      (method) => typeof challengeMethods[method] === "function",
    );
  }

  /** Publishes the resolved URLs of the OIDC (or plain OAuth2) endpoints. */
  #advertiseEndpoints(
    metadata: AuthorizationServerMetadata,
    endpoints: ResolvedEndpoints,
    oidc: boolean,
  ): void {
    for (const [key, endpoint] of ADVERTISED_ENTRIES) {
      if (endpoint.oidc !== oidc) continue;
      if (key === "endSession" && !this.#endSession) continue;
      const url = endpoints[key];
      if (url) metadata[endpoint.metadata] = url;
    }
  }

  /**
   * Handles a metadata request (GET /.well-known/oauth-authorization-server).
   *
   * Returns the authorization server metadata as JSON per RFC 8414.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc8414
   */
  async handleMetadataRequest(request: Request): Promise<Response> {
    try {
      const context = await this.authorizationContext(request);
      const metadata = this.getMetadata(context);
      return new Response(JSON.stringify(metadata), {
        status: 200,
        headers: {
          "Content-Type": "application/json;charset=UTF-8",
        },
      });
    } catch (error) {
      return this.handleError(error);
    }
  }

  /**
   * Handles a device authorization request (POST /device_authorization).
   *
   * Initiates the device authorization flow by generating a device_code
   * and user_code that the user can use to authorize the request on
   * a secondary device.
   *
   * Requires a grant extending {@linkcode DeviceAuthorizationGrant} registered
   * under `urn:ietf:params:oauth:grant-type:device_code`, and a
   * `verificationUri` on the resolved context; without either the endpoint
   * answers 500 `server_error`. A wrong method, or a content type other than
   * `application/x-www-form-urlencoded`, is a 400 `invalid_request`, as on the
   * token endpoint.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
   * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
   */
  async handleDeviceAuthorizationRequest(
    request: Request,
  ): Promise<Response> {
    try {
      const { context, body, client } = await this
        .#beginClientAuthenticatedRequest(request, {
          requiredGrantType: DEVICE_AUTHORIZATION_GRANT_TYPE,
        });

      const grant = this.#deviceAuthorizationGrant();

      const scopeText = body.get("scope");
      const scope = typeof scopeText === "string"
        ? grant.parseScope(scopeText)
        : undefined;

      // RFC 8628 §3.2 requires a verification_uri the user can visit.
      if (!context.verificationUri) {
        throw new ServerError(
          "verificationUri must be configured for the device authorization " +
            "endpoint (RFC 8628)",
        );
      }

      const authorization = await grant.initiateDeviceAuthorization(
        client,
        request,
        scope,
      );

      const response: DeviceAuthorizationResponse = {
        device_code: authorization.deviceCode,
        user_code: authorization.userCode,
        verification_uri: context.verificationUri,
        expires_in: Math.floor(
          (authorization.expiresAt.getTime() - Date.now()) / 1000,
        ),
        interval: authorization.interval,
      };

      return new Response(JSON.stringify(response), {
        status: 200,
        headers: {
          "Content-Type": "application/json;charset=UTF-8",
          "Cache-Control": "no-store",
          "Pragma": "no-cache",
        },
      });
    } catch (error) {
      return this.handleError(error, this.prepareClientAuthError(request));
    }
  }
}

/**
 * Returns a `fetch`-compatible function that dispatches requests directly
 * to the {@link AuthorizationServer}'s handlers in-process, bypassing the
 * network.
 *
 * Use this to point a `DirectClient` at a co-located authorization
 * server — the request flow becomes a plain method call, so token refresh
 * (and every other client → server interaction) stays in-process.
 *
 * Routing is by pathname against the endpoints the server resolves for the
 * request (so it follows per-request issuer/origin):
 * - `POST {tokenEndpoint}` → `handleTokenRequest`
 * - `POST {revocationEndpoint}` → `handleRevocationRequest`
 * - `POST {introspectionEndpoint}` → `handleIntrospectionRequest`
 * - `POST {deviceAuthorizationEndpoint}` → `handleDeviceAuthorizationRequest`
 * - `GET  /.well-known/oauth-authorization-server` → `handleMetadataRequest`
 *
 * The authorization endpoint is deliberately **not** routed: `/authorize`
 * needs an `authenticateUser` (and optional `handleConsent`) callback this
 * transport has no access to, and in real flows it's a browser navigation,
 * never a call through the client's `fetch`. A request to it throws an
 * actionable error pointing at `handleAuthorizeRequest`. Any other path also
 * throws — the helper intentionally does not proxy arbitrary paths; if a call
 * lands here unexpectedly, that's a wiring bug worth surfacing rather than
 * silently forwarding.
 */
export function localAuthServerFetch<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(authServer: AuthorizationServer<Client, User, S>): typeof fetch {
  return async (input, init) => {
    const request = input instanceof Request
      ? (init ? new Request(input, init) : input)
      : new Request(String(input), init);
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    const endpoints = await authServer.resolveEndpoints(request);
    const pathOf = (endpoint?: string): string | undefined =>
      endpoint ? new URL(endpoint).pathname : undefined;

    const handlers: Record<
      AdvertisedEndpointKey,
      ((request: Request) => Promise<Response>) | null
    > = {
      authorization: null,
      token: (request) => authServer.handleTokenRequest(request),
      revocation: (request) => authServer.handleRevocationRequest(request),
      introspection: (request) =>
        authServer.handleIntrospectionRequest(request),
      deviceAuthorization: (request) =>
        authServer.handleDeviceAuthorizationRequest(request),
      jwks: (request) => authServer.handleJwksRequest(request),
      userinfo: (request) => authServer.handleUserInfoRequest(request),
      endSession: null,
    };

    for (const [key, { methods }] of ADVERTISED_ENTRIES) {
      const handler = handlers[key];
      if (!handler || !methods.includes(method)) continue;
      if (path === pathOf(endpoints[key])) return await handler(request);
    }

    if (method === "GET" && path === ENDPOINT_PATHS.metadata) {
      return await authServer.handleMetadataRequest(request);
    }
    if (method === "GET" && path === ENDPOINT_PATHS.oidcMetadata) {
      return await authServer.handleOidcMetadataRequest(request);
    }

    const endSessionPath = pathOf(endpoints.endSession);
    if (endSessionPath && path === endSessionPath) {
      throw new Error(
        `localAuthServerFetch cannot dispatch the end-session endpoint ` +
          `(${method} ${path}). RP-initiated logout requires an endSession ` +
          `callback this transport has no access to — only the app knows how ` +
          `to end its own session — and in real flows it is a browser ` +
          `navigation, not a client fetch. Drive it directly via ` +
          `server.handleEndSessionRequest(request, endSession).`,
      );
    }

    const authorizePath = pathOf(endpoints.authorization);
    if (authorizePath && path === authorizePath) {
      throw new Error(
        `localAuthServerFetch cannot dispatch the authorization endpoint ` +
          `(${method} ${path}). /authorize requires an authenticateUser ` +
          `(and optional handleConsent) callback this transport has no ` +
          `access to, and in real flows it is a browser navigation, not a ` +
          `client fetch. Drive it directly via ` +
          `server.handleAuthorizeRequest(request, authenticateUser) or the ` +
          `createMemoryAuthorizationServer() harness's authorize() helper.`,
      );
    }

    throw new Error(
      `localAuthServerFetch: no handler for ${method} ${path}. ` +
        `Configure the authorization server with explicit endpoint URLs ` +
        `and point your client at the matching paths.`,
    );
  };
}

export { AbstractGrant } from "./grants/grant.ts";
export type {
  DispatchableGrant,
  GrantOptions,
  GrantServices,
} from "./grants/grant.ts";
export { AuthorizationCodeGrant } from "./grants/authorization-code.ts";
export type { PKCEClientCredentials } from "./grants/authorization-code.ts";
export type {
  AuthorizationCodeGrantOptions,
  AuthorizationCodeGrantServices,
  GenerateAuthorizationCodeOptions,
} from "./grants/authorization-code.ts";
export { ClientCredentialsGrant } from "./grants/client-credentials.ts";
export type {
  ClientCredentialsGrantOptions,
  ClientCredentialsGrantServices,
} from "./grants/client-credentials.ts";
export {
  createJwtAccessTokenGenerator,
  exportSigningKeyJwk,
  generateSigningKey,
  importSigningKeyJwk,
  RotatingSigningKeyProvider,
  type RotatingSigningKeyProviderOptions,
  type SigningKey,
  type SigningKeyProvider,
  signJwt,
  StaticSigningKeyProvider,
  verifyJwt,
  type VerifyJwtOptions,
} from "./signing-keys.ts";
export { RefreshTokenGrant } from "./grants/refresh-token.ts";
export type {
  RefreshTokenGrantOptions,
  RefreshTokenGrantServices,
  TokenReuseEvent,
} from "./grants/refresh-token.ts";
export { PasswordGrant } from "./grants/password.ts";
export type {
  PasswordGrantOptions,
  PasswordGrantServices,
} from "./grants/password.ts";
export { DeviceAuthorizationGrant } from "./grants/device-authorization.ts";
export type {
  DeviceAuthorizationGrantOptions,
  DeviceAuthorizationGrantServices,
} from "./grants/device-authorization.ts";

export {
  AbstractTokenService,
  type AbstractTokenServiceOptions,
  type TokenServiceInterface,
} from "./services/token.ts";
export type { ClientServiceInterface } from "./services/client.ts";
export {
  AbstractAuthorizationCodeService,
  type AbstractAuthorizationCodeServiceOptions,
  type AuthorizationCodeServiceInterface,
} from "./services/authorization-code.ts";
export type { DeviceAuthorizationServiceInterface } from "./services/device-authorization.ts";
export type { UserServiceInterface } from "./services/user.ts";

export type {
  AuthorizationCode,
  AuthorizeParameters,
} from "../models/authorization-code.ts";
export type { DeviceAuthorization } from "../models/device-authorization.ts";
export type {
  AuthorizationServerMetadata,
  DeviceAuthorizationResponse,
  ErrorResponse,
  OAuth2ErrorCode,
} from "../models/responses.ts";

export {
  challengeMethods,
  CODE_VERIFIER_MAX_LENGTH,
  CODE_VERIFIER_MIN_LENGTH,
  CODE_VERIFIER_PATTERN,
  generateCodeChallenge,
  generateCodeVerifier,
  generateState,
  getChallengeMethod,
  validateCodeChallenge,
  validateCodeVerifier,
  verifyCodeChallenge,
} from "../utils/pkce.ts";
export type { ChallengeMethod, ChallengeMethods } from "../utils/pkce.ts";

export {
  encodeBasicAuth,
  parseBasicAuth,
  tryParseBasicAuth,
} from "../utils/basic-auth.ts";
export type { BasicAuth } from "../utils/basic-auth.ts";

export {
  checkRedirectUriPattern,
  isRedirectUriPattern,
  matchRedirectUri,
} from "./redirect-uri.ts";
export type {
  IsPublicSuffix,
  RedirectUriPatternRule,
  RedirectUriPatternViolation,
} from "./redirect-uri.ts";
