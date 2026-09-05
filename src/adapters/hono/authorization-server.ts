/**
 * Hono adapter for the core {@link AuthorizationServer}.
 *
 * Provides Hono handler factories for each OAuth2 endpoint and a convenience
 * `routes()` aggregator that mounts all standard endpoints at conventional
 * paths. Also inherits resource-server-shaped helpers (`protect`,
 * `authenticate`, `getContext`) so the same instance can protect API routes.
 *
 * @example
 * ```ts
 * import { Hono } from "hono";
 * import { HonoAuthorizationServer } from "@udibo/oauth2/hono/authorization-server";
 *
 * const issuer = "https://auth.example.com";
 * const authServer = new HonoAuthorizationServer({
 *   grants: { ...grants },
 *   resolve: () => ({
 *     services: { clientService, tokenService, authorizationCodeService },
 *     issuer,
 *     authorizationEndpoint: `${issuer}/oauth2/authorize`,
 *     tokenEndpoint: `${issuer}/oauth2/token`,
 *     revocationEndpoint: `${issuer}/oauth2/revoke`,
 *     introspectionEndpoint: `${issuer}/oauth2/introspect`,
 *   }),
 * });
 *
 * const app = new Hono();
 * app.route("/oauth2", authServer.routes({ authenticateUser }));
 * app.use("/api/*", authServer.protect());
 * app.get("/api/me", (c) => c.json(authServer.getContext(c).user));
 * ```
 *
 * @module
 */

import { Hono } from "hono";
import type { Context, Handler, MiddlewareHandler } from "hono";

import type { RequireConditions } from "../../models/authorization.ts";
import type { ClientInterface } from "../../models/client.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import {
  type AuthenticateUserFn,
  AuthorizationServer,
  type AuthorizationServerOptions,
  ENDPOINT_METHODS,
  ENDPOINT_PATHS,
  type HandleConsentFn,
} from "../../server/authorization-server.ts";
import type { AuthenticatedContext } from "../../server/resource-server.ts";

import {
  authenticateHonoRequest,
  createProtectMiddleware,
  createRequireMiddleware,
  createRequireScopeMiddleware,
  readContext,
} from "./_common.ts";

/**
 * Authenticates the resource owner during an authorization request.
 *
 * Receives the Hono {@link Context} directly so the callback can read cookies
 * or session variables without reconstructing a {@link Request}. Return one
 * of:
 *
 * - `{ user, authorizedScope? }` — user is authenticated; the authorize flow
 *   continues.
 * - `null` — explicit denial; the framework redirects to `redirect_uri` with
 *   `error=access_denied`.
 * - A `Response` (typically `c.redirect(...)` to a login page) —
 *   short-circuits the authorize flow and is returned to the browser as-is.
 *   This is how login redirects, interstitials, etc. are wired without
 *   wrapping the framework handler.
 */
export type HonoAuthenticateUserFn<User> = (
  c: Context,
) => Promise<
  { user: User; authorizedScope?: AbstractScope } | Response | null
>;

/**
 * Collects consent from the resource owner for the requested scope.
 *
 * Receives the Hono {@link Context} so the callback can render a consent
 * page, read form input, etc. Return one of:
 *
 * - `{ approved: true, scope? }` — consent granted (optionally narrowing the
 *   scope per RFC 6749 §3.3).
 * - `{ approved: false }` — consent denied; the framework redirects to
 *   `redirect_uri` with `error=access_denied`.
 * - A `Response` (typically `c.html(...)` rendering a consent page) —
 *   short-circuits the authorize flow and is returned to the browser as-is.
 *   The consent UI should resubmit to the authorize endpoint with a
 *   decision parameter the callback can read on the next request.
 */
export type HonoHandleConsentFn<
  Client extends ClientInterface,
  S extends AbstractScope,
> = (
  c: Context,
  client: Client,
  requestedScope: S | undefined,
  user: unknown,
) => Promise<{ approved: boolean; scope?: S } | Response>;

/** Options for {@link HonoAuthorizationServer.routes}. */
export interface HonoRoutesOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> {
  /** Authenticates the resource owner at the authorize endpoint. */
  authenticateUser: HonoAuthenticateUserFn<User>;
  /** Collects consent for the requested scope. Omit to auto-consent. */
  handleConsent?: HonoHandleConsentFn<Client, S>;
}

/** Options for {@link HonoAuthorizationServer.authorizeHandler}. */
export type HonoAuthorizeHandlerOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> = HonoRoutesOptions<Client, User, S>;

/**
 * Hono-specific wrapper around {@link AuthorizationServer}. Adds endpoint
 * handler factories and the three resource-server-shaped helpers
 * (`protect`, `authenticate`, `getContext`) against this same instance.
 *
 * Resource-server behavior (realm, errorFormat, throwOnError, token lookup)
 * reads directly off the auth-server instance, so mutating those fields
 * after construction propagates without the need to rewire any companion
 * objects.
 */
export class HonoAuthorizationServer<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> extends AuthorizationServer<Client, User, S> {
  /** Forwards `options` to the core {@linkcode AuthorizationServer}. */
  constructor(options: AuthorizationServerOptions<Client, User, S>) {
    super(options);
  }

  /**
   * Returns a Hono middleware that validates the bearer token against this
   * server's token service. On success, sets the authenticated context at
   * `c.get("@udibo/oauth2")`; on failure returns an RFC 6749 error response
   * with a `WWW-Authenticate` header per RFC 6750 Section 3.
   */
  protect(requiredScope?: S | string): MiddlewareHandler {
    return createProtectMiddleware(this, requiredScope);
  }

  /**
   * Returns a Hono middleware that asserts an **already-authenticated** request
   * carries `requiredScope` without re-validating the token — the per-route
   * companion to {@link protect} for mounts that need different scopes per
   * route. See {@link HonoResourceServer.requireScope}.
   */
  requireScope(requiredScope: S | string): MiddlewareHandler {
    return createRequireScopeMiddleware(
      this,
      "HonoAuthorizationServer",
      requiredScope,
    );
  }

  /**
   * Middleware asserting the already-authenticated request satisfies every
   * condition (scope, permission, role, organization) on this server's own
   * protected routes. See {@link HonoResourceServer.require}.
   */
  require(conditions: RequireConditions): MiddlewareHandler {
    return createRequireMiddleware(
      this,
      "HonoAuthorizationServer",
      conditions,
    );
  }

  /**
   * Authenticates a Hono {@link Context} or a raw {@link Request} manually.
   * Throws on failure — pair with
   * {@link AuthorizationServer.handleAuthError} to convert to a response.
   */
  override authenticate(
    c: Context | Request,
    requiredScope?: S | string,
  ): Promise<AuthenticatedContext<Client, User, S>> {
    return authenticateHonoRequest(this, c, requiredScope);
  }

  /** Typed accessor for the authenticated OAuth2 context. */
  getContext(c: Context): AuthenticatedContext<Client, User, S> {
    return readContext<Client, User, S>(c, "HonoAuthorizationServer");
  }

  /**
   * Handler for the token endpoint (RFC 6749 Section 3.2).
   * Mount at `POST /token`.
   */
  tokenHandler(): Handler {
    return (c) => this.handleTokenRequest(c.req.raw);
  }

  /**
   * Handler for the authorization endpoint (RFC 6749 Section 3.1).
   * Mount at `GET /authorize`. Callbacks receive the Hono {@link Context}.
   */
  authorizeHandler(
    options: HonoAuthorizeHandlerOptions<Client, User, S>,
  ): Handler {
    const { authenticateUser, handleConsent } = options;
    return (c) => {
      const auth: AuthenticateUserFn<User> = () => authenticateUser(c);
      const consent: HandleConsentFn<Client, S> | undefined = handleConsent
        ? (client, requestedScope, user) =>
          handleConsent(c, client, requestedScope, user)
        : undefined;
      return this.handleAuthorizeRequest(c.req.raw, auth, consent);
    };
  }

  /**
   * Handler for the token revocation endpoint (RFC 7009).
   * Mount at `POST /revoke`.
   */
  revocationHandler(): Handler {
    return (c) => this.handleRevocationRequest(c.req.raw);
  }

  /**
   * Handler for the token introspection endpoint (RFC 7662).
   * Mount at `POST /introspect`.
   */
  introspectionHandler(): Handler {
    return (c) => this.handleIntrospectionRequest(c.req.raw);
  }

  /**
   * Handler for the authorization server metadata endpoint (RFC 8414).
   * Mount at `GET /.well-known/oauth-authorization-server`.
   */
  metadataHandler(): Handler {
    return (c) => this.handleMetadataRequest(c.req.raw);
  }

  /**
   * Handler for the OIDC discovery endpoint.
   * Mount at `GET /.well-known/openid-configuration`. 404s when OIDC issuance
   * is not configured.
   */
  oidcMetadataHandler(): Handler {
    return (c) => this.handleOidcMetadataRequest(c.req.raw);
  }

  /**
   * Handler for the JWKS endpoint (OIDC Discovery).
   * Mount at `GET /jwks`. 404s when OIDC issuance is not configured.
   */
  jwksHandler(): Handler {
    return (c) => this.handleJwksRequest(c.req.raw);
  }

  /**
   * Handler for the OIDC UserInfo endpoint.
   * Mount at `GET`/`POST /userinfo`.
   */
  userInfoHandler(): Handler {
    return (c) => this.handleUserInfoRequest(c.req.raw);
  }

  /**
   * Handler for the OIDC RP-Initiated Logout end-session endpoint.
   * Mount at `GET|POST /end_session`. Answers 404 unless the server was
   * constructed with an `endSession` callback.
   */
  endSessionHandler(): Handler {
    return (c) => this.handleEndSessionRequest(c.req.raw);
  }

  /**
   * Handler for the device authorization endpoint (RFC 8628).
   * Mount at `POST /device_authorization`.
   */
  deviceAuthorizationHandler(): Handler {
    return (c) => this.handleDeviceAuthorizationRequest(c.req.raw);
  }

  /**
   * Returns a Hono app with all standard OAuth2 endpoints mounted at
   * conventional paths, relative to whatever base path the caller mounts it
   * under.
   *
   * - `POST /token`
   * - `GET /authorize`
   * - `POST /revoke`
   * - `POST /introspect`
   * - `POST /device_authorization`
   * - `GET /.well-known/oauth-authorization-server`
   * - `GET /.well-known/openid-configuration`
   * - `GET /jwks` and `GET`/`POST /userinfo` (live when OIDC issuance is
   *   configured via `signingKeys`)
   *
   * Mount with `app.route("/oauth2", server.routes({...}))`.
   *
   * Every path and verb above comes from
   * {@link ENDPOINT_PATHS}/{@link ENDPOINT_METHODS}, so the mounted surface and
   * the URLs the server advertises can never drift apart. Users who want custom
   * paths or only a subset of endpoints should mount the individual handler
   * factories instead.
   */
  routes(options: HonoRoutesOptions<Client, User, S>): Hono {
    const handlers: Record<keyof typeof ENDPOINT_PATHS, Handler> = {
      authorization: this.authorizeHandler(options),
      token: this.tokenHandler(),
      revocation: this.revocationHandler(),
      introspection: this.introspectionHandler(),
      deviceAuthorization: this.deviceAuthorizationHandler(),
      jwks: this.jwksHandler(),
      userinfo: this.userInfoHandler(),
      endSession: this.endSessionHandler(),
      metadata: this.metadataHandler(),
      oidcMetadata: this.oidcMetadataHandler(),
    };
    const app = new Hono();
    for (const [key, handler] of Object.entries(handlers)) {
      const endpoint = key as keyof typeof ENDPOINT_PATHS;
      app.on(
        [...ENDPOINT_METHODS[endpoint]],
        ENDPOINT_PATHS[endpoint],
        handler,
      );
    }
    return app;
  }
}
