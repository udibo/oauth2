/**
 * Express adapter for the core {@link AuthorizationServer}.
 *
 * Provides Express handler factories for each OAuth2 endpoint and a
 * `routes()` middleware that serves all standard endpoints at conventional
 * paths. Also inherits resource-server-shaped helpers (`protect`,
 * `authenticate`, `getContext`) so the same instance can protect API routes.
 * The adapter depends on neither `express` nor its types, and works with
 * Express 4 and 5.
 *
 * The endpoint handlers read the raw request body themselves, so mount them
 * before any body-parsing middleware; a handler that finds the body already
 * consumed passes an error to `next` instead of guessing at it.
 *
 * @example
 * ```ts
 * import express from "express";
 * import {
 *   type ExpressAuthenticateUserFn,
 *   ExpressAuthorizationServer,
 * } from "@udibo/oauth2/express/authorization-server";
 * import type { AuthorizationServerOptions } from "@udibo/oauth2/server/authorization";
 * import type { BasicScope } from "@udibo/oauth2/server";
 *
 * interface Client { id: string }
 * interface User { id: string }
 * declare const options: AuthorizationServerOptions<Client, User, BasicScope>;
 * declare const authenticateUser: ExpressAuthenticateUserFn<User, express.Request>;
 *
 * const authServer = new ExpressAuthorizationServer<Client, User>(options);
 * const app = express();
 *
 * app.use("/oauth2", authServer.routes({ authenticateUser }));
 * app.use(express.json());
 * app.use("/api", authServer.protect());
 * app.get("/api/me", (_req, res) => {
 *   res.json(authServer.getContext(res).user);
 * });
 * ```
 *
 * @module
 */

import type { RequireConditions } from "../../models/authorization.ts";
import type {
  AuthenticationContext,
  AuthenticationRequest,
} from "../../models/authentication.ts";
import type { ClientInterface } from "../../models/client.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import {
  AuthorizationServer,
  type AuthorizationServerOptions,
  ENDPOINT_METHODS,
  ENDPOINT_PATHS,
} from "../../server/authorization-server.ts";
import type { AuthenticatedContext } from "../../server/resource-server.ts";

import {
  authenticateExpressRequest,
  createProtectMiddleware,
  createRequireMiddleware,
  createRequireScopeMiddleware,
  type ExpressMiddleware,
  type ExpressRequestLike,
  type ExpressResponseLike,
  fetchHandler,
  readContext,
} from "./_common.ts";

export type {
  ExpressMiddleware,
  ExpressNextFunction,
  ExpressRequestLike,
  ExpressResponseLike,
} from "./_common.ts";

/**
 * Authenticates the resource owner during an authorization request.
 *
 * Receives the Express request and response, so the callback can read the
 * app's own session (`req.session` under `express-session`). Return one of:
 *
 * - `{ user, authorizedScope?, authenticationContext?, reauthenticated? }` —
 *   user is authenticated; the authorize flow continues. Supply only verified
 *   event claims in `authenticationContext`. Set `reauthenticated: true` only
 *   when the user actively authenticated in response to this request.
 * - `null` — explicit denial; the framework redirects to `redirect_uri` with
 *   `error=access_denied`.
 * - A web `Response` — typically a 302 to your login page,
 *   `new Response(null, { status: 302, headers: { location } })` — which
 *   short-circuits the flow and is written to the browser as-is. Under
 *   `prompt=none` the server answers `login_required` instead.
 *
 * Do not write to `res` yourself; the adapter writes the response.
 */
export type ExpressAuthenticateUserFn<
  User,
  Req extends ExpressRequestLike = ExpressRequestLike,
  Res extends ExpressResponseLike = ExpressResponseLike,
> = (
  req: Req,
  res: Res,
  authentication?: AuthenticationRequest,
) => Promise<
  | {
      user: User;
      authorizedScope?: AbstractScope;
      authenticationContext?: AuthenticationContext;
      reauthenticated?: boolean;
    }
  | Response
  | null
>;

/**
 * Collects consent from the resource owner for the requested scope. Return
 * `{ approved: true, scope? }`, `{ approved: false }` (redirects with
 * `error=access_denied`), or a web `Response` rendering your consent page.
 * `scope`, when set, replaces the granted scope and is not checked against
 * the request, so return a subset. Do not write to `res` yourself.
 */
export type ExpressHandleConsentFn<
  Client extends ClientInterface,
  S extends AbstractScope,
  Req extends ExpressRequestLike = ExpressRequestLike,
  Res extends ExpressResponseLike = ExpressResponseLike,
> = (
  req: Req,
  res: Res,
  client: Client,
  requestedScope: S | undefined,
  user: unknown,
  authentication?: AuthenticationRequest,
) => Promise<{ approved: boolean; scope?: S } | Response>;

/** Options for {@link ExpressAuthorizationServer.routes}. */
export interface ExpressRoutesOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
  Req extends ExpressRequestLike = ExpressRequestLike,
  Res extends ExpressResponseLike = ExpressResponseLike,
> {
  /** Authenticates the resource owner at the authorize endpoint. */
  authenticateUser: ExpressAuthenticateUserFn<User, Req, Res>;
  /** Collects consent for the requested scope. Omit to auto-consent. */
  handleConsent?: ExpressHandleConsentFn<Client, S, Req, Res>;
}

/** Options for {@link ExpressAuthorizationServer.authorizeHandler}. */
export type ExpressAuthorizeHandlerOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
  Req extends ExpressRequestLike = ExpressRequestLike,
  Res extends ExpressResponseLike = ExpressResponseLike,
> = ExpressRoutesOptions<Client, User, S, Req, Res>;

/**
 * Express-specific wrapper around {@link AuthorizationServer}. Adds endpoint
 * handler factories and the resource-server-shaped helpers (`protect`,
 * `requireScope`, `require`, `authenticate`, `getContext`) against this same
 * instance.
 */
export class ExpressAuthorizationServer<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> extends AuthorizationServer<Client, User, S> {
  /** Forwards `options` to the core {@linkcode AuthorizationServer}. */
  constructor(options: AuthorizationServerOptions<Client, User, S>) {
    super(options);
  }

  /**
   * Returns an Express middleware that validates the bearer token against
   * this server's token service and stores the authenticated context on
   * `res.locals`. See {@link ExpressResourceServer.protect}.
   */
  protect(requiredScope?: S | string): ExpressMiddleware {
    return createProtectMiddleware(this, requiredScope);
  }

  /**
   * Returns an Express middleware that asserts an **already-authenticated**
   * request carries `requiredScope` without re-validating the token. See
   * {@link ExpressResourceServer.requireScope}.
   */
  requireScope(requiredScope: S | string): ExpressMiddleware {
    return createRequireScopeMiddleware(
      this,
      "ExpressAuthorizationServer",
      requiredScope,
    );
  }

  /**
   * Middleware asserting the already-authenticated request satisfies every
   * condition (scope, permission, role, organization). See
   * {@link ExpressResourceServer.require}.
   */
  require(conditions: RequireConditions): ExpressMiddleware {
    return createRequireMiddleware(
      this,
      "ExpressAuthorizationServer",
      conditions,
    );
  }

  /**
   * Authenticates an Express request or a raw {@link Request} inline. Throws
   * on failure — pair with {@link AuthorizationServer.handleAuthError} to
   * convert to a response.
   */
  override authenticate(
    req: ExpressRequestLike | Request,
    requiredScope?: S | string,
  ): Promise<AuthenticatedContext<Client, User, S>> {
    return authenticateExpressRequest(this, req, requiredScope);
  }

  /**
   * Typed accessor for the authenticated OAuth2 context {@link protect}
   * stored on `res.locals`.
   *
   * @throws {Error} If `protect` did not run first for this request.
   */
  getContext(res: ExpressResponseLike): AuthenticatedContext<Client, User, S> {
    return readContext<Client, User, S>(res, "ExpressAuthorizationServer");
  }

  /**
   * Handler for the token endpoint (RFC 6749 Section 3.2).
   * Mount at `POST /token`, before any body parser.
   */
  tokenHandler(): ExpressMiddleware {
    return fetchHandler((request) => this.handleTokenRequest(request));
  }

  /**
   * Handler for the authorization endpoint (RFC 6749 Section 3.1).
   * Mount at `GET /authorize`. Callbacks receive the Express request and
   * response; annotate their `req` parameter to type it as your app's
   * request.
   */
  authorizeHandler<
    Req extends ExpressRequestLike = ExpressRequestLike,
    Res extends ExpressResponseLike = ExpressResponseLike,
  >(
    options: ExpressAuthorizeHandlerOptions<Client, User, S, Req, Res>,
  ): ExpressMiddleware<Req, Res> {
    const { authenticateUser, handleConsent } = options;
    return fetchHandler<Req, Res>((request, req, res) =>
      this.handleAuthorizeRequest(
        request,
        (_request, authentication) =>
          authenticateUser(req, res, authentication),
        handleConsent
          ? (client, requestedScope, user, authentication) =>
              handleConsent(
                req,
                res,
                client,
                requestedScope,
                user,
                authentication,
              )
          : undefined,
      ),
    );
  }

  /**
   * Handler for the token revocation endpoint (RFC 7009).
   * Mount at `POST /revoke`, before any body parser.
   */
  revocationHandler(): ExpressMiddleware {
    return fetchHandler((request) => this.handleRevocationRequest(request));
  }

  /**
   * Handler for the token introspection endpoint (RFC 7662).
   * Mount at `POST /introspect`, before any body parser.
   */
  introspectionHandler(): ExpressMiddleware {
    return fetchHandler((request) => this.handleIntrospectionRequest(request));
  }

  /**
   * Handler for the authorization server metadata endpoint (RFC 8414).
   * Mount at `GET /.well-known/oauth-authorization-server`.
   */
  metadataHandler(): ExpressMiddleware {
    return fetchHandler((request) => this.handleMetadataRequest(request));
  }

  /**
   * Handler for the OIDC discovery endpoint.
   * Mount at `GET /.well-known/openid-configuration`. 404s when OIDC issuance
   * is not configured.
   */
  oidcMetadataHandler(): ExpressMiddleware {
    return fetchHandler((request) => this.handleOidcMetadataRequest(request));
  }

  /**
   * Handler for the JWKS endpoint (OIDC Discovery).
   * Mount at `GET /jwks`. 404s when OIDC issuance is not configured.
   */
  jwksHandler(): ExpressMiddleware {
    return fetchHandler((request) => this.handleJwksRequest(request));
  }

  /**
   * Handler for the OIDC UserInfo endpoint.
   * Mount at `GET`/`POST /userinfo`, before any body parser.
   */
  userInfoHandler(): ExpressMiddleware {
    return fetchHandler((request) => this.handleUserInfoRequest(request));
  }

  /**
   * Handler for the OIDC RP-Initiated Logout end-session endpoint.
   * Mount at `GET|POST /end_session`, before any body parser. Answers 404
   * unless the server was constructed with an `endSession` callback.
   */
  endSessionHandler(): ExpressMiddleware {
    return fetchHandler((request) => this.handleEndSessionRequest(request));
  }

  /**
   * Handler for the device authorization endpoint (RFC 8628).
   * Mount at `POST /device_authorization`, before any body parser.
   */
  deviceAuthorizationHandler(): ExpressMiddleware {
    return fetchHandler((request) =>
      this.handleDeviceAuthorizationRequest(request),
    );
  }

  /**
   * Returns one Express middleware serving all standard OAuth2 endpoints at
   * conventional paths, relative to wherever it is mounted:
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
   * - `GET`/`POST /end_session` (live when the server has an `endSession`
   *   callback)
   *
   * Mount with `app.use("/oauth2", server.routes({...}))`, before any body
   * parser. Any other path or verb falls through to `next()`. Every path and
   * verb comes from {@link ENDPOINT_PATHS}/{@link ENDPOINT_METHODS}; a `GET`
   * endpoint answers `HEAD` too, as an Express `get` route does. The
   * advertised URLs match the mount only when the issuer (or each explicit
   * `*Endpoint` in the resolved context) points at where you mounted it.
   */
  routes<
    Req extends ExpressRequestLike = ExpressRequestLike,
    Res extends ExpressResponseLike = ExpressResponseLike,
  >(
    options: ExpressRoutesOptions<Client, User, S, Req, Res>,
  ): ExpressMiddleware<Req, Res> {
    const handlers: Record<
      keyof typeof ENDPOINT_PATHS,
      ExpressMiddleware<Req, Res>
    > = {
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
    const table = new Map<string, ExpressMiddleware<Req, Res>>();
    for (const [key, handler] of Object.entries(handlers)) {
      const endpoint = key as keyof typeof ENDPOINT_PATHS;
      for (const method of ENDPOINT_METHODS[endpoint]) {
        table.set(`${method} ${ENDPOINT_PATHS[endpoint]}`, handler);
        if (method === "GET") {
          table.set(`HEAD ${ENDPOINT_PATHS[endpoint]}`, handler);
        }
      }
    }
    return (req, res, next) => {
      const path = (req.url ?? "/").split("?", 1)[0] || "/";
      const handler = table.get(`${req.method} ${path}`);
      if (handler) handler(req, res, next);
      else next();
    };
  }
}
