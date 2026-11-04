/**
 * Express adapter for the core {@link ResourceServer}.
 *
 * Provides middleware and accessors that let an Express 4 or 5 app
 * authenticate requests against an OAuth2 authorization server. The adapter
 * depends on neither `express` nor its types: its handlers are typed
 * structurally, so any Express request and response satisfy them.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { ExpressResourceServer } from "@udibo/oauth2/express/resource-server";
 * import type { TokenReaderInterface } from "@udibo/oauth2/server";
 *
 * interface Client { id: string }
 * interface User { id: string }
 * declare const tokenService: TokenReaderInterface<Client, User>;
 *
 * const resourceServer = new ExpressResourceServer<Client, User>({
 *   resolve: () => ({ services: { tokenService } }),
 * });
 * const app = express();
 *
 * app.use("/api", resourceServer.protect());
 * app.get("/api/me", (_req, res) => {
 *   res.json(resourceServer.getContext(res).user);
 * });
 * ```
 *
 * @module
 */

import type { RequireConditions } from "../../models/authorization.ts";
import type { ClientInterface } from "../../models/client.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import {
  type AuthenticatedContext,
  ResourceServer,
} from "../../server/resource-server.ts";

import {
  authenticateExpressRequest,
  createProtectMiddleware,
  createRequireMiddleware,
  createRequireScopeMiddleware,
  type ExpressMiddleware,
  type ExpressRequestLike,
  type ExpressResponseLike,
  readContext,
} from "./_common.ts";

export {
  type ExpressMiddleware,
  type ExpressNextFunction,
  type ExpressRequestLike,
  type ExpressResponseLike,
  OAUTH2_CONTEXT_KEY,
} from "./_common.ts";

/**
 * Express-specific wrapper around {@link ResourceServer}. Construction options
 * are identical to the core server; the subclass only adds Express middleware
 * helpers.
 *
 * `protect` reads the bearer token from the `Authorization` header. It never
 * reads the request stream, so routes behind it keep their body for later
 * middleware; a form-encoded `access_token` (RFC 6750 Section 2.2) is honored
 * only when a body parser has already parsed it onto `req.body`.
 */
export class ExpressResourceServer<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> extends ResourceServer<Client, User, S> {
  /**
   * Returns an Express middleware that validates the bearer token.
   *
   * On success, stores the authenticated context on `res.locals` (read it
   * with {@link getContext}) and calls `next()`. On failure, writes the error
   * response, with a `WWW-Authenticate` challenge (RFC 6750 Section 3) on a
   * 401 or 403, or passes the error to `next` when `throwOnError` is set.
   */
  protect(requiredScope?: S | string): ExpressMiddleware {
    return createProtectMiddleware(this, requiredScope);
  }

  /**
   * Returns an Express middleware that asserts the **already-authenticated**
   * request carries `requiredScope`, **without** re-validating the token.
   *
   * Mount it after {@link protect} when one authenticated mount exposes
   * routes needing different scopes. On insufficient scope it writes the same
   * RFC 6750 `insufficient_scope` response (403 with a `WWW-Authenticate`
   * header) as `protect`.
   *
   * @example
   * ```ts
   * import express from "express";
   * import { ExpressResourceServer } from "@udibo/oauth2/express/resource-server";
   *
   * declare const resourceServer: ExpressResourceServer<{ id: string }, { id: string }>;
   * declare const list: express.RequestHandler;
   * declare const create: express.RequestHandler;
   * const app = express();
   *
   * app.use("/api", resourceServer.protect());
   * app.get("/api/items", resourceServer.requireScope("read"), list);
   * app.post("/api/items", resourceServer.requireScope("write"), create);
   * ```
   */
  requireScope(requiredScope: S | string): ExpressMiddleware {
    return createRequireScopeMiddleware(
      this,
      "ExpressResourceServer",
      requiredScope,
    );
  }

  /**
   * Middleware asserting the already-authenticated request satisfies every
   * condition — AND semantics across keys, arrays mean all-of (see
   * {@linkcode RequireConditions}). Scope failures answer the RFC 6750
   * `insufficient_scope` challenge exactly as {@linkcode requireScope} does;
   * permission, role, and organization failures answer a plain 403. Mount
   * {@linkcode protect} first — this middleware does not validate the token.
   */
  require(conditions: RequireConditions): ExpressMiddleware {
    return createRequireMiddleware(this, "ExpressResourceServer", conditions);
  }

  /**
   * Authenticates an Express request or a raw {@link Request} inline, for
   * handlers that do not use {@link protect}. Throws on failure — pair with
   * {@link ResourceServer.handleAuthError} to convert to a response.
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
    return readContext<Client, User, S>(res, "ExpressResourceServer");
  }
}
