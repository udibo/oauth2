/**
 * Hono adapter for the core {@link ResourceServer}.
 *
 * Provides middleware and accessors that let a Hono app authenticate
 * requests against an OAuth2 authorization server. The core server
 * implementation is framework-agnostic; this adapter is the only place that
 * knows about `Context` and middleware wiring.
 *
 * @example
 * ```ts
 * import { Hono } from "hono";
 * import {
 *   HonoResourceServer,
 *   type HonoResourceServerVariables,
 * } from "@udibo/oauth2/hono/resource-server";
 *
 * const resourceServer = new HonoResourceServer({
 *   resolve: () => ({ services: { tokenService } }),
 * });
 * const app = new Hono<{
 *   Variables: HonoResourceServerVariables<Client, User>;
 * }>();
 *
 * app.use("/api/*", resourceServer.protect());
 * app.get("/api/me", (c) => c.json(resourceServer.getContext(c).user));
 * ```
 *
 * @module
 */

import type { Context, MiddlewareHandler } from "hono";

import type { ClientInterface } from "../../models/client.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import {
  type AuthenticatedContext,
  ResourceServer,
} from "../../server/resource-server.ts";

import type { RequireConditions } from "../../models/authorization.ts";
import {
  authenticateHonoRequest,
  createProtectMiddleware,
  createRequireMiddleware,
  createRequireScopeMiddleware,
  readContext,
} from "./_common.ts";

export {
  type HonoResourceServerVariables,
  OAUTH2_CONTEXT_KEY,
} from "./_common.ts";

/**
 * Hono-specific wrapper around {@link ResourceServer}. Construction options
 * are identical to the core server; the subclass only adds Hono middleware
 * helpers.
 */
export class HonoResourceServer<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> extends ResourceServer<Client, User, S> {
  /**
   * Returns a Hono middleware that validates the bearer token.
   *
   * On success, sets the authenticated context at `c.get("@udibo/oauth2")`
   * (typed via {@link HonoResourceServerVariables}) and calls `next()`. On
   * failure, returns an RFC 6749 error response with a `WWW-Authenticate`
   * header per RFC 6750 Section 3.
   */
  protect(requiredScope?: S | string): MiddlewareHandler {
    return createProtectMiddleware(this, requiredScope);
  }

  /**
   * Returns a Hono middleware that asserts the **already-authenticated**
   * request carries `requiredScope`, **without** re-validating the token.
   *
   * Mount it downstream of {@link protect} (or a BFF `protect`, which sets the
   * same context) when one authenticated mount exposes routes needing
   * different scopes — e.g. `read` on GETs, `write` on mutations — that a
   * single `protect(scope)` can't express. It reads the context `protect`
   * already populated and checks the scope in memory, so unlike a second
   * `protect(scope)` it performs no token lookup. On insufficient scope it
   * returns the same RFC 6750 `insufficient_scope` response (403 with a
   * `WWW-Authenticate` header) as `protect`.
   *
   * @example
   * ```ts
   * app.use("/api/*", resourceServer.protect()); // authenticate once
   * app.get("/api/items", resourceServer.requireScope("read"), list);
   * app.post("/api/items", resourceServer.requireScope("write"), create);
   * ```
   */
  requireScope(requiredScope: S | string): MiddlewareHandler {
    return createRequireScopeMiddleware(
      this,
      "HonoResourceServer",
      requiredScope,
    );
  }

  /**
   * Middleware asserting the already-authenticated request satisfies every
   * condition — AND semantics across keys, arrays mean all-of (see
   * {@linkcode RequireConditions}). Scope failures answer the RFC 6750
   * `insufficient_scope` challenge exactly as {@linkcode requireScope} does;
   * permission, role, and organization failures answer a plain 403. Mount a
   * {@linkcode protect} first — this middleware does not validate the token.
   *
   * @example
   * ```ts
   * app.use("/api/*", resourceServer.protect());
   * app.post(
   *   "/api/posts",
   *   resourceServer.require({ scope: "posts:write", permission: "posts:write" }),
   *   create,
   * );
   * ```
   */
  require(conditions: RequireConditions): MiddlewareHandler {
    return createRequireMiddleware(this, "HonoResourceServer", conditions);
  }

  /**
   * Authenticates a Hono {@link Context} or a raw {@link Request} manually,
   * for handlers that want to authenticate inline instead of using
   * {@link protect} as middleware. Throws on failure — pair with
   * {@link ResourceServer.handleAuthError} to convert to a response.
   */
  override authenticate(
    c: Context | Request,
    requiredScope?: S | string,
  ): Promise<AuthenticatedContext<Client, User, S>> {
    return authenticateHonoRequest(this, c, requiredScope);
  }

  /** Typed accessor for the authenticated OAuth2 context. */
  getContext(c: Context): AuthenticatedContext<Client, User, S> {
    return readContext<Client, User, S>(c, "HonoResourceServer");
  }
}
