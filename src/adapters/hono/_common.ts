/**
 * Internal helpers shared by the Hono adapters.
 *
 * Not part of the public API — use {@link HonoResourceServer} or
 * {@link HonoAuthorizationServer} instead. Keeping the `protect` /
 * `authenticate` / `getContext` implementations in one place lets both
 * adapter classes stay as direct subclasses of the server type they
 * specialize (no composition / companion objects) without duplicating the
 * Hono-specific plumbing.
 *
 * @module
 */

import type { Context, MiddlewareHandler } from "hono";

import type { ClientInterface } from "../../models/client.ts";
import type { RequireConditions } from "../../models/authorization.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import type { AuthenticatedContext } from "../../server/resource-server.ts";
import { ResourceServer } from "../../server/resource-server.ts";

/**
 * Key under which the authenticated OAuth2 context is stored on the Hono
 * context. Namespaced to avoid collisions with other middleware.
 */
export const OAUTH2_CONTEXT_KEY = "@udibo/oauth2" as const;

/**
 * Variables shape to plug into `Hono<{ Variables: ... }>` so
 * `c.get("@udibo/oauth2")` / `server.getContext(c)` is typed.
 */
export interface HonoResourceServerVariables<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> {
  /** The authenticated OAuth2 context set by the protect middleware. */
  [OAUTH2_CONTEXT_KEY]: AuthenticatedContext<Client, User, S>;
}

/**
 * Builds a Hono middleware that authenticates bearer tokens, stores the
 * authenticated context at {@link OAUTH2_CONTEXT_KEY}, and on failure returns
 * the server's auth error response.
 */
export function createProtectMiddleware<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  server: ResourceServer<Client, User, S>,
  requiredScope?: S | string,
): MiddlewareHandler {
  return async (c, next) => {
    try {
      const ctx = await baseAuthenticate(server, c.req.raw, requiredScope);
      c.set(OAUTH2_CONTEXT_KEY, ctx);
      await next();
    } catch (error) {
      return server.handleAuthError(error);
    }
  };
}

/**
 * Builds a Hono middleware that asserts the **already-authenticated** request
 * (whose context a prior `protect` / `attachToken` set) carries
 * `requiredScope`, without re-validating the token. Shared by both adapter
 * classes' `requireScope` so the check and error stay identical to `protect`'s
 * scope enforcement. `adapterName` names the class in the "context missing"
 * developer error.
 */
export function createRequireScopeMiddleware<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  server: ResourceServer<Client, User, S>,
  adapterName: string,
  requiredScope: S | string,
): MiddlewareHandler {
  return async (c, next) => {
    const { scope } = readContext<Client, User, S>(c, adapterName);
    try {
      server.assertScope(scope, requiredScope);
    } catch (error) {
      return server.handleAuthError(error);
    }
    await next();
  };
}

/**
 * Builds a Hono middleware that asserts the **already-authenticated** request
 * (whose context a prior `protect` set) satisfies `conditions`, without
 * re-validating the token. Shared by both adapter classes' `require` so the
 * checks and errors stay identical to {@link ResourceServer.assertAuthorized}.
 */
export function createRequireMiddleware<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  server: ResourceServer<Client, User, S>,
  adapterName: string,
  conditions: RequireConditions,
): MiddlewareHandler {
  return async (c, next) => {
    const context = readContext<Client, User, S>(c, adapterName);
    try {
      server.assertAuthorized(context, conditions);
    } catch (error) {
      return server.handleAuthError(error);
    }
    await next();
  };
}

/**
 * Resolves a Hono {@link Context} or raw {@link Request} to a Request and
 * calls the base {@link ResourceServer.authenticate} (bypassing any
 * Context-accepting override). This is what both adapter classes'
 * `authenticate` overrides end up calling.
 */
export function authenticateHonoRequest<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  server: ResourceServer<Client, User, S>,
  c: Context | Request,
  requiredScope?: S | string,
): Promise<AuthenticatedContext<Client, User, S>> {
  const request = c instanceof Request ? c : c.req.raw;
  return baseAuthenticate(server, request, requiredScope);
}

/**
 * Invokes the base {@link ResourceServer.authenticate} directly, bypassing
 * any subclass override. Necessary because {@link HonoResourceServer}
 * overrides `authenticate` to accept `Context | Request`; if this module
 * called `server.authenticate(...)` the dispatch would land back on that
 * override and recurse forever.
 */
function baseAuthenticate<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  server: ResourceServer<Client, User, S>,
  request: Request,
  requiredScope?: S | string,
): Promise<AuthenticatedContext<Client, User, S>> {
  // deno-lint-ignore no-explicit-any
  const base: any = ResourceServer.prototype;
  return base.authenticate.call(server, request, requiredScope);
}

/**
 * Reads the authenticated OAuth2 context off the Hono context. Throws if
 * `createProtectMiddleware` has not run first — the error message names the
 * class the user invoked to make the fix obvious.
 */
export function readContext<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  c: Context,
  adapterName: string,
): AuthenticatedContext<Client, User, S> {
  const ctx = c.get(OAUTH2_CONTEXT_KEY) as
    | AuthenticatedContext<Client, User, S>
    | undefined;
  if (!ctx) {
    throw new Error(
      `OAuth2 context missing; ensure ${adapterName}.protect() middleware ` +
        `runs before this handler.`,
    );
  }
  return ctx;
}
