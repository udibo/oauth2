/**
 * Internal helpers shared by the Express adapters.
 *
 * Not part of the public API — use {@link ExpressResourceServer} or
 * {@link ExpressAuthorizationServer} instead. The structural request,
 * response and middleware types are re-exported publicly.
 *
 * @module
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";

import type { RequireConditions } from "../../models/authorization.ts";
import type { ClientInterface } from "../../models/client.ts";
import type { AbstractScope } from "../../models/scope.ts";
import type { AuthenticatedContext } from "../../server/resource-server.ts";
import { ResourceServer } from "../../server/resource-server.ts";

/**
 * Key under which the authenticated OAuth2 context is stored on
 * `res.locals`. Namespaced to avoid collisions with other middleware.
 */
export const OAUTH2_CONTEXT_KEY = "@udibo/oauth2" as const;

/**
 * The parts of an Express request the adapters read. An Express 4 or 5
 * `Request` satisfies it, so handlers accept either without a dependency on
 * `express` or its types.
 */
export interface ExpressRequestLike extends IncomingMessage {
  /** The URL as received, before any mount path was stripped. */
  originalUrl?: string;
  /** `http` or `https`, honoring Express's `trust proxy` setting. */
  protocol?: string;
  /** Whatever a body parser that already ran left behind. */
  body?: unknown;
}

/** The parts of an Express response the adapters write. */
export interface ExpressResponseLike extends ServerResponse {
  /** Express's per-request locals, where `protect` stores its context. */
  locals: Record<string, unknown>;
}

/** Express's `next`: call with no argument to continue, or with an error. */
export type ExpressNextFunction = (error?: unknown) => void;

/** A middleware or route handler Express can mount. */
export type ExpressMiddleware<
  Req extends ExpressRequestLike = ExpressRequestLike,
  Res extends ExpressResponseLike = ExpressResponseLike,
> = (req: Req, res: Res, next: ExpressNextFunction) => void;

/**
 * How {@link toFetchRequest} supplies the body: `stream` hands the core the
 * unread request stream, and refuses one a body parser already consumed;
 * `parsed` never drains the stream, re-encoding a form body a parser left on
 * `req.body` so a form-encoded bearer token still reaches the core.
 */
export type BodySource = "stream" | "parsed";

const BODYLESS_METHODS = new Set(["GET", "HEAD"]);
const FORM_TYPE = "application/x-www-form-urlencoded";

/**
 * Builds the web {@link Request} the core servers read from an Express
 * request: the full original URL, every header as received, and the body as
 * `source` says.
 *
 * @throws {Error} With `stream`, when a body parser already read the body.
 */
export function toFetchRequest(
  req: ExpressRequestLike,
  source: BodySource,
): Request {
  const method = req.method ?? "GET";
  const headers = new Headers();
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const name = req.rawHeaders[i];
    if (!name.startsWith(":")) headers.append(name, req.rawHeaders[i + 1]);
  }
  const url = new URL(
    req.originalUrl ?? req.url ?? "/",
    `${req.protocol ?? "http"}://${req.headers.host ?? "localhost"}`,
  );
  if (BODYLESS_METHODS.has(method)) {
    return new Request(url, { method, headers });
  }
  if (source === "stream") {
    if (req.readableEnded) {
      throw new Error(
        "The request body was already read, likely by a body parser. Mount " +
          "the @udibo/oauth2 Express handlers before any body-parsing " +
          "middleware.",
      );
    }
    const init: RequestInit & { duplex: "half" } = {
      method,
      headers,
      body: Readable.toWeb(req) as ReadableStream<Uint8Array>,
      duplex: "half",
    };
    return new Request(url, init);
  }
  headers.delete("content-length");
  headers.delete("transfer-encoding");
  return new Request(url, { method, headers, body: parsedFormBody(req) });
}

function parsedFormBody(req: ExpressRequestLike): string | null {
  if (!req.readableEnded) return null;
  if (!req.headers["content-type"]?.includes(FORM_TYPE)) return null;
  const { body } = req;
  if (typeof body === "string") return body;
  if (Buffer.isBuffer(body)) return body.toString("utf8");
  if (body === null || typeof body !== "object") return null;
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(body)) {
    for (const item of Array.isArray(value) ? value : [value]) {
      if (typeof item === "string") params.append(name, item);
    }
  }
  return params.toString();
}

/**
 * Writes a core {@link Response} to `res`, keeping headers earlier
 * middleware set — `Set-Cookie` values are added to theirs, not replaced.
 */
export async function sendFetchResponse(
  res: ServerResponse,
  response: Response,
): Promise<void> {
  res.statusCode = response.status;
  for (const [name, value] of response.headers) {
    if (name !== "set-cookie") res.setHeader(name, value);
  }
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) {
    const existing = res.getHeader("set-cookie");
    const earlier =
      existing === undefined
        ? []
        : Array.isArray(existing)
          ? existing
          : [String(existing)];
    res.setHeader("set-cookie", [...earlier, ...cookies]);
  }
  const body = response.body
    ? Buffer.from(await response.arrayBuffer())
    : undefined;
  res.end(body);
}

/**
 * Wraps a core handler as Express middleware that writes its response, and
 * passes anything it throws to `next` (Express 4 does not catch a rejected
 * handler on its own).
 */
export function fetchHandler<
  Req extends ExpressRequestLike,
  Res extends ExpressResponseLike,
>(
  handle: (request: Request, req: Req, res: Res) => Promise<Response>,
): ExpressMiddleware<Req, Res> {
  return (req, res, next) => {
    Promise.resolve()
      .then(() => handle(toFetchRequest(req, "stream"), req, res))
      .then((response) => sendFetchResponse(res, response))
      .catch(next);
  };
}

/**
 * Builds an Express middleware that authenticates bearer tokens, stores the
 * authenticated context at `res.locals[OAUTH2_CONTEXT_KEY]`, and on failure
 * writes the server's auth error response.
 */
export function createProtectMiddleware<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  server: ResourceServer<Client, User, S>,
  requiredScope?: S | string,
): ExpressMiddleware {
  return (req, res, next) => {
    Promise.resolve()
      .then(() =>
        baseAuthenticate(server, toFetchRequest(req, "parsed"), requiredScope),
      )
      .then(
        (context) => {
          res.locals[OAUTH2_CONTEXT_KEY] = context;
          next();
        },
        (error: unknown) =>
          sendFetchResponse(res, server.handleAuthError(error)),
      )
      .catch(next);
  };
}

/**
 * Builds an Express middleware that asserts the **already-authenticated**
 * request carries `requiredScope`, without re-validating the token.
 * `adapterName` names the class in the "context missing" developer error.
 */
export function createRequireScopeMiddleware<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  server: ResourceServer<Client, User, S>,
  adapterName: string,
  requiredScope: S | string,
): ExpressMiddleware {
  return assertingMiddleware(server, adapterName, ({ scope }) =>
    server.assertScope(scope, requiredScope),
  );
}

/**
 * Builds an Express middleware that asserts the **already-authenticated**
 * request satisfies `conditions`, without re-validating the token.
 */
export function createRequireMiddleware<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  server: ResourceServer<Client, User, S>,
  adapterName: string,
  conditions: RequireConditions,
): ExpressMiddleware {
  return assertingMiddleware(server, adapterName, (context) =>
    server.assertAuthorized(context, conditions),
  );
}

function assertingMiddleware<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  server: ResourceServer<Client, User, S>,
  adapterName: string,
  assert: (context: AuthenticatedContext<Client, User, S>) => void,
): ExpressMiddleware {
  return (_req, res, next) => {
    let context: AuthenticatedContext<Client, User, S>;
    try {
      context = readContext<Client, User, S>(res, adapterName);
    } catch (error) {
      next(error);
      return;
    }
    try {
      assert(context);
    } catch (error) {
      Promise.resolve()
        .then(() => sendFetchResponse(res, server.handleAuthError(error)))
        .catch(next);
      return;
    }
    next();
  };
}

/**
 * Authenticates an Express request or a raw {@link Request} with the base
 * {@link ResourceServer.authenticate}, bypassing the adapters' override.
 */
export function authenticateExpressRequest<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  server: ResourceServer<Client, User, S>,
  req: ExpressRequestLike | Request,
  requiredScope?: S | string,
): Promise<AuthenticatedContext<Client, User, S>> {
  const request = req instanceof Request ? req : toFetchRequest(req, "parsed");
  return baseAuthenticate(server, request, requiredScope);
}

// Base method on purpose: the Express subclasses' override would recurse.
function baseAuthenticate<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  server: ResourceServer<Client, User, S>,
  request: Request,
  requiredScope?: S | string,
): Promise<AuthenticatedContext<Client, User, S>> {
  // oxlint-disable-next-line typescript/no-explicit-any
  const base: any = ResourceServer.prototype;
  return base.authenticate.call(server, request, requiredScope);
}

/**
 * Reads the authenticated OAuth2 context off `res.locals`.
 *
 * @throws {Error} If no `protect` middleware set it first; the message names
 * `adapterName`.
 */
export function readContext<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
>(
  res: ExpressResponseLike,
  adapterName: string,
): AuthenticatedContext<Client, User, S> {
  const context = res.locals[OAUTH2_CONTEXT_KEY] as
    | AuthenticatedContext<Client, User, S>
    | undefined;
  if (!context) {
    throw new Error(
      `OAuth2 context missing; ensure ${adapterName}.protect() middleware ` +
        `runs before this handler.`,
    );
  }
  return context;
}
