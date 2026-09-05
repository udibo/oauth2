/**
 * Resource Server implementation for protecting resources with OAuth2 tokens.
 *
 * Implements bearer token validation per RFC 6750.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6750
 * @module
 */

import type { ClientInterface } from "../models/client.ts";
import type { Token } from "../models/token.ts";
import type { AbstractScope, ScopeConstructor } from "../models/scope.ts";
import { BasicScope } from "../models/scope.ts";
import {
  AccessDeniedError,
  InsufficientPermissionsError,
  InsufficientScopeError,
  InvalidTokenError,
  type OAuth2Error,
  toOAuth2Error,
} from "../errors.ts";
import {
  type Authorization,
  authorizationFromClaims,
  type RequireConditions,
} from "../models/authorization.ts";
import type { TokenReaderInterface } from "./services/token.ts";

/** Bearer token regex pattern. */
export const BEARER_TOKEN =
  /^ *(?:[Bb][Ee][Aa][Rr][Ee][Rr]) +([\w-.~+/]+=*) *$/;

const FAILURE_LABELS = {
  organization: "requires organization",
  role: "requires role",
  orgRole: "requires organization role",
  permission: "requires permission",
} as const;

const CHALLENGE_ERROR_CODES = new Set([
  "invalid_request",
  "invalid_token",
  "insufficient_scope",
]);

/** Services required by the resource server. */
export interface ResourceServerServices<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> {
  /** Reads and validates access tokens for this request. */
  tokenService: TokenReaderInterface<Client, User, S>;
}

/** Per-request context resolved by a {@link ResourceServer}. */
export interface ResourceServerContext<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> {
  /** Tenant-scoped services to use for this request. */
  services: ResourceServerServices<Client, User, S>;
}

/** Options for configuring the resource server. */
export interface ResourceServerOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> {
  /**
   * Resolves the per-request context — the (e.g. tenant-scoped) {@link
   * ResourceServerServices} for THIS request — so a single instance serves
   * every tenant/origin. This is the only services seam: for a single-tenant
   * server it is a constant function returning the same services every time
   * (create the services once, outside `resolve`, and return them here).
   */
  resolve: (
    request: Request,
  ) =>
    | ResourceServerContext<Client, User, S>
    | Promise<ResourceServerContext<Client, User, S>>;
  /** Scope constructor used to parse and compare scopes. Defaults to {@linkcode BasicScope}. */
  Scope?: ScopeConstructor<S>;
  /** Protection space named in `WWW-Authenticate` challenges. Defaults to `"Service"`. */
  realm?: string;
  /**
   * Leeway in seconds applied to the access token's expiry, to absorb clock
   * drift between whoever issued the token and this server. Defaults to `0`:
   * a token whose expiry has passed is refused immediately.
   *
   * This is the one expiry check every token reader's result passes through,
   * which is why the leeway belongs here rather than in a reader:
   * {@linkcode IntrospectionTokenReader} reports the authorization server's
   * `exp` verbatim and has no notion of skew at all, and
   * {@linkcode JwksTokenReaderOptions.clockSkewSeconds} governs only that
   * reader's own claim checks. Set this whenever you need drift tolerance, no
   * matter which reader is in play.
   */
  clockSkewSeconds?: number;
  /**
   * Format for error responses.
   * - `"oauth2"` (default): Standard OAuth2 error format with `error`,
   *   `error_description`, and `error_uri` fields.
   * - `"problem-details"`: RFC 9457 Problem Details format with OAuth2
   *   extensions. `type` and `error_uri` carry the same URI; `detail` and
   *   `error_description` carry the same message.
   */
  errorFormat?: "oauth2" | "problem-details";
  /**
   * If true, handlers rethrow errors (as {@link OAuth2Error}) instead of
   * catching them and returning a response. Framework adapters that want to
   * build responses themselves should enable this. Default: false.
   */
  throwOnError?: boolean;
}

/** Authentication context returned by the resource server. */
export interface AuthenticatedContext<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> {
  /** The validated access token backing this request. */
  token: Token<Client, User, S>;
  /** The client the token was issued to. */
  client: Client;
  /** The resource owner, absent for client-credentials tokens. */
  user?: User;
  /** The scope granted to the token, if any. */
  scope?: S | null;
  /**
   * The token's claims as one checkable object — scope, roles, permissions,
   * and the active organization. Built from {@linkcode Token.claims}; a token
   * with no claims yields an authorization that answers scope checks only.
   */
  authorization: Authorization;
}

/**
 * Validates OAuth2 bearer access tokens (RFC 6750) so API endpoints can require
 * authentication. Framework-agnostic: it works on web `Request`/`Response`, so
 * an adapter (Hono, etc.) wires {@linkcode authenticate} into its middleware.
 *
 * A single instance serves every tenant/origin; per-request services come from
 * the `resolve` callback in {@linkcode ResourceServerOptions}. For a
 * single-tenant server, `resolve` is a constant function returning the same
 * services every time.
 *
 * {@linkcode authenticate} throws {@linkcode HttpError} subclasses on failure
 * ({@linkcode AccessDeniedError} when no token is sent,
 * {@linkcode InvalidTokenError} for an invalid/expired token, and
 * {@linkcode InsufficientScopeError} when scope is lacking); use
 * {@linkcode handleAuthError} to turn them into RFC 6750 responses.
 *
 * @template Client The client entity type.
 * @template User The resource-owner entity type.
 * @template S The scope type used for granted/required scope comparisons.
 *
 * @example
 * ```ts
 * import { Hono } from "hono";
 * import type { ClientInterface, TokenReaderInterface } from "@udibo/oauth2/server";
 * import { ResourceServer } from "@udibo/oauth2/server/resource";
 *
 * interface User { id: string }
 *
 * declare const app: Hono;
 * declare const tokenService: TokenReaderInterface<ClientInterface, User>;
 *
 * const server = new ResourceServer({
 *   resolve: () => ({ services: { tokenService } }),
 * });
 *
 * app.get("/api/me", async (c) => {
 *   try {
 *     const { user } = await server.authenticate(c.req.raw, "identity:read");
 *     return c.json(user ?? null);
 *   } catch (error) {
 *     return server.handleAuthError(error);
 *   }
 * });
 * ```
 */
export class ResourceServer<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> {
  /** Scope constructor used to parse and compare scopes. */
  Scope: ScopeConstructor<S>;
  /** Protection space named in `WWW-Authenticate` challenges. */
  realm: string;
  /** Leeway in seconds applied to the access token's expiry. Defaults to `0`. */
  clockSkewSeconds: number;
  /** Body format used for error responses: OAuth2 or RFC 9457 problem details. */
  errorFormat: "oauth2" | "problem-details";
  /** When true, handler boundaries rethrow {@linkcode OAuth2Error} instead of returning a response. */
  throwOnError: boolean;
  /** Resolves the per-request {@link ResourceServerContext}. */
  protected resolveContext: (
    request: Request,
  ) =>
    | ResourceServerContext<Client, User, S>
    | Promise<ResourceServerContext<Client, User, S>>;

  /** Creates a resource server from the given {@linkcode ResourceServerOptions}. */
  constructor(options: ResourceServerOptions<Client, User, S>) {
    this.Scope = options.Scope ??
      (BasicScope as unknown as ScopeConstructor<S>);
    this.realm = options.realm ?? "Service";
    this.clockSkewSeconds = options.clockSkewSeconds ?? 0;
    this.errorFormat = options.errorFormat ?? "oauth2";
    this.throwOnError = options.throwOnError ?? false;
    this.resolveContext = options.resolve;
  }

  /**
   * Builds a WWW-Authenticate header value per RFC 6750 Section 3.
   *
   * The header includes:
   * - realm: The protection space
   * - error: The error code (for 401/403 responses)
   * - error_description: Human-readable error description
   * - scope: Required scope (for insufficient_scope errors)
   *
   * RFC 6750 Section 3.1 registers exactly three challenge codes —
   * `invalid_request`, `invalid_token`, `insufficient_scope` — so an error
   * carrying anything else (including the `access_denied` this server raises
   * when a request presents no credentials at all, which the same section says
   * MUST NOT be given a code) produces a bare `realm` challenge. Pick the error
   * class accordingly: a client reads a coded challenge and acts on it, and
   * {@linkcode InsufficientScopeError} is the one that tells it "your token is
   * fine, it just lacks scope" rather than sending it off to refresh.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3
   */
  buildWwwAuthenticate(error?: OAuth2Error, requiredScope?: string): string {
    const quote = (value: string): string =>
      // deno-lint-ignore no-control-regex
      value.replace(/[\x00-\x1f\x7f]/g, "").replace(/\\/g, "\\\\").replace(
        /"/g,
        '\\"',
      );
    const parts: string[] = [`realm="${quote(this.realm)}"`];

    const code = error?.extensions.error;
    if (error && code && CHALLENGE_ERROR_CODES.has(code)) {
      parts.push(`error="${quote(code)}"`);
      if (error.message) {
        parts.push(`error_description="${quote(error.message)}"`);
      }
    }

    if (requiredScope) {
      parts.push(`scope="${quote(requiredScope)}"`);
    } else if (error instanceof InsufficientScopeError) {
      const scope =
        (error.extensions as { requiredScope?: string }).requiredScope;
      if (scope) {
        parts.push(`scope="${quote(scope)}"`);
      }
    }

    return `Bearer ${parts.join(", ")}`;
  }

  /**
   * Creates an error response for an OAuth2 error.
   *
   * The response body is formatted according to {@link errorFormat}:
   * - `"oauth2"`: `{ error, error_description?, error_uri? }` as JSON.
   * - `"problem-details"`: RFC 9457 Problem Details with OAuth2 extensions.
   *
   * Does **not** set any response headers beyond `Content-Type`. Any extra
   * response headers (`WWW-Authenticate`, `Cache-Control`, `Pragma`, …) must
   * be set on the error via its `headers` property before calling this
   * method; they are copied through verbatim.
   */
  createErrorResponse(error: unknown): Response {
    const oauth2Error = toOAuth2Error(error);

    const response = this.errorFormat === "problem-details"
      ? oauth2Error.getResponse()
      : this.#createOAuth2ErrorResponse(oauth2Error);

    for (const [key, value] of oauth2Error.headers) {
      if (key.toLowerCase() === "content-type") continue;
      response.headers.set(key, value);
    }

    return response;
  }

  #createOAuth2ErrorResponse(oauth2Error: OAuth2Error): Response {
    const body: Record<string, string> = {
      error: oauth2Error.extensions.error ?? "server_error",
    };
    const description = oauth2Error.extensions.error_description ??
      oauth2Error.exposedMessage;
    if (description) {
      body.error_description = description;
    }
    const errorUri = oauth2Error.extensions.error_uri ?? oauth2Error.type;
    if (errorUri) {
      body.error_uri = errorUri;
    }
    return new Response(JSON.stringify(body), {
      status: oauth2Error.status,
      headers: { "Content-Type": "application/json;charset=UTF-8" },
    });
  }

  /**
   * Normalizes an error at a handler boundary and either rethrows it (when
   * {@link throwOnError} is true) or converts it to a response.
   *
   * The optional `prepare` callback lets a handler annotate the error —
   * usually by setting headers like `Cache-Control` or `WWW-Authenticate`
   * that belong on both the thrown error and the response — before the
   * throw/respond decision is made.
   */
  handleError(
    error: unknown,
    prepare?: (error: OAuth2Error) => void,
  ): Response {
    const oauth2Error = toOAuth2Error(error);
    prepare?.(oauth2Error);
    if (this.throwOnError) throw oauth2Error;
    return this.createErrorResponse(oauth2Error);
  }

  /**
   * {@link handleError} variant that automatically attaches a
   * `WWW-Authenticate` header (per RFC 6750 Section 3) when the error's
   * status is 401 or 403. Use this at bearer-token boundaries to avoid the
   * boilerplate of building the header for each error response.
   *
   * @example
   * ```ts
   * import { Hono } from "hono";
   * import type { ClientInterface } from "@udibo/oauth2/server";
   * import { ResourceServer } from "@udibo/oauth2/server/resource";
   *
   * interface User { id: string }
   *
   * declare const app: Hono;
   * declare const server: ResourceServer<ClientInterface, User>;
   *
   * app.get("/api/me", async (c) => {
   *   try {
   *     const ctx = await server.authenticate(c.req.raw);
   *     return c.json(ctx.user ?? null);
   *   } catch (error) {
   *     return server.handleAuthError(error);
   *   }
   * });
   * ```
   */
  handleAuthError(error: unknown): Response {
    return this.handleError(error, (e) => {
      if (e.status === 401 || e.status === 403) {
        e.headers.set("WWW-Authenticate", this.buildWwwAuthenticate(e));
      }
    });
  }

  /**
   * Extracts an access token from a request.
   * Looks in the Authorization header (Bearer token) first,
   * then in the request body for form-encoded requests.
   */
  async getAccessToken(request: Request): Promise<string | null> {
    const authorization = request.headers.get("authorization");
    if (authorization) {
      const match = BEARER_TOKEN.exec(authorization);
      if (match) return match[1];
    }

    const contentType = request.headers.get("content-type");
    if (
      request.method === "POST" &&
      contentType?.includes("application/x-www-form-urlencoded")
    ) {
      try {
        const body = await request.clone().formData();
        const accessToken = body.get("access_token");
        if (typeof accessToken === "string") return accessToken;
      } catch {
        // ignore
      }
    }

    return null;
  }

  /**
   * Retrieves and validates a token by access token string.
   *
   * The token's expiry is compared against now with {@linkcode
   * clockSkewSeconds} of leeway, so the same tolerance applies whichever
   * token reader produced the token.
   *
   * @throws {InvalidTokenError} If the token is invalid, expired beyond the
   *   configured leeway, or revoked
   * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
   */
  async getToken(
    accessToken: string,
    services: ResourceServerServices<Client, User, S>,
  ): Promise<Token<Client, User, S>> {
    const { tokenService } = services;
    const token = await tokenService.getToken(accessToken);

    if (!token) {
      throw new InvalidTokenError("invalid access token");
    }

    if (token.accessTokenExpiresAt) {
      const deadline = token.accessTokenExpiresAt.getTime() +
        this.clockSkewSeconds * 1000;
      if (deadline < Date.now()) {
        throw new InvalidTokenError("access token has expired");
      }
    }

    return token;
  }

  /**
   * Authenticates a request and verifies the token has the required scope.
   *
   * @param request The incoming request
   * @param requiredScope Optional scope required to access the resource
   * @returns The authenticated context with token, client, user, and scope
   * @throws {AccessDeniedError} If no token is provided
   * @throws {InvalidTokenError} If the token is invalid or expired
   * @throws {InsufficientScopeError} If the token lacks required scope (HTTP 403)
   * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
   */
  async authenticate(
    request: Request,
    requiredScope?: S | string,
  ): Promise<AuthenticatedContext<Client, User, S>> {
    const accessToken = await this.getAccessToken(request);

    if (!accessToken) {
      throw new AccessDeniedError("authentication required");
    }

    const { services } = await this.resolveContext(request);
    const token = await this.getToken(accessToken, services);

    if (requiredScope) {
      this.assertScope(token.scope, requiredScope);
    }

    return {
      token,
      client: token.client,
      user: token.user,
      scope: token.scope,
      authorization: authorizationFromClaims(token.claims, token.scope),
    };
  }

  /**
   * Throws unless the authenticated context satisfies every condition —
   * the assertion behind the adapters' `require()` middleware, public so a
   * handler authenticating manually can reuse the same checks.
   *
   * Scope conditions go through {@linkcode assertScope}, so their failure is
   * the same RFC 6750 `insufficient_scope` challenge `requireScope` sends.
   * Every other condition is answered by the context's
   * {@linkcode AuthenticatedContext.authorization}; the first unmet one
   * throws a plain 403 naming the failed check.
   *
   * @throws {InsufficientScopeError} If the token lacks a required scope (403,
   *   `insufficient_scope` challenge).
   * @throws {InsufficientPermissionsError} If a permission, role, or
   *   organization condition fails (403, no challenge code).
   */
  assertAuthorized(
    context: AuthenticatedContext<Client, User, S>,
    conditions: RequireConditions,
  ): void {
    if (conditions.scope !== undefined) {
      const required = typeof conditions.scope === "string"
        ? conditions.scope
        : conditions.scope.join(" ");
      this.assertScope(context.scope, required);
    }
    const failure = context.authorization.unmet(conditions);
    if (failure) {
      const required = failure.required === true
        ? "an active organization"
        : failure.required;
      throw new InsufficientPermissionsError(
        `${FAILURE_LABELS[failure.kind]}: ${required}`,
      );
    }
  }

  /**
   * Throws {@link InsufficientScopeError} unless `granted` contains
   * `requiredScope`. Shared by {@link authenticate} and the adapters'
   * scope-only guards (`requireScope`) so the comparison and the RFC 6750
   * error stay identical — a guard that checks an already-authenticated
   * request's scope (without re-validating the token) calls this with the
   * context's `scope`. Public so a handler authenticating manually can reuse
   * the same check.
   *
   * @throws {InsufficientScopeError} If `granted` lacks `requiredScope` (403).
   */
  assertScope(
    granted: S | null | undefined,
    requiredScope: S | string,
  ): void {
    const scope = typeof requiredScope === "string"
      ? new this.Scope(requiredScope)
      : requiredScope;
    if (!granted?.has(scope)) {
      throw new InsufficientScopeError("insufficient scope", {
        extensions: { requiredScope: scope.toString() },
      });
    }
  }
}

export { IntrospectionTokenReader } from "./introspection-token-reader.ts";
export type { IntrospectionTokenReaderOptions } from "./introspection-token-reader.ts";
export { JwksTokenReader } from "./jwks-token-reader.ts";
export type {
  JwksTokenReaderOptions,
  JwtAccessTokenClaims,
} from "./jwks-token-reader.ts";
