/**
 * OAuth2 error classes following RFC 6749.
 *
 * These error classes map to the OAuth2 error codes defined in:
 * - RFC 6749 Section 4.1.2.1 (Authorization errors)
 * - RFC 6749 Section 5.2 (Token errors)
 * - RFC 6750 Section 3.1 (Bearer token errors)
 * - RFC 8628 Section 3.5 (Device flow errors)
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
 * @module
 */

import {
  createHttpErrorClass,
  HttpError,
  type HttpErrorOptions,
} from "@udibo/http-error";

/**
 * Problem Details extension members carried by every {@linkcode OAuth2Error}.
 *
 * These map the standard OAuth2 error response fields (RFC 6749 Section 5.2)
 * onto the error's `extensions` bag so they can be serialized in either the
 * OAuth2 error format or the RFC 9457 Problem Details format.
 */
export interface OAuth2ProblemDetailsExtensions {
  /** An ASCII error code. */
  error?: string;
  /** Human-readable error description. */
  error_description?: string;
  /** A URI identifying a human readable web page with information about the error. */
  error_uri?: string;
}

/**
 * Constructor type for OAuth2 error classes produced by
 * `createHttpErrorClass`. Declared explicitly so the exported error classes
 * have a JSR-fast public type (the inferred type spans multiple constructor
 * overloads and trips the `no-slow-types` rule).
 */
export type OAuth2ErrorClass<
  Extensions extends OAuth2ProblemDetailsExtensions =
    OAuth2ProblemDetailsExtensions,
> = {
  new <E extends Extensions = Extensions>(
    status?: number,
    message?: string,
    options?: HttpErrorOptions<E>,
  ): HttpError<E>;
  new <E extends Extensions = Extensions>(
    status?: number,
    options?: HttpErrorOptions<E>,
  ): HttpError<E>;
  new <E extends Extensions = Extensions>(
    message?: string,
    options?: HttpErrorOptions<E>,
  ): HttpError<E>;
  new <E extends Extensions = Extensions>(
    options?: HttpErrorOptions<E>,
  ): HttpError<E>;
  prototype: HttpError<Extensions>;
};

/**
 * An OAuth2 error: an {@linkcode HttpError} whose `extensions` carry the
 * OAuth2 error fields described by {@linkcode OAuth2ProblemDetailsExtensions}.
 * This is the common type for every error class in this module.
 */
export type OAuth2Error = HttpError<OAuth2ProblemDetailsExtensions>;
/**
 * The base OAuth2 error class, an {@linkcode HttpError} subclass that defaults
 * to the `server_error` code. Used as a catch-all and as the value-side
 * companion of the {@linkcode OAuth2Error} type; prefer a specific subclass
 * (e.g. {@linkcode InvalidRequestError}) when the condition is known.
 */
export const OAuth2Error: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "OAuth2 Error",
    extensions: {
      error: "server_error",
    },
  },
);

/** Type guard for OAuth2 errors. */
export function isOAuth2Error(value: unknown): value is OAuth2Error {
  return value instanceof HttpError && value.extensions.error !== undefined;
}

/**
 * Converts an arbitrary error into an {@link OAuth2Error}.
 *
 * If the input is already an OAuth2Error it is returned as-is; otherwise it is
 * wrapped in a {@link ServerError} with the original error attached as `cause`.
 *
 * The returned error also has its `type` and `extensions.error_uri` synced so
 * that if one is set the other is too. This lets both the standard OAuth2
 * error format (which emits `error_uri`) and the RFC 9457 Problem Details
 * format (which emits `type`) carry the same URI without the handler having to
 * set both fields.
 */
export function toOAuth2Error(error: unknown): OAuth2Error {
  const oauth2Error = isOAuth2Error(error)
    ? error
    : new ServerError("unexpected error", { cause: error });

  if (oauth2Error.type && !oauth2Error.extensions.error_uri) {
    oauth2Error.extensions.error_uri = oauth2Error.type;
  } else if (oauth2Error.extensions.error_uri && !oauth2Error.type) {
    oauth2Error.type = oauth2Error.extensions.error_uri;
  }

  return oauth2Error;
}

/**
 * The request is missing a required parameter, includes an unsupported parameter value,
 * repeats a parameter, includes multiple credentials, utilizes more than one mechanism
 * for authenticating the client, or is otherwise malformed.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export const InvalidRequestError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Invalid Request",
    status: 400,
    extensions: {
      error: "invalid_request",
    },
  },
);

/**
 * Client authentication failed.
 *
 * The authorization server MAY return an HTTP 401 (Unauthorized) status code
 * to indicate which HTTP authentication schemes are supported.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export const InvalidClientError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Invalid Client",
    status: 401,
    extensions: {
      error: "invalid_client",
    },
  },
);

/**
 * The provided authorization grant or refresh token is invalid, expired, revoked,
 * does not match the redirection URI used in the authorization request, or was issued to another client.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export const InvalidGrantError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Invalid Grant",
    status: 400,
    extensions: {
      error: "invalid_grant",
    },
  },
);

/**
 * The authenticated client is not authorized to use this authorization grant type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export const UnauthorizedClientError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Unauthorized Client",
    status: 401,
    extensions: {
      error: "unauthorized_client",
    },
  },
);

/**
 * The token type is not supported by the authorization server.
 *
 * Used by the revocation endpoint (RFC 7009) when the server doesn't
 * support revoking the presented token type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1
 */
export const UnsupportedTokenTypeError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Unsupported Token Type",
    status: 400,
    extensions: {
      error: "unsupported_token_type",
    },
  },
);

/**
 * The authorization grant type is not supported by the authorization server.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export const UnsupportedGrantTypeError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Unsupported Grant Type",
    status: 400,
    extensions: {
      error: "unsupported_grant_type",
    },
  },
);

/**
 * The resource owner or authorization server denied the request.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
 */
export const AccessDeniedError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Access Denied",
    status: 401,
    extensions: {
      error: "access_denied",
    },
  },
);

/**
 * The access token provided is expired, revoked, malformed, or invalid.
 *
 * Per RFC 6750, this error uses HTTP 401 status and should trigger
 * a WWW-Authenticate header with the "invalid_token" error code.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
 */
export const InvalidTokenError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Invalid Token",
    status: 401,
    extensions: {
      error: "invalid_token",
    },
  },
);

/**
 * The request requires higher privileges than provided by the access token.
 *
 * Per RFC 6750, this error uses HTTP 403 status and should trigger
 * a WWW-Authenticate header with the "insufficient_scope" error code
 * and optionally a "requiredScope" extension indicating required scope.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
 */
export const InsufficientScopeError: OAuth2ErrorClass<
  OAuth2ProblemDetailsExtensions & { requiredScope?: string }
> = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions & { requiredScope?: string }
>(
  {
    name: "Insufficient Scope",
    status: 403,
    extensions: {
      error: "insufficient_scope",
    },
  },
);

/**
 * The request requires an authorization the subject does not hold — a
 * permission, role, or organization context check failed on an otherwise
 * valid token. HTTP 403 with a bare `realm` challenge: RFC 6750 registers no
 * challenge code for this, so unlike {@link InsufficientScopeError} the
 * `WWW-Authenticate` header names no error — the body carries
 * `insufficient_permissions`.
 */
export const InsufficientPermissionsError: OAuth2ErrorClass =
  createHttpErrorClass<
    OAuth2ProblemDetailsExtensions
  >(
    {
      name: "Insufficient Permissions",
      status: 403,
      extensions: {
        error: "insufficient_permissions",
      },
    },
  );

/**
 * The authorization server does not support obtaining an authorization code using this method.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
 */
export const UnsupportedResponseTypeError: OAuth2ErrorClass =
  createHttpErrorClass<
    OAuth2ProblemDetailsExtensions
  >(
    {
      name: "Unsupported Response Type",
      status: 400,
      extensions: {
        error: "unsupported_response_type",
      },
    },
  );

/**
 * The requested scope is invalid, unknown, or malformed.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export const InvalidScopeError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Invalid Scope",
    status: 400,
    extensions: {
      error: "invalid_scope",
    },
  },
);

/**
 * The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
 */
export const ServerError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Server Error",
    status: 500,
    extensions: {
      error: "server_error",
    },
  },
);

/**
 * The authorization server is currently unable to handle the request due to a temporary overloading or maintenance.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
 */
export const TemporarilyUnavailableError: OAuth2ErrorClass =
  createHttpErrorClass<
    OAuth2ProblemDetailsExtensions
  >(
    {
      name: "Temporarily Unavailable",
      status: 503,
      extensions: {
        error: "temporarily_unavailable",
      },
    },
  );

/**
 * The authorization request is still pending user approval.
 *
 * Used in the device authorization flow (RFC 8628) when the user
 * has not yet authorized the request.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
 */
export const AuthorizationPendingError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Authorization Pending",
    status: 400,
    extensions: {
      error: "authorization_pending",
    },
  },
);

/**
 * The client is polling too frequently.
 *
 * Used in the device authorization flow (RFC 8628) when the client
 * polls faster than the allowed interval. The client should increase
 * its polling interval by 5 seconds.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
 */
export const SlowDownError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Slow Down",
    status: 400,
    extensions: {
      error: "slow_down",
    },
  },
);

/**
 * The device_code has expired.
 *
 * Used in the device authorization flow (RFC 8628) when the
 * device code expires before the user authorizes the request.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
 */
export const ExpiredTokenError: OAuth2ErrorClass = createHttpErrorClass<
  OAuth2ProblemDetailsExtensions
>(
  {
    name: "Expired Token",
    status: 400,
    extensions: {
      error: "expired_token",
    },
  },
);
