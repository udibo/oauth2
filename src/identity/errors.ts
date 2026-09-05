/**
 * A stable error contract for identity flows, so a front-end can switch on a
 * code instead of parsing messages, and the Hono route factory can map errors
 * to consistent responses.
 *
 * @module
 */

/**
 * Stable, machine-readable identity error codes. Most are raised by your store
 * or the service; `forbidden_origin` is raised by the Hono route factory's
 * same-origin guard before a handler runs.
 */
export type IdentityErrorCode =
  | "invalid_credentials"
  | "invalid_token"
  | "rate_limited"
  | "weak_password"
  | "identifier_taken"
  | "email_not_verified"
  | "mfa_not_enrolled"
  | "mfa_already_enrolled"
  | "captcha_failed"
  | "forbidden_origin";

/** Options for {@link IdentityError}. */
export interface IdentityErrorOptions extends ErrorOptions {
  /** For `rate_limited`: milliseconds until the caller may retry. */
  retryAfterMs?: number;
}

/**
 * A typed error for identity flows. Throw it from your `IdentityUserStore`
 * (e.g. `identifier_taken` on a duplicate) or your own validation; the Hono
 * route factory maps it to `{ error: code }` with the right status.
 */
export class IdentityError extends Error {
  /** Always `"IdentityError"`, so instances are recognizable across realms. */
  override readonly name = "IdentityError";
  /** The stable, machine-readable code a client can switch on. */
  readonly code: IdentityErrorCode;
  /** For `rate_limited`: ms until retry, if known. */
  readonly retryAfterMs?: number;

  /** Builds an identity error; `message` defaults to the `code` when omitted. */
  constructor(
    code: IdentityErrorCode,
    message?: string,
    options?: IdentityErrorOptions,
  ) {
    super(message ?? code, options);
    this.code = code;
    this.retryAfterMs = options?.retryAfterMs;
  }
}

/** Type guard for {@link IdentityError}. */
export function isIdentityError(value: unknown): value is IdentityError {
  return value instanceof IdentityError;
}

/** The HTTP statuses an identity error maps to (a `ContentfulStatusCode` union). */
export type IdentityErrorStatus = 400 | 401 | 403 | 409 | 422 | 429;

const STATUS: Record<IdentityErrorCode, IdentityErrorStatus> = {
  invalid_credentials: 401,
  invalid_token: 400,
  rate_limited: 429,
  weak_password: 422,
  identifier_taken: 409,
  email_not_verified: 403,
  mfa_not_enrolled: 409,
  mfa_already_enrolled: 409,
  captcha_failed: 403,
  forbidden_origin: 403,
};

/** The HTTP status conventionally paired with an identity error code. */
export function identityErrorStatus(
  code: IdentityErrorCode,
): IdentityErrorStatus {
  return STATUS[code] ?? 400;
}
