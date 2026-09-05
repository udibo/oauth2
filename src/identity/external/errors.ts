/**
 * The error contract for external-provider (social login) flows.
 *
 * Every failure in the external connector layer is thrown as an
 * {@link ExternalAuthError} whose message names the provider, what failed, and
 * the likely fix — misconfiguration is meant to be diagnosable from the
 * message alone. The {@link ExternalAuthErrorCode} tells app code how to
 * respond: `configuration` is a deploy-time bug to fix, everything else is a
 * per-attempt failure to surface to the user (usually "sign in again").
 *
 * @module
 */

/**
 * Machine-readable causes for an {@link ExternalAuthError}.
 *
 * - `configuration` — the connector is miswired (bad issuer, failed
 *   discovery, missing endpoint, provider/transient mismatch). Fix the
 *   deployment; retrying the sign-in will not help.
 * - `provider_error` — the provider rejected the request (callback `error`
 *   param, token-endpoint error, profile-endpoint failure, malformed
 *   response). The message carries the provider's error code/description.
 * - `invalid_callback` — the callback URL is missing `code` or `state`.
 * - `state_mismatch` — the callback `state` does not match the transient
 *   (possible CSRF or a stale/mixed-up sign-in attempt).
 * - `transient_expired` — the sign-in attempt outlived the configured max
 *   transient age; the user should start again.
 * - `nonce_mismatch` — the id_token `nonce` claim does not match the
 *   transient (possible token replay); the user should start again.
 */
export type ExternalAuthErrorCode =
  | "configuration"
  | "provider_error"
  | "invalid_callback"
  | "state_mismatch"
  | "transient_expired"
  | "nonce_mismatch";

/**
 * A diagnosable error from an external-provider flow. The message is always
 * prefixed with the provider id (e.g. `[google] …`) and states what failed
 * plus the likely fix; switch on {@link ExternalAuthError.code} to decide
 * whether to alert an operator (`configuration`) or restart the sign-in.
 */
export class ExternalAuthError extends Error {
  /** Always `"ExternalAuthError"`, so instances are recognizable across realms. */
  override readonly name = "ExternalAuthError";
  /** The machine-readable failure cause. */
  readonly code: ExternalAuthErrorCode;
  /** The id of the provider the failure belongs to (e.g. `"google"`). */
  readonly provider: string;

  /** Builds the error; `message` is prefixed with `[provider]` automatically. */
  constructor(
    provider: string,
    code: ExternalAuthErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(`[${provider}] ${message}`, options);
    this.provider = provider;
    this.code = code;
  }
}

/** Type guard for {@link ExternalAuthError}. */
export function isExternalAuthError(
  value: unknown,
): value is ExternalAuthError {
  return value instanceof ExternalAuthError;
}
