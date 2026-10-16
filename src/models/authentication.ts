/**
 * Verified authentication claims for one event, supplied by application policy.
 *
 * Capture this context at authorization-code issuance and persist it on codes
 * and tokens. Refresh rotations retain the original event. Omit unknown claims;
 * neither a requested assurance level nor token issuance time is evidence.
 *
 * @example
 * ```ts
 * const event: AuthenticationContext = {
 *   auth_time: 1_700_000_000,
 *   acr: "urn:example:password",
 *   amr: ["pwd"],
 * };
 * ```
 */
export interface AuthenticationContext {
  /** Verified authentication time in Unix seconds, not token issuance time. */
  readonly auth_time?: number;
  /** Achieved authentication context, never the requested preference. */
  readonly acr?: string;
  /** Truthful authentication methods; omitted when the complete set is unknown. */
  readonly amr?: readonly string[];
}

/**
 * The OpenID Connect authentication controls of one authorization request,
 * validated by the authorization server and handed to the application's
 * `authenticateUser` and `handleConsent` callbacks.
 *
 * The server enforces what it can verify: `prompt=none` never reaches a login
 * or consent page, and a code is issued only when the returned authentication
 * satisfies `prompt=login` and `max_age` (see
 * `satisfiesAuthenticationRequest`). `acrValues` is a preference the
 * application meets as it can; report the `acr` it actually achieved.
 *
 * @example
 * ```ts
 * const authentication: AuthenticationRequest = {
 *   prompt: ["login"],
 *   maxAge: 300,
 *   acrValues: ["urn:example:mfa"],
 * };
 * ```
 */
export interface AuthenticationRequest {
  /** Requested `prompt` values, each one the server supports; empty when absent. */
  readonly prompt: readonly string[];
  /** Requested `max_age` in seconds, when present. */
  readonly maxAge?: number;
  /** Requested `acr_values` in preference order; empty when absent. */
  readonly acrValues: readonly string[];
}
