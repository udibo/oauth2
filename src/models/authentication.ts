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
