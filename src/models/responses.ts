/**
 * OAuth2 error codes as defined in RFC 6749 and extensions.
 *
 * Includes the RFC 6750 Section 3.1 bearer-token error codes
 * (`invalid_token`, `insufficient_scope`) emitted by resource servers, in
 * addition to the RFC 6749 Section 5.2 / Section 4.1.2.1 codes and the RFC
 * 8628 device-flow codes.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
 */
export type OAuth2ErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "unsupported_response_type"
  | "unsupported_token_type"
  | "invalid_scope"
  | "invalid_token"
  | "insufficient_scope"
  | "access_denied"
  | "server_error"
  | "temporarily_unavailable"
  | "authorization_pending"
  | "slow_down"
  | "expired_token";

/**
 * Standard OAuth2 error response.
 *
 * Returned by OAuth2 endpoints when an error occurs.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export interface ErrorResponse {
  /** Error code from {@linkcode OAuth2ErrorCode}. */
  error: OAuth2ErrorCode;
  /** Human-readable error description. */
  error_description?: string;
  /** URI to a page with additional error information. */
  error_uri?: string;
}

/**
 * OAuth2 Authorization Server Metadata as defined in RFC 8414.
 *
 * Describes the configuration of an OAuth2 authorization server,
 * typically served at `/.well-known/oauth-authorization-server`.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8414#section-2
 */
export interface AuthorizationServerMetadata {
  /** Authorization server's issuer identifier (URL). */
  issuer: string;
  /** URL of the authorization endpoint. */
  authorization_endpoint?: string;
  /** URL of the token endpoint. */
  token_endpoint?: string;
  /** Supported client authentication methods at the token endpoint. */
  token_endpoint_auth_methods_supported?: string[];
  /**
   * URL of the token introspection endpoint (RFC 7662). Named
   * `introspection_endpoint` per the RFC 8414 / IANA metadata registry.
   */
  introspection_endpoint?: string;
  /** URL of the token revocation endpoint (RFC 7009). */
  revocation_endpoint?: string;
  /** URL of the device authorization endpoint (RFC 8628). */
  device_authorization_endpoint?: string;
  /** URL of the OIDC userinfo endpoint (OpenID Connect Discovery). */
  userinfo_endpoint?: string;
  /** URL of the OIDC RP-initiated logout (end-session) endpoint. */
  end_session_endpoint?: string;
  /** Supported PKCE code challenge methods. */
  code_challenge_methods_supported?: string[];
  /** Scopes supported by the authorization server. */
  scopes_supported?: string[];
  /** Supported response types. */
  response_types_supported?: string[];
  /** Supported grant types. */
  grant_types_supported?: string[];
  /** URL of the JWKS document (OIDC Discovery / RFC 8414). */
  jwks_uri?: string;
  /** JWS algorithms supported for id_token signing (OIDC Discovery). */
  id_token_signing_alg_values_supported?: string[];
  /** Subject identifier types supported (OIDC Discovery). */
  subject_types_supported?: string[];
}

/**
 * Device authorization response as defined in RFC 8628.
 *
 * Returned by the device authorization endpoint for the device flow.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
 */
export interface DeviceAuthorizationResponse {
  /** Device verification code. */
  device_code: string;
  /** User verification code to be displayed to the user. */
  user_code: string;
  /** Verification URI the user should visit. */
  verification_uri: string;
  /** Verification URI with user_code embedded (optional convenience). */
  verification_uri_complete?: string;
  /** Lifetime in seconds of the device and user codes. */
  expires_in: number;
  /** Minimum polling interval in seconds. */
  interval?: number;
}
