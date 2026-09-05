import type { AbstractScope, BasicScope } from "./scope.ts";
import type { ClientInterface } from "./client.ts";

/**
 * Token model representing an access token.
 *
 * Returned by the token services and the resource server, and part of the
 * public `TokenServiceInterface` / `TokenReaderInterface` surface that
 * consumers implement. The generic parameters allow customizing the client,
 * user, and scope types.
 */
export interface Token<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> {
  /** The access token string. */
  accessToken: string;
  /** When the access token expires. */
  accessTokenExpiresAt?: Date;
  /** The client this token was issued to. */
  client: Client;
  /** The user this token was issued for (if applicable). */
  user?: User;
  /** The scope granted to this token. */
  scope?: Scope | null;
  /**
   * The verified claims this token carried, when the reader that produced it
   * had them — a validated JWT's payload, or an introspection response. The
   * resource server builds its `Authorization` from these; a DB-backed token
   * service may leave them unset, which yields an authorization with scope
   * only.
   */
  claims?: Record<string, unknown>;
  /** The authorization code used to generate this token, for replay detection per RFC 6819. */
  code?: string;
  /**
   * OIDC nonce carried transiently from the authorization code so the token
   * endpoint can echo it in the id_token. Not persisted by token stores.
   */
  nonce?: string;
}

/** Token with refresh token capability. */
export interface RefreshToken<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> extends Token<Client, User, Scope> {
  /** The refresh token string. */
  refreshToken: string;
  /** When the refresh token expires. */
  refreshTokenExpiresAt?: Date;
  /**
   * The rotation family this refresh token belongs to: assigned at first
   * issuance and inherited by every rotation, so replay of a rotated-out
   * member can revoke the whole family (reuse detection).
   */
  familyId?: string;
  /**
   * When the rotation family was first issued: set alongside
   * {@linkcode RefreshToken.familyId} at first issuance and carried unchanged
   * through every rotation. It anchors the absolute cap
   * ({@linkcode TokenServiceInterface.refreshTokenFamilyExpiresAt}), so a token
   * service that persists refresh tokens **must** persist and restore it —
   * dropping it on the round trip disables the cap.
   *
   * A record without an anchor (one stored before the cap existed) rotates
   * once uncapped; that rotation is issued with a fresh anchor, so the family
   * is capped from then on.
   */
  familyCreatedAt?: Date;
}

/**
 * Standard OAuth2 token response.
 *
 * Returned by the token endpoint as defined in RFC 6749 Section 5.1.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
 */
export interface TokenResponse {
  /** Always "Bearer" for OAuth2 Bearer tokens. */
  token_type: "Bearer";
  /** The access token issued by the authorization server. */
  access_token: string;
  /** Token lifetime in seconds. */
  expires_in?: number;
  /** Refresh token for obtaining new access tokens. */
  refresh_token?: string;
  /** Space-delimited list of granted scopes. */
  scope?: string;
  /** OIDC ID Token, present when the `openid` scope was granted to a user. */
  id_token?: string;
}

/**
 * Token introspection response as defined in RFC 7662.
 *
 * Used by resource servers to query the authorization server
 * about the state of an access token. Authorization servers MAY
 * include additional extension fields; the index signature exposes
 * them to mapping functions like
 * {@linkcode IntrospectionTokenReaderOptions.getClient}.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
 */
export interface IntrospectionResponse {
  /** Whether the token is currently active. */
  active: boolean;
  /** Space-delimited list of scopes associated with the token. */
  scope?: string;
  /** Client identifier for the OAuth2 client that requested the token. */
  client_id?: string;
  /** Human-readable identifier for the resource owner. */
  username?: string;
  /** Type of the token (e.g., "Bearer"). */
  token_type?: string;
  /** Token expiration time (Unix timestamp). */
  exp?: number;
  /** Token issue time (Unix timestamp). */
  iat?: number;
  /** Token not-before time (Unix timestamp). */
  nbf?: number;
  /**
   * Subject identifier — the resource owner. Absent for a machine token
   * issued without a user (client credentials): its `client_id` identifies
   * the caller, and the missing `sub` marks that no resource owner is behind
   * the token.
   */
  sub?: string;
  /** Audience(s) the token is intended for. */
  aud?: string | string[];
  /** Issuer of the token. */
  iss?: string;
  /** Unique token identifier. */
  jti?: string;
  /** Extension fields. RFC 7662 allows servers to add their own claims. */
  [extension: string]: unknown;
}
