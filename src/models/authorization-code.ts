import type { AbstractScope, BasicScope } from "./scope.ts";
import type { ClientInterface } from "./client.ts";

/**
 * Authorization code model.
 *
 * Represents an authorization code issued by the authorization server
 * after the resource owner grants authorization. The code is exchanged
 * for tokens at the token endpoint.
 */
export interface AuthorizationCode<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> {
  /** The authorization code string. */
  code: string;
  /** When the code expires. */
  expiresAt: Date;
  /** The client that requested authorization. */
  client: Client;
  /** The user who authorized the request. */
  user: User;
  /** The scope that was authorized. */
  scope?: Scope | null;
  /** The redirect URI used in the authorization request. */
  redirectUri?: string;
  /** PKCE code challenge. */
  challenge?: string;
  /** PKCE challenge method (S256 or plain). */
  challengeMethod?: string;
  /** OIDC nonce from the authorization request, echoed into the id_token. */
  nonce?: string;
}

/**
 * Parameters from an authorization request.
 *
 * Parsed from the query string of an authorization endpoint request.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
 */
export interface AuthorizeParameters {
  /** Must be "code" for authorization code flow. */
  responseType?: string;
  /** Client identifier issued to the client. */
  clientId?: string;
  /** URI to redirect to after authorization. */
  redirectUri?: string;
  /** Opaque state value for CSRF protection. */
  state?: string;
  /** Space-delimited list of requested scopes. */
  scope?: string;
  /** PKCE code challenge (RFC 7636). */
  challenge?: string;
  /** PKCE code challenge method ("S256" or "plain"). */
  challengeMethod?: string;
  /** OIDC nonce (echoed into the id_token when `openid` is granted). */
  nonce?: string;
}
