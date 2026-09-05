/**
 * Authorization Code grant type implementation with PKCE support.
 * RFC 6749 Section 4.1 and RFC 7636.
 * @module
 */

import type { AuthorizationCode } from "../../models/authorization-code.ts";
import type {
  ClientCredentials,
  ClientInterface,
} from "../../models/client.ts";
import type { Token } from "../../models/token.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  ServerError,
} from "../../errors.ts";
import type { ChallengeMethod, ChallengeMethods } from "../../utils/pkce.ts";
import {
  challengeMethods as defaultChallengeMethods,
  getChallengeMethod,
  validateCodeVerifier,
} from "../../utils/pkce.ts";
import { authenticateClientCredentials } from "../client-authentication.ts";
import type { ClientServiceInterface } from "../services/client.ts";
import type { AuthorizationCodeServiceInterface } from "../services/authorization-code.ts";
import {
  AbstractGrant,
  type GrantOptions,
  type GrantServices,
} from "./grant.ts";

/** Services required by the authorization code grant. */
export interface AuthorizationCodeGrantServices<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> extends GrantServices<Client, User, S> {
  /** Generates, stores, and looks up authorization codes for the exchange. */
  authorizationCodeService: AuthorizationCodeServiceInterface<Client, User, S>;
}

/**
 * Options for configuring the authorization code grant.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
 * @see https://datatracker.ietf.org/doc/html/rfc7636
 */
export interface AuthorizationCodeGrantOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> extends
  GrantOptions<
    Client,
    User,
    S,
    AuthorizationCodeGrantServices<Client, User, S>
  > {
  /** Allow optional refresh token. Defaults to true. */
  allowRefreshToken?: boolean;
  /** Custom PKCE challenge methods. Defaults to S256 only. */
  challengeMethods?: ChallengeMethods;
  /**
   * Whether to require PKCE for all authorization requests.
   *
   * Per OAuth 2.1 and security best practices, PKCE is required for all OAuth
   * clients, including confidential clients. Defaults to `true`; set it to
   * `false` only to interoperate with legacy clients that cannot send a
   * `code_challenge`.
   *
   * @default true
   * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-7.5.2
   */
  requirePKCE?: boolean;
  /**
   * Whether a client that presents a `code_verifier` must still authenticate
   * with its client credentials.
   *
   * PKCE proves the token request comes from the same party that started the
   * authorization request; it says nothing about *which client* that party is.
   * OAuth 2.1 and RFC 7636 both treat PKCE as additional to client
   * authentication, never a replacement for it, so a confidential client's
   * secret is still required on this grant.
   *
   * Defaults to `true`: confidential clients authenticate alongside PKCE.
   * Public clients, which have no secret, are unaffected. Setting `false`
   * explicitly enables legacy behavior where PKCE replaces client credentials;
   * use that opt-out only for an integration that requires it.
   *
   * @default true
   * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-4.1.3
   * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.5
   * @see https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1
   */
  requireClientAuthentication?: boolean;
}

/** Client credentials extended with optional PKCE code_verifier. */
export interface PKCEClientCredentials extends ClientCredentials {
  /** The PKCE `code_verifier`, present when the client used PKCE (RFC 7636). */
  codeVerifier?: string;
}

/** Options for generating an authorization code. */
export interface GenerateAuthorizationCodeOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> {
  /** The client the code is issued to. */
  client: Client;
  /** The resource owner the code authorizes. */
  user: User;
  /** The scope to bind to the code. */
  scope?: S | null;
  /** Redirect URI to bind to the code; must match again at the token exchange. */
  redirectUri?: string | null;
  /** PKCE `code_challenge` to bind to the code (RFC 7636). */
  challenge?: string | null;
  /** PKCE `code_challenge_method` (e.g. `S256`). Defaults to `S256`. */
  challengeMethod?: string | null;
  /** OIDC nonce to bind to the code (echoed into the id_token). */
  nonce?: string | null;
}

/**
 * The authorization code grant type.
 *
 * Implements RFC 6749 Section 4.1 with PKCE support (RFC 7636).
 *
 * PKCE (Proof Key for Code Exchange) is **required by default** for all
 * clients, including confidential ones, per OAuth 2.1. Set `requirePKCE: false`
 * only to interoperate with legacy clients that cannot send a `code_challenge`.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
 * @see https://datatracker.ietf.org/doc/html/rfc7636
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.1
 */
export class AuthorizationCodeGrant<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> extends AbstractGrant<
  Client,
  User,
  S,
  AuthorizationCodeGrantServices<Client, User, S>
> {
  /** The OAuth2 grant type: `authorization_code`. */
  readonly grantType = "authorization_code";
  /** The PKCE challenge methods this grant accepts. Defaults to `S256` only. */
  challengeMethods: ChallengeMethods;
  /**
   * Whether PKCE is required for all authorization requests.
   * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-7.5.2
   */
  requirePKCE: boolean;
  /**
   * Whether a client presenting a `code_verifier` must still authenticate with
   * its client credentials. Defaults to `true`.
   * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.5
   */
  requireClientAuthentication: boolean;

  /** Creates the grant from its {@linkcode AuthorizationCodeGrantOptions}. */
  constructor(options: AuthorizationCodeGrantOptions<Client, User, S>) {
    super({
      ...options,
      allowRefreshToken: options.allowRefreshToken ?? true,
    });
    this.challengeMethods = options.challengeMethods ?? defaultChallengeMethods;
    this.requirePKCE = options.requirePKCE ?? true;
    this.requireClientAuthentication = options.requireClientAuthentication ??
      true;
  }

  /**
   * Extracts client credentials from a request, carrying the PKCE
   * `code_verifier` alongside them when the client sent one.
   *
   * Unless {@linkcode requireClientAuthentication} is set, a `code_verifier`
   * drops the `client_secret` from the returned credentials, so the client is
   * looked up rather than authenticated.
   */
  protected override getClientCredentials(
    request: Request,
    body: FormData,
  ): PKCEClientCredentials {
    const credentials = super.getClientCredentials(request, body);

    const codeVerifier = body.get("code_verifier");
    if (typeof codeVerifier === "string") {
      return this.requireClientAuthentication
        ? { ...credentials, codeVerifier }
        : { ...credentials, codeVerifier, clientSecret: undefined };
    }

    return credentials;
  }

  /** Gets a client by ID without authentication. */
  async getClient(
    clientId: string,
    clientService: ClientServiceInterface<Client, User>,
  ): Promise<Client> {
    const client = await clientService.get(clientId);
    if (!client) {
      throw new InvalidClientError("client not found");
    }
    return client;
  }

  /**
   * Authenticates a client from a request.
   *
   * By default a `code_verifier` stands in for `client_secret` authentication,
   * so the client is only looked up by id. Set
   * {@linkcode requireClientAuthentication} to `true` to require credentials
   * from a confidential client even when it sends a `code_verifier`.
   *
   * @throws {InvalidClientError} When the client is unknown or its credentials do not authenticate it.
   */
  override async getAuthenticatedClient(
    request: Request,
    body: FormData,
  ): Promise<Client> {
    const { clientService } = await this.resolveServices(request);
    const { clientId, clientSecret, codeVerifier } = this.getClientCredentials(
      request,
      body,
    );

    if (codeVerifier && !this.requireClientAuthentication) {
      const client = await clientService.get(clientId);
      if (!client) {
        throw new InvalidClientError("client authentication failed");
      }
      return client;
    }

    return await authenticateClientCredentials(
      { clientId, clientSecret },
      clientService,
    );
  }

  /**
   * Resolves an allowed challenge method by name, defaulting to `S256`.
   *
   * Only names {@linkcode challengeMethods} holds as its own callable
   * properties resolve, so a client cannot reach an inherited
   * `Object.prototype` member such as `toString` by naming it as its
   * `code_challenge_method`.
   */
  getChallengeMethod(
    challengeMethod?: string | null,
  ): ChallengeMethod | undefined {
    return getChallengeMethod(this.challengeMethods, challengeMethod);
  }

  /** Validates that the challenge method is allowed. */
  validateChallengeMethod(challengeMethod?: string | null): boolean {
    return !!this.getChallengeMethod(challengeMethod);
  }

  /**
   * Verifies that a code verifier matches the authorization code's challenge.
   * https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
   */
  async verifyCode(
    code: AuthorizationCode<Client, User, S>,
    verifier: string,
  ): Promise<boolean> {
    if (!code.challenge) return false;
    const challengeMethod = this.getChallengeMethod(code.challengeMethod);
    if (challengeMethod) {
      const challenge = await challengeMethod(verifier);
      if (challenge !== code.challenge) return false;
    } else {
      throw new ServerError("code_challenge_method not implemented");
    }
    return true;
  }

  /**
   * Generates and saves an authorization code. Resolves its own
   * `authorizationCodeService` from the request.
   */
  async generateAuthorizationCode(
    options: GenerateAuthorizationCodeOptions<Client, User, S>,
    request: Request,
  ): Promise<AuthorizationCode<Client, User, S>> {
    const { authorizationCodeService } = await this.resolveServices(request);
    const {
      client,
      user,
      scope,
      redirectUri,
      challenge,
      challengeMethod,
      nonce,
    } = options;

    const authorizationCode: AuthorizationCode<Client, User, S> = {
      code: await authorizationCodeService.generateCode(client, user, scope),
      expiresAt: await authorizationCodeService.expiresAt(client, user, scope),
      client,
      user,
    };

    if (scope) authorizationCode.scope = scope;
    if (redirectUri) authorizationCode.redirectUri = redirectUri;
    if (challenge) authorizationCode.challenge = challenge;
    if (challengeMethod) authorizationCode.challengeMethod = challengeMethod;
    if (nonce) authorizationCode.nonce = nonce;

    return await authorizationCodeService.save(authorizationCode);
  }

  /**
   * Handles a token request for the authorization code grant.
   *
   * Exchanges an authorization code for an access token. If PKCE was used
   * during authorization, the code_verifier must be provided.
   *
   * The code is claimed by revoking it: only the caller whose revoke wins
   * receives a token, so concurrent exchanges of one code cannot both succeed.
   *
   * @throws {InvalidRequestError} When `code` is missing, a required `code_verifier` is absent, or the verifier is malformed.
   * @throws {InvalidGrantError} When the code is unknown, expired, already claimed, or its verifier or `redirect_uri` does not match.
   * @throws {InvalidClientError} When the code was issued to another client.
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
   * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.5
   */
  async token(
    request: Request,
    client: Client,
    body: FormData,
  ): Promise<Token<Client, User, S>> {
    const { authorizationCodeService, tokenService } = await this
      .resolveServices(request);

    const code = body.get("code");
    if (typeof code !== "string") {
      throw new InvalidRequestError("code parameter required");
    }

    // RFC 6819 §4.4.1.1: code replay revokes already-issued tokens and rejects.
    if (await tokenService.revokeCode(code)) {
      throw new InvalidGrantError("code already used");
    }

    const authorizationCode = await authorizationCodeService.get(code);
    if (!authorizationCode || authorizationCode.expiresAt < new Date()) {
      throw new InvalidGrantError("invalid code");
    }
    if (!await authorizationCodeService.revoke(authorizationCode)) {
      throw new InvalidGrantError("code already used");
    }

    const codeVerifier = body.get("code_verifier");
    if (typeof codeVerifier === "string") {
      if (!validateCodeVerifier(codeVerifier)) {
        throw new InvalidRequestError(
          "code_verifier must be 43-128 characters using [A-Z] / [a-z] / [0-9] / - / . / _ / ~",
        );
      }
      if (!await this.verifyCode(authorizationCode, codeVerifier)) {
        throw new InvalidGrantError("code_verifier verification failed");
      }
    } else if (authorizationCode.challenge) {
      throw new InvalidRequestError("code_verifier required");
    } else if (this.requirePKCE) {
      throw new InvalidRequestError("PKCE is required for this grant");
    }

    const {
      client: codeClient,
      user,
      scope,
      redirectUri: expectedRedirectUri,
    } = authorizationCode;
    if (client.id.toString() !== codeClient.id.toString()) {
      throw new InvalidClientError("code was issued to another client");
    }

    const redirectUri = body.get("redirect_uri");
    if (expectedRedirectUri) {
      if (typeof redirectUri !== "string") {
        throw new InvalidGrantError("redirect_uri parameter required");
      } else if (redirectUri !== expectedRedirectUri) {
        throw new InvalidGrantError("incorrect redirect_uri");
      }
    } else if (redirectUri) {
      throw new InvalidGrantError("did not expect redirect_uri parameter");
    }

    const token = await this.generateToken(client, user, scope, tokenService);
    token.code = code;
    const saved = await tokenService.save(token);
    if (authorizationCode.nonce) saved.nonce = authorizationCode.nonce;
    return saved;
  }
}
