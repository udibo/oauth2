/**
 * Authorization Code grant type implementation with PKCE support.
 * RFC 6749 Section 4.1 and RFC 7636.
 * @module
 */

import type { AuthorizationCode } from "../../models/authorization-code.ts";
import type { AuthenticationContext } from "../../models/authentication.ts";
import { snapshotAuthenticationContext } from "../../utils/authentication-context.ts";
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
  isOAuth2Error,
  type OAuth2Error,
  ServerError,
} from "../../errors.ts";
import type { ChallengeMethod, ChallengeMethods } from "../../utils/pkce.ts";
import {
  challengeMethods as defaultChallengeMethods,
  getChallengeMethod,
  validateCodeVerifier,
} from "../../utils/pkce.ts";
import { authenticateClientCredentials } from "../client-authentication.ts";
import { sha256Hash } from "../utils/hash.ts";
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
 * What the authorization code grant observed when a code that already issued
 * tokens was presented again. Passed to
 * {@link AuthorizationCodeGrantOptions.onCodeReuse}.
 */
export interface CodeReuseEvent<Client extends ClientInterface> {
  /**
   * The SHA-256 digest of the replayed code, as lowercase hex — the value a
   * store that hashes codes keys them on, so it correlates without recording
   * the code itself.
   */
  codeHash: string;
  /**
   * The client that presented the code. It is the code's own client only when
   * the token service's `revokeCode` honors its `client` argument. A public
   * client, or any client the grant looks up by id because
   * `requireClientAuthentication` is `false`, is named by `client_id` alone,
   * so whoever holds the spent code can present it as that client.
   */
  client: Client;
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
> extends GrantOptions<
  Client,
  User,
  S,
  AuthorizationCodeGrantServices<Client, User, S>
> {
  /** Whether to issue a refresh token with the access token. Defaults to `true`. */
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
   * Defaults to `true`: confidential clients authenticate alongside PKCE, and
   * a public client authenticates by `client_id` alone — one that attaches a
   * `client_secret` it was never issued is refused, as on every other grant.
   * Setting `false` explicitly enables legacy behavior where PKCE replaces
   * client credentials: a request carrying a `code_verifier` is looked up by
   * id, so a presented secret is not checked at all. Use that opt-out only for
   * an integration that requires it.
   *
   * @default true
   * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-4.1.3
   * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.5
   * @see https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1
   */
  requireClientAuthentication?: boolean;
  /**
   * Called when a code that already issued tokens is presented again and the
   * token service's `revokeCode` revoked those tokens — record it as a
   * security event. A `revokeCode` that honors its `client` argument revokes
   * nothing, and so does not fire this, for a client other than the code's
   * own; {@linkcode CodeReuseEvent.client} says who that excludes.
   *
   * Trigger point `code-reuse` (see `docs/trigger-points.md`).
   * Fire-and-forget: it is awaited, but a throw is caught and logged, never
   * rethrown, so a failing security-logging hook cannot change the
   * client-facing `invalid_grant` a replayed code always yields.
   */
  onCodeReuse?: (event: CodeReuseEvent<Client>) => void | Promise<void>;
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
  /** Verified event to capture on this code, supplied by authentication policy. */
  authenticationContext?: AuthenticationContext;
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
  readonly #onCodeReuse?: (
    event: CodeReuseEvent<Client>,
  ) => void | Promise<void>;

  /** Creates the grant from its {@linkcode AuthorizationCodeGrantOptions}. */
  constructor(options: AuthorizationCodeGrantOptions<Client, User, S>) {
    super({
      ...options,
      allowRefreshToken: options.allowRefreshToken ?? true,
    });
    this.challengeMethods = options.challengeMethods ?? defaultChallengeMethods;
    this.requirePKCE = options.requirePKCE ?? true;
    this.requireClientAuthentication =
      options.requireClientAuthentication ?? true;
    this.#onCodeReuse = options.onCodeReuse;
  }

  /**
   * Extracts client credentials from a request, carrying the PKCE
   * `code_verifier` alongside them when the client sent one.
   *
   * When {@linkcode requireClientAuthentication} is explicitly `false`, a
   * `code_verifier` drops the `client_secret` from the returned credentials,
   * so the client is looked up rather than authenticated.
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
   * Confidential clients authenticate with their registered secret by default,
   * including when they send a `code_verifier`. Setting
   * {@linkcode requireClientAuthentication} to `false` makes a request carrying
   * a `code_verifier` look up the client by id without authenticating it.
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
    const authenticationContext = snapshotAuthenticationContext(
      options.authenticationContext,
    );
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
    if (authenticationContext) {
      authorizationCode.authenticationContext = authenticationContext;
    }

    return await authorizationCodeService.save(authorizationCode);
  }

  /**
   * Handles a token request for the authorization code grant.
   *
   * Exchanges an authorization code for an access token. If PKCE was used
   * during authorization, the code_verifier must be provided.
   *
   * A failed exchange still consumes the code: one that fails the
   * client-match, verifier or `redirect_uri` check, whose token cannot be
   * generated, or that `exchangeCode` refuses with an OAuth2 error, is claimed
   * before the error is thrown. Any other error from `exchangeCode`, such as a
   * lost database connection, leaves the code claimable. Only the caller whose
   * claim wins receives a token, given an atomic
   * `authorizationCodeService.revoke`.
   *
   * When the token service implements
   * {@linkcode TokenServiceInterface.exchangeCode}, the grant claims the code
   * and saves the token in that one call. Otherwise it claims the code with
   * `authorizationCodeService.revoke` before its checks and saves the token
   * with `tokenService.save` after them; a replay that lands between those
   * two calls finds no token to revoke, so the token saved afterwards stays
   * live.
   *
   * A code presented after it was claimed, whether it was gone when the
   * request read it or a concurrent exchange won the claim, even one that
   * then fails its checks, asks
   * `tokenService.revokeCode` to revoke the tokens issued from it on behalf of
   * the presenting client, fires `onCodeReuse` when it did, and fails with
   * `invalid_grant` (RFC 6819 §4.4.1.1).
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
    const { authorizationCodeService, tokenService } =
      await this.resolveServices(request);

    const code = body.get("code");
    if (typeof code !== "string") {
      throw new InvalidRequestError("code parameter required");
    }

    const authorizationCode = await authorizationCodeService.get(code);
    if (!authorizationCode) {
      throw await this.#refuseClaimedCode(
        tokenService,
        code,
        client,
        "invalid code",
      );
    }
    if (authorizationCode.expiresAt < new Date()) {
      throw new InvalidGrantError("invalid code");
    }

    const exchangeCode = tokenService.exchangeCode?.bind(tokenService);
    if (
      !exchangeCode &&
      !(await authorizationCodeService.revoke(authorizationCode))
    ) {
      throw await this.#refuseClaimedCode(tokenService, code, client);
    }

    let token: Token<Client, User, S>;
    try {
      await this.#checkExchange(authorizationCode, client, body);
      token = await this.generateToken(
        client,
        authorizationCode.user,
        authorizationCode.scope,
        tokenService,
        authorizationCode.authenticationContext,
      );
    } catch (error) {
      if (exchangeCode) {
        await this.#consumeFailedExchange(
          authorizationCodeService,
          tokenService,
          authorizationCode,
          client,
        );
      }
      throw error;
    }
    token.code = code;

    let saved: Token<Client, User, S> | undefined;
    if (exchangeCode) {
      try {
        saved = await exchangeCode(authorizationCode, token);
      } catch (error) {
        if (isOAuth2Error(error)) {
          await this.#consumeFailedExchange(
            authorizationCodeService,
            tokenService,
            authorizationCode,
            client,
          );
        }
        throw error;
      }
    } else {
      saved = await tokenService.save(token);
    }
    if (!saved) {
      throw await this.#refuseClaimedCode(tokenService, code, client);
    }
    if (authorizationCode.nonce) saved.nonce = authorizationCode.nonce;
    return saved;
  }

  async #checkExchange(
    authorizationCode: AuthorizationCode<Client, User, S>,
    client: Client,
    body: FormData,
  ): Promise<void> {
    const codeVerifier = body.get("code_verifier");
    if (typeof codeVerifier === "string") {
      if (!validateCodeVerifier(codeVerifier)) {
        throw new InvalidRequestError(
          "code_verifier must be 43-128 characters using [A-Z] / [a-z] / [0-9] / - / . / _ / ~",
        );
      }
      if (!(await this.verifyCode(authorizationCode, codeVerifier))) {
        throw new InvalidGrantError("code_verifier verification failed");
      }
    } else if (authorizationCode.challenge) {
      throw new InvalidRequestError("code_verifier required");
    } else if (this.requirePKCE) {
      throw new InvalidRequestError("PKCE is required for this grant");
    }

    if (client.id.toString() !== authorizationCode.client.id.toString()) {
      throw new InvalidClientError("code was issued to another client");
    }

    const redirectUri = body.get("redirect_uri");
    const expectedRedirectUri = authorizationCode.redirectUri;
    if (expectedRedirectUri) {
      if (typeof redirectUri !== "string") {
        throw new InvalidGrantError("redirect_uri parameter required");
      } else if (redirectUri !== expectedRedirectUri) {
        throw new InvalidGrantError("incorrect redirect_uri");
      }
    } else if (redirectUri) {
      throw new InvalidGrantError("did not expect redirect_uri parameter");
    }
  }

  async #consumeFailedExchange(
    authorizationCodeService: AuthorizationCodeGrantServices<
      Client,
      User,
      S
    >["authorizationCodeService"],
    tokenService: AuthorizationCodeGrantServices<
      Client,
      User,
      S
    >["tokenService"],
    authorizationCode: AuthorizationCode<Client, User, S>,
    client: Client,
  ): Promise<void> {
    try {
      if (!(await authorizationCodeService.revoke(authorizationCode))) {
        await this.#refuseClaimedCode(
          tokenService,
          authorizationCode.code,
          client,
        );
      }
    } catch (error) {
      console.error(
        "[@udibo/oauth2] could not consume the code of a failed exchange:",
        error instanceof Error ? error.message : error,
      );
    }
  }

  async #refuseClaimedCode(
    tokenService: AuthorizationCodeGrantServices<
      Client,
      User,
      S
    >["tokenService"],
    code: string,
    client: Client,
    unrevokedMessage = "code already used",
  ): Promise<OAuth2Error> {
    if (!(await tokenService.revokeCode(code, client))) {
      return new InvalidGrantError(unrevokedMessage);
    }
    await this.#notifyCodeReuse({ codeHash: await sha256Hash(code), client });
    return new InvalidGrantError("code already used");
  }

  async #notifyCodeReuse(event: CodeReuseEvent<Client>): Promise<void> {
    if (!this.#onCodeReuse) return;
    try {
      await this.#onCodeReuse(event);
    } catch (error) {
      console.error(
        "[@udibo/oauth2] onCodeReuse hook failed:",
        error instanceof Error ? error.message : error,
      );
    }
  }
}
