/**
 * Base grant type implementation for OAuth2.
 *
 * Provides the abstract base class and the framework-facing grant contract for
 * implementing OAuth2 grant types per RFC 6749.
 *
 * **Service resolution.** A grant holds no storage. It is constructed with a
 * `resolve(request) => services` function that returns the full set of services
 * that grant needs, and the base resolves them per request through
 * `resolveServices`. The grant infers its `Client`/`User`/`Scope` types from
 * that `resolve` return, so a grant can be built standalone (e.g. for tests) and
 * the {@link AuthorizationServer} infers its own generics from the grants. The
 * base provides stateless helpers (`acceptedScope`, `generateToken`) that take
 * the resolved services as arguments.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4
 * @module
 */

import type {
  ClientCredentials,
  ClientInterface,
} from "../../models/client.ts";
import type { RefreshToken, Token } from "../../models/token.ts";
import type { AbstractScope, ScopeConstructor } from "../../models/scope.ts";
import { BasicScope } from "../../models/scope.ts";
import { InvalidScopeError } from "../../errors.ts";
import {
  authenticateClientCredentials,
  extractClientCredentials,
} from "../client-authentication.ts";
import type { ClientServiceInterface } from "../services/client.ts";
import type { TokenServiceInterface } from "../services/token.ts";

/**
 * The core services every grant needs: client lookup/authentication and token
 * storage. Each grant defines its own services interface by extending this with
 * the grant-specific services it resolves (e.g. `authorizationCodeService`).
 */
export interface GrantServices<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> {
  /** Looks up and authenticates clients presenting a token request. */
  clientService: ClientServiceInterface<Client, User>;
  /** Generates and persists access and refresh tokens. */
  tokenService: TokenServiceInterface<Client, User, Scope>;
}

/**
 * The framework-facing grant contract that {@link AuthorizationServer}
 * dispatches through. It carries no grant-specific service types, so any grant —
 * including a third-party grant with its own services — is assignable to it and
 * lives in the server's grant map without `any`. Grants resolve their own
 * services from the request, so these methods take no services argument.
 */
export interface DispatchableGrant<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> {
  /** The OAuth2 `grant_type` value this grant handles (e.g. `authorization_code`). */
  readonly grantType: string;
  /**
   * Whether this grant's tokens represent an end-user authentication, making
   * them eligible for an id_token. Treated as `true` when absent; grants with
   * no authentication event (client_credentials) set `false`.
   */
  readonly issuesIdToken?: boolean;
  /**
   * Authenticates the client presenting this grant's token request. `body` is
   * the request's form body, parsed once by the token endpoint — a grant reads
   * its parameters from it instead of consuming the request.
   */
  getAuthenticatedClient(request: Request, body: FormData): Promise<Client>;
  /**
   * Exchanges the request for a token. `body` is the request's form body,
   * parsed once by the token endpoint.
   */
  token(
    request: Request,
    client: Client,
    body: FormData,
  ): Promise<Token<Client, User, Scope>>;
}

/**
 * Configuration shared by all grants: how to reach the services the grant
 * needs, plus the scope and refresh-token settings. Each grant's own options
 * type extends this with its grant-specific settings.
 */
export interface GrantOptions<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
  Services extends GrantServices<Client, User, Scope> = GrantServices<
    Client,
    User,
    Scope
  >,
> {
  /** Resolves the services this grant needs for a request. */
  resolve: (request: Request) => Services | Promise<Services>;
  /** Scope constructor used to parse scope strings. Defaults to {@linkcode BasicScope}. */
  Scope?: ScopeConstructor<Scope>;
  /** Allow optional refresh token. */
  allowRefreshToken?: boolean;
}

/**
 * Abstract base class for grant type implementations.
 *
 * Extend this to create custom grant types, parameterized by the services
 * interface the grant resolves. A subclass implements {@link token}, reaches
 * its services through {@link resolveServices}, and overrides
 * {@link getAuthenticatedClient} only when it authenticates clients by
 * something other than their registered credentials (as the authorization-code
 * grant does for PKCE).
 */
export abstract class AbstractGrant<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
  Services extends GrantServices<Client, User, Scope> = GrantServices<
    Client,
    User,
    Scope
  >,
> implements DispatchableGrant<Client, User, Scope> {
  /** The OAuth2 `grant_type` value this grant handles (e.g. `authorization_code`). */
  abstract readonly grantType: string;
  /** Constructor used to parse scope strings into {@linkcode Scope} objects. */
  Scope: ScopeConstructor<Scope>;
  /** Allow optional refresh token. Defaults to false. */
  allowRefreshToken: boolean;
  #resolve: (request: Request) => Services | Promise<Services>;

  /** Creates a grant from the shared {@linkcode GrantOptions}. */
  constructor(options: GrantOptions<Client, User, Scope, Services>) {
    this.allowRefreshToken = options.allowRefreshToken ?? false;
    this.Scope = options.Scope ??
      (BasicScope as unknown as ScopeConstructor<Scope>);
    this.#resolve = options.resolve;
  }

  /** The services this grant needs for `request`, from its `resolve` option. */
  protected resolveServices(request: Request): Promise<Services> {
    return Promise.resolve(this.#resolve(request));
  }

  /** Parses a scope string into a Scope object. */
  parseScope(scopeText?: string | null): Scope | undefined {
    return scopeText ? new this.Scope(scopeText) : undefined;
  }

  /**
   * Validates and returns the accepted scope for the client and user, per the
   * `TokenServiceInterface.acceptedScope` contract: a returned scope replaces
   * the requested one (narrowing), `null`/`undefined` accepts the requested
   * scope as-is, and `false` rejects.
   *
   * `user` is `undefined` when the client is acting as its own resource owner
   * (client credentials, RFC 6749 §4.4), so the token service decides scope
   * from the client alone.
   *
   * Throws InvalidScopeError if the scope is rejected.
   */
  async acceptedScope(
    client: Client,
    user: User | undefined,
    scope: Scope | null | undefined,
    tokenService: TokenServiceInterface<Client, User, Scope>,
  ): Promise<Scope | null | undefined> {
    const acceptedScope = await tokenService.acceptedScope(client, user, scope);
    if (acceptedScope === false) {
      throw new InvalidScopeError(scope ? "invalid scope" : "scope required");
    }
    return acceptedScope ?? scope;
  }

  /**
   * Extracts client credentials from a request: HTTP Basic first, then the
   * `client_id`/`client_secret` of the already-parsed `body`. Override to add
   * grant-specific credential rules (as the authorization-code grant does for
   * PKCE).
   *
   * @throws {InvalidClientError} If the request presents no usable credentials.
   */
  protected getClientCredentials(
    request: Request,
    body: FormData,
  ): ClientCredentials {
    return extractClientCredentials(request, body);
  }

  /**
   * Clamps a token's expiries to the absolute expiry of its rotation family,
   * so nothing derived from a family outlives it — an access token issued a
   * moment before the ceiling included. Mutates `token`; a token with no
   * expiry of its own takes the family's.
   */
  protected capAtFamilyExpiry(
    token: Token<Client, User, Scope> | RefreshToken<Client, User, Scope>,
    familyExpiresAt: Date,
  ): void {
    if (
      !token.accessTokenExpiresAt ||
      familyExpiresAt < token.accessTokenExpiresAt
    ) {
      token.accessTokenExpiresAt = familyExpiresAt;
    }
    if ("refreshToken" in token) {
      const refreshToken = token as RefreshToken<Client, User, Scope>;
      if (
        !refreshToken.refreshTokenExpiresAt ||
        familyExpiresAt < refreshToken.refreshTokenExpiresAt
      ) {
        refreshToken.refreshTokenExpiresAt = familyExpiresAt;
      }
    }
  }

  /**
   * Generates a token for a client and user from a resolved `tokenService`.
   * Includes a refresh token if allowed, which starts a new rotation family:
   * `familyId` plus the `familyCreatedAt` anchor the refresh grant caps
   * rotations against. When the token service caps families
   * ({@linkcode TokenServiceInterface.refreshTokenFamilyExpiresAt}), both
   * expiries are clamped to the new family's ceiling.
   *
   * Pass `user: undefined` for a token the client holds as its own resource
   * owner (client credentials, RFC 6749 §4.4). Such a token is never issued a
   * refresh token whatever `allowRefreshToken` says — there is no resource
   * owner whose authorization a rotation could carry forward.
   */
  async generateToken(
    client: Client,
    user: User | undefined,
    scope: Scope | null | undefined,
    tokenService: TokenServiceInterface<Client, User, Scope>,
  ): Promise<Token<Client, User, Scope>> {
    const token: Token<Client, User, Scope> = {
      accessToken: await tokenService.generateAccessToken(client, user, scope),
      client,
    };

    if (user !== undefined) token.user = user;
    if (scope) token.scope = scope;

    const accessTokenExpiresAt = await tokenService.accessTokenExpiresAt(
      client,
      user,
      scope,
    );
    if (accessTokenExpiresAt) token.accessTokenExpiresAt = accessTokenExpiresAt;

    if (this.allowRefreshToken && user !== undefined) {
      const refreshToken = await tokenService.generateRefreshToken(
        client,
        user,
        scope,
      );
      if (refreshToken) {
        const familyCreatedAt = new Date();
        const result: RefreshToken<Client, User, Scope> = {
          ...token,
          refreshToken,
          familyId: crypto.randomUUID(),
          familyCreatedAt,
        };
        const refreshTokenExpiresAt = await tokenService.refreshTokenExpiresAt(
          client,
          user,
          scope,
        );
        if (refreshTokenExpiresAt) {
          result.refreshTokenExpiresAt = refreshTokenExpiresAt;
        }
        const familyExpiresAt = await tokenService
          .refreshTokenFamilyExpiresAt?.(client, user, familyCreatedAt, scope);
        if (familyExpiresAt) this.capAtFamilyExpiry(result, familyExpiresAt);
        return result;
      }
    }

    return token;
  }

  /**
   * Authenticates the client presenting this grant's token request against the
   * grant's own `clientService`, from the credentials the request presents.
   *
   * Override to apply grant-specific authentication rules — the
   * authorization-code grant accepts a PKCE `code_verifier` in place of a
   * client secret for public clients.
   *
   * @throws {InvalidClientError} If authentication fails.
   */
  async getAuthenticatedClient(
    request: Request,
    body: FormData,
  ): Promise<Client> {
    const { clientService } = await this.resolveServices(request);
    return await authenticateClientCredentials(
      this.getClientCredentials(request, body),
      clientService,
    );
  }

  /**
   * Handles a token request. `body` is the request's form body, parsed once by
   * the token endpoint; the grant resolves the services it needs from the
   * request internally.
   */
  abstract token(
    request: Request,
    client: Client,
    body: FormData,
  ): Promise<Token<Client, User, Scope>>;
}
