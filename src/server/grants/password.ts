/**
 * Resource Owner Password Credentials grant type implementation.
 * RFC 6749 Section 4.3.
 *
 * @deprecated The password grant is **NOT RECOMMENDED** for use and is
 * removed in OAuth 2.1. It exposes user credentials directly to clients
 * and cannot support modern security features like MFA.
 *
 * Consider using the authorization code grant with PKCE instead.
 *
 * This grant performs **no second-factor check**: a token request is
 * non-interactive, so there is nowhere to challenge the user. Wiring it means
 * enforcing your own MFA policy inside `getAuthenticated`, or accepting that a
 * password alone mints tokens for every user — including ones enrolled in MFA.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.4
 * @module
 */

import type { ClientInterface } from "../../models/client.ts";
import type { Token } from "../../models/token.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import { InvalidGrantError, InvalidRequestError } from "../../errors.ts";
import type { UserServiceInterface } from "../services/user.ts";
import {
  AbstractGrant,
  type GrantOptions,
  type GrantServices,
} from "./grant.ts";

/** Services required by the password grant. */
export interface PasswordGrantServices<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> extends GrantServices<Client, User, S> {
  /** Authenticates the resource owner by username and password. */
  userService: UserServiceInterface<User>;
}

/** Options for configuring the password grant. */
export interface PasswordGrantOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> extends
  GrantOptions<Client, User, S, PasswordGrantServices<Client, User, S>> {
  /** Allow optional refresh token. Defaults to true. */
  allowRefreshToken?: boolean;
}

/**
 * The resource owner password credentials grant type.
 *
 * Allows exchanging a user's username and password directly for tokens.
 * This grant type should only be used when there is a high degree of trust
 * between the resource owner and the client.
 *
 * @deprecated This grant is **NOT RECOMMENDED** and is removed in OAuth 2.1.
 * Use the authorization code grant with PKCE instead. Only use this for:
 * - Legacy system migration
 * - First-party trusted applications where no alternative exists
 *
 * Security concerns:
 * - Exposes user credentials directly to the client application
 * - Cannot support MFA or other modern authentication flows
 * - No user consent UI for scope approval
 *
 * **MFA is not enforced here and cannot be.** The grant treats a truthy
 * {@linkcode UserServiceInterface.getAuthenticated} result as sufficient to
 * issue tokens; it never asks whether the user has a second factor, and a
 * token request has no interactive step in which to challenge one. If any of
 * your users can enroll in MFA, either reject them from `getAuthenticated`
 * (fail closed) or accept that their password alone yields full tokens.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.4
 */
export class PasswordGrant<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> extends AbstractGrant<
  Client,
  User,
  S,
  PasswordGrantServices<Client, User, S>
> {
  /** The OAuth2 grant type: `password`. */
  readonly grantType = "password";

  /** Creates the grant from its {@linkcode PasswordGrantOptions}. */
  constructor(options: PasswordGrantOptions<Client, User, S>) {
    super({
      ...options,
      allowRefreshToken: options.allowRefreshToken ?? true,
    });
  }

  /**
   * Handles a token request for the password grant.
   * Validates the username/password and issues tokens.
   *
   * The password is the only factor checked. Any second-factor policy must be
   * applied by {@linkcode UserServiceInterface.getAuthenticated}, whose errors
   * propagate to the token response unchanged.
   *
   * @throws {InvalidRequestError} If `username` or `password` is missing.
   * @throws {InvalidGrantError} If user authentication fails.
   * @throws {InvalidScopeError} If the requested scope is rejected.
   */
  async token(
    request: Request,
    client: Client,
    body: FormData,
  ): Promise<Token<Client, User, S>> {
    const { tokenService, userService } = await this.resolveServices(request);

    const scopeText = body.get("scope");
    let scope = this.parseScope(
      typeof scopeText === "string" ? scopeText : undefined,
    );

    const username = body.get("username");
    if (!username || typeof username !== "string") {
      throw new InvalidRequestError("username parameter required");
    }

    const password = body.get("password");
    if (!password || typeof password !== "string") {
      throw new InvalidRequestError("password parameter required");
    }

    const user = await userService.getAuthenticated(username, password);
    if (!user) {
      throw new InvalidGrantError("user authentication failed");
    }

    const acceptedScope = await this.acceptedScope(
      client,
      user,
      scope,
      tokenService,
    );
    scope = acceptedScope ?? undefined;

    const token = await this.generateToken(client, user, scope, tokenService);
    return await tokenService.save(token);
  }
}
