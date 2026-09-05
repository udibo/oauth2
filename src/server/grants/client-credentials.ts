/**
 * Client Credentials grant type implementation.
 * RFC 6749 Section 4.4.
 * @module
 */

import type { ClientInterface } from "../../models/client.ts";
import type { Token } from "../../models/token.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import {
  AbstractGrant,
  type GrantOptions,
  type GrantServices,
} from "./grant.ts";

/** Services required by the client credentials grant. */
export type ClientCredentialsGrantServices<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> = GrantServices<Client, User, S>;

/**
 * Options for configuring the client credentials grant. This grant never issues
 * a refresh token (RFC 6749 §4.4.3), so `allowRefreshToken` is not offered.
 */
export type ClientCredentialsGrantOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> = Omit<
  GrantOptions<
    Client,
    User,
    S,
    ClientCredentialsGrantServices<Client, User, S>
  >,
  "allowRefreshToken"
>;

/**
 * The client credentials grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-4.4
 *
 * Used for machine-to-machine authentication where the client itself
 * is the resource owner. Does not support refresh tokens.
 *
 * **The token need not carry a user.** RFC 6749 §4.4 has no resource owner, so
 * a `ClientServiceInterface.getUser` that resolves nothing is the conformant
 * case, not an error: the grant issues a token whose {@linkcode Token.user} is
 * unset, and `createJwtAccessTokenGenerator` names the client as its subject
 * (RFC 9068 §2.2). Resolving a human owner instead makes the machine
 * indistinguishable from that person — the _Client Impersonating Resource
 * Owner_ attack of RFC 9700 §4.15 — so map a client to a user only when that
 * user is a principal of its own, such as a per-application service account.
 */
export class ClientCredentialsGrant<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> extends AbstractGrant<
  Client,
  User,
  S,
  ClientCredentialsGrantServices<Client, User, S>
> {
  /** The OAuth2 grant type: `client_credentials`. */
  readonly grantType = "client_credentials";
  /** Machine flow — no end-user authentication event, so no id_token. */
  readonly issuesIdToken = false;

  /** Creates the grant from its {@linkcode ClientCredentialsGrantOptions}. */
  constructor(options: ClientCredentialsGrantOptions<Client, User, S>) {
    super({ ...options, allowRefreshToken: false });
  }

  /**
   * Handles a token request for the client credentials grant. Issues an access
   * token (never a refresh token) to the client acting as its own resource
   * owner.
   *
   * The token's {@linkcode Token.user} is whatever
   * `ClientServiceInterface.getUser` resolves for the client, and is left
   * unset when it resolves nothing — a user-less machine token, not a failure.
   *
   * @throws {InvalidScopeError} If the requested scope is rejected.
   */
  async token(
    request: Request,
    client: Client,
    body: FormData,
  ): Promise<Token<Client, User, S>> {
    const { tokenService, clientService } = await this.resolveServices(request);

    const scopeText = body.get("scope");
    let scope = this.parseScope(
      typeof scopeText === "string" ? scopeText : undefined,
    );

    const user = await clientService.getUser(client);

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
