/**
 * Client Credentials grant type implementation.
 * RFC 6749 Section 4.4.
 * @module
 */

import type { ClientInterface } from "../../models/client.ts";
import type { Token } from "../../models/token.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import { InvalidClientError } from "../../errors.ts";
import { authenticateClientCredentials } from "../client-authentication.ts";
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
 * **Only confidential clients may use it.** RFC 6749 §4.4 restricts this grant
 * to confidential clients, so a request that presents no client secret — a
 * public client, or a confidential client leaving its secret out — is refused
 * with 401 `invalid_client`. Register a machine client with a secret and send
 * that secret with HTTP Basic or as `client_secret` in the body. The grant
 * relies on `ClientServiceInterface.getAuthenticated` refusing a public client
 * that presents a secret, which `runClientServiceContractTests` pins. A client
 * service written before 0.9.2 must pass `runClientServiceContractTests`, or
 * `client_credentials` is not limited to confidential clients.
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
   * Authenticates the client from a request that must carry its client
   * secret, by HTTP Basic or in the body. Credentials are read through
   * {@linkcode getClientCredentials} and checked by the grant's
   * `clientService.getAuthenticated`.
   *
   * A subclass that authenticates clients by other means, such as a signed
   * client assertion, overrides this method and must itself admit only
   * confidential clients.
   *
   * @throws {InvalidClientError} If the request presents no non-empty client
   * secret, or authentication fails.
   */
  override async getAuthenticatedClient(
    request: Request,
    body: FormData,
  ): Promise<Client> {
    const credentials = this.getClientCredentials(request, body);
    if (!credentials.clientSecret) {
      throw new InvalidClientError("client authentication failed");
    }
    const { clientService } = await this.resolveServices(request);
    return await authenticateClientCredentials(credentials, clientService);
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
