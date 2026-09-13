import type { ClientInterface } from "../../models/client.ts";

/**
 * Service interface for client management.
 */
export interface ClientServiceInterface<
  Client extends ClientInterface,
  User,
> {
  /** Retrieves a client by ID. */
  get(id: string): Promise<Client | undefined>;

  /**
   * Authenticates a client from the credentials a request presented, resolving
   * the client on success and `undefined` on failure. The authorization server
   * answers `undefined` with `invalid_client`.
   *
   * A client registered with a secret is confidential; one registered without
   * a secret is public:
   *
   * - A **public** client must resolve when `secret` is omitted. The server
   *   always advertises `none` in `token_endpoint_auth_methods_supported`, so
   *   an implementation that demands a secret from every client makes that
   *   advertisement false.
   * - A **confidential** client resolves only with its correct `secret`. With
   *   the secret missing or wrong, resolve `undefined`.
   *
   * `runClientServiceContractTests` from `@udibo/oauth2/testing/contract` pins
   * both rules; run it against your implementation. It does not pin whether a
   * public client that presents a `secret` resolves, so do not rely on either
   * answer.
   *
   * @param id The presented `client_id` — unauthenticated input.
   * @param secret The presented `client_secret`, omitted when the request
   * carried none.
   */
  getAuthenticated(
    id: string,
    secret?: string,
  ): Promise<Client | undefined>;

  /** Retrieves a user associated with a client (for client-credentials grant). */
  getUser(client: Client | string): Promise<User | undefined>;
}
