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
   * - A **public** client must resolve `undefined` when a non-empty `secret` is
   *   presented. It was issued no secret, so a request carrying one is
   *   misconfigured or confused about the client's type, and the server answers
   *   `invalid_client` rather than silently treating it as public. An empty
   *   `secret` carries no credential — a Basic header of `client_id:` decodes
   *   to one — and counts as presenting none, so the client resolves.
   * - A **confidential** client resolves only with its correct `secret`. With
   *   the secret missing or wrong, resolve `undefined`.
   *
   * `runClientServiceContractTests` from `@udibo/oauth2/testing/contract` pins
   * all three rules; run it against your implementation.
   *
   * @param id The presented `client_id` — unauthenticated input.
   * @param secret The presented `client_secret`, omitted when the request
   * carried none.
   */
  getAuthenticated(
    id: string,
    secret?: string,
  ): Promise<Client | undefined>;

  /**
   * Resolves the user a client-credentials token acts for. Resolving
   * `undefined` is the conformant case and yields a user-less machine token;
   * see `ClientCredentialsGrant` before mapping a client to a human user.
   */
  getUser(client: Client | string): Promise<User | undefined>;
}
