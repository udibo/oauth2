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

  /** Retrieves an authenticated client. */
  getAuthenticated(
    id: string,
    secret?: string,
  ): Promise<Client | undefined>;

  /** Retrieves a user associated with a client (for client-credentials grant). */
  getUser(client: Client | string): Promise<User | undefined>;
}
