/**
 * Contract test suite for {@link ClientServiceInterface} implementations.
 *
 * `getUser` is contract-conformant either way: resolving a user and resolving
 * nothing are both required to pass. A client that resolves nothing is a
 * machine client whose token carries no resource owner (RFC 6749 §4.4), not a
 * misconfiguration — the client credentials grant issues it a user-less token.
 * Resolve a user only when that user is a principal of its own, such as a
 * per-application service account; resolving a human owner hands the machine
 * that person's identity (RFC 9700 §4.15).
 *
 * @example
 * ```ts
 * import { runClientServiceContractTests } from "@udibo/oauth2/testing/contract";
 * import type { ClientInterface } from "@udibo/oauth2/server";
 * import type {
 *   ClientServiceInterface,
 *   UserServiceInterface,
 * } from "@udibo/oauth2/server/authorization";
 *
 * interface AppUser {
 *   id: string;
 *   username: string;
 * }
 * interface DrizzleUserService extends UserServiceInterface<AppUser> {
 *   register(user: AppUser, password: string): Promise<void>;
 * }
 * interface DrizzleClientService
 *   extends ClientServiceInterface<ClientInterface, AppUser> {
 *   register(
 *     client: ClientInterface,
 *     secret?: string,
 *     ownerUserId?: string,
 *   ): Promise<void>;
 * }
 * declare function freshServices(): Promise<{
 *   userService: DrizzleUserService;
 *   clientService: DrizzleClientService;
 * }>;
 *
 * runClientServiceContractTests<ClientInterface, AppUser>({
 *   makeServices: freshServices,
 *   addUser: (svc, user, pw) => (svc as DrizzleUserService).register(user, pw),
 *   addClient: (svc, client, secret, ownerUserId) =>
 *     (svc as DrizzleClientService).register(client, secret, ownerUserId),
 * });
 * ```
 *
 * @module
 */

import { assertEquals, assertStrictEquals } from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";

import type { ClientInterface } from "../../models/client.ts";
import type { ClientServiceInterface } from "../../server/services/client.ts";
import type { UserServiceInterface } from "../../server/services/user.ts";
import type { MemoryUserShape } from "../services.ts";

/** Options for {@link runClientServiceContractTests}. */
export interface ClientServiceContractOptions<
  C extends ClientInterface,
  U extends MemoryUserShape,
> {
  /**
   * Returns fresh services for each test. The `userService` is needed
   * because `clientService.getUser(client)` resolves through it.
   */
  makeServices():
    | Promise<{
      userService: UserServiceInterface<U>;
      clientService: ClientServiceInterface<C, U>;
    }>
    | {
      userService: UserServiceInterface<U>;
      clientService: ClientServiceInterface<C, U>;
    };
  /** Adds a user via the consumer's preferred mechanism. */
  addUser(
    service: UserServiceInterface<U>,
    user: U,
    password: string,
  ): Promise<void>;
  /**
   * Adds a client. Pass `secret` to register a confidential client; omit
   * for public. `ownerUserId` is the user returned by `getUser`; omit it to
   * register a client that resolves no user, which the suite requires to be
   * supported.
   */
  addClient(
    service: ClientServiceInterface<C, U>,
    client: C,
    secret?: string,
    ownerUserId?: string,
  ): Promise<void>;
  /** Builds a distinct user fixture for the given sequence number. Defaults to a minimal `{ id, username }` shape. */
  makeUser?(seq: number): U;
  /** Builds a distinct client fixture for the given sequence number. Defaults to a client granting `client_credentials`. */
  makeClient?(seq: number): C;
  /** Overrides the name passed to the outer `describe` block. */
  describeName?: string;
}

const defaultMakeUser = <U extends MemoryUserShape>(seq: number): U =>
  ({ id: `u${seq}`, username: `user${seq}` }) as U;
const defaultMakeClient = <C extends ClientInterface>(seq: number): C =>
  ({ id: `client-${seq}`, grants: ["client_credentials"] }) as C;

/** Runs the {@link ClientServiceInterface} contract suite. */
export function runClientServiceContractTests<
  C extends ClientInterface,
  U extends MemoryUserShape,
>(
  options: ClientServiceContractOptions<C, U>,
): void {
  const makeUser = options.makeUser ?? defaultMakeUser<U>;
  const makeClient = options.makeClient ?? defaultMakeClient<C>;

  describe(options.describeName ?? "ClientServiceInterface contract", () => {
    let userService: UserServiceInterface<U>;
    let clientService: ClientServiceInterface<C, U>;

    beforeEach(async () => {
      const services = await options.makeServices();
      userService = services.userService;
      clientService = services.clientService;
    });

    describe("get", () => {
      it("returns undefined for an unknown id", async () => {
        assertStrictEquals(await clientService.get("missing"), undefined);
      });

      it("returns the registered client", async () => {
        const client = makeClient(1);
        await options.addClient(clientService, client);
        const fetched = await clientService.get(client.id);
        assertEquals(fetched?.id, client.id);
      });
    });

    describe("getAuthenticated", () => {
      it("returns the public client without a secret", async () => {
        const client = makeClient(2);
        await options.addClient(clientService, client);
        const auth = await clientService.getAuthenticated(client.id);
        assertEquals(auth?.id, client.id);
      });

      it("returns undefined for a confidential client when no secret is supplied", async () => {
        const client = makeClient(3);
        await options.addClient(clientService, client, "secret");
        assertStrictEquals(
          await clientService.getAuthenticated(client.id),
          undefined,
        );
      });

      it("returns undefined for a confidential client with a wrong secret", async () => {
        const client = makeClient(4);
        await options.addClient(clientService, client, "correct");
        assertStrictEquals(
          await clientService.getAuthenticated(client.id, "wrong"),
          undefined,
        );
      });

      it("returns the confidential client with a matching secret", async () => {
        const client = makeClient(5);
        await options.addClient(clientService, client, "matching");
        const auth = await clientService.getAuthenticated(
          client.id,
          "matching",
        );
        assertEquals(auth?.id, client.id);
      });
    });

    describe("getUser", () => {
      it("resolves nothing for a client registered without a user, rather than failing", async () => {
        const client = makeClient(6);
        await options.addClient(clientService, client);
        assertStrictEquals(await clientService.getUser(client), undefined);
      });

      it("returns the associated user when one was registered", async () => {
        const user = makeUser(7);
        const client = makeClient(7);
        await options.addUser(userService, user, "pw");
        await options.addClient(clientService, client, undefined, user.id);
        const owner = await clientService.getUser(client);
        assertEquals(owner?.id, user.id);
      });

      it("accepts a client id (not just a client object)", async () => {
        const user = makeUser(8);
        const client = makeClient(8);
        await options.addUser(userService, user, "pw");
        await options.addClient(clientService, client, undefined, user.id);
        const owner = await clientService.getUser(client.id);
        assertEquals(owner?.id, user.id);
      });
    });
  });
}
