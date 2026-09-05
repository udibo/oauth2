/**
 * Contract test suite for {@link UserServiceInterface} implementations.
 *
 * Apps that swap a `MemoryUserService` for a DB-backed implementation
 * can run this suite against their factory to verify they satisfy what
 * the framework expects.
 *
 * @example
 * ```ts
 * import { runUserServiceContractTests } from "@udibo/oauth2/testing/contract";
 * import type { UserServiceInterface } from "@udibo/oauth2/server/authorization";
 *
 * interface AppUser {
 *   id: string;
 *   username: string;
 * }
 * interface DrizzleUserService extends UserServiceInterface<AppUser> {
 *   register(user: AppUser, password: string): Promise<void>;
 * }
 * declare function freshUserService(): Promise<DrizzleUserService>;
 *
 * runUserServiceContractTests<AppUser>({
 *   makeService: freshUserService,
 *   addUser: (svc, user, password) =>
 *     (svc as DrizzleUserService).register(user, password),
 * });
 * ```
 *
 * @module
 */

import { assertEquals, assertStrictEquals } from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";

import type { UserServiceInterface } from "../../server/services/user.ts";
import type { MemoryUserShape } from "../services.ts";

/** Options for {@link runUserServiceContractTests}. */
export interface UserServiceContractOptions<U extends MemoryUserShape> {
  /**
   * Returns a fresh service for each test. Must be isolated — one test
   * leaking state into another defeats the contract guarantees.
   */
  makeService(): Promise<UserServiceInterface<U>> | UserServiceInterface<U>;
  /**
   * Adds a user with the given password to the service. Not part of the
   * interface, so the consumer supplies it. For the framework's own
   * `MemoryUserService` this is `(svc, user, pw) => svc.add(user, pw)`.
   */
  addUser(
    service: UserServiceInterface<U>,
    user: U,
    password: string,
  ): Promise<void>;
  /**
   * Optional factory for the test user. Defaults to a sequenced
   * `{ id, username }` shape that satisfies {@link MemoryUserShape}.
   * Override when your `User` requires extra fields.
   */
  makeUser?(seq: number): U;
  /**
   * Optional name for the inner `describe` block. Defaults to
   * `"UserServiceInterface contract"`.
   */
  describeName?: string;
}

const defaultMakeUser = <U extends MemoryUserShape>(seq: number): U =>
  ({ id: `u${seq}`, username: `user${seq}` }) as U;

/**
 * Runs the {@link UserServiceInterface} contract suite. Call from your
 * own test file — the suite registers `describe` / `it` blocks that the
 * runner picks up.
 */
export function runUserServiceContractTests<U extends MemoryUserShape>(
  options: UserServiceContractOptions<U>,
): void {
  const makeUser = options.makeUser ?? defaultMakeUser<U>;

  describe(options.describeName ?? "UserServiceInterface contract", () => {
    let service: UserServiceInterface<U>;

    beforeEach(async () => {
      service = await options.makeService();
    });

    describe("get", () => {
      it("returns undefined for an unknown id", async () => {
        assertStrictEquals(await service.get("does-not-exist"), undefined);
      });

      it("returns the user for a known id", async () => {
        const user = makeUser(1);
        await options.addUser(service, user, "pw");
        const fetched = await service.get(user.id);
        assertEquals(fetched?.id, user.id);
        assertEquals(fetched?.username, user.username);
      });
    });

    describe("getAuthenticated", () => {
      it("returns undefined for an unknown username", async () => {
        assertStrictEquals(
          await service.getAuthenticated("nobody", "pw"),
          undefined,
        );
      });

      it("returns undefined for a wrong password", async () => {
        const user = makeUser(2);
        await options.addUser(service, user, "correct");
        assertStrictEquals(
          await service.getAuthenticated(user.username, "wrong"),
          undefined,
        );
      });

      it("returns the user when username + password match", async () => {
        const user = makeUser(3);
        await options.addUser(service, user, "secret");
        const auth = await service.getAuthenticated(user.username, "secret");
        assertEquals(auth?.id, user.id);
      });
    });
  });
}
