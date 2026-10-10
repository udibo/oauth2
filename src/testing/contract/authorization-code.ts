import { beforeEach, describe, expect, it } from "vitest";
import type { ClientInterface } from "../../models/client.ts";
import type { AuthorizationCode } from "../../models/authorization-code.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import type { AuthorizationCodeServiceInterface } from "../../server/services/authorization-code.ts";
import type { ClientServiceInterface } from "../../server/services/client.ts";
import type { UserServiceInterface } from "../../server/services/user.ts";
import type { MemoryUserShape } from "../services.ts";

/** Options for {@link runAuthorizationCodeServiceContractTests}. */
export interface AuthorizationCodeServiceContractOptions<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> {
  /** Returns fresh services for each test. */
  makeServices():
    | Promise<{
        userService: UserServiceInterface<U>;
        clientService: ClientServiceInterface<C, U>;
        authorizationCodeService: AuthorizationCodeServiceInterface<C, U, S>;
      }>
    | {
        userService: UserServiceInterface<U>;
        clientService: ClientServiceInterface<C, U>;
        authorizationCodeService: AuthorizationCodeServiceInterface<C, U, S>;
      };
  /** Persists a user with the given password into the user service under test. */
  addUser(
    service: UserServiceInterface<U>,
    user: U,
    password: string,
  ): Promise<void>;
  /** Persists a client (optionally with a secret and owning user) into the client service under test. */
  addClient(
    service: ClientServiceInterface<C, U>,
    client: C,
    secret?: string,
    ownerUserId?: string,
  ): Promise<void>;
  /** Builds a distinct user fixture for the given sequence number. Defaults to a minimal `{ id, username }` shape. */
  makeUser?(seq: number): U;
  /** Builds a distinct client fixture for the given sequence number. Defaults to a client granting `authorization_code`. */
  makeClient?(seq: number): C;
  /** Overrides the name passed to the outer `describe` block. */
  describeName?: string;
}

const defaultMakeUser = <U extends MemoryUserShape>(seq: number): U =>
  ({ id: `u${seq}`, username: `user${seq}` }) as U;
const defaultMakeClient = <C extends ClientInterface>(seq: number): C =>
  ({ id: `client-${seq}`, grants: ["authorization_code"] }) as C;

/** Runs the {@link AuthorizationCodeServiceInterface} contract suite. */
export function runAuthorizationCodeServiceContractTests<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
>(options: AuthorizationCodeServiceContractOptions<C, U, S>): void {
  const makeUser = options.makeUser ?? defaultMakeUser<U>;
  const makeClient = options.makeClient ?? defaultMakeClient<C>;

  describe(
    options.describeName ?? "AuthorizationCodeServiceInterface contract",
    () => {
      let userService: UserServiceInterface<U>;
      let clientService: ClientServiceInterface<C, U>;
      let codeService: AuthorizationCodeServiceInterface<C, U, S>;
      let user: U;
      let client: C;

      beforeEach(async () => {
        const services = await options.makeServices();
        userService = services.userService;
        clientService = services.clientService;
        codeService = services.authorizationCodeService;
        user = makeUser(1);
        client = makeClient(1);
        await options.addUser(userService, user, "pw");
        await options.addClient(clientService, client);
      });

      it("generateCode returns unique strings", async () => {
        const a = await codeService.generateCode(client, user);
        const b = await codeService.generateCode(client, user);
        expect(a !== b).toStrictEqual(true);
      });

      it("expiresAt returns a future date", async () => {
        const expires = await codeService.expiresAt(client, user);
        expect(expires.getTime() > Date.now()).toStrictEqual(true);
      });

      it("save + get round-trips an authorization code", async () => {
        const code = await codeService.generateCode(client, user);
        const expiresAt = await codeService.expiresAt(client, user);
        const ac: AuthorizationCode<C, U, S> = {
          code,
          expiresAt,
          client,
          user,
          redirectUri: "http://app/cb",
          challenge: "abc",
          challengeMethod: "S256",
          nonce: "nonce-1",
        };
        await codeService.save(ac);
        const fetched = await codeService.get(code);
        expect(fetched?.code).toStrictEqual(code);
        expect(fetched?.client.id).toStrictEqual(client.id);
        expect(fetched?.redirectUri).toStrictEqual("http://app/cb");
        expect(fetched?.challenge).toStrictEqual("abc");
        expect(fetched?.nonce).toStrictEqual("nonce-1");
      });

      it("get returns undefined for an unknown code", async () => {
        expect(await codeService.get("missing")).toBe(undefined);
      });

      it("revoke deletes the code by string", async () => {
        const code = await codeService.generateCode(client, user);
        await codeService.save({
          code,
          expiresAt: await codeService.expiresAt(client, user),
          client,
          user,
        });
        const ok = await codeService.revoke(code);
        expect(ok).toBe(true);
        expect(await codeService.get(code)).toBe(undefined);
      });

      it("revoke deletes the code by object", async () => {
        const code = await codeService.generateCode(client, user);
        const ac: AuthorizationCode<C, U, S> = {
          code,
          expiresAt: await codeService.expiresAt(client, user),
          client,
          user,
        };
        await codeService.save(ac);
        const ok = await codeService.revoke(ac);
        expect(ok).toBe(true);
        expect(await codeService.get(code)).toBe(undefined);
      });

      it("revoke returns false for an unknown code", async () => {
        expect(await codeService.revoke("missing")).toBe(false);
      });
    },
  );
}
