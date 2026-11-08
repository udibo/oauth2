/**
 * Contract test suite for {@link TokenServiceInterface.exchangeDeviceCode},
 * the atomic redemption of an approved device authorization (RFC 8628).
 *
 * The suite checks the exchange under concurrent callers: eight exchanges of
 * one device code, an exchange of an authorization that was already claimed,
 * a second exchange held behind the first, and an exchange whose insert
 * fails. Each case asserts the store's end state, the live tokens and whether
 * the authorization can still be claimed, not only the value each call
 * resolved.
 *
 * The store under test awaits {@link DeviceCodeExchangeBarriers.afterClaim}
 * inside `exchangeDeviceCode`, between its claim and its insert, so the suite
 * can hold an exchange there; a store that never reaches the barrier fails
 * every held case. Only a store whose `exchangeDeviceCode` never awaits
 * between its claim and its insert, such as `MemoryTokenService` paired with
 * its device store, opts out with `exchangeAwaitsBarrier: false`.
 *
 * @example Verify a database-backed store
 * ```ts
 * import { runDeviceCodeExchangeContractTests } from "@udibo/oauth2/testing/contract";
 * import type {
 *   DeviceCodeExchangeBarriers,
 *   DeviceCodeExchangeContractServices,
 * } from "@udibo/oauth2/testing/contract";
 * import type { MemoryUserShape } from "@udibo/oauth2/testing";
 * import type { ClientInterface } from "@udibo/oauth2/server";
 *
 * declare function freshServices(
 *   barriers: DeviceCodeExchangeBarriers,
 * ): Promise<DeviceCodeExchangeContractServices<ClientInterface, MemoryUserShape>>;
 * declare function addUser(service: unknown, user: MemoryUserShape, password: string): Promise<void>;
 * declare function addClient(service: unknown, client: ClientInterface): Promise<void>;
 *
 * runDeviceCodeExchangeContractTests({
 *   makeServices: freshServices,
 *   addUser,
 *   addClient,
 * });
 * ```
 *
 * @module
 */

import { assert, beforeEach, describe, expect, it } from "vitest";
import type { ClientInterface } from "../../models/client.ts";
import type { DeviceAuthorization } from "../../models/device-authorization.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import type { Token } from "../../models/token.ts";
import type { ClientServiceInterface } from "../../server/services/client.ts";
import type { DeviceAuthorizationServiceInterface } from "../../server/services/device-authorization.ts";
import type { TokenServiceInterface } from "../../server/services/token.ts";
import type { UserServiceInterface } from "../../server/services/user.ts";
import type { MemoryUserShape } from "../services.ts";
import { CONCURRENT_CALLERS, race } from "./_race.ts";

/**
 * The point inside a store's
 * {@linkcode TokenServiceInterface.exchangeDeviceCode} at which
 * {@link runDeviceCodeExchangeContractTests} holds an exchange. Wire it into a
 * test build of the store.
 */
export interface DeviceCodeExchangeBarriers {
  /**
   * Await this inside `exchangeDeviceCode` after claiming the authorization
   * and before persisting the token, still inside the atomic step. When it
   * rejects, fail the exchange as a failed insert would: leave the
   * authorization claimable, persist nothing, and reject or resolve
   * `undefined`.
   */
  afterClaim(): Promise<void>;
}

/** Services built for each case of {@link runDeviceCodeExchangeContractTests}. */
export interface DeviceCodeExchangeContractServices<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> {
  /** The user service both stores hydrate users from. */
  userService: UserServiceInterface<U>;
  /** The client service both stores hydrate clients from. */
  clientService: ClientServiceInterface<C, U>;
  /** The device store `exchangeDeviceCode` claims authorizations from. */
  deviceAuthorizationService: DeviceAuthorizationServiceInterface<C, U, S>;
  /** The token service under test. It must implement `exchangeDeviceCode`. */
  tokenService: TokenServiceInterface<C, U, S>;
}

/** Options for {@link runDeviceCodeExchangeContractTests}. */
export interface DeviceCodeExchangeContractOptions<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> {
  /**
   * Returns fresh services for each case, with `exchangeDeviceCode` awaiting
   * `barriers.afterClaim()` between its claim and its insert. A store that
   * sets `exchangeAwaitsBarrier: false` ignores `barriers`.
   */
  makeServices(
    barriers: DeviceCodeExchangeBarriers,
  ):
    | Promise<DeviceCodeExchangeContractServices<C, U, S>>
    | DeviceCodeExchangeContractServices<C, U, S>;
  /** Persists a user with the given password into the user service under test. */
  addUser(
    service: UserServiceInterface<U>,
    user: U,
    password: string,
  ): Promise<void>;
  /** Persists a client into the client service under test. */
  addClient(service: ClientServiceInterface<C, U>, client: C): Promise<void>;
  /** Builds a distinct user fixture for the given sequence number. Defaults to a minimal `{ id, username }` shape. */
  makeUser?(seq: number): U;
  /** Builds a distinct client fixture for the given sequence number. Defaults to a client granting the device-code grant. */
  makeClient?(seq: number): C;
  /**
   * Whether `exchangeDeviceCode` awaits `barriers.afterClaim()`. Defaults to
   * `true`. Set `false` only when it never awaits between its claim and its
   * insert, as in `MemoryTokenService`; the held cases are then skipped.
   */
  exchangeAwaitsBarrier?: boolean;
  /**
   * Milliseconds the suite lets a call run against a held exchange before it
   * releases the exchange. Defaults to 100.
   */
  blockedAfterMs?: number;
  /** Overrides the name passed to the outer `describe` block. */
  describeName?: string;
}

interface Hold {
  reached: PromiseWithResolvers<void>;
  release: PromiseWithResolvers<void>;
}

const defaultMakeUser = <U extends MemoryUserShape>(seq: number): U =>
  ({ id: `u${seq}`, username: `user${seq}` }) as U;
const defaultMakeClient = <C extends ClientInterface>(seq: number): C =>
  ({
    id: `client-${seq}`,
    grants: ["urn:ietf:params:oauth:grant-type:device_code"],
  }) as C;

async function settledWithin<T>(
  promise: Promise<T>,
  ms: number,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, ms);
  });
  try {
    await Promise.race([
      promise.then(
        () => undefined,
        () => undefined,
      ),
      timeout,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Runs the device code exchange contract suite against a token service that
 * implements {@linkcode TokenServiceInterface.exchangeDeviceCode}.
 */
export function runDeviceCodeExchangeContractTests<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
>(options: DeviceCodeExchangeContractOptions<C, U, S>): void {
  const makeUser = options.makeUser ?? defaultMakeUser<U>;
  const makeClient = options.makeClient ?? defaultMakeClient<C>;
  const pausable = options.exchangeAwaitsBarrier ?? true;
  const blockedAfterMs = options.blockedAfterMs ?? 100;

  describe(
    options.describeName ?? "TokenServiceInterface.exchangeDeviceCode contract",
    () => {
      let deviceService: DeviceAuthorizationServiceInterface<C, U, S>;
      let tokenService: TokenServiceInterface<C, U, S>;
      let user: U;
      let client: C;
      let armed: Hold | undefined;

      const barriers: DeviceCodeExchangeBarriers = {
        async afterClaim() {
          const hold = armed;
          if (!hold) return;
          armed = undefined;
          hold.reached.resolve();
          await hold.release.promise;
        },
      };

      beforeEach(async () => {
        armed = undefined;
        const services = await options.makeServices(barriers);
        deviceService = services.deviceAuthorizationService;
        tokenService = services.tokenService;
        user = makeUser(1);
        client = makeClient(1);
        await options.addUser(services.userService, user, "pw");
        await options.addClient(services.clientService, client);
      });

      function exchange(
        authorization: DeviceAuthorization<C, U, S>,
        token: Token<C, U, S>,
      ): Promise<Token<C, U, S> | undefined> {
        assert(
          typeof tokenService.exchangeDeviceCode === "function",
          "runDeviceCodeExchangeContractTests needs a token service that implements exchangeDeviceCode",
        );
        return tokenService.exchangeDeviceCode(authorization, token);
      }

      async function approved(): Promise<DeviceAuthorization<C, U, S>> {
        const authorization: DeviceAuthorization<C, U, S> = {
          deviceCode: await deviceService.generateDeviceCode(client),
          userCode: await deviceService.generateUserCode(client),
          expiresAt: await deviceService.expiresAt(client),
          client,
          interval: deviceService.interval,
        };
        await deviceService.save(authorization);
        const byUserCode = await deviceService.getByUserCode(
          authorization.userCode,
        );
        assert(byUserCode, "getByUserCode should resolve what was saved");
        await deviceService.approve(byUserCode, user);
        const byDeviceCode = await deviceService.getByDeviceCode(
          authorization.deviceCode,
        );
        assert(byDeviceCode, "getByDeviceCode should resolve what was saved");
        return { ...byDeviceCode, userCode: authorization.userCode };
      }

      async function tokenFor(): Promise<Token<C, U, S>> {
        return {
          accessToken: await tokenService.generateAccessToken(client, user),
          accessTokenExpiresAt: new Date(Date.now() + 60_000),
          client,
          user,
        };
      }

      async function live(tokens: Token<C, U, S>[]): Promise<string[]> {
        const found: string[] = [];
        for (const token of tokens) {
          if (await tokenService.getToken(token.accessToken)) {
            found.push(token.accessToken);
          }
        }
        return found;
      }

      async function claimable(
        authorization: DeviceAuthorization<C, U, S>,
      ): Promise<boolean> {
        return (
          (await deviceService.getByDeviceCode(authorization.deviceCode)) !==
          undefined
        );
      }

      function arm(): Hold {
        const hold: Hold = {
          reached: Promise.withResolvers<void>(),
          release: Promise.withResolvers<void>(),
        };
        armed = hold;
        return hold;
      }

      async function untilHeld<T>(hold: Hold, call: Promise<T>): Promise<void> {
        const outcome = await Promise.race([
          hold.reached.promise.then(() => "held" as const),
          call.then(
            () => "settled" as const,
            () => "settled" as const,
          ),
        ]);
        assert(
          outcome === "held",
          "exchangeDeviceCode settled without awaiting barriers.afterClaim; " +
            "wire the barrier in between its claim and its insert, or, only " +
            "if it never awaits between them, set exchangeAwaitsBarrier: false",
        );
      }

      it("implements exchangeDeviceCode", () => {
        assert(
          typeof tokenService.exchangeDeviceCode === "function",
          "the device code exchange contract covers exchangeDeviceCode",
        );
      });

      it("claims the authorization by both codes and saves its token in one call", async () => {
        const authorization = await approved();
        const token = await tokenFor();

        const saved = await exchange(authorization, token);

        expect(saved?.accessToken).toBe(token.accessToken);
        expect(await live([token])).toStrictEqual([token.accessToken]);
        expect(
          await deviceService.getByDeviceCode(authorization.deviceCode),
          "an exchanged device code must be spent",
        ).toBe(undefined);
        expect(
          await deviceService.getByUserCode(authorization.userCode),
          "an exchanged authorization must not resolve by its user code",
        ).toBe(undefined);
        expect(await deviceService.revoke(authorization.deviceCode)).toBe(
          false,
        );
      });

      it("refuses an authorization that was already claimed, persisting nothing", async () => {
        const authorization = await approved();
        expect(await deviceService.revoke(authorization)).toBe(true);
        const token = await tokenFor();

        expect(await exchange(authorization, token)).toBe(undefined);
        expect(await live([token])).toStrictEqual([]);
      });

      it(`persists exactly one token for ${CONCURRENT_CALLERS} concurrent exchanges of one device code`, async () => {
        const authorization = await approved();
        const tokens = await race(() => tokenFor());

        const results = await race((caller) =>
          exchange(authorization, tokens[caller]),
        );

        expect(
          results.filter((result) => result !== undefined).length,
          "exchangeDeviceCode must claim its authorization once",
        ).toBe(1);
        expect(
          await live(tokens),
          "a losing exchange must persist nothing: a token saved before the " +
            "claim is decided stays live for a device that was refused",
        ).toHaveLength(1);
      });

      it("refuses a second exchange that starts while the first is held after its claim", async ({
        skip,
      }) => {
        skip(
          !pausable,
          "exchangeDeviceCode cannot be held (exchangeAwaitsBarrier: false)",
        );
        const authorization = await approved();
        const first = await tokenFor();
        const second = await tokenFor();

        const hold = arm();
        const held = exchange(authorization, first);
        await untilHeld(hold, held);
        const racing = exchange(authorization, second);
        await settledWithin(racing, blockedAfterMs);
        hold.release.resolve();

        expect((await held)?.accessToken).toBe(first.accessToken);
        expect(await racing).toBe(undefined);
        expect(await live([first, second])).toStrictEqual([first.accessToken]);
      });

      it("leaves the authorization claimable and persists nothing when the token cannot be persisted", async () => {
        const authorization = await approved();
        const unpersistable = await tokenFor();
        const accessToken = unpersistable.accessToken;
        Object.defineProperty(unpersistable, "accessToken", {
          enumerable: true,
          get(): string {
            throw new Error("forced persistence failure");
          },
        });

        const outcome = await Promise.allSettled([
          exchange(authorization, unpersistable),
        ]);

        if (outcome[0].status === "fulfilled") {
          expect(outcome[0].value).toBe(undefined);
        }
        expect(
          await claimable(authorization),
          "a failed exchange must not spend the user's approval",
        ).toBe(true);
        expect(await tokenService.getToken(accessToken)).toBe(undefined);
        const retry = await tokenFor();
        expect((await exchange(authorization, retry))?.accessToken).toBe(
          retry.accessToken,
        );
      });

      it("rolls the claim back when the insert fails after it", async ({
        skip,
      }) => {
        skip(
          !pausable,
          "exchangeDeviceCode cannot be held (exchangeAwaitsBarrier: false)",
        );
        const authorization = await approved();
        const token = await tokenFor();

        const hold = arm();
        const call = exchange(authorization, token);
        await untilHeld(hold, call);
        hold.release.reject(new Error("forced insert failure"));
        const outcome = await Promise.allSettled([call]);

        if (outcome[0].status === "fulfilled") {
          expect(outcome[0].value).toBe(undefined);
        }
        expect(
          await claimable(authorization),
          "the claim and the insert are one step: a failed insert must " +
            "leave the authorization claimable",
        ).toBe(true);
        expect(await live([token])).toStrictEqual([]);
        const retry = await tokenFor();
        expect((await exchange(authorization, retry))?.accessToken).toBe(
          retry.accessToken,
        );
      });
    },
  );
}
