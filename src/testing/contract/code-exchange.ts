/**
 * Contract test suite for {@link TokenServiceInterface.exchangeCode} and its
 * linearizability with {@link TokenServiceInterface.revokeCode}.
 *
 * `runTokenServiceContractTests` checks `revokeCode` for one caller. This
 * suite checks the atomic code exchange under concurrent callers: two
 * exchanges of one code, a replay of the code racing its exchange through
 * the authorization code grant, an exchange of an unrelated code, and an
 * exchange whose insert fails. Each case asserts the store's end state, the
 * live tokens and whether the code can still be claimed, not only the value
 * each call resolved.
 *
 * The store under test awaits {@link CodeExchangeBarriers.afterClaim} inside
 * `exchangeCode`, between its claim and its insert, so the suite can hold an
 * exchange there and race the other call against it; a store that never
 * reaches the barrier fails every held case. Only a store whose
 * `exchangeCode` never awaits between its claim and its insert, such as
 * `MemoryTokenService` paired with its code store, opts out with
 * `exchangeAwaitsBarrier: false`; the suite then runs those schedules as
 * overlapping calls.
 *
 * @module
 */

import { assert, beforeEach, describe, expect, it } from "vitest";
import { InvalidGrantError } from "../../errors.ts";
import type { AuthorizationCode } from "../../models/authorization-code.ts";
import type { ClientInterface } from "../../models/client.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import type { Token } from "../../models/token.ts";
import {
  AuthorizationCodeGrant,
  type CodeReuseEvent,
} from "../../server/grants/authorization-code.ts";
import type { AuthorizationCodeServiceInterface } from "../../server/services/authorization-code.ts";
import type { ClientServiceInterface } from "../../server/services/client.ts";
import type { TokenServiceInterface } from "../../server/services/token.ts";
import type { UserServiceInterface } from "../../server/services/user.ts";
import type { MemoryUserShape } from "../services.ts";
import { race } from "./_race.ts";

/**
 * The point inside a store's {@linkcode TokenServiceInterface.exchangeCode}
 * at which {@link runCodeExchangeContractTests} holds an exchange. Wire it
 * into a test build of the store.
 */
export interface CodeExchangeBarriers {
  /**
   * Await this inside `exchangeCode` after claiming the code and before
   * persisting the token, still inside the atomic step: within the
   * transaction and holding the code's lock. When it rejects, fail the
   * exchange as a failed insert would: leave the code claimable, persist
   * nothing, and reject or resolve `undefined`.
   */
  afterClaim(): Promise<void>;
}

/** Services built for each case of {@link runCodeExchangeContractTests}. */
export interface CodeExchangeContractServices<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> {
  /** The user service both stores hydrate users from. */
  userService: UserServiceInterface<U>;
  /** The client service both stores hydrate clients from. */
  clientService: ClientServiceInterface<C, U>;
  /** The code store `exchangeCode` claims codes from. */
  authorizationCodeService: AuthorizationCodeServiceInterface<C, U, S>;
  /** The token service under test. It must implement `exchangeCode`. */
  tokenService: TokenServiceInterface<C, U, S>;
}

/** Options for {@link runCodeExchangeContractTests}. */
export interface CodeExchangeContractOptions<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> {
  /**
   * Returns fresh services for each case, with `exchangeCode` awaiting
   * `barriers.afterClaim()` between its claim and its insert. A store that
   * sets `exchangeAwaitsBarrier: false` ignores `barriers`.
   */
  makeServices(
    barriers: CodeExchangeBarriers,
  ):
    | Promise<CodeExchangeContractServices<C, U, S>>
    | CodeExchangeContractServices<C, U, S>;
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
  /** Builds a distinct client fixture for the given sequence number. Defaults to a client granting `authorization_code` and `refresh_token`. */
  makeClient?(seq: number): C;
  /**
   * Whether `exchangeCode` awaits `barriers.afterClaim()`. Defaults to
   * `true`: the suite holds an exchange between its claim and its insert
   * while it runs a second exchange, a replay through the grant, or an
   * exchange of another code, and fails the insert there. Set `false` only
   * when `exchangeCode` never awaits between its claim and its insert, as in
   * `MemoryTokenService`; the suite then runs those schedules as overlapping
   * calls, which cannot reach a gap inside `exchangeCode`.
   */
  exchangeAwaitsBarrier?: boolean;
  /**
   * Milliseconds the suite lets a call run against a held exchange before it
   * releases the exchange; a call that has not settled by then is taken to be
   * waiting on it. Defaults to 100. Raise it for a store whose calls take
   * longer to reach the lock they wait on.
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
    grants: ["authorization_code", "refresh_token"],
  }) as C;

async function settledWithin<T>(
  promise: Promise<T>,
  ms: number,
): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<false>((resolve) => {
    timer = setTimeout(() => resolve(false), ms);
  });
  try {
    return await Promise.race([
      promise.then(
        () => true,
        () => true,
      ),
      timeout,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Runs the code exchange contract suite: concurrent schedules of
 * {@linkcode TokenServiceInterface.exchangeCode} against itself, and against
 * a replay of the code through the authorization code grant, which calls
 * {@linkcode TokenServiceInterface.revokeCode}. The service must implement
 * `exchangeCode`.
 */
export function runCodeExchangeContractTests<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
>(options: CodeExchangeContractOptions<C, U, S>): void {
  const makeUser = options.makeUser ?? defaultMakeUser<U>;
  const makeClient = options.makeClient ?? defaultMakeClient<C>;
  const pausable = options.exchangeAwaitsBarrier ?? true;
  const blockedAfterMs = options.blockedAfterMs ?? 100;

  describe(
    options.describeName ?? "TokenServiceInterface.exchangeCode contract",
    () => {
      let services: CodeExchangeContractServices<C, U, S>;
      let codeService: AuthorizationCodeServiceInterface<C, U, S>;
      let tokenService: TokenServiceInterface<C, U, S>;
      let user: U;
      let client: C;
      let armed: Hold | undefined;

      const barriers: CodeExchangeBarriers = {
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
        services = await options.makeServices(barriers);
        codeService = services.authorizationCodeService;
        tokenService = services.tokenService;
        user = makeUser(1);
        client = makeClient(1);
        await options.addUser(services.userService, user, "pw");
        await options.addClient(services.clientService, client);
      });

      function exchangeCode(
        authorizationCode: AuthorizationCode<C, U, S>,
        token: Token<C, U, S>,
      ): Promise<Token<C, U, S> | undefined> {
        assert(
          typeof tokenService.exchangeCode === "function",
          "runCodeExchangeContractTests needs a token service that implements exchangeCode",
        );
        return tokenService.exchangeCode(authorizationCode, token);
      }

      async function savedCode(): Promise<AuthorizationCode<C, U, S>> {
        const authorizationCode: AuthorizationCode<C, U, S> = {
          code: await codeService.generateCode(client, user),
          expiresAt: await codeService.expiresAt(client, user),
          client,
          user,
        };
        await codeService.save(authorizationCode);
        return authorizationCode;
      }

      async function tokenFor(
        authorizationCode: AuthorizationCode<C, U, S>,
      ): Promise<Token<C, U, S>> {
        return {
          accessToken: await tokenService.generateAccessToken(client, user),
          accessTokenExpiresAt: new Date(Date.now() + 60_000),
          client,
          user,
          code: authorizationCode.code,
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
        authorizationCode: AuthorizationCode<C, U, S>,
      ): Promise<boolean> {
        return (await codeService.get(authorizationCode.code)) !== undefined;
      }

      function arm(): Hold {
        const hold: Hold = {
          reached: Promise.withResolvers<void>(),
          release: Promise.withResolvers<void>(),
        };
        armed = hold;
        return hold;
      }

      async function untilHeld<T>(
        hold: Hold,
        exchange: Promise<T>,
      ): Promise<void> {
        const outcome = await Promise.race([
          hold.reached.promise.then(() => "held" as const),
          exchange.then(
            () => "settled" as const,
            () => "settled" as const,
          ),
        ]);
        assert(
          outcome === "held",
          "exchangeCode settled without awaiting barriers.afterClaim; wire " +
            "the barrier into exchangeCode between its claim and its " +
            "insert, or, only if exchangeCode never awaits between them, " +
            "set exchangeAwaitsBarrier: false",
        );
      }

      function codeGrant(
        reuseEvents: CodeReuseEvent<C>[],
      ): AuthorizationCodeGrant<C, U, S> {
        return new AuthorizationCodeGrant<C, U, S>({
          resolve: () => ({
            clientService: services.clientService,
            authorizationCodeService: codeService,
            tokenService,
          }),
          requirePKCE: false,
          onCodeReuse: (event) => {
            reuseEvents.push(event);
          },
        });
      }

      function redeem(
        grant: AuthorizationCodeGrant<C, U, S>,
        authorizationCode: AuthorizationCode<C, U, S>,
      ): Promise<Token<C, U, S>> {
        const body = new FormData();
        body.set("grant_type", "authorization_code");
        body.set("code", authorizationCode.code);
        return grant.token(
          new Request("https://as.test/token", { method: "POST" }),
          client,
          body,
        );
      }

      it("implements exchangeCode", () => {
        assert(
          typeof tokenService.exchangeCode === "function",
          "the code exchange contract covers exchangeCode",
        );
      });

      it("claims the code and saves its token in one call, findable by the code", async () => {
        const authorizationCode = await savedCode();
        const token = await tokenFor(authorizationCode);

        const saved = await exchangeCode(authorizationCode, token);

        expect(saved?.accessToken).toBe(token.accessToken);
        expect(
          await claimable(authorizationCode),
          "an exchanged code must be spent",
        ).toBe(false);
        expect(await codeService.revoke(authorizationCode.code)).toBe(false);
        expect(await live([token])).toStrictEqual([token.accessToken]);
        expect(
          await tokenService.revokeCode(authorizationCode.code, client),
          "revokeCode must find the token exchangeCode saved by its code",
        ).toBe(true);
        expect(await live([token])).toStrictEqual([]);
      });

      it("refuses a code that was already claimed or never stored, persisting nothing", async () => {
        const claimed = await savedCode();
        await codeService.revoke(claimed.code);
        const afterClaim = await tokenFor(claimed);
        const unknown: AuthorizationCode<C, U, S> = {
          ...claimed,
          code: await codeService.generateCode(client, user),
        };
        const forUnknown = await tokenFor(unknown);

        expect(await exchangeCode(claimed, afterClaim)).toBe(undefined);
        expect(await exchangeCode(unknown, forUnknown)).toBe(undefined);
        expect(await live([afterClaim, forUnknown])).toStrictEqual([]);
      });

      it("gives concurrent exchanges of one code exactly one token", async () => {
        const authorizationCode = await savedCode();
        const tokens = await race(() => tokenFor(authorizationCode));

        const results = await race((caller) =>
          exchangeCode(authorizationCode, tokens[caller]),
        );

        expect(
          results.filter((result) => result !== undefined).length,
          "exchangeCode must claim its code once, however many callers race",
        ).toBe(1);
        expect(await live(tokens)).toHaveLength(1);
      });

      it("revokes the exchanged token when the code's own client replays it through the grant", async () => {
        const authorizationCode = await savedCode();
        const reuseEvents: CodeReuseEvent<C>[] = [];
        const grant = codeGrant(reuseEvents);
        const issued = await redeem(grant, authorizationCode);

        const replay = await Promise.allSettled([
          redeem(grant, authorizationCode),
        ]);

        assert(replay[0].status === "rejected");
        expect(replay[0].reason).toBeInstanceOf(InvalidGrantError);
        expect(await live([issued])).toStrictEqual([]);
        expect(reuseEvents).toHaveLength(1);
      });

      it("leaves no live token when the code is replayed through the grant while its exchange is in flight", async () => {
        const authorizationCode = await savedCode();
        const reuseEvents: CodeReuseEvent<C>[] = [];
        const grant = codeGrant(reuseEvents);

        let outcomes: PromiseSettledResult<Token<C, U, S>>[];
        if (pausable) {
          const hold = arm();
          const first = redeem(grant, authorizationCode);
          await untilHeld(hold, first);
          const replay = redeem(grant, authorizationCode);
          await settledWithin(replay, blockedAfterMs);
          hold.release.resolve();
          outcomes = await Promise.allSettled([first, replay]);
        } else {
          outcomes = await Promise.allSettled([
            redeem(grant, authorizationCode),
            redeem(grant, authorizationCode),
          ]);
        }

        const issued = outcomes.flatMap((outcome) =>
          outcome.status === "fulfilled" ? [outcome.value] : [],
        );
        const refused = outcomes.flatMap((outcome) =>
          outcome.status === "rejected" ? [outcome.reason] : [],
        );
        expect(issued).toHaveLength(1);
        expect(refused).toHaveLength(1);
        expect(refused[0]).toBeInstanceOf(InvalidGrantError);
        expect(
          await live(issued),
          "a replay that lands while the exchange is between its claim and " +
            "its insert must still leave no live token issued from the code: " +
            "revokeCode has to see the token, or the replay has to wait for " +
            "the exchange and lose the claim",
        ).toStrictEqual([]);
        expect(reuseEvents).toHaveLength(1);
      });

      it("refuses a second exchange that starts while the first is held after its claim", async ({
        skip,
      }) => {
        skip(
          !pausable,
          "exchangeCode cannot be held (exchangeAwaitsBarrier: false)",
        );
        const authorizationCode = await savedCode();
        const first = await tokenFor(authorizationCode);
        const second = await tokenFor(authorizationCode);

        const hold = arm();
        const held = exchangeCode(authorizationCode, first);
        await untilHeld(hold, held);
        const racing = exchangeCode(authorizationCode, second);
        await settledWithin(racing, blockedAfterMs);
        hold.release.resolve();

        expect((await held)?.accessToken).toBe(first.accessToken);
        expect(await racing).toBe(undefined);
        expect(await live([first, second])).toStrictEqual([first.accessToken]);
      });

      it("does not hold an exchange of another code behind a held one", async ({
        skip,
      }) => {
        skip(
          !pausable,
          "exchangeCode cannot be held (exchangeAwaitsBarrier: false)",
        );
        const authorizationCode = await savedCode();
        const token = await tokenFor(authorizationCode);
        const otherCode = await savedCode();
        const otherToken = await tokenFor(otherCode);

        const hold = arm();
        const exchange = exchangeCode(authorizationCode, token);
        await untilHeld(hold, exchange);
        const other = exchangeCode(otherCode, otherToken);
        const settled = await settledWithin(other, 5_000);
        hold.release.resolve();

        expect(
          settled,
          "the code lock must be keyed by code, so one login's exchange " +
            "never waits on another's",
        ).toBe(true);
        expect((await other)?.accessToken).toBe(otherToken.accessToken);
        expect((await exchange)?.accessToken).toBe(token.accessToken);
      });

      it("leaves the code claimable and persists nothing when the token cannot be persisted", async () => {
        const authorizationCode = await savedCode();
        const unpersistable = await tokenFor(authorizationCode);
        const accessToken = unpersistable.accessToken;
        Object.defineProperty(unpersistable, "accessToken", {
          enumerable: true,
          get(): string {
            throw new Error("forced persistence failure");
          },
        });

        const outcome = await Promise.allSettled([
          exchangeCode(authorizationCode, unpersistable),
        ]);

        if (outcome[0].status === "fulfilled") {
          expect(outcome[0].value).toBe(undefined);
        }
        expect(
          await claimable(authorizationCode),
          "a failed exchange must not spend its code",
        ).toBe(true);
        expect(await tokenService.getToken(accessToken)).toBe(undefined);
        const retry = await tokenFor(authorizationCode);
        expect(
          (await exchangeCode(authorizationCode, retry))?.accessToken,
        ).toBe(retry.accessToken);
      });

      it("rolls the claim back when the insert fails after it", async ({
        skip,
      }) => {
        skip(
          !pausable,
          "exchangeCode cannot be held (exchangeAwaitsBarrier: false)",
        );
        const authorizationCode = await savedCode();
        const token = await tokenFor(authorizationCode);

        const hold = arm();
        const exchange = exchangeCode(authorizationCode, token);
        await untilHeld(hold, exchange);
        hold.release.reject(new Error("forced insert failure"));
        const outcome = await Promise.allSettled([exchange]);

        if (outcome[0].status === "fulfilled") {
          expect(outcome[0].value).toBe(undefined);
        }
        expect(
          await claimable(authorizationCode),
          "the claim and the insert are one step: a failed insert must " +
            "leave the code claimable",
        ).toBe(true);
        expect(await live([token])).toStrictEqual([]);
        const retry = await tokenFor(authorizationCode);
        expect(
          (await exchangeCode(authorizationCode, retry))?.accessToken,
          "a failed exchange must release the code",
        ).toBe(retry.accessToken);
      });
    },
  );
}
