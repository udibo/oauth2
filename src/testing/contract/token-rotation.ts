/**
 * Contract test suite for {@link TokenServiceInterface.rotate} and its
 * linearizability with {@link TokenServiceInterface.revokeFamily}.
 *
 * `runTokenServiceContractTests` checks what one caller sees. This suite
 * checks what concurrent callers see: two rotations of one refresh token, a
 * family revocation racing a rotation, a replay racing a refresh through the
 * refresh grant, a rotation in an unrelated family, and a rotation whose
 * insert fails. Each case asserts the store's end state, the live tokens of
 * the family, not only the value each call resolved.
 *
 * The store under test awaits {@link TokenRotationBarriers.afterClaim} inside
 * `rotate`, between its claim and its insert, so the suite can hold a rotation
 * there and race the other call against it; a store that never reaches the
 * barrier fails every held case. Only a store whose `rotate` never awaits
 * between its claim and its insert, such as `MemoryTokenService`, opts out with
 * `rotateAwaitsBarrier: false`; the suite then runs those schedules as
 * overlapping calls.
 *
 * @module
 */

import { assert, beforeEach, describe, expect, it } from "vitest";
import { InvalidGrantError } from "../../errors.ts";
import type { ClientInterface } from "../../models/client.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import type { RefreshToken } from "../../models/token.ts";
import { RefreshTokenGrant } from "../../server/grants/refresh-token.ts";
import type { TokenReuseEvent } from "../../server/grants/refresh-token.ts";
import type { ClientServiceInterface } from "../../server/services/client.ts";
import type { TokenServiceInterface } from "../../server/services/token.ts";
import type { UserServiceInterface } from "../../server/services/user.ts";
import type { MemoryUserShape } from "../services.ts";
import { race } from "./_race.ts";

/**
 * The point inside a store's {@linkcode TokenServiceInterface.rotate} at which
 * {@link runTokenRotationContractTests} holds a rotation. Wire it into a test
 * build of the store.
 */
export interface TokenRotationBarriers {
  /**
   * Await this inside `rotate` after claiming `current` and before persisting
   * `next`, still inside the atomic step: within the transaction and holding
   * the family's lock. When it rejects, fail the rotation as a failed insert
   * would: leave `current` live, persist nothing, and reject or resolve
   * `undefined`.
   */
  afterClaim(): Promise<void>;
}

/** Services built for each case of {@link runTokenRotationContractTests}. */
export interface TokenRotationContractServices<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> {
  /** The user service the token service hydrates users from. */
  userService: UserServiceInterface<U>;
  /** The client service the token service hydrates clients from. */
  clientService: ClientServiceInterface<C, U>;
  /** The token service under test. It must implement `rotate`. */
  tokenService: TokenServiceInterface<C, U, S>;
}

/** Options for {@link runTokenRotationContractTests}. */
export interface TokenRotationContractOptions<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> {
  /**
   * Returns fresh services for each case, with `rotate` awaiting
   * `barriers.afterClaim()` between its claim and its insert. A store that
   * sets `rotateAwaitsBarrier: false` ignores `barriers`.
   */
  makeServices(
    barriers: TokenRotationBarriers,
  ):
    | Promise<TokenRotationContractServices<C, U, S>>
    | TokenRotationContractServices<C, U, S>;
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
   * Whether `rotate` awaits `barriers.afterClaim()`. Defaults to `true`: the
   * suite holds a rotation between its claim and its insert while it runs a
   * family revocation, a second rotation, a replayed refresh, or a rotation in
   * another family, and fails the insert there. Set `false` only when
   * `rotate` never awaits between its claim and its insert, as in
   * `MemoryTokenService`; the suite then runs those schedules as overlapping
   * calls, which cannot reach a gap inside `rotate`.
   */
  rotateAwaitsBarrier?: boolean;
  /**
   * Milliseconds the suite lets a call run against a held rotation before it
   * releases the rotation; a call that has not settled by then is taken to
   * be waiting on it. Defaults to 100. Raise it for a store whose calls take
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

type Settled<T> = PromiseSettledResult<Awaited<T>>;

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
 * Runs the rotation contract suite: concurrent schedules of
 * {@linkcode TokenServiceInterface.rotate} against itself, against
 * {@linkcode TokenServiceInterface.revokeFamily}, and through the refresh
 * grant. The service must implement `rotate`, `revokeFamily` and
 * `getRevokedRefreshToken`.
 */
export function runTokenRotationContractTests<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
>(options: TokenRotationContractOptions<C, U, S>): void {
  const makeUser = options.makeUser ?? defaultMakeUser<U>;
  const makeClient = options.makeClient ?? defaultMakeClient<C>;
  const pausable = options.rotateAwaitsBarrier ?? true;
  const blockedAfterMs = options.blockedAfterMs ?? 100;

  describe(
    options.describeName ?? "TokenServiceInterface.rotate contract",
    () => {
      let clientService: ClientServiceInterface<C, U>;
      let tokenService: TokenServiceInterface<C, U, S>;
      let user: U;
      let client: C;
      let armed: Hold | undefined;
      let family: string;
      let otherFamily: string;

      const barriers: TokenRotationBarriers = {
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
        family = crypto.randomUUID();
        otherFamily = crypto.randomUUID();
        const services = await options.makeServices(barriers);
        clientService = services.clientService;
        tokenService = services.tokenService;
        user = makeUser(1);
        client = makeClient(1);
        await options.addUser(services.userService, user, "pw");
        await options.addClient(clientService, client);
      });

      function rotate(
        current: RefreshToken<C, U, S>,
        next: RefreshToken<C, U, S>,
      ): Promise<RefreshToken<C, U, S> | undefined> {
        assert(
          typeof tokenService.rotate === "function",
          "runTokenRotationContractTests needs a token service that implements rotate",
        );
        return tokenService.rotate(current, next);
      }

      async function member(familyId: string): Promise<RefreshToken<C, U, S>> {
        return {
          accessToken: await tokenService.generateAccessToken(client, user),
          accessTokenExpiresAt: new Date(Date.now() + 60_000),
          refreshToken: (await tokenService.generateRefreshToken(
            client,
            user,
          ))!,
          refreshTokenExpiresAt: new Date(Date.now() + 600_000),
          familyId,
          familyCreatedAt: new Date(Date.now() - 60_000),
          client,
          user,
        };
      }

      async function savedMember(
        familyId: string,
      ): Promise<RefreshToken<C, U, S>> {
        const token = await member(familyId);
        await tokenService.save(token);
        return token;
      }

      async function live(
        tokens: RefreshToken<C, U, S>[],
      ): Promise<RefreshToken<C, U, S>[]> {
        const found: RefreshToken<C, U, S>[] = [];
        for (const token of tokens) {
          if (
            (await tokenService.getRefreshToken(token.refreshToken)) ||
            (await tokenService.getToken(token.accessToken))
          ) {
            found.push(token);
          }
        }
        return found;
      }

      async function liveOf(refreshTokens: string[]): Promise<string[]> {
        const found: string[] = [];
        for (const refreshToken of refreshTokens) {
          if (await tokenService.getRefreshToken(refreshToken)) {
            found.push(refreshToken);
          }
        }
        return found;
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
        hold: Pick<Hold, "reached">,
        rotation: Promise<T>,
        unheld = "rotate settled without awaiting barriers.afterClaim; wire " +
          "the barrier into rotate between its claim and its insert, or, " +
          "only if rotate never awaits between them, set " +
          "rotateAwaitsBarrier: false",
      ): Promise<void> {
        const outcome = await Promise.race([
          hold.reached.promise.then(() => "held" as const),
          rotation.then(
            () => "settled" as const,
            () => "settled" as const,
          ),
        ]);
        assert(outcome === "held", unheld);
      }

      /**
       * Runs `during` while `rotate(current, next)` is held after its claim,
       * or, for a store that cannot be held, while the rotation is in flight.
       */
      async function whileRotating<T>(
        current: RefreshToken<C, U, S>,
        next: RefreshToken<C, U, S>,
        during: () => Promise<T>,
      ): Promise<[Settled<RefreshToken<C, U, S> | undefined>, Settled<T>]> {
        if (!pausable) {
          const rotation = rotate(current, next);
          const other = during();
          return await Promise.all([
            Promise.allSettled([rotation]).then(([r]) => r),
            Promise.allSettled([other]).then(([o]) => o),
          ]);
        }
        const hold = arm();
        const rotation = rotate(current, next);
        await untilHeld(hold, rotation);
        const other = during();
        await settledWithin(other, blockedAfterMs);
        hold.release.resolve();
        return await Promise.all([
          Promise.allSettled([rotation]).then(([r]) => r),
          Promise.allSettled([other]).then(([o]) => o),
        ]);
      }

      /**
       * Wraps the token service to record every refresh token the grant
       * generates, and to run `beforeRotate` before each `rotate` reaches the
       * store.
       */
      function observe(beforeRotate?: () => Promise<void>): {
        observed: TokenServiceInterface<C, U, S>;
        issued: string[];
      } {
        const issued: string[] = [];
        const observed = new Proxy(tokenService, {
          get(target, prop) {
            if (prop === "generateRefreshToken") {
              return async (...args: [C, U, S | null | undefined]) => {
                const value = await target.generateRefreshToken(...args);
                if (value) issued.push(value);
                return value;
              };
            }
            if (prop === "rotate" && beforeRotate) {
              return async (
                current: RefreshToken<C, U, S>,
                next: RefreshToken<C, U, S>,
              ) => {
                await beforeRotate();
                return await rotate(current, next);
              };
            }
            const value = Reflect.get(target, prop, target);
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
        return { observed, issued };
      }

      function refreshGrant(
        service: TokenServiceInterface<C, U, S>,
        reuseEvents: TokenReuseEvent<C, U>[],
      ): RefreshTokenGrant<C, U, S> {
        return new RefreshTokenGrant<C, U, S>({
          resolve: () => ({ clientService, tokenService: service }),
          onTokenReuse: (event) => {
            reuseEvents.push(event);
          },
        });
      }

      function refresh(
        grant: RefreshTokenGrant<C, U, S>,
        refreshToken: string,
      ): Promise<RefreshToken<C, U, S>> {
        const body = new FormData();
        body.set("grant_type", "refresh_token");
        body.set("refresh_token", refreshToken);
        return grant.token(
          new Request("https://as.test/token", { method: "POST" }),
          client,
          body,
        );
      }

      it("implements rotate, revokeFamily and getRevokedRefreshToken", () => {
        assert(
          typeof tokenService.rotate === "function" &&
            typeof tokenService.revokeFamily === "function" &&
            typeof tokenService.getRevokedRefreshToken === "function",
          "the rotation contract covers rotate together with reuse detection",
        );
      });

      it("refuses to rotate a member of a family revoked before it began", async () => {
        const parent = await savedMember(family);
        const next = await member(family);
        await tokenService.revokeFamily!(family);

        expect(await rotate(parent, next)).toBe(undefined);
        expect(
          await live([parent, next]),
          "a rotation that starts after its family was revoked must not " +
            "give the family a live member again",
        ).toStrictEqual([]);
      });

      it("leaves no live member when the family is revoked while a rotation is in flight", async () => {
        const parent = await savedMember(family);
        const next = await member(family);

        const [rotated, revoked] = await whileRotating(parent, next, () =>
          tokenService.revokeFamily!(family),
        );

        assert(revoked.status === "fulfilled");
        assert(rotated.status === "fulfilled");
        expect([undefined, next.refreshToken]).toContain(
          rotated.value?.refreshToken,
        );
        expect(
          await live([parent, next]),
          "revokeFamily must wait for a rotation holding the family, or the " +
            "successor that rotation commits afterwards stays live in a " +
            "family the server revoked",
        ).toStrictEqual([]);
      });

      it("revokes the successor of a rotation that committed before the family was revoked", async () => {
        const parent = await savedMember(family);
        const next = await member(family);
        expect((await rotate(parent, next))?.refreshToken).toBe(
          next.refreshToken,
        );

        expect(await tokenService.revokeFamily!(family)).toBe(true);
        expect(await live([parent, next])).toStrictEqual([]);
      });

      it("gives concurrent rotations of one refresh token exactly one successor", async () => {
        const parent = await savedMember(family);
        const successors = await race(() => member(family));

        const results = await race((caller) =>
          rotate(parent, successors[caller]),
        );

        expect(
          results.filter((result) => result !== undefined).length,
          "rotate must claim its parent once, however many callers race",
        ).toBe(1);
        expect(await live([parent, ...successors])).toHaveLength(1);
      });

      it("refuses a second rotation that starts while the first is held after its claim", async ({
        skip,
      }) => {
        skip(!pausable, "rotate cannot be held (rotateAwaitsBarrier: false)");
        const parent = await savedMember(family);
        const first = await member(family);
        const second = await member(family);

        const [held, racing] = await whileRotating(parent, first, () =>
          rotate(parent, second),
        );

        assert(held.status === "fulfilled" && racing.status === "fulfilled");
        expect(held.value?.refreshToken).toBe(first.refreshToken);
        expect(racing.value).toBe(undefined);
        expect(await live([parent, first, second])).toStrictEqual([first]);
      });

      it("answers a refresh that loses the claim to a concurrent one with invalid_grant, keeping the winner's successor", async () => {
        const parent = await savedMember(family);
        const held = Promise.withResolvers<void>();
        const release = Promise.withResolvers<void>();
        let rotations = 0;
        const { observed, issued } = observe(async () => {
          if (rotations++ === 0) {
            held.resolve();
            await release.promise;
          }
        });
        const reuseEvents: TokenReuseEvent<C, U>[] = [];
        const grant = refreshGrant(observed, reuseEvents);

        const first = refresh(grant, parent.refreshToken);
        await untilHeld(
          { reached: held },
          first,
          "the refresh grant settled without calling rotate",
        );
        const second = await refresh(grant, parent.refreshToken);
        release.resolve();
        const firstOutcome = await Promise.allSettled([first]);

        assert(firstOutcome[0].status === "rejected");
        expect(firstOutcome[0].reason).toBeInstanceOf(InvalidGrantError);
        expect(
          reuseEvents,
          "losing the claim is a race, not a replay of a rotated-out token",
        ).toStrictEqual([]);
        const liveRefreshTokens = await liveOf([
          parent.refreshToken,
          ...issued,
        ]);
        expect(liveRefreshTokens).toStrictEqual([second.refreshToken]);
      });

      it("answers a replay that arrives while a rotation is held after its claim with invalid_grant, without revoking the family", async ({
        skip,
      }) => {
        skip(!pausable, "rotate cannot be held (rotateAwaitsBarrier: false)");
        const parent = await savedMember(family);
        const { observed, issued } = observe();
        const reuseEvents: TokenReuseEvent<C, U>[] = [];
        const grant = refreshGrant(observed, reuseEvents);

        const hold = arm();
        const first = refresh(grant, parent.refreshToken);
        await untilHeld(hold, first);
        const replay = refresh(grant, parent.refreshToken);
        await settledWithin(replay, blockedAfterMs);
        hold.release.resolve();
        const [firstOutcome, replayOutcome] = await Promise.allSettled([
          first,
          replay,
        ]);

        assert(firstOutcome.status === "fulfilled");
        assert(replayOutcome.status === "rejected");
        expect(replayOutcome.reason).toBeInstanceOf(InvalidGrantError);
        expect(
          reuseEvents,
          "a replay inside the claim-to-insert gap found no live successor " +
            "and was taken for theft",
        ).toStrictEqual([]);
        const liveRefreshTokens = await liveOf([
          parent.refreshToken,
          ...issued,
        ]);
        expect(liveRefreshTokens).toStrictEqual([
          firstOutcome.value.refreshToken,
        ]);
      });

      it("does not hold a rotation in another family behind a held one", async () => {
        const parent = await savedMember(family);
        const next = await member(family);
        const otherParent = await savedMember(otherFamily);
        const otherNext = await member(otherFamily);

        if (!pausable) {
          const [rotated, other] = await Promise.all([
            rotate(parent, next),
            rotate(otherParent, otherNext),
          ]);
          expect(rotated?.refreshToken).toBe(next.refreshToken);
          expect(other?.refreshToken).toBe(otherNext.refreshToken);
          return;
        }
        const hold = arm();
        const rotation = rotate(parent, next);
        await untilHeld(hold, rotation);
        const other = rotate(otherParent, otherNext);
        const settled = await settledWithin(other, 5_000);
        hold.release.resolve();
        expect(
          settled,
          "the family lock must be keyed by family, so one login's " +
            "rotation never waits on another's",
        ).toBe(true);
        expect((await other)?.refreshToken).toBe(otherNext.refreshToken);
        expect((await rotation)?.refreshToken).toBe(next.refreshToken);
      });

      it("leaves the parent live and persists nothing when the successor cannot be persisted", async () => {
        const parent = await savedMember(family);
        const unpersistable = await member(family);
        Object.defineProperty(unpersistable, "refreshToken", {
          enumerable: true,
          get(): string {
            throw new Error("forced persistence failure");
          },
        });

        const outcome = await Promise.allSettled([
          rotate(parent, unpersistable),
        ]);

        if (outcome[0].status === "fulfilled") {
          expect(outcome[0].value).toBe(undefined);
        }
        expect(
          await tokenService.getRefreshToken(parent.refreshToken),
          "a failed rotation must not spend its parent",
        ).not.toBe(undefined);
        expect(await tokenService.getToken(unpersistable.accessToken)).toBe(
          undefined,
        );
        const retry = await member(family);
        expect((await rotate(parent, retry))?.refreshToken).toBe(
          retry.refreshToken,
        );
      });

      it("rolls the claim back when the insert fails after it", async ({
        skip,
      }) => {
        skip(!pausable, "rotate cannot be held (rotateAwaitsBarrier: false)");
        const parent = await savedMember(family);
        const next = await member(family);

        const hold = arm();
        const rotation = rotate(parent, next);
        await untilHeld(hold, rotation);
        hold.release.reject(new Error("forced insert failure"));
        const outcome = await Promise.allSettled([rotation]);

        if (outcome[0].status === "fulfilled") {
          expect(outcome[0].value).toBe(undefined);
        }
        expect(
          await tokenService.getRefreshToken(parent.refreshToken),
          "the claim and the insert are one step: a failed insert must " +
            "leave the parent live",
        ).not.toBe(undefined);
        expect(await live([next])).toStrictEqual([]);
        expect(
          await tokenService.getRevokedRefreshToken!(next.refreshToken),
        ).toBe(undefined);
        const retry = await member(family);
        expect(
          (await rotate(parent, retry))?.refreshToken,
          "a failed rotation must release the family",
        ).toBe(retry.refreshToken);
      });
    },
  );
}
