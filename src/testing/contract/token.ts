/**
 * Contract test suite for {@link TokenServiceInterface} implementations.
 *
 * Verifies the methods the framework actually calls during the OAuth2
 * flows: token persistence, refresh-token lookup, revocation by token
 * value or by authorization code, and per-(client, user) lifetime/scope
 * generation.
 *
 * Both a token with a user and a token without one are exercised. The client
 * credentials grant (RFC 6749 §4.4) has no resource owner, so the framework
 * calls `acceptedScope`, `generateAccessToken`, and `accessTokenExpiresAt`
 * with `user: undefined` and persists a token whose `user` is unset — a store
 * that requires a user cannot hold a machine token.
 *
 * When the service implements `rotate`, its single-caller contract is checked
 * here too; `runTokenRotationContractTests` checks it under concurrent callers.
 *
 * @module
 */

import { setTimeout as delay } from "node:timers/promises";
import { assert, beforeEach, describe, expect, it } from "vitest";
import type { ClientInterface } from "../../models/client.ts";
import { BasicScope } from "../../models/scope.ts";
import type { AbstractScope } from "../../models/scope.ts";
import type { RefreshToken, Token } from "../../models/token.ts";
import type { ClientServiceInterface } from "../../server/services/client.ts";
import type { TokenServiceInterface } from "../../server/services/token.ts";
import type { UserServiceInterface } from "../../server/services/user.ts";
import type { MemoryUserShape } from "../services.ts";

/** Options for {@link runTokenServiceContractTests}. */
export interface TokenServiceContractOptions<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> {
  /** Returns fresh services for each test. */
  makeServices():
    | Promise<{
        userService: UserServiceInterface<U>;
        clientService: ClientServiceInterface<C, U>;
        tokenService: TokenServiceInterface<C, U, S>;
      }>
    | {
        userService: UserServiceInterface<U>;
        clientService: ClientServiceInterface<C, U>;
        tokenService: TokenServiceInterface<C, U, S>;
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
  /** Builds a distinct client fixture for the given sequence number. Defaults to a client granting `authorization_code` and `refresh_token`. */
  makeClient?(seq: number): C;
  /** Builds a scope from its string value. Defaults to a {@linkcode BasicScope}. */
  makeScope?(value: string): S;
  /**
   * A scope value the service accepts for the fixture client. The
   * `acceptedScope` case with a user requests it and expects it back
   * unchanged; the case with no user requests it and expects it not to be
   * refused. Set it when `acceptedScope` refuses scopes outside a fixed
   * vocabulary, for example `"openid"`. Defaults to `"read"`.
   */
  supportedScope?: string;
  /**
   * Returns a new rotation-family id the store accepts as a
   * {@linkcode RefreshToken.familyId}, distinct on every call. The family cases
   * call it for each family they create and for a family that was never
   * issued, so each case sees only its own families. Users, clients and the
   * authorization-code and unknown-token probes keep fixed values, so a store
   * that keeps state across cases still needs `makeServices` to isolate those.
   * Set it when the store keeps family ids in a format other than a UUID.
   * Defaults to `crypto.randomUUID()`.
   */
  makeFamilyId?(): string;
  /**
   * Set to `false` when the service deliberately omits the optional
   * reuse-detection pair, {@linkcode TokenServiceInterface.getRevokedRefreshToken}
   * and {@linkcode TokenServiceInterface.revokeFamily}. The suite then
   * registers an ignored case naming what is not covered — a replayed
   * rotated-out refresh token cannot be detected, so a stolen token keeps
   * working alongside the victim's, and revoking a rotated-out token at the
   * revocation endpoint leaves its successor live — instead of passing in
   * silence. Defaults to
   * `true`, so a service that meant to implement the pair and does not fails
   * loudly rather than losing reuse detection quietly.
   */
  refreshTokenReuseDetection?: boolean;
  /**
   * Set to `false` when the service's `revokeCode` deliberately ignores its
   * `client` argument. The suite then registers an ignored case naming what is
   * not covered — any client that presents a spent code revokes the tokens
   * issued from it, so a client that sees a leaked code can end the session it
   * started — instead of passing in silence. Defaults to `true`.
   */
  revokeCodeChecksClient?: boolean;
  /**
   * Set to `false` when the service's `revokeCode` deliberately ignores its
   * `codeVerifierHash` argument. The suite then registers an ignored case
   * naming what is not covered — a replay that names a public client by
   * `client_id`, with any verifier, revokes the tokens issued from its spent
   * code, so anyone who holds a leaked code can end the session it started —
   * instead of passing in silence. Defaults to `true`.
   */
  revokeCodeChecksVerifier?: boolean;
  /** Overrides the name passed to the outer `describe` block. */
  describeName?: string;
}

const defaultMakeUser = <U extends MemoryUserShape>(seq: number): U =>
  ({ id: `u${seq}`, username: `user${seq}` }) as U;
const defaultMakeClient = <C extends ClientInterface>(seq: number): C =>
  ({
    id: `client-${seq}`,
    grants: ["authorization_code", "refresh_token"],
  }) as C;
const defaultMakeScope = <S extends AbstractScope>(value: string): S =>
  new BasicScope(value) as unknown as S;
const defaultMakeFamilyId = (): string => crypto.randomUUID();
const randomVerifierHash = (): string =>
  Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");

/** Runs the {@link TokenServiceInterface} contract suite. */
export function runTokenServiceContractTests<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
>(options: TokenServiceContractOptions<C, U, S>): void {
  const makeUser = options.makeUser ?? defaultMakeUser<U>;
  const makeClient = options.makeClient ?? defaultMakeClient<C>;
  const makeScope = options.makeScope ?? defaultMakeScope<S>;
  const supportedScope = options.supportedScope ?? "read";
  const makeFamilyId = options.makeFamilyId ?? defaultMakeFamilyId;
  const expectReuseDetection = options.refreshTokenReuseDetection ?? true;
  const expectCodeClientCheck = options.revokeCodeChecksClient ?? true;
  const expectCodeVerifierCheck = options.revokeCodeChecksVerifier ?? true;

  describe(options.describeName ?? "TokenServiceInterface contract", () => {
    let userService: UserServiceInterface<U>;
    let clientService: ClientServiceInterface<C, U>;
    let tokenService: TokenServiceInterface<C, U, S>;
    let user: U;
    let client: C;

    beforeEach(async () => {
      const services = await options.makeServices();
      userService = services.userService;
      clientService = services.clientService;
      tokenService = services.tokenService;
      user = makeUser(1);
      client = makeClient(1);
      await options.addUser(userService, user, "pw");
      await options.addClient(clientService, client);
    });

    async function familyMember(
      familyId: string,
      refreshTokenExpiresAt = new Date(Date.now() + 600_000),
    ): Promise<RefreshToken<C, U, S>> {
      const accessToken = await tokenService.generateAccessToken(client, user);
      const refreshToken = (await tokenService.generateRefreshToken(
        client,
        user,
      ))!;
      return {
        accessToken,
        accessTokenExpiresAt: new Date(Date.now() + 60_000),
        refreshToken,
        refreshTokenExpiresAt,
        familyId,
        familyCreatedAt: new Date(Date.now() - 60_000),
        client,
        user,
      };
    }

    async function saveFamilyMember(
      familyId: string,
      refreshTokenExpiresAt?: Date,
    ): Promise<RefreshToken<C, U, S>> {
      const token = await familyMember(familyId, refreshTokenExpiresAt);
      await tokenService.save(token);
      return token;
    }

    async function isLive(token: RefreshToken<C, U, S>): Promise<boolean> {
      return (
        (await tokenService.getRefreshToken(token.refreshToken)) !==
          undefined ||
        (await tokenService.getToken(token.accessToken)) !== undefined
      );
    }

    async function rotateTo(
      current: RefreshToken<C, U, S>,
      next: RefreshToken<C, U, S>,
    ): Promise<void> {
      if (tokenService.rotate) {
        assert(await tokenService.rotate(current, next));
        return;
      }
      const claimed = tokenService.revokeRotated
        ? await tokenService.revokeRotated(current)
        : await tokenService.revoke(current);
      assert(claimed);
      await tokenService.save(next);
    }

    describe("generateAccessToken / generateRefreshToken", () => {
      it("produces unique access tokens", async () => {
        const a = await tokenService.generateAccessToken(client, user);
        const b = await tokenService.generateAccessToken(client, user);
        expect(typeof a).toStrictEqual("string");
        expect(typeof b).toStrictEqual("string");
        assert(a !== b, "access tokens should not collide");
      });

      it("produces unique refresh tokens (or undefined to opt out)", async () => {
        const a = await tokenService.generateRefreshToken(client, user);
        const b = await tokenService.generateRefreshToken(client, user);
        if (a !== undefined && b !== undefined) {
          assert(a !== b, "refresh tokens should not collide");
        }
      });
    });

    describe("acceptedScope", () => {
      it("returns the requested scope unchanged for the simple case", async () => {
        const requested = makeScope(supportedScope);
        const result = await tokenService.acceptedScope(
          client,
          user,
          requested,
        );
        expect(result?.toString()).toStrictEqual(supportedScope);
      });
    });

    describe("save + getToken", () => {
      it("round-trips an access-only token", async () => {
        const accessToken = await tokenService.generateAccessToken(
          client,
          user,
        );
        const expiresAt = new Date(Date.now() + 60_000);
        const token: Token<C, U, S> = {
          accessToken,
          accessTokenExpiresAt: expiresAt,
          client,
          user,
        };
        await tokenService.save(token);
        const fetched = await tokenService.getToken(accessToken);
        expect(fetched?.client.id).toStrictEqual(client.id);
        expect(
          (fetched?.user as MemoryUserShape | undefined)?.id,
        ).toStrictEqual(user.id);
        expect(fetched?.accessTokenExpiresAt?.getTime()).toBe(
          expiresAt.getTime(),
        );
      });

      it("returns undefined for an unknown access token", async () => {
        expect(await tokenService.getToken("nope")).toBe(undefined);
      });
    });

    describe("tokens with no user", () => {
      it("generates an access token for a client with no user", async () => {
        const accessToken = await tokenService.generateAccessToken(
          client,
          undefined,
        );
        expect(typeof accessToken).toStrictEqual("string");
      });

      it("accepts scope for a client with no user", async () => {
        const result = await tokenService.acceptedScope(
          client,
          undefined,
          makeScope(supportedScope),
        );
        assert(
          result !== false,
          "scope must not be rejected for lack of a user",
        );
      });

      it("dates the expiry of an access token with no user", async () => {
        const expiresAt = await tokenService.accessTokenExpiresAt(
          client,
          undefined,
        );
        if (expiresAt) assert(expiresAt.getTime() > Date.now());
      });

      it("round-trips a token with no user", async () => {
        const accessToken = await tokenService.generateAccessToken(
          client,
          undefined,
        );
        await tokenService.save({ accessToken, client });
        const fetched = await tokenService.getToken(accessToken);
        expect(fetched?.client.id).toStrictEqual(client.id);
        expect(fetched?.user).toBe(undefined);
      });

      it("revokes a token with no user", async () => {
        const accessToken = await tokenService.generateAccessToken(
          client,
          undefined,
        );
        await tokenService.save({ accessToken, client });
        expect(await tokenService.revoke(accessToken)).toBe(true);
        expect(await tokenService.getToken(accessToken)).toBe(undefined);
      });
    });

    describe("save + getRefreshToken", () => {
      it("round-trips a refresh token", async () => {
        const accessToken = await tokenService.generateAccessToken(
          client,
          user,
        );
        const refreshToken = (await tokenService.generateRefreshToken(
          client,
          user,
        ))!;
        const token: RefreshToken<C, U, S> = {
          accessToken,
          accessTokenExpiresAt: new Date(Date.now() + 60_000),
          refreshToken,
          refreshTokenExpiresAt: new Date(Date.now() + 600_000),
          client,
          user,
        };
        await tokenService.save(token);
        const fetched = await tokenService.getRefreshToken(refreshToken);
        expect(fetched?.client.id).toStrictEqual(client.id);
      });

      it("returns undefined for an unknown refresh token", async () => {
        expect(await tokenService.getRefreshToken("nope")).toBe(undefined);
      });
    });

    describe("revoke", () => {
      it("revokes by token object", async () => {
        const accessToken = await tokenService.generateAccessToken(
          client,
          user,
        );
        const token: Token<C, U, S> = {
          accessToken,
          client,
          user,
        };
        await tokenService.save(token);
        const ok = await tokenService.revoke(token);
        expect(ok).toBe(true);
        expect(await tokenService.getToken(accessToken)).toBe(undefined);
      });

      it("revokes by access token string", async () => {
        const accessToken = await tokenService.generateAccessToken(
          client,
          user,
        );
        await tokenService.save({ accessToken, client, user });
        const ok = await tokenService.revoke(accessToken);
        expect(ok).toBe(true);
        expect(await tokenService.getToken(accessToken)).toBe(undefined);
      });

      it("revokes by refresh token string when hint='refresh_token'", async () => {
        const accessToken = await tokenService.generateAccessToken(
          client,
          user,
        );
        const refreshToken = (await tokenService.generateRefreshToken(
          client,
          user,
        ))!;
        await tokenService.save({
          accessToken,
          refreshToken,
          client,
          user,
        } as RefreshToken<C, U, S>);
        const ok = await tokenService.revoke(refreshToken, "refresh_token");
        expect(ok).toBe(true);
        expect(await tokenService.getRefreshToken(refreshToken)).toBe(
          undefined,
        );
        expect(await tokenService.getToken(accessToken)).toBe(undefined);
      });

      it("returns false for an unknown token string", async () => {
        expect(await tokenService.revoke("missing")).toBe(false);
      });

      it("answers true only for the call that removed a live token", async () => {
        const accessToken = await tokenService.generateAccessToken(
          client,
          user,
        );
        const token: Token<C, U, S> = { accessToken, client, user };
        expect(
          await tokenService.revoke(token),
          "a token that was never saved was not revoked by this call — " +
            "answering true makes a single-use check built on the result inert",
        ).toBe(false);
        await tokenService.save(token);
        expect(await tokenService.revoke(token)).toBe(true);
        expect(await tokenService.revoke(token)).toBe(false);
      });
    });

    describe("revokeCode", () => {
      it("revokes every token issued under a given authorization code", async () => {
        const code = "shared-code";
        const accessToken1 = await tokenService.generateAccessToken(
          client,
          user,
        );
        const accessToken2 = await tokenService.generateAccessToken(
          client,
          user,
        );
        await tokenService.save({
          accessToken: accessToken1,
          code,
          client,
          user,
        });
        await tokenService.save({
          accessToken: accessToken2,
          code,
          client,
          user,
        });
        const ok = await tokenService.revokeCode(code);
        expect(ok).toBe(true);
        expect(await tokenService.getToken(accessToken1)).toBe(undefined);
        expect(await tokenService.getToken(accessToken2)).toBe(undefined);
      });

      it("returns false when no tokens were issued for the code", async () => {
        expect(await tokenService.revokeCode("never-used")).toBe(false);
      });

      if (expectCodeClientCheck) {
        async function issueFromCode(code: string): Promise<string> {
          const accessToken = await tokenService.generateAccessToken(
            client,
            user,
          );
          await tokenService.save({ accessToken, code, client, user });
          return accessToken;
        }

        it("revokes nothing for a client other than the one the code's tokens were issued to", async () => {
          const other = makeClient(2);
          await options.addClient(clientService, other);
          const accessToken = await issueFromCode("replayed-code");

          expect(
            await tokenService.revokeCode("replayed-code", other),
            "a client that could never have redeemed the code must not " +
              "revoke what it issued",
          ).toBe(false);
          expect(await tokenService.getToken(accessToken)).not.toBe(undefined);
        });

        it("revokes for the client the code's tokens were issued to, after another client was refused", async () => {
          const other = makeClient(2);
          await options.addClient(clientService, other);
          const accessToken = await issueFromCode("replayed-code");
          await tokenService.revokeCode("replayed-code", other);

          expect(await tokenService.revokeCode("replayed-code", client)).toBe(
            true,
          );
          expect(await tokenService.getToken(accessToken)).toBe(undefined);
        });

        it("revokes nothing in a rotated family for a client other than the one the code's tokens were issued to", async () => {
          const other = makeClient(2);
          await options.addClient(clientService, other);
          const family = makeFamilyId();
          const issued = {
            ...(await familyMember(family)),
            code: "rotated-replayed-code",
          };
          await tokenService.save(issued);
          const rotated = await familyMember(family);
          await rotateTo(issued, rotated);

          expect(
            await tokenService.revokeCode("rotated-replayed-code", other),
          ).toBe(false);
          expect(
            await isLive(rotated),
            "the client check comes before any family is revoked — a " +
              "client that could never have redeemed the code must not end " +
              "the session rotated from it",
          ).toBe(true);
        });
      } else {
        it.skip("revokeCode ignores the presenting client — any client that presents a spent code revokes its tokens (revokeCodeChecksClient: false)", () => {});
      }

      if (expectCodeVerifierCheck) {
        async function issueBoundCode(
          code: string,
          codeVerifierHash?: string,
        ): Promise<string> {
          const accessToken = await tokenService.generateAccessToken(
            client,
            user,
          );
          await tokenService.save({
            accessToken,
            code,
            codeVerifierHash,
            client,
            user,
          });
          return accessToken;
        }

        it("revokes nothing for a codeVerifierHash other than the one the code's tokens were saved with", async () => {
          const accessToken = await issueBoundCode(
            "bound-code",
            randomVerifierHash(),
          );

          expect(
            await tokenService.revokeCode(
              "bound-code",
              client,
              randomVerifierHash(),
            ),
            "a replay without the verifier that redeemed the code proves " +
              "nothing, so it must not revoke what the code issued",
          ).toBe(false);
          expect(await tokenService.getToken(accessToken)).not.toBe(undefined);
        });

        it("revokes for the codeVerifierHash the code's tokens were saved with, after another was refused", async () => {
          const codeVerifierHash = randomVerifierHash();
          const accessToken = await issueBoundCode(
            "bound-code",
            codeVerifierHash,
          );
          await tokenService.revokeCode(
            "bound-code",
            client,
            randomVerifierHash(),
          );

          expect(
            await tokenService.revokeCode(
              "bound-code",
              client,
              codeVerifierHash,
            ),
          ).toBe(true);
          expect(await tokenService.getToken(accessToken)).toBe(undefined);
        });

        if (expectCodeClientCheck) {
          it("revokes nothing for another client that presents the codeVerifierHash the code's tokens were saved with", async () => {
            const other = makeClient(2);
            await options.addClient(clientService, other);
            const codeVerifierHash = randomVerifierHash();
            const accessToken = await issueBoundCode(
              "bound-code",
              codeVerifierHash,
            );

            expect(
              await tokenService.revokeCode(
                "bound-code",
                other,
                codeVerifierHash,
              ),
              "a matching verifier does not lift the client check",
            ).toBe(false);
            expect(await tokenService.getToken(accessToken)).not.toBe(
              undefined,
            );
          });
        }

        it("revokes nothing for a codeVerifierHash when the code's tokens were saved without one", async () => {
          const accessToken = await issueBoundCode("unbound-code");

          expect(
            await tokenService.revokeCode(
              "unbound-code",
              client,
              randomVerifierHash(),
            ),
            "a code redeemed without PKCE binds no verifier, so no verifier " +
              "a replay presents can match it",
          ).toBe(false);
          expect(await tokenService.getToken(accessToken)).not.toBe(undefined);
        });

        it("revokes a code saved with a codeVerifierHash when none is passed, for a client that authenticated", async () => {
          const accessToken = await issueBoundCode(
            "bound-code",
            randomVerifierHash(),
          );

          expect(
            await tokenService.revokeCode("bound-code", client),
            "the grant omits codeVerifierHash for a client that " +
              "authenticated with its secret, where the client check suffices",
          ).toBe(true);
          expect(await tokenService.getToken(accessToken)).toBe(undefined);
        });

        it("revokes nothing in a rotated family for a codeVerifierHash other than the one the code's tokens were saved with", async () => {
          const family = makeFamilyId();
          const issued = {
            ...(await familyMember(family)),
            code: "rotated-bound-code",
            codeVerifierHash: randomVerifierHash(),
          };
          await tokenService.save(issued);
          const rotated = await familyMember(family);
          await rotateTo(issued, rotated);

          expect(
            await tokenService.revokeCode(
              "rotated-bound-code",
              client,
              randomVerifierHash(),
            ),
          ).toBe(false);
          expect(
            await isLive(rotated),
            "the verifier check comes before any family is revoked — a " +
              "replay without the redeeming verifier must not end the " +
              "session rotated from the code",
          ).toBe(true);
        });
      } else {
        it.skip("revokeCode ignores the presented verifier — a replay that names a public client, with any verifier, revokes its spent code's tokens (revokeCodeChecksVerifier: false)", () => {});
      }
    });

    if (expectReuseDetection) {
      describe("refresh-token rotation family", () => {
        let family: string;
        let otherFamily: string;

        beforeEach(() => {
          family = makeFamilyId();
          otherFamily = makeFamilyId();
        });

        it("implements both halves of reuse detection", () => {
          assert(
            typeof tokenService.getRevokedRefreshToken === "function" &&
              typeof tokenService.revokeFamily === "function",
            "getRevokedRefreshToken and revokeFamily are optional, but " +
              "without both the refresh grant cannot tell a replayed " +
              "rotated-out token from an unknown one and reuse detection is " +
              "silently disabled. Implement them, or pass " +
              "`refreshTokenReuseDetection: false` to record the gap.",
          );
        });

        it("keeps a rotated-out refresh token findable, with its family", async () => {
          const token = await saveFamilyMember(family);
          await tokenService.revoke(token.refreshToken, "refresh_token");
          expect(
            await tokenService.getRefreshToken(token.refreshToken),
            "a rotated-out token must no longer refresh",
          ).toBe(undefined);
          const revoked = await tokenService.getRevokedRefreshToken!(
            token.refreshToken,
          );
          assert(
            revoked !== undefined,
            "a revoked refresh token must stay findable — deleting the row " +
              "is what turns a replay into an ordinary unknown token",
          );
          expect(revoked.familyId).toBe(family);
        });

        it("does not report a live refresh token as revoked", async () => {
          const token = await saveFamilyMember(family);
          expect(
            await tokenService.getRevokedRefreshToken!(token.refreshToken),
            "reporting a live token as revoked turns every legitimate " +
              "refresh into a detected replay",
          ).toBe(undefined);
        });

        it("returns undefined for a refresh token that was never issued", async () => {
          expect(
            await tokenService.getRevokedRefreshToken!("never-issued"),
          ).toBe(undefined);
        });

        it("revokes every live member of a replayed token's family", async () => {
          const first = await saveFamilyMember(family);
          const second = await saveFamilyMember(family);
          expect(await tokenService.revokeFamily!(family)).toBe(true);
          expect(await tokenService.getRefreshToken(first.refreshToken)).toBe(
            undefined,
          );
          expect(await tokenService.getRefreshToken(second.refreshToken)).toBe(
            undefined,
          );
          expect(
            await tokenService.getToken(second.accessToken),
            "the family's access tokens die with it — leaving them live " +
              "keeps the thief's session alive for their remaining lifetime",
          ).toBe(undefined);
        });

        it("leaves other families untouched", async () => {
          const mine = await saveFamilyMember(family);
          const theirs = await saveFamilyMember(otherFamily);
          await tokenService.revokeFamily!(family);
          expect(await tokenService.getRefreshToken(mine.refreshToken)).toBe(
            undefined,
          );
          assert(
            (await tokenService.getRefreshToken(theirs.refreshToken)) !==
              undefined,
            "one compromised family must not sign every other session out",
          );
        });

        it("returns false when the family has no live tokens", async () => {
          expect(await tokenService.revokeFamily!(makeFamilyId())).toBe(false);
        });

        it("keeps a revoked family revoked: a successor saved after revokeFamily is not live", async ({
          skip,
        }) => {
          skip(
            typeof tokenService.rotate === "function",
            "the service implements rotate, so the refresh grant never saves " +
              "a successor separately; runTokenRotationContractTests checks " +
              "revokeFamily against rotate",
          );
          const parent = await saveFamilyMember(family);
          const successor = await familyMember(family);
          const claimed = tokenService.revokeRotated
            ? await tokenService.revokeRotated(parent)
            : await tokenService.revoke(parent);
          expect(claimed).toBe(true);
          expect(
            await tokenService.getRefreshToken(parent.refreshToken),
            "the claim spends the presented refresh token",
          ).toBe(undefined);

          await tokenService.revokeFamily!(family);
          await tokenService.save(successor);

          expect(
            await tokenService.getRefreshToken(successor.refreshToken),
            "a successor saved after its family was revoked must be stored " +
              "already revoked: the refresh grant claims a token and saves " +
              "its successor in two calls, and a revokeFamily that lands " +
              "between them otherwise leaves the successor live",
          ).toBe(undefined);
          expect(
            await tokenService.getToken(successor.accessToken),
            "a successor saved after its family was revoked must be stored " +
              "already revoked, its access token included",
          ).toBe(undefined);
          if (tokenService.hasLiveRefreshToken) {
            expect(
              await tokenService.hasLiveRefreshToken(family),
              "a successor saved after its family was revoked must be stored " +
                "already revoked, so the family has no live member",
            ).toBe(false);
          }
        });

        it("stamps a token revokeRotated revoked with its rotation time", async ({
          skip,
        }) => {
          skip(
            typeof tokenService.revokeRotated !== "function",
            "the service does not implement revokeRotated",
          );
          const token = await saveFamilyMember(family);
          const before = Date.now();
          expect(await tokenService.revokeRotated!(token)).toBe(true);
          const revoked = await tokenService.getRevokedRefreshToken!(
            token.refreshToken,
          );
          assert(revoked !== undefined);
          assert(
            revoked.rotatedAt instanceof Date &&
              revoked.rotatedAt.getTime() >= before - 1000 &&
              revoked.rotatedAt.getTime() <= Date.now() + 1000,
            "without rotatedAt the refresh grant's replayGraceSeconds never " +
              "applies, so every straggler revokes its family",
          );
        });

        it("rotates in one call: the parent is spent and stamped, the successor live", async ({
          skip,
        }) => {
          skip(
            typeof tokenService.rotate !== "function",
            "the service does not implement rotate",
          );
          const parent = await saveFamilyMember(family);
          const next = await familyMember(family);
          const before = Date.now();

          const rotated = await tokenService.rotate!(parent, next);

          expect(rotated?.refreshToken).toBe(next.refreshToken);
          expect(
            (await tokenService.getRefreshToken(next.refreshToken))?.familyId,
          ).toBe(family);
          expect(await tokenService.getToken(next.accessToken)).not.toBe(
            undefined,
          );
          expect(await tokenService.getRefreshToken(parent.refreshToken)).toBe(
            undefined,
          );
          expect(
            await tokenService.getToken(parent.accessToken),
            "rotation ends the parent's access token, as revokeRotated does",
          ).toBe(undefined);
          const tombstone = await tokenService.getRevokedRefreshToken!(
            parent.refreshToken,
          );
          expect(tombstone?.familyId).toBe(family);
          assert(
            tombstone?.rotatedAt instanceof Date &&
              tombstone.rotatedAt.getTime() >= before - 1000 &&
              tombstone.rotatedAt.getTime() <= Date.now() + 1000,
            "rotate must stamp rotatedAt as revokeRotated does, or the " +
              "refresh grant's replayGraceSeconds and the revocation " +
              "endpoint's family revocation stop applying",
          );
        });

        it("refuses to rotate a refresh token that is no longer live, persisting nothing", async ({
          skip,
        }) => {
          skip(
            typeof tokenService.rotate !== "function",
            "the service does not implement rotate",
          );
          const parent = await saveFamilyMember(family);
          const first = await familyMember(family);
          const second = await familyMember(family);
          const revokedParent = await saveFamilyMember(family);
          const third = await familyMember(family);
          await tokenService.revoke(
            revokedParent.refreshToken,
            "refresh_token",
          );

          expect(await tokenService.rotate!(parent, first)).not.toBe(undefined);
          expect(
            await tokenService.rotate!(parent, second),
            "a refresh token is claimed once",
          ).toBe(undefined);
          expect(await tokenService.rotate!(revokedParent, third)).toBe(
            undefined,
          );
          for (const refused of [second, third]) {
            expect(
              await tokenService.getRefreshToken(refused.refreshToken),
            ).toBe(undefined);
            expect(await tokenService.getToken(refused.accessToken)).toBe(
              undefined,
            );
            expect(
              await tokenService.getRevokedRefreshToken!(refused.refreshToken),
            ).toBe(undefined);
          }
        });

        it("finds a rotated-out token's family, so revoking it ends the live successor", async ({
          skip,
        }) => {
          skip(
            typeof tokenService.revokeRotated !== "function",
            "the service does not implement revokeRotated",
          );
          const rotatedOut = await saveFamilyMember(family);
          expect(await tokenService.revokeRotated!(rotatedOut)).toBe(true);
          const successor = await saveFamilyMember(family);
          const unrelated = await saveFamilyMember(otherFamily);

          const tombstone = await tokenService.getRevokedRefreshToken!(
            rotatedOut.refreshToken,
          );
          assert(
            tombstone?.familyId === family && tombstone.rotatedAt,
            "the revocation endpoint finds the family to end from the " +
              "rotated-out token's record; without its familyId and " +
              "rotatedAt, a sign-out racing a refresh leaves the successor live",
          );
          expect(
            tombstone.client.id.toString(),
            "the endpoint revokes the family only for the client the token " +
              "was issued to",
          ).toBe(client.id.toString());
          expect(await tokenService.revokeFamily!(tombstone.familyId)).toBe(
            true,
          );
          expect(
            await tokenService.getRefreshToken(successor.refreshToken),
          ).toBe(undefined);
          expect(await tokenService.getToken(successor.accessToken)).toBe(
            undefined,
          );
          assert(
            (await tokenService.getRefreshToken(unrelated.refreshToken)) !==
              undefined,
          );
        });

        it("revokes the rotated successors of a replayed code's tokens, leaving other families live", async () => {
          const code = "rotated-code";
          const issued = { ...(await familyMember(family)), code };
          await tokenService.save(issued);
          const rotated = await familyMember(family);
          await rotateTo(issued, rotated);
          const latest = await familyMember(family);
          await rotateTo(rotated, latest);
          const unrelated = await saveFamilyMember(otherFamily);
          expect(await isLive(latest)).toBe(true);

          expect(
            await tokenService.revokeCode(code, client),
            "the replay ended a live token, so the grant must report it",
          ).toBe(true);
          expect(
            await tokenService.getRefreshToken(latest.refreshToken),
            "a rotated successor carries no code, so revoking only the " +
              "rows issued with the code leaves the stolen code's session " +
              "refreshing — revoke every live member of their families",
          ).toBe(undefined);
          expect(
            await tokenService.getToken(latest.accessToken),
            "the successor's access token ends with its family",
          ).toBe(undefined);
          if (tokenService.hasLiveRefreshToken) {
            expect(await tokenService.hasLiveRefreshToken(family)).toBe(false);
          }
          assert(
            (await tokenService.getRefreshToken(unrelated.refreshToken)) !==
              undefined,
            "a replayed code must not end families it did not issue",
          );
        });

        it("keeps a replayed code's family revoked: a successor saved after revokeCode is not live", async ({
          skip,
        }) => {
          skip(
            typeof tokenService.rotate === "function",
            "the service implements rotate, so the refresh grant never saves " +
              "a successor separately; runTokenRotationContractTests checks " +
              "revokeCode against rotate",
          );
          const code = "claimed-code";
          const issued = { ...(await familyMember(family)), code };
          await tokenService.save(issued);
          const next = await familyMember(family);
          const claimed = tokenService.revokeRotated
            ? await tokenService.revokeRotated(issued)
            : await tokenService.revoke(issued);
          expect(claimed).toBe(true);

          await tokenService.revokeCode(code, client);
          await tokenService.save(next);

          expect(
            await isLive(next),
            "a successor saved after its code was replayed must be stored " +
              "already revoked: the refresh grant claims a token and saves " +
              "its successor in two calls, and a replay that lands between " +
              "them otherwise leaves the successor live",
          ).toBe(false);
          if (tokenService.hasLiveRefreshToken) {
            expect(await tokenService.hasLiveRefreshToken(family)).toBe(false);
          }
        });

        it("leaves rotatedAt unset on a token revoked other than by rotation", async () => {
          const token = await saveFamilyMember(family);
          await tokenService.revoke(token.refreshToken, "refresh_token");
          const revoked = await tokenService.getRevokedRefreshToken!(
            token.refreshToken,
          );
          expect(
            revoked?.rotatedAt,
            "a revoked token that looks rotated gets the replay grace a " +
              "signed-out session must never have",
          ).toBe(undefined);
        });

        it("reports whether a family still has a live refresh token", async ({
          skip,
        }) => {
          skip(
            typeof tokenService.hasLiveRefreshToken !== "function",
            "the service does not implement hasLiveRefreshToken",
          );
          const token = await saveFamilyMember(family);
          await saveFamilyMember(otherFamily);
          expect(await tokenService.hasLiveRefreshToken!(family)).toBe(true);
          await tokenService.revoke(token.refreshToken, "refresh_token");
          expect(
            await tokenService.hasLiveRefreshToken!(family),
            "a family whose last token was revoked has no successor to protect",
          ).toBe(false);
          expect(await tokenService.hasLiveRefreshToken!(otherFamily)).toBe(
            true,
          );
          expect(await tokenService.hasLiveRefreshToken!(makeFamilyId())).toBe(
            false,
          );
        });

        it("does not count an expired refresh token as live", async ({
          skip,
        }) => {
          skip(
            typeof tokenService.hasLiveRefreshToken !== "function",
            "the service does not implement hasLiveRefreshToken",
          );
          await saveFamilyMember(family, new Date(Date.now() - 1000));
          expect(
            await tokenService.hasLiveRefreshToken!(family),
            "an expired successor cannot be used, so a replay of its " +
              "predecessor must not be excused as a straggler",
          ).toBe(false);
        });

        async function rotateOut(
          skip: (condition: boolean, note: string) => void,
        ): Promise<{
          tombstone: RefreshToken<C, U, S>;
          successor: RefreshToken<C, U, S>;
        }> {
          skip(
            typeof tokenService.isWithinReplayGrace !== "function",
            "the service does not implement isWithinReplayGrace",
          );
          skip(
            typeof tokenService.rotate !== "function" &&
              typeof tokenService.revokeRotated !== "function",
            "the service implements neither rotate nor revokeRotated",
          );
          const parent = await saveFamilyMember(family);
          const successor = await familyMember(family);
          if (tokenService.rotate) {
            assert(await tokenService.rotate(parent, successor));
          } else {
            assert(await tokenService.revokeRotated!(parent));
            await tokenService.save(successor);
          }
          const tombstone = await tokenService.getRevokedRefreshToken!(
            parent.refreshToken,
          );
          assert(
            tombstone?.familyId === family && tombstone.rotatedAt,
            "a store that judges the replay grace must still return every " +
              "rotated-out tombstone, with its family and rotatedAt; hiding " +
              "one inside the window hides the family from a sign-out " +
              "racing the refresh, which then leaves the successor live",
          );
          return { tombstone, successor };
        }

        it("returns the tombstone of a token inside its replay grace, so revoking it ends the successor", async ({
          skip,
        }) => {
          const { tombstone, successor } = await rotateOut(skip);

          expect(
            await tokenService.isWithinReplayGrace!(tombstone, 60),
            "a token rotated out a moment ago is inside a 60-second grace",
          ).toBe(true);
          expect(await tokenService.revokeFamily!(tombstone.familyId!)).toBe(
            true,
          );
          expect(
            await tokenService.getRefreshToken(successor.refreshToken),
          ).toBe(undefined);
        });

        it("judges a rotated-out token inside a one-second grace, then outside it once the second has passed", async ({
          skip,
        }) => {
          const { tombstone } = await rotateOut(skip);

          expect(
            await tokenService.isWithinReplayGrace!(tombstone, 1),
            "a token rotated out a moment ago is inside a one-second grace",
          ).toBe(true);

          await delay(1_200);

          expect(
            await tokenService.isWithinReplayGrace!(tombstone, 1),
            "a grace that answers true regardless of elapsed time excuses " +
              "every replay while the family is live, which turns reuse " +
              "detection off",
          ).toBe(false);
          expect(await tokenService.isWithinReplayGrace!(tombstone, 3600)).toBe(
            true,
          );
        });
      });
    } else {
      it.skip("refresh-token reuse detection is not implemented — a replayed rotated-out token cannot be detected, and revoking one does not end its successor (refreshTokenReuseDetection: false)", () => {});
    }
  });
}
