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
   * Set to `false` when the service deliberately omits the optional
   * reuse-detection pair, {@linkcode TokenServiceInterface.getRevokedRefreshToken}
   * and {@linkcode TokenServiceInterface.revokeFamily}. The suite then
   * registers an ignored case naming what is not covered — a replayed
   * rotated-out refresh token cannot be detected, so a stolen token keeps
   * working alongside the victim's — instead of passing in silence. Defaults to
   * `true`, so a service that meant to implement the pair and does not fails
   * loudly rather than losing reuse detection quietly.
   */
  refreshTokenReuseDetection?: boolean;
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

/** Runs the {@link TokenServiceInterface} contract suite. */
export function runTokenServiceContractTests<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
>(options: TokenServiceContractOptions<C, U, S>): void {
  const makeUser = options.makeUser ?? defaultMakeUser<U>;
  const makeClient = options.makeClient ?? defaultMakeClient<C>;
  const makeScope = options.makeScope ?? defaultMakeScope<S>;
  const expectReuseDetection = options.refreshTokenReuseDetection ?? true;

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
        const requested = makeScope("read");
        const result = await tokenService.acceptedScope(
          client,
          user,
          requested,
        );
        expect(result?.toString()).toStrictEqual("read");
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
          makeScope("read"),
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
    });

    if (expectReuseDetection) {
      describe("refresh-token rotation family", () => {
        const FAMILY = "family-1";
        const OTHER_FAMILY = "family-2";

        async function saveFamilyMember(
          familyId: string,
        ): Promise<RefreshToken<C, U, S>> {
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
            familyId,
            familyCreatedAt: new Date(Date.now() - 60_000),
            client,
            user,
          };
          await tokenService.save(token);
          return token;
        }

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
          const token = await saveFamilyMember(FAMILY);
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
          expect(revoked.familyId).toBe(FAMILY);
        });

        it("does not report a live refresh token as revoked", async () => {
          const token = await saveFamilyMember(FAMILY);
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
          const first = await saveFamilyMember(FAMILY);
          const second = await saveFamilyMember(FAMILY);
          expect(await tokenService.revokeFamily!(FAMILY)).toBe(true);
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
          const mine = await saveFamilyMember(FAMILY);
          const theirs = await saveFamilyMember(OTHER_FAMILY);
          await tokenService.revokeFamily!(FAMILY);
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
          expect(await tokenService.revokeFamily!("never-issued")).toBe(false);
        });
      });
    } else {
      it.skip("refresh-token reuse detection is not implemented — a replayed rotated-out token cannot be detected (refreshTokenReuseDetection: false)", () => {});
    }
  });
}
