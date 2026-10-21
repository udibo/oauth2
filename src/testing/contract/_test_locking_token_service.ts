import type { ClientInterface } from "../../models/client.ts";
import type { BasicScope } from "../../models/scope.ts";
import type { RefreshToken, Token } from "../../models/token.ts";
import type { TokenServiceInterface } from "../../server/services/token.ts";
import type { MemoryUserShape } from "../services.ts";
import type { TokenRotationBarriers } from "./token-rotation.ts";

type AnyToken<C extends ClientInterface, U> =
  | Token<C, U, BasicScope>
  | RefreshToken<C, U, BasicScope>;

/**
 * A token store shaped like a database-backed one: `rotate` awaits between its
 * claim and its insert, both become visible only when it commits, and
 * `rotate` and `revokeFamily` serialize on a per-family lock instead of a
 * revoked-family marker. It proves that `runTokenRotationContractTests`
 * holds a rotation where such a store needs it held. Given `familyIdFormat`,
 * it throws on a family id outside it, as a typed column would.
 */
export class LockingTokenService<
  C extends ClientInterface,
  U extends MemoryUserShape,
> implements TokenServiceInterface<C, U, BasicScope> {
  accessTokenLifetime = 3600;
  refreshTokenLifetime = 1_209_600;
  readonly #barriers: TokenRotationBarriers;
  readonly #byAccess = new Map<string, AnyToken<C, U>>();
  readonly #byRefresh = new Map<string, RefreshToken<C, U, BasicScope>>();
  readonly #revoked = new Map<string, RefreshToken<C, U, BasicScope>>();
  readonly #byCode = new Map<string, Set<string>>();
  readonly #codeClients = new Map<string, string>();
  readonly #codeFamilies = new Map<string, Set<string>>();
  readonly #locks = new Map<string, Promise<void>>();
  readonly #familyIdFormat: RegExp | undefined;

  constructor(
    barriers: TokenRotationBarriers,
    options: { familyIdFormat?: RegExp } = {},
  ) {
    this.#barriers = barriers;
    this.#familyIdFormat = options.familyIdFormat;
  }

  protected checkFamilyId(familyId: string | undefined): void {
    if (
      familyId !== undefined &&
      this.#familyIdFormat &&
      !this.#familyIdFormat.test(familyId)
    ) {
      throw new TypeError(`invalid input syntax for family id: "${familyId}"`);
    }
  }

  acceptedScope(
    _client: C,
    _user: U | undefined,
    scope?: BasicScope | null,
  ): Promise<BasicScope | null | undefined> {
    return Promise.resolve(scope);
  }

  generateAccessToken(): Promise<string> {
    return Promise.resolve(crypto.randomUUID());
  }

  generateRefreshToken(): Promise<string> {
    return Promise.resolve(crypto.randomUUID());
  }

  accessTokenExpiresAt(): Promise<Date> {
    return Promise.resolve(
      new Date(Date.now() + this.accessTokenLifetime * 1000),
    );
  }

  refreshTokenExpiresAt(): Promise<Date> {
    return Promise.resolve(
      new Date(Date.now() + this.refreshTokenLifetime * 1000),
    );
  }

  getToken(accessToken: string): Promise<Token<C, U, BasicScope> | undefined> {
    const token = this.#byAccess.get(accessToken);
    return Promise.resolve(token && { ...token });
  }

  getRefreshToken(
    refreshToken: string,
  ): Promise<RefreshToken<C, U, BasicScope> | undefined> {
    const token = this.#byRefresh.get(refreshToken);
    return Promise.resolve(token && { ...token });
  }

  getRevokedRefreshToken(
    refreshToken: string,
  ): Promise<RefreshToken<C, U, BasicScope> | undefined> {
    const token = this.#revoked.get(refreshToken);
    return Promise.resolve(token && { ...token });
  }

  save(
    token: RefreshToken<C, U, BasicScope>,
  ): Promise<RefreshToken<C, U, BasicScope>>;
  save(token: Token<C, U, BasicScope>): Promise<Token<C, U, BasicScope>>;
  save(token: AnyToken<C, U>): Promise<AnyToken<C, U>> {
    if ("refreshToken" in token) this.checkFamilyId(token.familyId);
    this.#insert({ ...token });
    return Promise.resolve(token);
  }

  revoke(token: AnyToken<C, U>): Promise<boolean>;
  revoke(token: string, hint?: string | null): Promise<boolean>;
  revoke(
    token: AnyToken<C, U> | string,
    hint?: string | null,
  ): Promise<boolean> {
    const found =
      typeof token !== "string"
        ? "refreshToken" in token
          ? this.#byRefresh.get(token.refreshToken)
          : this.#byAccess.get(token.accessToken)
        : hint === "refresh_token"
          ? this.#byRefresh.get(token)
          : this.#byAccess.get(token);
    if (!found) return Promise.resolve(false);
    this.#remove(found);
    return Promise.resolve(true);
  }

  revokeRotated(token: RefreshToken<C, U, BasicScope>): Promise<boolean> {
    const found = this.#byRefresh.get(token.refreshToken);
    if (!found) return Promise.resolve(false);
    this.#remove(found, new Date());
    return Promise.resolve(true);
  }

  rotate(
    current: RefreshToken<C, U, BasicScope>,
    next: RefreshToken<C, U, BasicScope>,
  ): Promise<RefreshToken<C, U, BasicScope> | undefined> {
    this.checkFamilyId(current.familyId);
    this.checkFamilyId(next.familyId);
    return this.#withFamilyLock(current.familyId, async () => {
      const parent = this.#byRefresh.get(current.refreshToken);
      if (!parent) return undefined;
      const successor = { ...next };
      await this.#barriers.afterClaim();
      this.#remove(parent, new Date());
      this.#insert(successor);
      return next;
    });
  }

  revokeFamily(familyId: string): Promise<boolean> {
    this.checkFamilyId(familyId);
    return this.#withFamilyLock(familyId, () => {
      let revoked = false;
      for (const token of [...this.#byRefresh.values()]) {
        if (token.familyId === familyId) {
          this.#remove(token);
          revoked = true;
        }
      }
      return Promise.resolve(revoked);
    });
  }

  hasLiveRefreshToken(familyId: string): Promise<boolean> {
    this.checkFamilyId(familyId);
    const now = Date.now();
    return Promise.resolve(
      [...this.#byRefresh.values()].some(
        (token) =>
          token.familyId === familyId &&
          (!token.refreshTokenExpiresAt ||
            token.refreshTokenExpiresAt.getTime() > now),
      ),
    );
  }

  async revokeCode(code: string, client?: C): Promise<boolean> {
    const accessTokens = this.#byCode.get(code);
    if (client && this.#codeClients.get(code) !== client.id.toString()) {
      return false;
    }
    if (!accessTokens?.size) return false;
    for (const familyId of this.#codeFamilies.get(code) ?? []) {
      await this.revokeFamily(familyId);
    }
    for (const accessToken of accessTokens) {
      const found = this.#byAccess.get(accessToken);
      if (found) this.#remove(found);
    }
    this.#byCode.delete(code);
    this.#codeFamilies.delete(code);
    return true;
  }

  #insert(token: AnyToken<C, U>): void {
    this.#byAccess.set(token.accessToken, token);
    if ("refreshToken" in token) this.#byRefresh.set(token.refreshToken, token);
    if (token.code) {
      const bucket = this.#byCode.get(token.code) ?? new Set();
      bucket.add(token.accessToken);
      this.#byCode.set(token.code, bucket);
      this.#codeClients.set(token.code, token.client.id.toString());
      if ("refreshToken" in token && token.familyId) {
        const families = this.#codeFamilies.get(token.code) ?? new Set();
        families.add(token.familyId);
        this.#codeFamilies.set(token.code, families);
      }
    }
  }

  #remove(token: AnyToken<C, U>, rotatedAt?: Date): void {
    this.#byAccess.delete(token.accessToken);
    if ("refreshToken" in token) {
      this.#byRefresh.delete(token.refreshToken);
      this.#revoked.set(token.refreshToken, { ...token, rotatedAt });
    }
  }

  async #withFamilyLock<T>(
    familyId: string | undefined,
    critical: () => Promise<T>,
  ): Promise<T> {
    if (familyId === undefined) return await critical();
    const previous = this.#locks.get(familyId) ?? Promise.resolve();
    const released = Promise.withResolvers<void>();
    const tail = previous.then(() => released.promise);
    this.#locks.set(familyId, tail);
    await previous;
    try {
      return await critical();
    } finally {
      released.resolve();
      if (this.#locks.get(familyId) === tail) this.#locks.delete(familyId);
    }
  }
}
