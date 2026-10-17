import type { ClientInterface } from "../../models/client.ts";
import type { AuthenticationContext } from "../../models/authentication.ts";
import type { AuthorizationCode } from "../../models/authorization-code.ts";
import type { RefreshToken, Token } from "../../models/token.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import type { ClientServiceInterface } from "./client.ts";
import type { UserServiceInterface } from "./user.ts";

/**
 * Minimal interface for reading/validating tokens.
 *
 * This is all a resource server needs to authenticate requests.
 * Implement this when your resource server validates tokens against
 * an external authorization server (e.g., via introspection) or
 * a shared token store.
 */
export interface TokenReaderInterface<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> {
  /** Retrieves an existing token by access token string. */
  getToken(
    accessToken: string,
  ): Promise<Token<Client, User, Scope> | undefined>;
}

/**
 * Full service interface for token lifecycle management.
 *
 * Extends {@linkcode TokenReaderInterface} with methods for generating,
 * saving, and revoking tokens. Used by the authorization server and
 * its grant types.
 *
 * **A token need not have a user.** The client credentials grant (RFC 6749
 * §4.4) has no resource owner, so when `ClientServiceInterface.getUser`
 * resolves none it calls `acceptedScope`, `generateAccessToken`, and
 * `accessTokenExpiresAt` with `user: undefined` and saves a {@linkcode Token}
 * whose `user` is unset. An implementation that
 * dereferences `user` without checking will throw on those requests, and a
 * store with a non-nullable user column cannot persist the result — decide
 * scope and lifetime from the client alone when it is absent.
 * `generateRefreshToken` and `refreshTokenExpiresAt` always receive a user:
 * a token with no resource owner is never issued a refresh token.
 */
export interface TokenServiceInterface<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> extends TokenReaderInterface<Client, User, Scope> {
  /** Lifetime of access tokens in seconds. */
  accessTokenLifetime: number;

  /** Lifetime of refresh tokens in seconds. */
  refreshTokenLifetime: number;

  /**
   * Validates and returns the accepted scope for a client and user. Return a
   * scope to grant it (it may narrow the requested scope, RFC 6749 §3.3),
   * `null`/`undefined` to accept the requested scope as-is, or `false` to
   * reject with `invalid_scope`. `user` is `undefined` for a client acting as
   * its own resource owner (client credentials).
   * @returns The accepted scope, null/undefined to accept as-is, or false to reject.
   */
  acceptedScope(
    client: Client,
    user: User | undefined,
    scope?: Scope | null,
  ): Promise<Scope | null | undefined | false>;

  /**
   * Generates an access token string. `user` is `undefined` for a client
   * acting as its own resource owner (client credentials) — a signed-token
   * generator names the client as the subject then, per RFC 9068 §2.2.
   * Forward `authenticationContext` to a signed-token generator so it uses
   * the credential's event, including the original event on refresh.
   * `expiresAt` is the expiry the grant will store for this token — already
   * clamped to the refresh family's cap when one applies. Forward it too, so
   * a signed token's `exp` never outlives what the server itself honors; the
   * grants always pass it, and a wrapper that drops it leaves offline
   * verifiers accepting the token past its stored expiry.
   */
  generateAccessToken(
    client: Client,
    user: User | undefined,
    scope?: Scope | null,
    authenticationContext?: AuthenticationContext,
    expiresAt?: Date,
  ): Promise<string>;

  /** Generates a refresh token string. */
  generateRefreshToken(
    client: Client,
    user: User,
    scope?: Scope | null,
  ): Promise<string | undefined>;

  /**
   * Gets the date that a new access token would expire at. `user` is
   * `undefined` for a client acting as its own resource owner (client
   * credentials).
   */
  accessTokenExpiresAt(
    client: Client,
    user: User | undefined,
    scope?: Scope | null,
  ): Promise<Date | undefined>;

  /** Gets the date that a new refresh token would expire at. */
  refreshTokenExpiresAt(
    client: Client,
    user: User,
    scope?: Scope | null,
  ): Promise<Date | undefined>;

  /**
   * Gets the absolute date a rotation family stops being refreshable, from the
   * family's anchor ({@linkcode RefreshToken.familyCreatedAt}).
   *
   * **This method is the whole cap.** The grants clamp a rotation's access and
   * refresh expiries to the date it returns and answer `invalid_grant` once
   * that date has passed; a refresh-token record without `familyCreatedAt` is
   * never capped. Return `undefined` — or leave the method off
   * entirely, which is the default — and the family is never capped, however
   * the service is otherwise configured. Implement it to cap per client (see
   * {@linkcode AbstractTokenService.refreshTokenMaxLifetime} for the
   * service-wide version, which is what the abstract implementation reads).
   *
   * `user` is the refreshed token's own — `undefined` when the store returns a
   * token that has none, so cap from the client alone in that case.
   */
  refreshTokenFamilyExpiresAt?(
    client: Client,
    user: User | undefined,
    familyCreatedAt: Date,
    scope?: Scope | null,
  ): Promise<Date | undefined>;

  /** Retrieves an existing token by refresh token. */
  getRefreshToken(
    refreshToken: string,
  ): Promise<RefreshToken<Client, User, Scope> | undefined>;

  /** Persists a refresh token and returns the saved record. */
  save(
    token: RefreshToken<Client, User, Scope>,
  ): Promise<RefreshToken<Client, User, Scope>>;
  /** Persists an access token and returns the saved record. */
  save(token: Token<Client, User, Scope>): Promise<Token<Client, User, Scope>>;
  /**
   * Persists either token kind and returns the saved record. Preserve
   * `authenticationContext` on save and every read, including refresh and
   * revoked records; never reconstruct it from a user's current session.
   */
  save(
    token: Token<Client, User, Scope> | RefreshToken<Client, User, Scope>,
  ): Promise<Token<Client, User, Scope> | RefreshToken<Client, User, Scope>>;

  /** Revokes a token record. Resolves true if a token was revoked. */
  revoke(
    token: Token<Client, User, Scope> | RefreshToken<Client, User, Scope>,
  ): Promise<boolean>;
  /**
   * Revokes a token by string, using `hint` (`access_token`/`refresh_token`,
   * RFC 7009 §2.1) to disambiguate which kind to look up first.
   */
  revoke(token: string, hint?: string | null): Promise<boolean>;
  /** Revokes a token given as a record or string. Resolves true if revoked. */
  revoke(
    token:
      | Token<Client, User, Scope>
      | RefreshToken<Client, User, Scope>
      | string,
    hint?: string | null,
  ): Promise<boolean>;

  /**
   * Revokes a refresh token that has just been superseded by rotation.
   * Atomically claims the active token: resolves `true` once, and `false` for
   * concurrent or repeated claims. The grant saves a successor only after a
   * successful claim. Apply the same guarantee to `revoke` when it is the fallback.
   *
   * Rotation is bookkeeping inside a **continuing** grant: the person stays
   * signed in and the successor token takes over. Implement this when
   * {@linkcode revoke} carries end-of-grant side effects — ending the session
   * the token belongs to, cascading to sibling records — so a routine refresh
   * cannot terminate the very session it renews. When absent, the refresh
   * grant falls back to {@linkcode revoke}.
   *
   * Stamp the revoked record with {@linkcode RefreshToken.rotatedAt} here and
   * return it, with its `familyId`, from {@linkcode getRevokedRefreshToken}.
   * The refresh grant's `replayGraceSeconds` reads it, and the revocation
   * endpoint revokes the family of a token presented after rotation replaced
   * it, so a sign-out racing a refresh still ends the successor.
   */
  revokeRotated?(token: RefreshToken<Client, User, Scope>): Promise<boolean>;

  /**
   * Rotates a refresh token in one atomic step: claims `current` and persists
   * `next`, its successor in the same family, or does neither. Resolves the
   * saved successor, or `undefined` with nothing persisted when `current` was
   * already claimed or revoked, or its family has been revoked. Concurrent
   * calls for one `current` produce exactly one successor.
   *
   * When implemented, the refresh grant calls it instead of
   * {@linkcode revokeRotated} (or {@linkcode revoke}) followed by
   * {@linkcode save}. Without it, the grant claims and saves in two calls,
   * and a request that presents `current` between them finds it revoked with
   * no live successor: reuse detection revokes the family and fires
   * `onTokenReuse`, so a benign concurrent refresh signs the person out, and a
   * store whose `revokeFamily` does not keep the family revoked leaves the
   * successor live.
   *
   * Treat the claim as a rotation, never an end of grant: stamp the
   * rotated-out record with {@linkcode RefreshToken.rotatedAt} exactly as
   * {@linkcode revokeRotated} does, keep it findable through
   * {@linkcode getRevokedRefreshToken}, and revoke its access token as
   * `revokeRotated` would. Make it linearizable with
   * {@linkcode revokeFamily}, as that method requires.
   * `runTokenRotationContractTests` checks it under concurrent callers, with
   * the store's barrier wired between its claim and its insert.
   */
  rotate?(
    current: RefreshToken<Client, User, Scope>,
    next: RefreshToken<Client, User, Scope>,
  ): Promise<RefreshToken<Client, User, Scope> | undefined>;

  /**
   * Revokes all tokens issued with the given authorization code, called by the
   * authorization code grant when a code is presented after it was claimed.
   * Returns true if any tokens were revoked, which the grant reports as a code
   * replay (RFC 6819 §4.4.1.1).
   *
   * `client` is the client that presented the code. Revoke only when it is the
   * client the code's tokens were issued to; for any other client revoke
   * nothing and resolve `false`. A different confidential client could never
   * have redeemed the code, since that needs the code's own client's
   * credentials, so its replay says nothing about theft. The gate names a
   * public client, or any client when the grant's
   * `requireClientAuthentication` is `false`, by `client_id` alone, so anyone
   * holding such a client's spent code can still present it as that client
   * and revoke. A store that ignores `client` revokes on any client's replay,
   * which lets a client that sees a leaked, spent code end the session it
   * started.
   *
   * With {@linkcode exchangeCode}, make the two linearizable: a call that
   * begins once `exchangeCode` has claimed the code must find and revoke the
   * token it saved. Committing the claim and the insert together, as one
   * database transaction does, meets this.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.1.1
   */
  revokeCode(code: string, client?: Client): Promise<boolean>;

  /**
   * Exchanges an authorization code in one atomic step: claims
   * `authorizationCode` as `AuthorizationCodeServiceInterface.revoke`
   * would, and persists `token`, the token issued from it, or does neither.
   * Resolves the saved token, or `undefined` with nothing persisted when the
   * code was already claimed or never stored. Concurrent calls for one code
   * persist exactly one token. `token.code` is already set to the code.
   *
   * When implemented, the authorization code grant calls it instead of
   * claiming the code through the authorization code service and saving the
   * token with {@linkcode save}. Without it, the grant claims and saves in two
   * calls, and a replay that arrives between them finds the code claimed but
   * no token to revoke: the replay is refused, and the token the first
   * exchange saves next stays live. With it, a replay finds the token
   * {@linkcode revokeCode} can revoke.
   *
   * After a successful call the code service's `get` must resolve `undefined`
   * for the code, as after `revoke`. A failed insert must leave the code
   * claimable. Store the token so `revokeCode` finds it by the code, and make
   * the two linearizable, as `revokeCode` requires.
   * `runCodeExchangeContractTests` checks it under concurrent callers, with
   * the store's barrier wired between its claim and its insert.
   */
  exchangeCode?(
    authorizationCode: AuthorizationCode<Client, User, Scope>,
    token: Token<Client, User, Scope>,
  ): Promise<Token<Client, User, Scope> | undefined>;

  /**
   * Looks up a refresh token that has already been revoked/rotated out. The
   * refresh grant's reuse detection reads it, and so does the revocation
   * endpoint, to revoke the family of a token rotation replaced. Implement
   * this (with {@linkcode revokeFamily}) by keeping revoked refresh-token
   * records findable instead of deleting them; when absent, reuse detection
   * is silently disabled and `/revoke` cannot reach a successor.
   *
   * Return the tombstone unconditionally. Apply any replay grace through
   * `RefreshTokenGrantOptions.replayGraceSeconds`, judged on the store's clock
   * by {@linkcode isWithinReplayGrace} when it needs one, never by hiding
   * recent tombstones here: a hidden tombstone also hides the family from a
   * sign-out racing the refresh, which then leaves the successor live.
   */
  getRevokedRefreshToken?(
    refreshToken: string,
  ): Promise<RefreshToken<Client, User, Scope> | undefined>;

  /**
   * Revokes every token belonging to a rotation family — called by the
   * refresh grant when a rotated-out member is replayed, so a stolen token
   * can't keep a session alive, and by the revocation endpoint when it is
   * given a token whose tombstone carries {@linkcode RefreshToken.rotatedAt}.
   * Returns true if anything was revoked.
   *
   * `/revoke` ends the family without firing `onTokenReuse`; it reports the
   * revocation to `AuthorizationServerOptions.onRotatedOutRevocation` instead.
   *
   * Without {@linkcode rotate}, keep the family revoked: a successor that a
   * concurrent rotation saves after this call must be stored already revoked,
   * as `MemoryTokenService` does. A store that implements `rotate` meets this
   * through the linearizability below, since the refresh grant then never
   * saves a rotation's successor separately.
   *
   * With {@linkcode rotate}, make the two linearizable: once this resolves,
   * the family has no live member and no later `rotate` of a member
   * succeeds, and a `rotate` that committed before this began has its
   * successor revoked. A store whose `rotate` can be paused between its claim
   * and its insert meets this by taking one per-family lock in both methods.
   */
  revokeFamily?(familyId: string): Promise<boolean>;

  /**
   * Whether the rotation family still has a live, unexpired refresh token.
   * Read by the refresh grant's `replayGraceSeconds`: without it, the grace
   * never applies and every replay is treated as reuse.
   */
  hasLiveRefreshToken?(familyId: string): Promise<boolean>;

  /**
   * Whether `tombstone`, a record {@linkcode getRevokedRefreshToken} just
   * returned, was rotated out no more than `graceSeconds` ago, measured on the
   * clock that stamped its rotation. Implement it when that clock is the
   * store's own, such as a database's, so instances whose clocks drift
   * apart agree on the refresh grant's `replayGraceSeconds` window. Without
   * it, the grant compares {@linkcode RefreshToken.rotatedAt} with its own
   * `Date.now()`.
   *
   * The grant calls it only when `replayGraceSeconds` is above zero and the
   * tombstone carries `rotatedAt` and a `familyId`; `graceSeconds` may be
   * fractional. The window still needs {@linkcode hasLiveRefreshToken}.
   * The grant treats the replay as outside the window, whatever this
   * resolves, once `rotatedAt` is more than five minutes ahead of the
   * grant's clock or more than `graceSeconds` plus five minutes behind it.
   * Implementing this never licenses hiding a tombstone from
   * `getRevokedRefreshToken`.
   */
  isWithinReplayGrace?(
    tombstone: RefreshToken<Client, User, Scope>,
    graceSeconds: number,
  ): Promise<boolean>;
}

/** Options for configuring an abstract token service. */
export interface AbstractTokenServiceOptions<
  Client extends ClientInterface,
  User,
> {
  /** Lifetime of access tokens in seconds. Defaults to 3600 (1 hour). */
  accessTokenLifetime?: number;
  /** Lifetime of refresh tokens in seconds. Defaults to 1209600 (14 days). */
  refreshTokenLifetime?: number;
  /**
   * Absolute lifetime of a refresh-token family in seconds, read by this
   * class's {@linkcode AbstractTokenService.refreshTokenFamilyExpiresAt}. Omit
   * to leave families uncapped, so rotation extends a family indefinitely.
   * Must be at least `refreshTokenLifetime`.
   */
  refreshTokenMaxLifetime?: number;
  /** Client service for hydrating tokens. */
  clientService?: ClientServiceInterface<Client, User>;
  /** User service for hydrating tokens. */
  userService?: UserServiceInterface<User>;
}

/**
 * Abstract token service with sensible defaults for token generation.
 *
 * Provides default implementations for:
 * - `acceptedScope` — accepts scope as-is
 * - `generateAccessToken` / `generateRefreshToken` — crypto.randomUUID()
 * - `accessTokenExpiresAt` / `refreshTokenExpiresAt` — based on lifetime settings
 *
 * Subclasses must implement the storage methods:
 * `getToken`, `getRefreshToken`, `save`, `revoke`, `revokeCode`
 */
export abstract class AbstractTokenService<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> implements TokenServiceInterface<Client, User, Scope> {
  /** Lifetime of access tokens in seconds. */
  accessTokenLifetime: number;
  /** Lifetime of refresh tokens in seconds. */
  refreshTokenLifetime: number;
  /**
   * Absolute lifetime of a refresh-token family in seconds, or `undefined` for
   * an uncapped family. Enforced only through this class's
   * {@linkcode refreshTokenFamilyExpiresAt}: an override that ignores it
   * ignores the cap.
   */
  refreshTokenMaxLifetime?: number;
  /** Client service used by subclasses to hydrate tokens. */
  protected clientService?: ClientServiceInterface<Client, User>;
  /** User service used by subclasses to hydrate tokens. */
  protected userService?: UserServiceInterface<User>;

  /**
   * Lifetimes default to 3600 seconds (access) and 1209600 seconds / 14 days
   * (refresh) when not supplied. `refreshTokenMaxLifetime` has no default —
   * refresh-token families are uncapped unless one is configured.
   *
   * @throws {TypeError} If `refreshTokenLifetime` exceeds
   * `refreshTokenMaxLifetime`, which would truncate every issued refresh token.
   */
  constructor(options?: AbstractTokenServiceOptions<Client, User>) {
    this.accessTokenLifetime = options?.accessTokenLifetime ?? 3600;
    this.refreshTokenLifetime = options?.refreshTokenLifetime ?? 1209600;
    this.refreshTokenMaxLifetime = options?.refreshTokenMaxLifetime;
    if (
      this.refreshTokenMaxLifetime !== undefined &&
      this.refreshTokenLifetime > this.refreshTokenMaxLifetime
    ) {
      throw new TypeError(
        "refreshTokenLifetime must not exceed refreshTokenMaxLifetime",
      );
    }
    this.clientService = options?.clientService;
    this.userService = options?.userService;
  }

  /**
   * Accepts the requested scope unchanged. Override to narrow or reject scope
   * (return `false` to reject with `invalid_scope`).
   */
  acceptedScope(
    _client: Client,
    _user: User | undefined,
    scope?: Scope | null,
  ): Promise<Scope | null | undefined | false> {
    return Promise.resolve(scope);
  }

  /** Generates an opaque access token string. Override to issue a different format. */
  generateAccessToken(
    _client: Client,
    _user: User | undefined,
    _scope?: Scope | null,
    _authenticationContext?: AuthenticationContext,
    _expiresAt?: Date,
  ): Promise<string> {
    return Promise.resolve(crypto.randomUUID());
  }

  /** Generates an opaque refresh token string. Override to issue a different format. */
  generateRefreshToken(
    _client: Client,
    _user: User,
    _scope?: Scope | null,
  ): Promise<string | undefined> {
    return Promise.resolve(crypto.randomUUID());
  }

  /** Computes the access token expiry as now plus {@linkcode accessTokenLifetime}. */
  accessTokenExpiresAt(
    _client: Client,
    _user: User | undefined,
    _scope?: Scope | null,
  ): Promise<Date | undefined> {
    return Promise.resolve(
      new Date(Date.now() + this.accessTokenLifetime * 1000),
    );
  }

  /** Computes the refresh token expiry as now plus {@linkcode refreshTokenLifetime}. */
  refreshTokenExpiresAt(
    _client: Client,
    _user: User,
    _scope?: Scope | null,
  ): Promise<Date | undefined> {
    return Promise.resolve(
      new Date(Date.now() + this.refreshTokenLifetime * 1000),
    );
  }

  /**
   * Computes the family's absolute expiry as its anchor plus
   * {@linkcode refreshTokenMaxLifetime}, or `undefined` when no cap is
   * configured. Override to cap per client instead of service-wide.
   */
  refreshTokenFamilyExpiresAt(
    _client: Client,
    _user: User | undefined,
    familyCreatedAt: Date,
    _scope?: Scope | null,
  ): Promise<Date | undefined> {
    return Promise.resolve(
      this.refreshTokenMaxLifetime == null
        ? undefined
        : new Date(
            familyCreatedAt.getTime() + this.refreshTokenMaxLifetime * 1000,
          ),
    );
  }

  /** Retrieves a persisted token by its access token string. */
  abstract getToken(
    accessToken: string,
  ): Promise<Token<Client, User, Scope> | undefined>;

  /** Retrieves a persisted token by its refresh token string. */
  abstract getRefreshToken(
    refreshToken: string,
  ): Promise<RefreshToken<Client, User, Scope> | undefined>;

  /** Persists a refresh token and returns the saved record. */
  abstract save(
    token: RefreshToken<Client, User, Scope>,
  ): Promise<RefreshToken<Client, User, Scope>>;
  /** Persists an access token and returns the saved record. */
  abstract save(
    token: Token<Client, User, Scope>,
  ): Promise<Token<Client, User, Scope>>;
  /** Persists either token kind and returns the saved record. */
  abstract save(
    token: Token<Client, User, Scope> | RefreshToken<Client, User, Scope>,
  ): Promise<Token<Client, User, Scope> | RefreshToken<Client, User, Scope>>;

  /** Revokes a token record. Resolves true if a token was revoked. */
  abstract revoke(
    token: Token<Client, User, Scope> | RefreshToken<Client, User, Scope>,
  ): Promise<boolean>;
  /**
   * Revokes a token by string, using `hint` (`access_token`/`refresh_token`,
   * RFC 7009 §2.1) to disambiguate which kind to look up first.
   */
  abstract revoke(token: string, hint?: string | null): Promise<boolean>;
  /** Revokes a token given as a record or string. Resolves true if revoked. */
  abstract revoke(
    token:
      | Token<Client, User, Scope>
      | RefreshToken<Client, User, Scope>
      | string,
    hint?: string | null,
  ): Promise<boolean>;

  /**
   * Revokes every token issued from the given authorization code, returning
   * true if any were revoked (signaling code replay per RFC 6819 §4.4.1.1).
   * Revoke nothing when `client` is not the client the tokens were issued to
   * ({@linkcode TokenServiceInterface.revokeCode} explains why).
   */
  abstract revokeCode(code: string, client?: Client): Promise<boolean>;
}
