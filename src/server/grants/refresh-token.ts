/**
 * Refresh Token grant type implementation.
 * RFC 6749 Section 6.
 * @module
 */

import type { ClientInterface } from "../../models/client.ts";
import type { RefreshToken } from "../../models/token.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
} from "../../errors.ts";
import {
  AbstractGrant,
  type GrantOptions,
  type GrantServices,
} from "./grant.ts";

/** Services required by the refresh token grant. */
export type RefreshTokenGrantServices<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> = GrantServices<Client, User, S>;

/**
 * What the refresh grant observed when a rotated-out refresh token was
 * replayed. Passed to {@link RefreshTokenGrantOptions.onTokenReuse}.
 */
export interface TokenReuseEvent<Client extends ClientInterface, User> {
  /** The rotation family the replayed token belonged to. */
  familyId: string;
  /** The client the replayed token was issued to. */
  client: Client;
  /** The user the replayed token was issued for, if any. */
  user?: User;
  /** Whether {@linkcode TokenServiceInterface.revokeFamily} revoked anything. */
  familyRevoked: boolean;
}

/**
 * Options for configuring the refresh token grant. The grant always issues a
 * refresh token, so `allowRefreshToken` is not offered.
 */
export interface RefreshTokenGrantOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> extends Omit<
  GrantOptions<Client, User, S, RefreshTokenGrantServices<Client, User, S>>,
  "allowRefreshToken"
> {
  /**
   * Called when reuse detection catches a rotated-out refresh token being
   * replayed by the client it was issued to (after the family was revoked) —
   * record it as a security event. Reuse detection runs only when the token
   * service implements both `getRevokedRefreshToken` and `revokeFamily`.
   *
   * Trigger point `token-reuse` (see `docs/trigger-points.md`).
   * Fire-and-forget: it is awaited, but a throw is caught and logged, never
   * rethrown, so a failing security-logging hook cannot change the
   * client-facing `invalid_grant` a replayed token always yields.
   */
  onTokenReuse?: (event: TokenReuseEvent<Client, User>) => void | Promise<void>;
  /**
   * Seconds after a refresh token is rotated during which presenting it again
   * is answered with `invalid_grant` but not treated as reuse: the family
   * keeps its live token and `onTokenReuse` does not fire. Defaults to `0`,
   * which turns the grace off.
   *
   * It covers a client that sends a request with the old refresh token after
   * its own concurrent request already rotated it, such as a backend-for-
   * frontend whose instances do not coordinate refreshes, so that one
   * straggler does not sign the user out. It applies only while the family
   * still has a live refresh token, and only to a token the grant rotated
   * out, not to one revoked any other way. Outside the window, or with no
   * live successor, reuse detection runs as usual.
   *
   * The cost is that a stolen refresh token replayed within the window after
   * the legitimate client rotated it goes unflagged: the family is not
   * revoked and no reuse event is raised. It cuts the other way too: when a
   * thief rotates a stolen live token first, the legitimate client's replay
   * within the window is refused without revoking the family, so the thief
   * keeps the session and the user is the one signed out. Keep the window to
   * seconds.
   *
   * Needs a token service that sets {@linkcode RefreshToken.rotatedAt} in
   * `revokeRotated` and implements `hasLiveRefreshToken`; with any other
   * service the grace never applies.
   */
  replayGraceSeconds?: number;
}

/**
 * The refresh token grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-6
 *
 * Allows clients to obtain a new access token using a refresh token
 * without requiring the user to re-authenticate.
 */
export class RefreshTokenGrant<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> extends AbstractGrant<
  Client,
  User,
  S,
  RefreshTokenGrantServices<Client, User, S>
> {
  /** The OAuth2 grant type: `refresh_token`. */
  readonly grantType = "refresh_token";
  #onTokenReuse?: (
    event: TokenReuseEvent<Client, User>,
  ) => void | Promise<void>;
  readonly #replayGraceMs: number;

  /** Creates the grant from its {@linkcode RefreshTokenGrantOptions}. */
  constructor(options: RefreshTokenGrantOptions<Client, User, S>) {
    super({ ...options, allowRefreshToken: true });
    this.#onTokenReuse = options.onTokenReuse;
    const graceSeconds = options.replayGraceSeconds ?? 0;
    if (!Number.isFinite(graceSeconds) || graceSeconds < 0) {
      throw new RangeError(
        `replayGraceSeconds must be a non-negative number of seconds, got ${graceSeconds}`,
      );
    }
    this.#replayGraceMs = graceSeconds * 1000;
  }

  /**
   * Handles a token request for the refresh token grant. Issues a new access
   * token (and rotates the refresh token when the token service supports it)
   * from a valid, unexpired refresh token.
   *
   * Rotation revokes the exchanged token through the token service's
   * `revokeRotated` when implemented, falling back to `revoke` — so a service
   * whose `revoke` ends the owning session can keep this bookkeeping step
   * from signing the person out.
   *
   * Rotation renews the refresh token's sliding lifetime, bounded by the
   * family's absolute cap when the token service implements
   * {@linkcode TokenServiceInterface.refreshTokenFamilyExpiresAt} and the
   * record carries a {@linkcode RefreshToken.familyCreatedAt} anchor: both the
   * access and refresh expiries are clamped to the family's ceiling, and once
   * the cap has passed the exchange fails, so the client must obtain a fresh
   * authorization.
   *
   * @throws {InvalidRequestError} If `refresh_token` is missing.
   * @throws {InvalidGrantError} If the refresh token is unknown or expired, its
   * family has outlived the absolute cap, or a concurrent exchange already
   * claimed it.
   * @throws {InvalidClientError} If the token was issued to another client.
   * @throws {InvalidScopeError} If the requested scope exceeds the original grant.
   */
  async token(
    request: Request,
    client: Client,
    body: FormData,
  ): Promise<RefreshToken<Client, User, S>> {
    const { tokenService } = await this.resolveServices(request);

    const refreshTokenStr = body.get("refresh_token");
    if (typeof refreshTokenStr !== "string") {
      throw new InvalidRequestError("refresh_token parameter required");
    }

    const currentToken = await tokenService.getRefreshToken(refreshTokenStr);
    if (!currentToken) {
      // Reuse detection: an unknown-but-previously-rotated token means the
      // old member of a rotation family was replayed (stolen or raced) —
      // revoke the entire family so neither party keeps a live session.
      if (tokenService.getRevokedRefreshToken && tokenService.revokeFamily) {
        const replayed =
          await tokenService.getRevokedRefreshToken(refreshTokenStr);
        if (
          replayed?.familyId &&
          replayed.client.id.toString() === client.id.toString() &&
          !(await this.#withinReplayGrace(tokenService, replayed))
        ) {
          const familyRevoked = await tokenService.revokeFamily(
            replayed.familyId,
          );
          await this.#notifyTokenReuse({
            familyId: replayed.familyId,
            client: replayed.client,
            user: replayed.user,
            familyRevoked,
          });
        }
      }
      throw new InvalidGrantError("invalid refresh_token");
    }
    if (
      currentToken.refreshTokenExpiresAt &&
      currentToken.refreshTokenExpiresAt < new Date()
    ) {
      throw new InvalidGrantError("invalid refresh_token");
    }

    const { client: tokenClient, user, scope } = currentToken;
    if (client.id.toString() !== tokenClient.id.toString()) {
      throw new InvalidClientError(
        "refresh_token was issued to another client",
      );
    }

    // RFC 6749 §6: a requested scope may only narrow, never exceed, the original grant.
    let nextScope = scope;
    const requestedScopeText = body.get("scope");
    if (typeof requestedScopeText === "string") {
      const requestedScope = this.parseScope(requestedScopeText);
      if (requestedScope) {
        if (!scope || !scope.has(requestedScope)) {
          throw new InvalidScopeError(
            "requested scope exceeds the scope of the original grant",
          );
        }
        nextScope = requestedScope;
      }
    }

    const familyExpiresAt =
      currentToken.familyCreatedAt && tokenService.refreshTokenFamilyExpiresAt
        ? await tokenService.refreshTokenFamilyExpiresAt(
            client,
            user,
            currentToken.familyCreatedAt,
            nextScope,
          )
        : undefined;
    if (familyExpiresAt && familyExpiresAt.getTime() <= Date.now()) {
      throw new InvalidGrantError("refresh_token family expired");
    }

    const nextToken = await this.generateToken(
      client,
      user,
      nextScope,
      tokenService,
      currentToken.authenticationContext,
      familyExpiresAt,
    );

    const nextRefreshToken: RefreshToken<Client, User, S> =
      "refreshToken" in nextToken
        ? (nextToken as RefreshToken<Client, User, S>)
        : {
            ...nextToken,
            refreshToken: currentToken.refreshToken,
            refreshTokenExpiresAt: currentToken.refreshTokenExpiresAt,
          };
    // A rotation stays in its ancestor's family so replaying any rotated-out
    // member revokes the whole chain.
    nextRefreshToken.familyId =
      currentToken.familyId ?? nextRefreshToken.familyId;
    nextRefreshToken.familyCreatedAt =
      currentToken.familyCreatedAt ?? nextRefreshToken.familyCreatedAt;
    if (familyExpiresAt) {
      this.capAtFamilyExpiry(nextRefreshToken, familyExpiresAt);
    }

    const claimed = tokenService.revokeRotated
      ? await tokenService.revokeRotated(currentToken)
      : await tokenService.revoke(currentToken);
    if (!claimed) {
      throw new InvalidGrantError("refresh_token was already consumed");
    }
    return await tokenService.save(nextRefreshToken);
  }

  async #withinReplayGrace(
    tokenService: RefreshTokenGrantServices<Client, User, S>["tokenService"],
    replayed: RefreshToken<Client, User, S>,
  ): Promise<boolean> {
    const { rotatedAt, familyId } = replayed;
    if (this.#replayGraceMs === 0 || !rotatedAt || !familyId) return false;
    if (Date.now() - rotatedAt.getTime() > this.#replayGraceMs) return false;
    return (await tokenService.hasLiveRefreshToken?.(familyId)) ?? false;
  }

  async #notifyTokenReuse(event: TokenReuseEvent<Client, User>): Promise<void> {
    if (!this.#onTokenReuse) return;
    try {
      await this.#onTokenReuse(event);
    } catch (error) {
      console.error(
        "[@udibo/oauth2] onTokenReuse hook failed:",
        error instanceof Error ? error.message : error,
      );
    }
  }
}
