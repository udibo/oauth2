/**
 * Device Authorization Grant implementation (RFC 8628).
 *
 * This grant type allows devices with limited input capabilities
 * to obtain user authorization by having the user authorize
 * the request on a secondary device.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628
 * @module
 */

import type { ClientInterface } from "../../models/client.ts";
import type { Token } from "../../models/token.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import {
  AccessDeniedError,
  AuthorizationPendingError,
  ExpiredTokenError,
  InvalidGrantError,
  InvalidRequestError,
  SlowDownError,
} from "../../errors.ts";
import type { DeviceAuthorization } from "../../models/device-authorization.ts";
import type { DeviceAuthorizationServiceInterface } from "../services/device-authorization.ts";
import {
  AbstractGrant,
  type GrantOptions,
  type GrantServices,
} from "./grant.ts";

/**
 * Services required by the device authorization grant.
 */
export interface DeviceAuthorizationGrantServices<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> extends GrantServices<Client, User, S> {
  /** Generates, stores, and polls device/user codes for the device flow. */
  deviceAuthorizationService: DeviceAuthorizationServiceInterface<
    Client,
    User,
    S
  >;
}

/**
 * Options for configuring the device authorization grant.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628
 */
export interface DeviceAuthorizationGrantOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope,
> extends
  GrantOptions<
    Client,
    User,
    S,
    DeviceAuthorizationGrantServices<Client, User, S>
  > {
  /** Allow optional refresh token. Defaults to true. */
  allowRefreshToken?: boolean;
}

/**
 * The Device Authorization Grant type (RFC 8628).
 *
 * This grant is used for devices that lack a browser or have limited
 * input capabilities (TVs, game consoles, CLI tools, etc.).
 *
 * Flow:
 * 1. Device requests authorization, receives device_code and user_code
 * 2. User visits verification_uri on another device and enters user_code
 * 3. User authorizes or denies the request
 * 4. Device polls token endpoint with device_code until authorized/denied/expired
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628
 */
export class DeviceAuthorizationGrant<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> extends AbstractGrant<
  Client,
  User,
  S,
  DeviceAuthorizationGrantServices<Client, User, S>
> {
  /**
   * The grant type identifier.
   * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
   */
  readonly grantType = "urn:ietf:params:oauth:grant-type:device_code";

  /** Creates the grant from its {@linkcode DeviceAuthorizationGrantOptions}. */
  constructor(options: DeviceAuthorizationGrantOptions<Client, User, S>) {
    super({
      ...options,
      allowRefreshToken: options.allowRefreshToken ?? true,
    });
  }

  /**
   * Initiates a device authorization request.
   *
   * Called by the device authorization endpoint to create a new
   * pending authorization that the user can approve. Resolves its own
   * `deviceAuthorizationService` from the request.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
   */
  async initiateDeviceAuthorization(
    client: Client,
    request: Request,
    scope?: S | null,
  ): Promise<DeviceAuthorization<Client, User, S>> {
    const { deviceAuthorizationService } = await this.resolveServices(request);

    const deviceAuthorization: DeviceAuthorization<Client, User, S> = {
      deviceCode: await deviceAuthorizationService.generateDeviceCode(
        client,
        scope,
      ),
      userCode: await deviceAuthorizationService.generateUserCode(
        client,
        scope,
      ),
      expiresAt: await deviceAuthorizationService.expiresAt(client, scope),
      client,
      scope,
      interval: deviceAuthorizationService.interval,
    };

    return await deviceAuthorizationService.save(deviceAuthorization);
  }

  /**
   * Handles a token request for the device authorization grant.
   *
   * The client polls this endpoint with the device_code until:
   * - The user authorizes the request (returns tokens)
   * - The user denies the request (returns access_denied)
   * - The device_code expires (returns expired_token)
   * - The client polls too frequently (returns slow_down)
   *
   * Ownership is authenticated before the authorization is acted on: a client
   * polling a device code issued to a different client is refused
   * `invalid_grant` whether that code is live or expired, and the record is
   * left untouched, so a poll the caller is not entitled to make can neither
   * destroy the authorization nor distinguish its state.
   *
   * The device code is claimed by revoking it once the user has approved, so
   * concurrent polls of one approved device code cannot both receive a token.
   * Recording the poll time is bookkeeping for `slow_down` only: it is skipped
   * on every outcome that revokes the authorization. When the store **raises**
   * for the vanished record — as it must, if a lost race is to be
   * distinguishable — the poll is refused with `invalid_grant` rather than
   * surfacing the store's own error. A store whose poll write instead resolves
   * for a record that is gone leaves that poll answering
   * `authorization_pending`, and the next one gets `invalid_grant` from the
   * existence check; the code is still single-use either way, because only the
   * caller whose `revoke` resolved `true` is issued a token.
   *
   * @throws {InvalidRequestError} If `device_code` is missing.
   * @throws {InvalidGrantError} If the device code is unknown, was issued to another client, or was already claimed by another poll.
   * @throws {ExpiredTokenError} If the device code has expired.
   * @throws {SlowDownError} If the client polls faster than the interval allows.
   * @throws {AccessDeniedError} If the user denied the request.
   * @throws {AuthorizationPendingError} If the user has not yet approved the request.
   * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
   * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
   */
  async token(
    request: Request,
    client: Client,
    body: FormData,
  ): Promise<Token<Client, User, S>> {
    const { deviceAuthorizationService, tokenService } = await this
      .resolveServices(request);

    const deviceCode = body.get("device_code");
    if (typeof deviceCode !== "string") {
      throw new InvalidRequestError("device_code parameter required");
    }

    const authorization = await deviceAuthorizationService.getByDeviceCode(
      deviceCode,
    );
    if (!authorization) {
      throw new InvalidGrantError("invalid device_code");
    }

    if (authorization.client.id !== client.id) {
      throw new InvalidGrantError("device_code was issued to another client");
    }

    if (authorization.expiresAt < new Date()) {
      await deviceAuthorizationService.revoke(authorization);
      throw new ExpiredTokenError("device_code has expired");
    }

    if (authorization.lastPolled) {
      const elapsed = Date.now() - authorization.lastPolled.getTime();
      const minInterval = authorization.interval * 1000;
      if (elapsed < minInterval) {
        authorization.interval += 5;
        await this.#recordPoll(
          deviceAuthorizationService,
          authorization,
          deviceCode,
        );
        throw new SlowDownError("polling too frequently");
      }
    }

    if (authorization.denied) {
      await deviceAuthorizationService.revoke(authorization);
      throw new AccessDeniedError("authorization request was denied");
    }

    if (!authorization.authorized || !authorization.user) {
      await this.#recordPoll(
        deviceAuthorizationService,
        authorization,
        deviceCode,
      );
      throw new AuthorizationPendingError(
        "authorization request is pending user approval",
      );
    }

    const { user, scope } = authorization;

    if (!await deviceAuthorizationService.revoke(authorization)) {
      throw new InvalidGrantError("device_code already used");
    }

    const token = await this.generateToken(client, user, scope, tokenService);
    return await tokenService.save(token);
  }

  async #recordPoll(
    deviceAuthorizationService: DeviceAuthorizationServiceInterface<
      Client,
      User,
      S
    >,
    authorization: DeviceAuthorization<Client, User, S>,
    deviceCode: string,
  ): Promise<void> {
    try {
      await deviceAuthorizationService.updateLastPolled(authorization);
    } catch (error) {
      let stillStored;
      try {
        stillStored = await deviceAuthorizationService.getByDeviceCode(
          deviceCode,
        );
      } catch {
        throw error;
      }
      if (stillStored) throw error;
      throw new InvalidGrantError("device_code already used");
    }
  }
}
