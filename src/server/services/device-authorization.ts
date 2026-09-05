/**
 * Device authorization service interface for the Device Authorization Grant (RFC 8628).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628
 * @module
 */

import type { ClientInterface } from "../../models/client.ts";
import type { DeviceAuthorization } from "../../models/device-authorization.ts";
import type { AbstractScope } from "../../models/scope.ts";

/**
 * Service interface for managing device authorizations.
 *
 * Implementations must handle:
 * - Generating and storing device codes and user codes
 * - Looking up device codes for polling
 * - Looking up user codes for user authorization
 * - Marking codes as authorized or denied
 * - Cleaning up expired codes
 *
 * **Every method taking a `DeviceAuthorization` must accept the records this
 * same service returns**, not only a record the caller assembled. A store that
 * looks a record up by one code commonly returns it carrying only that code —
 * {@linkcode DeviceAuthorizationServiceInterface.getByUserCode} has no device
 * code to fill in — so resolve the stored authorization by whichever code the
 * argument carries rather than by assuming both are populated. The grant hands
 * {@linkcode DeviceAuthorizationServiceInterface.updateLastPolled} and
 * {@linkcode DeviceAuthorizationServiceInterface.revoke} the record from
 * `getByDeviceCode`, and a verification page hands
 * {@linkcode DeviceAuthorizationServiceInterface.approve},
 * {@linkcode DeviceAuthorizationServiceInterface.deny} and `revoke` the record
 * from `getByUserCode`.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628
 */
export interface DeviceAuthorizationServiceInterface<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope,
> {
  /**
   * Lifetime of device codes in seconds.
   * RFC 8628 does not specify a default, but 15-30 minutes is common.
   * @default 1800 (30 minutes)
   */
  lifetime: number;

  /**
   * Minimum polling interval in seconds.
   * Clients should not poll more frequently than this.
   * @default 5
   */
  interval: number;

  /**
   * Generates a unique device code.
   *
   * The device code is a long, high-entropy string used by the client
   * to poll for authorization status.
   */
  generateDeviceCode(
    client: Client,
    scope?: Scope | null,
  ): Promise<string>;

  /**
   * Generates a user code.
   *
   * The user code should be short and easy for users to type.
   * Common formats include: ABCD-1234, WDJB-MJHT, 12345678
   */
  generateUserCode(
    client: Client,
    scope?: Scope | null,
  ): Promise<string>;

  /**
   * Returns when the codes should expire.
   */
  expiresAt(
    client: Client,
    scope?: Scope | null,
  ): Promise<Date>;

  /**
   * Saves a device authorization request.
   */
  save(
    authorization: DeviceAuthorization<Client, User, Scope>,
  ): Promise<DeviceAuthorization<Client, User, Scope>>;

  /**
   * Gets a device authorization by device code.
   *
   * Used by the client when polling for authorization status.
   */
  getByDeviceCode(
    deviceCode: string,
  ): Promise<DeviceAuthorization<Client, User, Scope> | undefined>;

  /**
   * Gets a device authorization by user code.
   *
   * Used during user authorization to look up the pending request.
   */
  getByUserCode(
    userCode: string,
  ): Promise<DeviceAuthorization<Client, User, Scope> | undefined>;

  /**
   * Marks a device authorization as authorized by the user.
   *
   * @param authorization The authorization to approve
   * @param user The user who approved the request
   * @param scope Optional scope (may be narrower than originally requested)
   */
  approve(
    authorization: DeviceAuthorization<Client, User, Scope>,
    user: User,
    scope?: Scope | null,
  ): Promise<DeviceAuthorization<Client, User, Scope>>;

  /**
   * Marks a device authorization as denied by the user.
   */
  deny(
    authorization: DeviceAuthorization<Client, User, Scope>,
  ): Promise<DeviceAuthorization<Client, User, Scope>>;

  /**
   * Updates the last polled time for a device authorization.
   *
   * Used to track polling frequency and enforce slow_down errors.
   *
   * **A failure here is re-classified by re-reading the device code.** The
   * grant calls this only on the non-terminal polling path, and when it
   * rejects, the grant asks {@linkcode
   * DeviceAuthorizationServiceInterface.getByDeviceCode} whether the record is
   * still stored: gone means a concurrent poll claimed it, and the caller is
   * refused `invalid_grant`; still there means the store itself failed, and
   * the original error propagates. **That read must therefore be at least as
   * fresh as the write that just failed** — serve it from the primary, never a
   * replica that can lag behind it, or a transient write failure on a live
   * authorization will tell a legitimate device its code was already used,
   * which RFC 8628 §3.5 makes terminal.
   */
  updateLastPolled(
    authorization: DeviceAuthorization<Client, User, Scope>,
  ): Promise<DeviceAuthorization<Client, User, Scope>>;

  /**
   * Revokes a device authorization, accepting the record or its raw device code.
   *
   * **Implementations must compare and delete atomically.** The device
   * authorization grant claims an approved authorization by revoking it and
   * issues a token only to the caller whose revoke resolved `true`, so this
   * boolean is the single-use guarantee (RFC 8628 §3.5): resolve `true` only
   * for the call that removed a live authorization, and `false` for every other
   * call — one already revoked, expired, or never stored. An implementation
   * that reads then deletes in two steps, or that returns `true`
   * unconditionally, lets two concurrent polls of one device code both mint
   * tokens. In SQL this is a `DELETE ... WHERE device_code = $1` whose
   * affected-row count is the answer.
   *
   * **The authorization must become unreachable by both of its codes.** A
   * verification page revokes the record it read from
   * {@linkcode DeviceAuthorizationServiceInterface.getByUserCode} to cancel a
   * request; if that leaves the device-code entry behind, the device's next
   * poll still redeems the cancelled — possibly already approved —
   * authorization for a token.
   */
  revoke(
    authorization: DeviceAuthorization<Client, User, Scope> | string,
  ): Promise<boolean>;
}
