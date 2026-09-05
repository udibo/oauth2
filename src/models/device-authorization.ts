import type { ClientInterface } from "./client.ts";
import type { AbstractScope, BasicScope } from "./scope.ts";

/**
 * Device authorization request stored by the service.
 *
 * Contains all the information needed to complete the device flow
 * once the user has authorized the request.
 */
export interface DeviceAuthorization<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> {
  /** The device verification code. */
  deviceCode: string;
  /** The user verification code (displayed to the user). */
  userCode: string;
  /** When the codes expire. */
  expiresAt: Date;
  /** The client that initiated the request. */
  client: Client;
  /** The scope requested by the client. */
  scope?: Scope | null;
  /** The minimum polling interval in seconds. */
  interval: number;
  /** Whether the user has authorized the request. */
  authorized?: boolean;
  /** The user who authorized the request (set after authorization). */
  user?: User;
  /** Whether the request was denied. */
  denied?: boolean;
  /** The last time the client polled for this code. */
  lastPolled?: Date;
}
