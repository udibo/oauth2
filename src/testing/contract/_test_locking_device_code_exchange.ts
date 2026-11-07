import type { DeviceAuthorization } from "../../models/device-authorization.ts";
import type { BasicScope } from "../../models/scope.ts";
import type { Token } from "../../models/token.ts";
import type { TestClient, TestUser } from "../_test_fixtures.ts";
import {
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  MemoryTokenService,
  MemoryUserService,
} from "../services.ts";
import type {
  DeviceCodeExchangeBarriers,
  DeviceCodeExchangeContractServices,
} from "./device-code-exchange.ts";

type TestAuthorization = DeviceAuthorization<TestClient, TestUser, BasicScope>;
type TestToken = Token<TestClient, TestUser, BasicScope>;

class DeviceCodeLocks {
  readonly #tails = new Map<string, Promise<void>>();

  async hold<T>(deviceCode: string, critical: () => Promise<T>): Promise<T> {
    const previous = this.#tails.get(deviceCode) ?? Promise.resolve();
    const released = Promise.withResolvers<void>();
    const tail = previous.then(() => released.promise);
    this.#tails.set(deviceCode, tail);
    await previous;
    try {
      return await critical();
    } finally {
      released.resolve();
      if (this.#tails.get(deviceCode) === tail) this.#tails.delete(deviceCode);
    }
  }
}

class SaveThenRevokeTokenService extends MemoryTokenService<
  TestClient,
  TestUser,
  BasicScope
> {
  readonly #devices: MemoryDeviceAuthorizationService<
    TestClient,
    TestUser,
    BasicScope
  >;
  readonly #barriers: DeviceCodeExchangeBarriers;
  readonly #locks: DeviceCodeLocks | undefined;

  constructor(
    services: {
      clientService: MemoryClientService<TestClient, TestUser>;
      userService: MemoryUserService<TestUser>;
    },
    devices: MemoryDeviceAuthorizationService<TestClient, TestUser, BasicScope>,
    barriers: DeviceCodeExchangeBarriers,
    locks: DeviceCodeLocks | undefined,
  ) {
    super(services);
    this.#devices = devices;
    this.#barriers = barriers;
    this.#locks = locks;
  }

  override readonly exchangeDeviceCode = (
    authorization: TestAuthorization,
    token: TestToken,
  ): Promise<TestToken | undefined> => {
    const critical = async (): Promise<TestToken | undefined> => {
      if (!(await this.#devices.getByDeviceCode(authorization.deviceCode))) {
        return undefined;
      }
      if (this.#locks) await this.#barriers.afterClaim();
      await this.save(token);
      if (!(await this.#devices.revoke(authorization.deviceCode))) {
        return undefined;
      }
      return token;
    };
    return this.#locks
      ? this.#locks.hold(authorization.deviceCode, critical)
      : critical();
  };
}

/**
 * Builds a device store and a token service whose `exchangeDeviceCode` saves
 * the token and then revokes the authorization, like a database pair that
 * commits both at the end. By default the exchange serializes on a
 * per-device-code lock and awaits the barrier inside it, which satisfies
 * `runDeviceCodeExchangeContractTests`. `{ locksDeviceCodes: false }` drops the
 * lock and the barrier, so concurrent exchanges each persist a token before
 * one wins the revoke, to prove the suite fails such a store.
 */
export function lockingDeviceCodeExchangeServices(
  barriers: DeviceCodeExchangeBarriers,
  shape: { locksDeviceCodes?: boolean } = {},
): DeviceCodeExchangeContractServices<TestClient, TestUser> {
  const userService = new MemoryUserService<TestUser>();
  const clientService = new MemoryClientService<TestClient, TestUser>(
    userService,
  );
  const deviceAuthorizationService = new MemoryDeviceAuthorizationService<
    TestClient,
    TestUser,
    BasicScope
  >({ clientService, userService });
  const tokenService = new SaveThenRevokeTokenService(
    { clientService, userService },
    deviceAuthorizationService,
    barriers,
    (shape.locksDeviceCodes ?? true) ? new DeviceCodeLocks() : undefined,
  );
  return {
    userService,
    clientService,
    deviceAuthorizationService,
    tokenService,
  };
}
