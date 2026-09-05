import {
  assert,
  assertEquals,
  assertInstanceOf,
  assertRejects,
  assertStrictEquals,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import type { DeviceAuthorization } from "../../models/device-authorization.ts";
import { BasicScope } from "../../models/scope.ts";
import {
  AccessDeniedError,
  AuthorizationPendingError,
  ExpiredTokenError,
  InvalidGrantError,
  InvalidRequestError,
  isOAuth2Error,
  SlowDownError,
} from "../../errors.ts";
import {
  exchangeToken,
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
  tokenRequest,
} from "../../testing/_test_fixtures.ts";
import { DeviceAuthorizationGrant } from "./device-authorization.ts";

/**
 * A compare-and-delete device authorization store that holds every write until
 * two polls have both read the authorization, so the read-then-delete window a
 * real store faces under concurrency is exercised deterministically instead of
 * by luck of scheduling.
 */
class RacingDeviceAuthorizationService
  extends MemoryDeviceAuthorizationService<TestClient, TestUser, BasicScope> {
  #bothRead = Promise.withResolvers<void>();
  #reads = 0;
  #claimedDeviceCodes = new Set<string>();

  override async getByDeviceCode(
    deviceCode: string,
  ): Promise<
    DeviceAuthorization<TestClient, TestUser, BasicScope> | undefined
  > {
    const authorization = await super.getByDeviceCode(deviceCode);
    if (++this.#reads >= 2) this.#bothRead.resolve();
    return authorization;
  }

  override async updateLastPolled(
    authorization: DeviceAuthorization<TestClient, TestUser, BasicScope>,
  ): Promise<DeviceAuthorization<TestClient, TestUser, BasicScope>> {
    await this.#bothRead.promise;
    return await super.updateLastPolled(authorization);
  }

  override async revoke(
    authorization:
      | DeviceAuthorization<TestClient, TestUser, BasicScope>
      | string,
  ): Promise<boolean> {
    await this.#bothRead.promise;
    const deviceCode = typeof authorization === "string"
      ? authorization
      : authorization.deviceCode;
    if (this.#claimedDeviceCodes.has(deviceCode)) return false;
    this.#claimedDeviceCodes.add(deviceCode);
    return await super.revoke(authorization);
  }
}

/**
 * A store whose poll-time write always fails, standing in for the store a
 * losing poll meets after a concurrent poll consumed the device code. When
 * `consumedByConcurrentPoll` is set it deletes the record before failing, which
 * is what a real store does when its `UPDATE ... WHERE device_code = $1`
 * matches no row; otherwise the record survives and the failure is the store
 * itself breaking.
 */
class FailingPollWriteService
  extends MemoryDeviceAuthorizationService<TestClient, TestUser, BasicScope> {
  consumedByConcurrentPoll = false;
  readonly failure = new Error("poll-time write failed");

  override async updateLastPolled(
    authorization: DeviceAuthorization<TestClient, TestUser, BasicScope>,
  ): Promise<DeviceAuthorization<TestClient, TestUser, BasicScope>> {
    if (this.consumedByConcurrentPoll) await super.revoke(authorization);
    throw this.failure;
  }
}

/**
 * A store that goes down mid-poll: the authorization is read, then the
 * poll-time write fails and so does the read the grant uses to classify it.
 * The grant must surface the **write** failure — the real cause an operator
 * needs — not whatever the recheck raised on its way to answering.
 */
class UnreachableStoreService
  extends MemoryDeviceAuthorizationService<TestClient, TestUser, BasicScope> {
  readonly writeFailure = new Error("poll-time write failed");
  readonly readFailure = new Error("recheck read failed");
  #reads = 0;

  override updateLastPolled(
    _authorization: DeviceAuthorization<TestClient, TestUser, BasicScope>,
  ): Promise<DeviceAuthorization<TestClient, TestUser, BasicScope>> {
    return Promise.reject(this.writeFailure);
  }

  override getByDeviceCode(
    deviceCode: string,
  ): Promise<
    DeviceAuthorization<TestClient, TestUser, BasicScope> | undefined
  > {
    this.#reads++;
    return this.#reads === 1
      ? super.getByDeviceCode(deviceCode)
      : Promise.reject(this.readFailure);
  }
}

/** A store that counts the poll-time writes the grant performs. */
class PollWriteCountingService
  extends MemoryDeviceAuthorizationService<TestClient, TestUser, BasicScope> {
  pollWrites = 0;

  override updateLastPolled(
    authorization: DeviceAuthorization<TestClient, TestUser, BasicScope>,
  ): Promise<DeviceAuthorization<TestClient, TestUser, BasicScope>> {
    this.pollWrites++;
    return super.updateLastPolled(authorization);
  }
}

const testUser: TestUser = { id: "user-1", username: "testuser" };
const testClient: TestClient = { id: "client-1", confidential: true };

async function createTestGrant() {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  const deviceAuthorizationService = new MemoryDeviceAuthorizationService({
    clientService,
    userService,
  });

  await userService.add(testUser, "password");

  const grant = new DeviceAuthorizationGrant<TestClient, TestUser, BasicScope>({
    resolve: () => ({
      clientService,
      tokenService,
      deviceAuthorizationService,
    }),
  });

  return { grant, clientService, tokenService, deviceAuthorizationService };
}

async function createGrantWithStore<
  Store extends MemoryDeviceAuthorizationService<
    TestClient,
    TestUser,
    BasicScope
  >,
>(
  createStore: (options: {
    clientService: MemoryClientService<TestClient, TestUser>;
    userService: MemoryUserService<TestUser>;
  }) => Store,
): Promise<{
  grant: DeviceAuthorizationGrant<TestClient, TestUser, BasicScope>;
  deviceAuthorizationService: Store;
}> {
  const userService = new MemoryUserService<TestUser>();
  const clientService = new MemoryClientService<TestClient, TestUser>(
    userService,
  );
  const tokenService = new MemoryTokenService({ clientService, userService });
  const deviceAuthorizationService = createStore({
    clientService,
    userService,
  });

  await userService.add(testUser, "password");
  await clientService.add(testClient, "secret", testUser.id);

  const grant = new DeviceAuthorizationGrant<TestClient, TestUser, BasicScope>({
    resolve: () => ({
      clientService,
      tokenService,
      deviceAuthorizationService,
    }),
  });

  return { grant, deviceAuthorizationService };
}

describe("DeviceAuthorizationGrant", () => {
  describe("grantType", () => {
    it("should return the RFC 8628 grant type URI", async () => {
      const { grant } = await createTestGrant();
      assertStrictEquals(
        grant.grantType,
        "urn:ietf:params:oauth:grant-type:device_code",
      );
    });
  });

  describe("initiateDeviceAuthorization", () => {
    it("should create device authorization with device_code and user_code", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = new Request("http://localhost/device_authorization", {
        method: "POST",
      });
      const authorization = await grant.initiateDeviceAuthorization(
        testClient,
        request,
      );

      assertStrictEquals(typeof authorization.deviceCode, "string");
      assertStrictEquals(typeof authorization.userCode, "string");
      assertStrictEquals(authorization.client.id, testClient.id);
      assertStrictEquals(typeof authorization.expiresAt, "object");
      assertStrictEquals(authorization.interval, 5);
    });

    it("should include scope when provided", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");
      const scope = new BasicScope("read write");

      const request = new Request("http://localhost/device_authorization", {
        method: "POST",
      });
      const authorization = await grant.initiateDeviceAuthorization(
        testClient,
        request,
        scope,
      );

      assertStrictEquals(authorization.scope?.toString(), "read write");
    });

    it("should not include scope when none is provided", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = new Request("http://localhost/device_authorization", {
        method: "POST",
      });
      const authorization = await grant.initiateDeviceAuthorization(
        testClient,
        request,
      );

      assertStrictEquals(authorization.scope, undefined);
    });

    it("should save the authorization", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = new Request("http://localhost/device_authorization", {
        method: "POST",
      });
      const authorization = await grant.initiateDeviceAuthorization(
        testClient,
        request,
      );

      const saved = await deviceAuthorizationService.getByDeviceCode(
        authorization.deviceCode,
      );
      assertStrictEquals(saved?.deviceCode, authorization.deviceCode);
    });
  });

  describe("token", () => {
    it("should throw InvalidRequestError when device_code is missing", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        InvalidRequestError,
        "device_code parameter required",
      );
    });

    it("should throw InvalidGrantError for non-existent device_code", async () => {
      const { grant, clientService } = await createTestGrant();
      await clientService.add(testClient, "secret");

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "non-existent",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        InvalidGrantError,
        "invalid device_code",
      );
    });

    it("should throw ExpiredTokenError for expired device_code", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "expired-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() - 1000),
        client: testClient,
        interval: 5,
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "expired-code",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        ExpiredTokenError,
        "device_code has expired",
      );
    });

    it("should revoke expired device_code when detected", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "expired-revoke",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() - 1000),
        client: testClient,
        interval: 5,
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "expired-revoke",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        ExpiredTokenError,
      );

      const revoked = await deviceAuthorizationService.getByDeviceCode(
        "expired-revoke",
      );
      assertStrictEquals(revoked, undefined);
    });

    it("should throw InvalidGrantError when device_code belongs to different client", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      const otherClient: TestClient = { id: "other-client" };
      await clientService.add(testClient, "secret", testUser.id);
      await clientService.add(otherClient);

      const authorization = {
        deviceCode: "test-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: otherClient,
        interval: 5,
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "test-code",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        InvalidGrantError,
        "device_code was issued to another client",
      );
    });

    describe("polling a device_code issued to another client", () => {
      const LIVE = () => new Date(Date.now() + 300000);
      const EXPIRED = () => new Date(Date.now() - 1000);

      async function createForeignAuthorization(expiresAt: Date) {
        const { grant, clientService, deviceAuthorizationService } =
          await createTestGrant();
        const otherClient: TestClient = { id: "other-client" };
        await clientService.add(testClient, "secret", testUser.id);
        await clientService.add(otherClient);
        await deviceAuthorizationService.save({
          deviceCode: "foreign-code",
          userCode: "WXYZ-9876",
          expiresAt,
          client: otherClient,
          interval: 5,
        });
        return { grant, deviceAuthorizationService };
      }

      async function refusalFor(
        grant: DeviceAuthorizationGrant<TestClient, TestUser, BasicScope>,
        deviceCode: string,
      ): Promise<{ code: string | undefined; message: string }> {
        const request = tokenRequest({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: deviceCode,
        });
        const error = await assertRejects(() =>
          exchangeToken(grant, request, testClient)
        );
        assert(
          isOAuth2Error(error),
          "the grant must refuse a poll with an OAuth2 error",
        );
        return { code: error.extensions.error, message: error.message };
      }

      it("answers invalid_grant for a device_code that was never issued", async () => {
        const { grant } = await createForeignAuthorization(LIVE());

        assertEquals(await refusalFor(grant, "never-issued"), {
          code: "invalid_grant",
          message: "invalid device_code",
        });
      });

      it("answers invalid_grant for a live device_code owned by another client", async () => {
        const { grant } = await createForeignAuthorization(LIVE());

        assertEquals(await refusalFor(grant, "foreign-code"), {
          code: "invalid_grant",
          message: "device_code was issued to another client",
        });
      });

      it("answers invalid_grant, not expired_token, for an expired device_code owned by another client", async () => {
        const { grant } = await createForeignAuthorization(EXPIRED());

        assertEquals(await refusalFor(grant, "foreign-code"), {
          code: "invalid_grant",
          message: "device_code was issued to another client",
        });
      });

      it("leaves an expired device_code owned by another client stored", async () => {
        const { grant, deviceAuthorizationService } =
          await createForeignAuthorization(EXPIRED());

        await refusalFor(grant, "foreign-code");

        const stillStored = await deviceAuthorizationService.getByDeviceCode(
          "foreign-code",
        );
        assert(
          stillStored,
          "an unauthenticated poll must not destroy another client's record",
        );
      });
    });

    it("should throw AuthorizationPendingError when user has not authorized", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "pending-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        authorized: false,
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "pending-code",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        AuthorizationPendingError,
        "authorization request is pending user approval",
      );
    });

    it("should update lastPolled timestamp on each poll", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "poll-track",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        authorized: false,
      };
      await deviceAuthorizationService.save(authorization);

      const before = Date.now();

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "poll-track",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        AuthorizationPendingError,
      );

      const updated = await deviceAuthorizationService.getByDeviceCode(
        "poll-track",
      );
      assertStrictEquals(updated?.lastPolled instanceof Date, true);
      assertStrictEquals(updated!.lastPolled!.getTime() >= before, true);
    });

    it("should throw AccessDeniedError when user denied the request", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "denied-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        denied: true,
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "denied-code",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        AccessDeniedError,
        "authorization request was denied",
      );
    });

    it("should revoke denied authorization after throwing AccessDeniedError", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "denied-revoke",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        denied: true,
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "denied-revoke",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        AccessDeniedError,
      );

      const revoked = await deviceAuthorizationService.getByDeviceCode(
        "denied-revoke",
      );
      assertStrictEquals(revoked, undefined);
    });

    it("should throw SlowDownError when polling too frequently", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "fast-poll-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        lastPolled: new Date(),
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "fast-poll-code",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        SlowDownError,
        "polling too frequently",
      );
    });

    it("should increase interval by 5 seconds on slow_down per RFC 8628 Section 3.5", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "interval-increase",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        lastPolled: new Date(),
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "interval-increase",
      });

      await assertRejects(
        () => exchangeToken(grant, request, testClient),
        SlowDownError,
      );

      const updated = await deviceAuthorizationService.getByDeviceCode(
        "interval-increase",
      );
      assertStrictEquals(updated?.interval, 10);
    });

    it("issues a token to only one of two concurrent polls of the same approved device_code", async () => {
      const { grant, deviceAuthorizationService } = await createGrantWithStore(
        (options) => new RacingDeviceAuthorizationService(options),
      );

      await deviceAuthorizationService.save({
        deviceCode: "raced-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        authorized: true,
        user: testUser,
      });

      const poll = () =>
        exchangeToken(
          grant,
          tokenRequest({
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: "raced-code",
          }),
          testClient,
        );
      const results = await Promise.allSettled([poll(), poll()]);

      const issued = results.filter((result) => result.status === "fulfilled");
      const refused = results.filter((result) => result.status === "rejected");
      assertStrictEquals(issued.length, 1);
      assertStrictEquals(refused.length, 1);
      assertInstanceOf(
        (refused[0] as PromiseRejectedResult).reason,
        InvalidGrantError,
      );
    });

    it("refuses with invalid_grant when a concurrent poll consumes the device code while the poll time is being recorded", async () => {
      const { grant, deviceAuthorizationService } = await createGrantWithStore(
        (options) => new FailingPollWriteService(options),
      );
      deviceAuthorizationService.consumedByConcurrentPoll = true;

      await deviceAuthorizationService.save({
        deviceCode: "consumed-mid-poll",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
      });

      await assertRejects(
        () =>
          exchangeToken(
            grant,
            tokenRequest({
              grant_type: "urn:ietf:params:oauth:grant-type:device_code",
              device_code: "consumed-mid-poll",
            }),
            testClient,
          ),
        InvalidGrantError,
        "device_code already used",
      );
    });

    it("refuses with invalid_grant instead of slow_down when the device code is consumed while a throttled poll is recorded", async () => {
      const { grant, deviceAuthorizationService } = await createGrantWithStore(
        (options) => new FailingPollWriteService(options),
      );
      deviceAuthorizationService.consumedByConcurrentPoll = true;

      await deviceAuthorizationService.save({
        deviceCode: "throttled-consumed",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        lastPolled: new Date(),
      });

      await assertRejects(
        () =>
          exchangeToken(
            grant,
            tokenRequest({
              grant_type: "urn:ietf:params:oauth:grant-type:device_code",
              device_code: "throttled-consumed",
            }),
            testClient,
          ),
        InvalidGrantError,
        "device_code already used",
      );
    });

    it("rethrows a poll-time write failure when the device code is still stored", async () => {
      const { grant, deviceAuthorizationService } = await createGrantWithStore(
        (options) => new FailingPollWriteService(options),
      );

      await deviceAuthorizationService.save({
        deviceCode: "store-broken",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
      });

      const error = await assertRejects(() =>
        exchangeToken(
          grant,
          tokenRequest({
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: "store-broken",
          }),
          testClient,
        )
      );
      assertStrictEquals(error, deviceAuthorizationService.failure);
    });

    it("surfaces the write failure, not the recheck's, when the store is down", async () => {
      const { grant, deviceAuthorizationService } = await createGrantWithStore(
        (options) => new UnreachableStoreService(options),
      );
      await deviceAuthorizationService.save({
        deviceCode: "store-down",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
      });

      const error = await assertRejects(() =>
        exchangeToken(
          grant,
          tokenRequest({
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: "store-down",
          }),
          testClient,
        )
      );
      assertStrictEquals(
        error,
        deviceAuthorizationService.writeFailure,
        "the recheck classifies the failure; it must never replace it",
      );
    });

    it("issues one token however many polls race for the same code", async () => {
      const { grant, deviceAuthorizationService } = await createGrantWithStore(
        (options) =>
          new MemoryDeviceAuthorizationService<
            TestClient,
            TestUser,
            BasicScope
          >(options),
      );
      await deviceAuthorizationService.save({
        deviceCode: "five-way-race",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        authorized: true,
        user: testUser,
      });

      const poll = () =>
        exchangeToken(
          grant,
          tokenRequest({
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: "five-way-race",
          }),
          testClient,
        );
      const results = await Promise.allSettled([
        poll(),
        poll(),
        poll(),
        poll(),
        poll(),
      ]);

      assertStrictEquals(
        results.filter((result) => result.status === "fulfilled").length,
        1,
        "the compare-and-delete claim admits exactly one poll at any width",
      );
      for (const result of results) {
        if (result.status === "rejected") {
          assertInstanceOf(result.reason, InvalidGrantError);
        }
      }
    });

    it("does not record a poll time on the approved authorization it claims", async () => {
      const { grant, deviceAuthorizationService } = await createGrantWithStore(
        (options) => new PollWriteCountingService(options),
      );

      await deviceAuthorizationService.save({
        deviceCode: "claimed-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        authorized: true,
        user: testUser,
      });

      await exchangeToken(
        grant,
        tokenRequest({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: "claimed-code",
        }),
        testClient,
      );

      assertStrictEquals(deviceAuthorizationService.pollWrites, 0);
    });

    it("does not record a poll time on a denied authorization it revokes", async () => {
      const { grant, deviceAuthorizationService } = await createGrantWithStore(
        (options) => new PollWriteCountingService(options),
      );

      await deviceAuthorizationService.save({
        deviceCode: "denied-poll-write",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        denied: true,
      });

      await assertRejects(
        () =>
          exchangeToken(
            grant,
            tokenRequest({
              grant_type: "urn:ietf:params:oauth:grant-type:device_code",
              device_code: "denied-poll-write",
            }),
            testClient,
          ),
        AccessDeniedError,
      );

      assertStrictEquals(deviceAuthorizationService.pollWrites, 0);
    });

    it("should return token when user has authorized", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "approved-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        authorized: true,
        user: testUser,
        scope: new BasicScope("read write"),
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "approved-code",
      });

      const token = await exchangeToken(grant, request, testClient);

      assertStrictEquals(typeof token.accessToken, "string");
      assertStrictEquals(token.client.id, testClient.id);
      assertStrictEquals(token.user?.id, testUser.id);
      assertStrictEquals(token.scope?.toString(), "read write");
    });

    it("should return token without scope when authorization has no scope", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "no-scope-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        authorized: true,
        user: testUser,
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "no-scope-code",
      });

      const token = await exchangeToken(grant, request, testClient);

      assertStrictEquals(typeof token.accessToken, "string");
      assertStrictEquals(token.scope, undefined);
    });

    it("should include refresh token by default", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "refresh-default-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        authorized: true,
        user: testUser,
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "refresh-default-code",
      });

      const token = await exchangeToken(grant, request, testClient);

      assertStrictEquals("refreshToken" in token, true);
    });

    it("should not include refresh token when allowRefreshToken is false", async () => {
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const tokenService = new MemoryTokenService({
        clientService,
        userService,
      });
      const deviceAuthorizationService = new MemoryDeviceAuthorizationService({
        clientService,
        userService,
      });

      await userService.add(testUser, "password");
      await clientService.add(testClient, "secret", testUser.id);

      const grant = new DeviceAuthorizationGrant<
        TestClient,
        TestUser,
        BasicScope
      >({
        resolve: () => ({
          clientService,
          tokenService,
          deviceAuthorizationService,
        }),
        allowRefreshToken: false,
      });

      const authorization = {
        deviceCode: "no-refresh-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        authorized: true,
        user: testUser,
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "no-refresh-code",
      });

      const token = await exchangeToken(grant, request, testClient);

      assertStrictEquals("refreshToken" in token, false);
    });

    it("should revoke device authorization after token issuance", async () => {
      const { grant, clientService, deviceAuthorizationService } =
        await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "revoke-after-use",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        authorized: true,
        user: testUser,
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "revoke-after-use",
      });

      await exchangeToken(grant, request, testClient);

      const revoked = await deviceAuthorizationService.getByDeviceCode(
        "revoke-after-use",
      );
      assertStrictEquals(revoked, undefined);
    });

    it("should save the generated token", async () => {
      const {
        grant,
        clientService,
        deviceAuthorizationService,
        tokenService,
      } = await createTestGrant();
      await clientService.add(testClient, "secret", testUser.id);

      const authorization = {
        deviceCode: "save-token-code",
        userCode: "ABCD-1234",
        expiresAt: new Date(Date.now() + 300000),
        client: testClient,
        interval: 5,
        authorized: true,
        user: testUser,
      };
      await deviceAuthorizationService.save(authorization);

      const request = tokenRequest({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: "save-token-code",
      });

      const token = await exchangeToken(grant, request, testClient);

      const savedToken = await tokenService.getToken(token.accessToken);
      assertStrictEquals(savedToken?.accessToken, token.accessToken);
    });
  });
});
