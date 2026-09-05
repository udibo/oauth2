/**
 * Contract test suite for {@link DeviceAuthorizationServiceInterface}
 * implementations (RFC 8628).
 *
 * @module
 */

import { assert, assertEquals, assertStrictEquals } from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";

import type { ClientInterface } from "../../models/client.ts";
import type { DeviceAuthorization } from "../../models/device-authorization.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import type { ClientServiceInterface } from "../../server/services/client.ts";
import type { DeviceAuthorizationServiceInterface } from "../../server/services/device-authorization.ts";
import type { UserServiceInterface } from "../../server/services/user.ts";
import type { MemoryUserShape } from "../services.ts";

/** Options for {@link runDeviceAuthorizationServiceContractTests}. */
export interface DeviceAuthorizationServiceContractOptions<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> {
  /** Returns fresh services for each test. */
  makeServices():
    | Promise<{
      userService: UserServiceInterface<U>;
      clientService: ClientServiceInterface<C, U>;
      deviceAuthorizationService: DeviceAuthorizationServiceInterface<C, U, S>;
    }>
    | {
      userService: UserServiceInterface<U>;
      clientService: ClientServiceInterface<C, U>;
      deviceAuthorizationService: DeviceAuthorizationServiceInterface<C, U, S>;
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
  /** Builds a distinct client fixture for the given sequence number. Defaults to a client granting the device-code grant. */
  makeClient?(seq: number): C;
  /** Overrides the name passed to the outer `describe` block. */
  describeName?: string;
}

const defaultMakeUser = <U extends MemoryUserShape>(seq: number): U =>
  ({ id: `u${seq}`, username: `user${seq}` }) as U;
const defaultMakeClient = <C extends ClientInterface>(seq: number): C =>
  ({
    id: `client-${seq}`,
    grants: ["urn:ietf:params:oauth:grant-type:device_code"],
  }) as C;

/** Runs the {@link DeviceAuthorizationServiceInterface} contract suite. */
export function runDeviceAuthorizationServiceContractTests<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
>(
  options: DeviceAuthorizationServiceContractOptions<C, U, S>,
): void {
  const makeUser = options.makeUser ?? defaultMakeUser<U>;
  const makeClient = options.makeClient ?? defaultMakeClient<C>;

  describe(
    options.describeName ??
      "DeviceAuthorizationServiceInterface contract",
    () => {
      let userService: UserServiceInterface<U>;
      let clientService: ClientServiceInterface<C, U>;
      let deviceService: DeviceAuthorizationServiceInterface<C, U, S>;
      let user: U;
      let client: C;

      beforeEach(async () => {
        const services = await options.makeServices();
        userService = services.userService;
        clientService = services.clientService;
        deviceService = services.deviceAuthorizationService;
        user = makeUser(1);
        client = makeClient(1);
        await options.addUser(userService, user, "pw");
        await options.addClient(clientService, client);
      });

      async function makeDeviceAuth(): Promise<DeviceAuthorization<C, U, S>> {
        return {
          deviceCode: await deviceService.generateDeviceCode(client),
          userCode: await deviceService.generateUserCode(client),
          expiresAt: await deviceService.expiresAt(client),
          client,
          interval: deviceService.interval,
        };
      }

      it("generateDeviceCode and generateUserCode produce unique strings", async () => {
        const d1 = await deviceService.generateDeviceCode(client);
        const d2 = await deviceService.generateDeviceCode(client);
        const u1 = await deviceService.generateUserCode(client);
        const u2 = await deviceService.generateUserCode(client);
        assert(d1 !== d2, "device codes should not collide");
        assert(u1 !== u2, "user codes should not collide");
      });

      it("save + lookup by device code", async () => {
        const auth = await makeDeviceAuth();
        await deviceService.save(auth);
        const fetched = await deviceService.getByDeviceCode(auth.deviceCode);
        assertEquals(fetched?.deviceCode, auth.deviceCode);
        assertEquals(fetched?.client.id, client.id);
      });

      it("save + lookup by user code", async () => {
        const auth = await makeDeviceAuth();
        await deviceService.save(auth);
        const fetched = await deviceService.getByUserCode(auth.userCode);
        assertEquals(fetched?.userCode, auth.userCode);
      });

      it("getByDeviceCode / getByUserCode return undefined for unknown codes", async () => {
        assertStrictEquals(
          await deviceService.getByDeviceCode("missing"),
          undefined,
        );
        assertStrictEquals(
          await deviceService.getByUserCode("missing"),
          undefined,
        );
      });

      it("approve marks the authorization with the approving user", async () => {
        const auth = await makeDeviceAuth();
        await deviceService.save(auth);
        const approved = await deviceService.approve(auth, user);
        assertStrictEquals(approved.authorized, true);
        assertEquals((approved.user as MemoryUserShape).id, user.id);
        const refetched = await deviceService.getByDeviceCode(auth.deviceCode);
        assertStrictEquals(refetched?.authorized, true);
      });

      it("deny marks the authorization as denied", async () => {
        const auth = await makeDeviceAuth();
        await deviceService.save(auth);
        const denied = await deviceService.deny(auth);
        assertStrictEquals(denied.denied, true);
        const refetched = await deviceService.getByDeviceCode(auth.deviceCode);
        assertStrictEquals(refetched?.denied, true);
      });

      it("updateLastPolled records a poll time", async () => {
        const auth = await makeDeviceAuth();
        await deviceService.save(auth);
        const updated = await deviceService.updateLastPolled(auth);
        assert(updated.lastPolled instanceof Date);
        const refetched = await deviceService.getByDeviceCode(auth.deviceCode);
        assert(refetched?.lastPolled instanceof Date);
      });

      it("revoke deletes by object and by string", async () => {
        const auth1 = await makeDeviceAuth();
        await deviceService.save(auth1);
        assertStrictEquals(await deviceService.revoke(auth1), true);
        assertStrictEquals(
          await deviceService.getByDeviceCode(auth1.deviceCode),
          undefined,
        );

        const auth2 = await makeDeviceAuth();
        await deviceService.save(auth2);
        assertStrictEquals(await deviceService.revoke(auth2.deviceCode), true);
        assertStrictEquals(
          await deviceService.getByDeviceCode(auth2.deviceCode),
          undefined,
        );
      });

      it("revoke answers true only for the call that removed a live authorization", async () => {
        const auth = await makeDeviceAuth();
        await deviceService.save(auth);

        assertStrictEquals(await deviceService.revoke(auth), true);
        assertStrictEquals(await deviceService.revoke(auth), false);
        assertStrictEquals(await deviceService.revoke(auth.deviceCode), false);
      });

      async function saveDeviceAuth(): Promise<{
        auth: DeviceAuthorization<C, U, S>;
        byDeviceCode: DeviceAuthorization<C, U, S>;
        byUserCode: DeviceAuthorization<C, U, S>;
      }> {
        const auth = await makeDeviceAuth();
        await deviceService.save(auth);
        const byDeviceCode = await deviceService.getByDeviceCode(
          auth.deviceCode,
        );
        const byUserCode = await deviceService.getByUserCode(auth.userCode);
        assert(byDeviceCode, "getByDeviceCode should resolve what was saved");
        assert(byUserCode, "getByUserCode should resolve what was saved");
        return { auth, byDeviceCode, byUserCode };
      }

      async function assertUnreachableByEitherCode(
        auth: DeviceAuthorization<C, U, S>,
      ): Promise<void> {
        assertStrictEquals(
          await deviceService.getByDeviceCode(auth.deviceCode),
          undefined,
          "a revoked authorization must not resolve by its device code",
        );
        assertStrictEquals(
          await deviceService.getByUserCode(auth.userCode),
          undefined,
          "a revoked authorization must not resolve by its user code",
        );
      }

      it("revoke by full record clears both the device-code and user-code lookups", async () => {
        const { auth } = await saveDeviceAuth();
        assertStrictEquals(await deviceService.revoke(auth), true);
        await assertUnreachableByEitherCode(auth);
      });

      it("revoke by raw device code clears both the device-code and user-code lookups", async () => {
        const { auth } = await saveDeviceAuth();
        assertStrictEquals(await deviceService.revoke(auth.deviceCode), true);
        await assertUnreachableByEitherCode(auth);
      });

      it("revoke accepts the record getByDeviceCode returns and clears both lookups", async () => {
        const { auth, byDeviceCode } = await saveDeviceAuth();
        assertStrictEquals(await deviceService.revoke(byDeviceCode), true);
        await assertUnreachableByEitherCode(auth);
      });

      it("revoke accepts the record getByUserCode returns and clears both lookups", async () => {
        const { auth, byUserCode } = await saveDeviceAuth();
        assertStrictEquals(await deviceService.revoke(byUserCode), true);
        await assertUnreachableByEitherCode(auth);
      });

      it("revoke answers true once across the hydrated shapes of one authorization", async () => {
        const { byDeviceCode, byUserCode } = await saveDeviceAuth();
        assertStrictEquals(await deviceService.revoke(byDeviceCode), true);
        assertStrictEquals(await deviceService.revoke(byUserCode), false);
      });

      it("revoke answers true to exactly one of two concurrent claims", async () => {
        const { auth, byDeviceCode } = await saveDeviceAuth();
        const claims = await Promise.all([
          deviceService.revoke(byDeviceCode),
          deviceService.revoke(byDeviceCode),
        ]);
        assertEquals(
          claims.filter(Boolean).length,
          1,
          "concurrent polls of one device code must not both be told they claimed it",
        );
        await assertUnreachableByEitherCode(auth);
      });

      it("revoke of a user-code-hydrated record consumes the device code", async () => {
        const { auth, byUserCode } = await saveDeviceAuth();
        await deviceService.approve(byUserCode, user);
        await deviceService.revoke(byUserCode);
        assertStrictEquals(
          await deviceService.getByDeviceCode(auth.deviceCode),
          undefined,
          "a cancelled authorization must not stay redeemable by its device code",
        );
      });

      it("approve accepts the record getByUserCode returns", async () => {
        const { auth, byUserCode } = await saveDeviceAuth();
        const approved = await deviceService.approve(byUserCode, user);
        assertStrictEquals(approved.authorized, true);
        const refetched = await deviceService.getByDeviceCode(auth.deviceCode);
        assertStrictEquals(refetched?.authorized, true);
        assertEquals(
          (refetched?.user as MemoryUserShape | undefined)?.id,
          user.id,
        );
      });

      it("approve accepts the record getByDeviceCode returns", async () => {
        const { auth, byDeviceCode } = await saveDeviceAuth();
        await deviceService.approve(byDeviceCode, user);
        const refetched = await deviceService.getByUserCode(auth.userCode);
        assertStrictEquals(refetched?.authorized, true);
      });

      it("deny accepts the record getByUserCode returns", async () => {
        const { auth, byUserCode } = await saveDeviceAuth();
        const denied = await deviceService.deny(byUserCode);
        assertStrictEquals(denied.denied, true);
        const refetched = await deviceService.getByDeviceCode(auth.deviceCode);
        assertStrictEquals(refetched?.denied, true);
      });

      it("updateLastPolled accepts the record getByDeviceCode returns", async () => {
        const { auth, byDeviceCode } = await saveDeviceAuth();
        const updated = await deviceService.updateLastPolled(byDeviceCode);
        assert(updated.lastPolled instanceof Date);
        const refetched = await deviceService.getByDeviceCode(auth.deviceCode);
        assert(
          refetched?.lastPolled instanceof Date,
          "the poll time must be visible to the next read",
        );
      });
    },
  );
}
