import { assert, beforeEach, describe, expect, it } from "vitest";
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
        deviceAuthorizationService: DeviceAuthorizationServiceInterface<
          C,
          U,
          S
        >;
      }>
    | {
        userService: UserServiceInterface<U>;
        clientService: ClientServiceInterface<C, U>;
        deviceAuthorizationService: DeviceAuthorizationServiceInterface<
          C,
          U,
          S
        >;
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
>(options: DeviceAuthorizationServiceContractOptions<C, U, S>): void {
  const makeUser = options.makeUser ?? defaultMakeUser<U>;
  const makeClient = options.makeClient ?? defaultMakeClient<C>;

  describe(
    options.describeName ?? "DeviceAuthorizationServiceInterface contract",
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
        expect(fetched?.deviceCode).toStrictEqual(auth.deviceCode);
        expect(fetched?.client.id).toStrictEqual(client.id);
      });

      it("save + lookup by user code", async () => {
        const auth = await makeDeviceAuth();
        await deviceService.save(auth);
        const fetched = await deviceService.getByUserCode(auth.userCode);
        expect(fetched?.userCode).toStrictEqual(auth.userCode);
      });

      it("getByDeviceCode / getByUserCode return undefined for unknown codes", async () => {
        expect(await deviceService.getByDeviceCode("missing")).toBe(undefined);
        expect(await deviceService.getByUserCode("missing")).toBe(undefined);
      });

      it("approve marks the authorization with the approving user", async () => {
        const auth = await makeDeviceAuth();
        await deviceService.save(auth);
        const approved = await deviceService.approve(auth, user);
        expect(approved.authorized).toBe(true);
        expect((approved.user as MemoryUserShape).id).toStrictEqual(user.id);
        const refetched = await deviceService.getByDeviceCode(auth.deviceCode);
        expect(refetched?.authorized).toBe(true);
      });

      it("deny marks the authorization as denied", async () => {
        const auth = await makeDeviceAuth();
        await deviceService.save(auth);
        const denied = await deviceService.deny(auth);
        expect(denied.denied).toBe(true);
        const refetched = await deviceService.getByDeviceCode(auth.deviceCode);
        expect(refetched?.denied).toBe(true);
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
        expect(await deviceService.revoke(auth1)).toBe(true);
        expect(await deviceService.getByDeviceCode(auth1.deviceCode)).toBe(
          undefined,
        );

        const auth2 = await makeDeviceAuth();
        await deviceService.save(auth2);
        expect(await deviceService.revoke(auth2.deviceCode)).toBe(true);
        expect(await deviceService.getByDeviceCode(auth2.deviceCode)).toBe(
          undefined,
        );
      });

      it("revoke answers true only for the call that removed a live authorization", async () => {
        const auth = await makeDeviceAuth();
        await deviceService.save(auth);

        expect(await deviceService.revoke(auth)).toBe(true);
        expect(await deviceService.revoke(auth)).toBe(false);
        expect(await deviceService.revoke(auth.deviceCode)).toBe(false);
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
        expect(
          await deviceService.getByDeviceCode(auth.deviceCode),
          "a revoked authorization must not resolve by its device code",
        ).toBe(undefined);
        expect(
          await deviceService.getByUserCode(auth.userCode),
          "a revoked authorization must not resolve by its user code",
        ).toBe(undefined);
      }

      it("revoke by full record clears both the device-code and user-code lookups", async () => {
        const { auth } = await saveDeviceAuth();
        expect(await deviceService.revoke(auth)).toBe(true);
        await assertUnreachableByEitherCode(auth);
      });

      it("revoke by raw device code clears both the device-code and user-code lookups", async () => {
        const { auth } = await saveDeviceAuth();
        expect(await deviceService.revoke(auth.deviceCode)).toBe(true);
        await assertUnreachableByEitherCode(auth);
      });

      it("revoke accepts the record getByDeviceCode returns and clears both lookups", async () => {
        const { auth, byDeviceCode } = await saveDeviceAuth();
        expect(await deviceService.revoke(byDeviceCode)).toBe(true);
        await assertUnreachableByEitherCode(auth);
      });

      it("revoke accepts the record getByUserCode returns and clears both lookups", async () => {
        const { auth, byUserCode } = await saveDeviceAuth();
        expect(await deviceService.revoke(byUserCode)).toBe(true);
        await assertUnreachableByEitherCode(auth);
      });

      it("revoke answers true once across the hydrated shapes of one authorization", async () => {
        const { byDeviceCode, byUserCode } = await saveDeviceAuth();
        expect(await deviceService.revoke(byDeviceCode)).toBe(true);
        expect(await deviceService.revoke(byUserCode)).toBe(false);
      });

      it("revoke answers true to exactly one of two concurrent claims", async () => {
        const { auth, byDeviceCode } = await saveDeviceAuth();
        const claims = await Promise.all([
          deviceService.revoke(byDeviceCode),
          deviceService.revoke(byDeviceCode),
        ]);
        expect(
          claims.filter(Boolean).length,
          "concurrent polls of one device code must not both be told they claimed it",
        ).toStrictEqual(1);
        await assertUnreachableByEitherCode(auth);
      });

      it("revoke of a user-code-hydrated record consumes the device code", async () => {
        const { auth, byUserCode } = await saveDeviceAuth();
        await deviceService.approve(byUserCode, user);
        await deviceService.revoke(byUserCode);
        expect(
          await deviceService.getByDeviceCode(auth.deviceCode),
          "a cancelled authorization must not stay redeemable by its device code",
        ).toBe(undefined);
      });

      it("approve accepts the record getByUserCode returns", async () => {
        const { auth, byUserCode } = await saveDeviceAuth();
        const approved = await deviceService.approve(byUserCode, user);
        expect(approved.authorized).toBe(true);
        const refetched = await deviceService.getByDeviceCode(auth.deviceCode);
        expect(refetched?.authorized).toBe(true);
        expect(
          (refetched?.user as MemoryUserShape | undefined)?.id,
        ).toStrictEqual(user.id);
      });

      it("approve accepts the record getByDeviceCode returns", async () => {
        const { auth, byDeviceCode } = await saveDeviceAuth();
        await deviceService.approve(byDeviceCode, user);
        const refetched = await deviceService.getByUserCode(auth.userCode);
        expect(refetched?.authorized).toBe(true);
      });

      it("deny accepts the record getByUserCode returns", async () => {
        const { auth, byUserCode } = await saveDeviceAuth();
        const denied = await deviceService.deny(byUserCode);
        expect(denied.denied).toBe(true);
        const refetched = await deviceService.getByDeviceCode(auth.deviceCode);
        expect(refetched?.denied).toBe(true);
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
