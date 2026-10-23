/**
 * Runs the identity store suites against stores shaped like a relational
 * backend: user ids and subjects must name existing users, record ids are
 * UUIDs, token hashes are unique across every test, and recovery codes are kept
 * only for a user with an active credential. The `Memory*` registrations in
 * `contract.test.ts` accept any string, so they cannot show that the suites
 * work against a store like this.
 *
 * @module
 */

import { describe, expect, it } from "vitest";
import { MemoryLockoutStore } from "../../identity/lockout.ts";
import type { MfaStore } from "../../identity/mfa/service.ts";
import { MemoryMfaStore } from "../../identity/mfa/service.ts";
import type { OtpStore } from "../../identity/otp.ts";
import { MemoryOtpStore } from "../../identity/otp.ts";
import type { TokenFlowStore } from "../../identity/token-flow.ts";
import { MemoryTokenFlowStore } from "../../identity/token-flow.ts";
import { runLockoutStoreContractTests } from "./lockout-store.ts";
import { runMfaStoreContractTests } from "./mfa-store.ts";
import { runOtpStoreContractTests } from "./otp-store.ts";
import { runTokenFlowStoreContractTests } from "./token-flow-store.ts";

const USER = "0192f1a4-0000-7000-8000-000000000001";
const OTHER_USER = "0192f1a4-0000-7000-8000-000000000002";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function existingUser(userId: string): string {
  if (userId !== USER && userId !== OTHER_USER) {
    throw new Error(`no user ${userId}`);
  }
  return userId;
}

function uuid(id: string): string {
  if (!UUID.test(id)) throw new Error(`invalid uuid ${id}`);
  return id;
}

function userKeyed<T extends object>(store: T): T {
  return new Proxy(store, {
    get(target, property) {
      const value: unknown = Reflect.get(target, property, target);
      if (typeof value !== "function") return value;
      return async (userId: string, ...rest: unknown[]): Promise<unknown> =>
        await Reflect.apply(value, target, [existingUser(userId), ...rest]);
    },
  });
}

class CredentialBoundMfaStore extends MemoryMfaStore {
  override async setRecoveryHashes(
    userId: string,
    hashes: string[],
  ): Promise<void> {
    if ((await this.getTotp(userId))?.secretBase32 === undefined) return;
    await super.setRecoveryHashes(userId, hashes);
  }
}

const savedTokenHashes = new Set<string>();

function relationalTokenFlowStore(): TokenFlowStore {
  const store = new MemoryTokenFlowStore();
  return {
    save: async (record) => {
      existingUser(record.subject);
      if (savedTokenHashes.has(record.tokenHash)) {
        throw new Error(`duplicate token hash ${record.tokenHash}`);
      }
      savedTokenHashes.add(record.tokenHash);
      await store.save(record);
    },
    get: (tokenHash) => store.get(tokenHash),
    markConsumed: (tokenHash, consumedAt) =>
      store.markConsumed(tokenHash, consumedAt),
    deleteBySubject: (purpose, subject) =>
      store.deleteBySubject(purpose, existingUser(subject)),
  };
}

function uuidKeyedOtpStore(): OtpStore {
  const store = new MemoryOtpStore();
  return {
    create: async (record) =>
      await store.create({ ...record, id: uuid(record.id) }),
    findActive: (email, purpose) => store.findActive(email, purpose),
    recordAttempt: async (id) => await store.recordAttempt(uuid(id)),
    consume: async (id) => await store.consume(uuid(id)),
    invalidateById: async (id) => await store.invalidateById(uuid(id)),
    invalidate: (email, purpose) => store.invalidate(email, purpose),
  };
}

describe("relational fixture stores", () => {
  it("refuse the ids a relational backend would refuse", async () => {
    await expect(
      userKeyed(new MemoryLockoutStore()).get("user-1"),
    ).rejects.toThrow("no user user-1");
    await expect(uuidKeyedOtpStore().consume("otp-1")).rejects.toThrow(
      "invalid uuid otp-1",
    );
    const mfa: MfaStore = new CredentialBoundMfaStore();
    await mfa.setRecoveryHashes(USER, ["h1"]);
    expect(await mfa.getRecoveryHashes(USER)).toStrictEqual([]);
  });
});

runMfaStoreContractTests({
  describeName:
    "a credential-bound, user-keyed MfaStore satisfies the contract",
  userId: USER,
  otherUserId: OTHER_USER,
  makeStore: () => userKeyed(new CredentialBoundMfaStore()),
});

runLockoutStoreContractTests({
  describeName: "a user-keyed LockoutStore satisfies the contract",
  userId: USER,
  otherUserId: OTHER_USER,
  makeStore: () => userKeyed(new MemoryLockoutStore()),
});

runTokenFlowStoreContractTests({
  describeName:
    "a TokenFlowStore with user subjects and globally unique hashes satisfies the contract",
  subject: USER,
  otherSubject: OTHER_USER,
  makeStore: relationalTokenFlowStore,
});

runOtpStoreContractTests({
  describeName: "a UUID-keyed OtpStore satisfies the contract",
  makeStore: uuidKeyedOtpStore,
});
