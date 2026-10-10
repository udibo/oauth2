/**
 * Contract test suite for {@link MfaStore} implementations.
 *
 * `MfaService` leans on three store methods for its concurrency guarantees —
 * `activateTotp` (compare-and-swap on the pending secret), `advanceLastStep`
 * (monotonic replay guard), and `consumeRecoveryHash` (single-use recovery
 * codes). This suite checks each of them with concurrent calls, so a
 * read-modify-write implementation fails here instead of silently letting two
 * requests spend one recovery code.
 *
 * @example Verify a database-backed store
 * ```ts
 * import { runMfaStoreContractTests } from "@udibo/oauth2/testing/contract";
 * import type { MfaStore } from "@udibo/oauth2/identity/mfa";
 *
 * declare function freshMfaStore(): Promise<MfaStore>;
 *
 * runMfaStoreContractTests({
 *   describeName: "DrizzleMfaStore satisfies MfaStore contract",
 *   makeStore: freshMfaStore,
 * });
 * ```
 *
 * @module
 */

import { beforeEach, describe, expect, it } from "vitest";
import type { MfaStore } from "../../identity/mfa/service.ts";
import { CONCURRENT_CALLERS, race } from "./_race.ts";

/** Options for {@link runMfaStoreContractTests}. */
export interface MfaStoreContractOptions {
  /**
   * Returns a fresh, empty store for each test. Isolation is required — a
   * recovery hash left behind by one test makes the single-use checks
   * meaningless.
   */
  makeStore(): Promise<MfaStore> | MfaStore;
  /**
   * Overrides the name passed to the outer `describe` block. Defaults to
   * `"MfaStore contract"`.
   */
  describeName?: string;
}

const USER = "user-1";
const OTHER_USER = "user-2";
const SECRET_A = "AAAAAAAAAAAAAAAA";
const SECRET_B = "BBBBBBBBBBBBBBBB";

function countTrue(results: boolean[]): number {
  return results.filter((result) => result).length;
}

/**
 * Runs the {@link MfaStore} contract suite. Call it from your own test file —
 * it registers `describe` / `it` blocks the test runner picks up.
 *
 * The atomicity cases issue overlapping calls — eight on one key where only one
 * may win — and assert the outcome a conditional write produces. An
 * implementation that reads, then awaits, then writes fails them in practice,
 * which is the point: the same store passes every sequential check. A race is
 * probabilistic, so a lucky interleaving can still pass a single run.
 */
export function runMfaStoreContractTests(
  options: MfaStoreContractOptions,
): void {
  describe(options.describeName ?? "MfaStore contract", () => {
    let store: MfaStore;

    beforeEach(async () => {
      store = await options.makeStore();
    });

    describe("getTotp / setPendingTotp", () => {
      it("returns undefined for a user with no record", async () => {
        expect(await store.getTotp(USER)).toBe(undefined);
      });

      it("stores a pending secret without activating it", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        const record = await store.getTotp(USER);
        expect(record?.pendingSecretBase32).toStrictEqual(SECRET_A);
        expect(record?.secretBase32).toBe(undefined);
      });

      it("replaces a previous pending secret", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        await store.setPendingTotp(USER, SECRET_B);
        const record = await store.getTotp(USER);
        expect(record?.pendingSecretBase32).toStrictEqual(SECRET_B);
      });

      it("keeps an active credential when a new enrollment starts", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        await store.activateTotp(USER, SECRET_A, 100);
        await store.setPendingTotp(USER, SECRET_B);
        const record = await store.getTotp(USER);
        expect(record?.secretBase32).toStrictEqual(SECRET_A);
        expect(record?.lastStep).toStrictEqual(100);
        expect(record?.pendingSecretBase32).toStrictEqual(SECRET_B);
      });

      it("keeps each user's record separate", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        expect(await store.getTotp(OTHER_USER)).toBe(undefined);
      });
    });

    describe("activateTotp", () => {
      it("promotes the matching pending secret and clears it", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        expect(await store.activateTotp(USER, SECRET_A, 42)).toBe(true);
        const record = await store.getTotp(USER);
        expect(record?.secretBase32).toStrictEqual(SECRET_A);
        expect(record?.lastStep).toStrictEqual(42);
        expect(record?.pendingSecretBase32).toBe(undefined);
      });

      it("refuses when the user has no pending secret", async () => {
        expect(await store.activateTotp(USER, SECRET_A, 42)).toBe(false);
        expect(await store.getTotp(USER)).toBe(undefined);
      });

      it("refuses a secret a newer enrollment replaced, changing nothing", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        await store.setPendingTotp(USER, SECRET_B);
        expect(await store.activateTotp(USER, SECRET_A, 42)).toBe(false);
        const record = await store.getTotp(USER);
        expect(record?.secretBase32).toBe(undefined);
        expect(record?.pendingSecretBase32).toStrictEqual(SECRET_B);
      });

      it(`activates for exactly one of ${CONCURRENT_CALLERS} concurrent confirmations`, async () => {
        await store.setPendingTotp(USER, SECRET_A);
        const results = await race((caller) =>
          store.activateTotp(USER, SECRET_A, 10 + caller),
        );
        expect(
          countTrue(results),
          "the pending secret must be claimable once — a second concurrent " +
            "confirmation finds it already spent",
        ).toBe(1);
        const record = await store.getTotp(USER);
        expect(record?.secretBase32).toStrictEqual(SECRET_A);
        expect(record?.pendingSecretBase32).toBe(undefined);
      });

      it("activates for exactly one of two concurrent enrollments", async () => {
        await store.setPendingTotp(USER, SECRET_B);
        const results = await Promise.all([
          store.activateTotp(USER, SECRET_A, 10),
          store.activateTotp(USER, SECRET_B, 20),
        ]);
        expect(countTrue(results)).toBe(1);
        const record = await store.getTotp(USER);
        expect(
          record?.secretBase32,
          "only the secret that was actually pending may become active",
        ).toStrictEqual(SECRET_B);
      });
    });

    describe("clearTotp", () => {
      it("removes the active credential and any pending secret", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        await store.activateTotp(USER, SECRET_A, 5);
        await store.setPendingTotp(USER, SECRET_B);
        await store.clearTotp(USER);
        expect(await store.getTotp(USER)).toBe(undefined);
      });

      it("is a no-op for a user with no record", async () => {
        await store.clearTotp(USER);
        expect(await store.getTotp(USER)).toBe(undefined);
      });
    });

    describe("advanceLastStep", () => {
      beforeEach(async () => {
        await store.setPendingTotp(USER, SECRET_A);
        await store.activateTotp(USER, SECRET_A, 100);
      });

      it("advances to a higher step", async () => {
        expect(await store.advanceLastStep(USER, 101)).toBe(true);
        expect((await store.getTotp(USER))?.lastStep).toStrictEqual(101);
      });

      it("refuses the step already spent", async () => {
        expect(await store.advanceLastStep(USER, 100)).toBe(false);
        expect((await store.getTotp(USER))?.lastStep).toStrictEqual(100);
      });

      it("refuses an earlier step, leaving the guard where it was", async () => {
        expect(await store.advanceLastStep(USER, 99)).toBe(false);
        expect((await store.getTotp(USER))?.lastStep).toStrictEqual(100);
      });

      it("refuses for a user with no record", async () => {
        expect(await store.advanceLastStep(OTHER_USER, 1)).toBe(false);
      });

      it(`admits exactly one of ${CONCURRENT_CALLERS} concurrent claims on the same step`, async () => {
        const results = await race(() => store.advanceLastStep(USER, 101));
        expect(
          countTrue(results),
          "a time step is spendable once — the loser must read as a replay",
        ).toBe(1);
        expect((await store.getTotp(USER))?.lastStep).toStrictEqual(101);
      });

      it("never regresses under concurrent claims on different steps", async () => {
        await Promise.all([
          store.advanceLastStep(USER, 105),
          store.advanceLastStep(USER, 101),
        ]);
        expect(
          (await store.getTotp(USER))?.lastStep,
          "the highest accepted step must survive a concurrent lower one",
        ).toStrictEqual(105);
      });
    });

    describe("recovery hashes", () => {
      it("returns an empty list for a user with none", async () => {
        expect(await store.getRecoveryHashes(USER)).toStrictEqual([]);
      });

      it("replaces the stored set exactly", async () => {
        await store.setRecoveryHashes(USER, ["h1", "h2", "h3"]);
        expect([...(await store.getRecoveryHashes(USER))].sort()).toStrictEqual(
          ["h1", "h2", "h3"],
        );
        await store.setRecoveryHashes(USER, ["h4"]);
        expect(await store.getRecoveryHashes(USER)).toStrictEqual(["h4"]);
      });

      it("clears the set when given an empty list", async () => {
        await store.setRecoveryHashes(USER, ["h1"]);
        await store.setRecoveryHashes(USER, []);
        expect(await store.getRecoveryHashes(USER)).toStrictEqual([]);
      });

      it("keeps each user's codes separate", async () => {
        await store.setRecoveryHashes(USER, ["h1"]);
        expect(await store.getRecoveryHashes(OTHER_USER)).toStrictEqual([]);
        expect(await store.consumeRecoveryHash(OTHER_USER, "h1")).toBe(false);
        expect(await store.getRecoveryHashes(USER)).toStrictEqual(["h1"]);
      });

      it("burns a consumed hash and refuses it afterwards", async () => {
        await store.setRecoveryHashes(USER, ["h1", "h2"]);
        expect(await store.consumeRecoveryHash(USER, "h1")).toBe(true);
        expect(await store.consumeRecoveryHash(USER, "h1")).toBe(false);
        expect(await store.getRecoveryHashes(USER)).toStrictEqual(["h2"]);
      });

      it("refuses a hash that was never stored", async () => {
        await store.setRecoveryHashes(USER, ["h1"]);
        expect(await store.consumeRecoveryHash(USER, "nope")).toBe(false);
        expect(await store.getRecoveryHashes(USER)).toStrictEqual(["h1"]);
      });

      it(`burns a code for exactly one of ${CONCURRENT_CALLERS} concurrent redemptions`, async () => {
        await store.setRecoveryHashes(USER, ["h1", "h2"]);
        const results = await race(() => store.consumeRecoveryHash(USER, "h1"));
        expect(
          countTrue(results),
          "a recovery code is single-use — requests racing one code must " +
            "not each be told they redeemed it",
        ).toBe(1);
        expect(await store.getRecoveryHashes(USER)).toStrictEqual(["h2"]);
      });

      it("burns both codes when two different ones are redeemed concurrently", async () => {
        await store.setRecoveryHashes(USER, ["h1", "h2", "h3"]);
        const results = await Promise.all([
          store.consumeRecoveryHash(USER, "h1"),
          store.consumeRecoveryHash(USER, "h2"),
        ]);
        expect(countTrue(results)).toBe(2);
        expect(
          await store.getRecoveryHashes(USER),
          "neither deletion may be lost to the other's stale read",
        ).toStrictEqual(["h3"]);
      });
    });
  });
}
