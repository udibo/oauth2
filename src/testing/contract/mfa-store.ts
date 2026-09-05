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

import { assertEquals, assertStrictEquals } from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";

import type { MfaStore } from "../../identity/mfa/service.ts";

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
 * The atomicity cases issue two or more overlapping calls and assert the
 * outcome a conditional write produces. An implementation that reads, then
 * awaits, then writes fails them, which is the point: the same store passes
 * every sequential check.
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
        assertStrictEquals(await store.getTotp(USER), undefined);
      });

      it("stores a pending secret without activating it", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        const record = await store.getTotp(USER);
        assertEquals(record?.pendingSecretBase32, SECRET_A);
        assertStrictEquals(record?.secretBase32, undefined);
      });

      it("replaces a previous pending secret", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        await store.setPendingTotp(USER, SECRET_B);
        const record = await store.getTotp(USER);
        assertEquals(record?.pendingSecretBase32, SECRET_B);
      });

      it("keeps an active credential when a new enrollment starts", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        await store.activateTotp(USER, SECRET_A, 100);
        await store.setPendingTotp(USER, SECRET_B);
        const record = await store.getTotp(USER);
        assertEquals(record?.secretBase32, SECRET_A);
        assertEquals(record?.lastStep, 100);
        assertEquals(record?.pendingSecretBase32, SECRET_B);
      });

      it("keeps each user's record separate", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        assertStrictEquals(await store.getTotp(OTHER_USER), undefined);
      });
    });

    describe("activateTotp", () => {
      it("promotes the matching pending secret and clears it", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        assertStrictEquals(await store.activateTotp(USER, SECRET_A, 42), true);
        const record = await store.getTotp(USER);
        assertEquals(record?.secretBase32, SECRET_A);
        assertEquals(record?.lastStep, 42);
        assertStrictEquals(record?.pendingSecretBase32, undefined);
      });

      it("refuses when the user has no pending secret", async () => {
        assertStrictEquals(await store.activateTotp(USER, SECRET_A, 42), false);
        assertStrictEquals(await store.getTotp(USER), undefined);
      });

      it("refuses a secret a newer enrollment replaced, changing nothing", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        await store.setPendingTotp(USER, SECRET_B);
        assertStrictEquals(await store.activateTotp(USER, SECRET_A, 42), false);
        const record = await store.getTotp(USER);
        assertStrictEquals(record?.secretBase32, undefined);
        assertEquals(record?.pendingSecretBase32, SECRET_B);
      });

      it("activates for exactly one of two concurrent confirmations", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        const results = await Promise.all([
          store.activateTotp(USER, SECRET_A, 10),
          store.activateTotp(USER, SECRET_A, 20),
        ]);
        assertStrictEquals(
          countTrue(results),
          1,
          "the pending secret must be claimable once — a second concurrent " +
            "confirmation finds it already spent",
        );
        const record = await store.getTotp(USER);
        assertEquals(record?.secretBase32, SECRET_A);
        assertStrictEquals(record?.pendingSecretBase32, undefined);
      });

      it("activates for exactly one of two concurrent enrollments", async () => {
        await store.setPendingTotp(USER, SECRET_B);
        const results = await Promise.all([
          store.activateTotp(USER, SECRET_A, 10),
          store.activateTotp(USER, SECRET_B, 20),
        ]);
        assertStrictEquals(countTrue(results), 1);
        const record = await store.getTotp(USER);
        assertEquals(
          record?.secretBase32,
          SECRET_B,
          "only the secret that was actually pending may become active",
        );
      });
    });

    describe("clearTotp", () => {
      it("removes the active credential and any pending secret", async () => {
        await store.setPendingTotp(USER, SECRET_A);
        await store.activateTotp(USER, SECRET_A, 5);
        await store.setPendingTotp(USER, SECRET_B);
        await store.clearTotp(USER);
        assertStrictEquals(await store.getTotp(USER), undefined);
      });

      it("is a no-op for a user with no record", async () => {
        await store.clearTotp(USER);
        assertStrictEquals(await store.getTotp(USER), undefined);
      });
    });

    describe("advanceLastStep", () => {
      beforeEach(async () => {
        await store.setPendingTotp(USER, SECRET_A);
        await store.activateTotp(USER, SECRET_A, 100);
      });

      it("advances to a higher step", async () => {
        assertStrictEquals(await store.advanceLastStep(USER, 101), true);
        assertEquals((await store.getTotp(USER))?.lastStep, 101);
      });

      it("refuses the step already spent", async () => {
        assertStrictEquals(await store.advanceLastStep(USER, 100), false);
        assertEquals((await store.getTotp(USER))?.lastStep, 100);
      });

      it("refuses an earlier step, leaving the guard where it was", async () => {
        assertStrictEquals(await store.advanceLastStep(USER, 99), false);
        assertEquals((await store.getTotp(USER))?.lastStep, 100);
      });

      it("refuses for a user with no record", async () => {
        assertStrictEquals(await store.advanceLastStep(OTHER_USER, 1), false);
      });

      it("admits exactly one of two concurrent claims on the same step", async () => {
        const results = await Promise.all([
          store.advanceLastStep(USER, 101),
          store.advanceLastStep(USER, 101),
        ]);
        assertStrictEquals(
          countTrue(results),
          1,
          "a time step is spendable once — the loser must read as a replay",
        );
        assertEquals((await store.getTotp(USER))?.lastStep, 101);
      });

      it("never regresses under concurrent claims on different steps", async () => {
        await Promise.all([
          store.advanceLastStep(USER, 105),
          store.advanceLastStep(USER, 101),
        ]);
        assertEquals(
          (await store.getTotp(USER))?.lastStep,
          105,
          "the highest accepted step must survive a concurrent lower one",
        );
      });
    });

    describe("recovery hashes", () => {
      it("returns an empty list for a user with none", async () => {
        assertEquals(await store.getRecoveryHashes(USER), []);
      });

      it("replaces the stored set exactly", async () => {
        await store.setRecoveryHashes(USER, ["h1", "h2", "h3"]);
        assertEquals(
          [...await store.getRecoveryHashes(USER)].sort(),
          ["h1", "h2", "h3"],
        );
        await store.setRecoveryHashes(USER, ["h4"]);
        assertEquals(await store.getRecoveryHashes(USER), ["h4"]);
      });

      it("clears the set when given an empty list", async () => {
        await store.setRecoveryHashes(USER, ["h1"]);
        await store.setRecoveryHashes(USER, []);
        assertEquals(await store.getRecoveryHashes(USER), []);
      });

      it("keeps each user's codes separate", async () => {
        await store.setRecoveryHashes(USER, ["h1"]);
        assertEquals(await store.getRecoveryHashes(OTHER_USER), []);
        assertStrictEquals(
          await store.consumeRecoveryHash(OTHER_USER, "h1"),
          false,
        );
        assertEquals(await store.getRecoveryHashes(USER), ["h1"]);
      });

      it("burns a consumed hash and refuses it afterwards", async () => {
        await store.setRecoveryHashes(USER, ["h1", "h2"]);
        assertStrictEquals(await store.consumeRecoveryHash(USER, "h1"), true);
        assertStrictEquals(await store.consumeRecoveryHash(USER, "h1"), false);
        assertEquals(await store.getRecoveryHashes(USER), ["h2"]);
      });

      it("refuses a hash that was never stored", async () => {
        await store.setRecoveryHashes(USER, ["h1"]);
        assertStrictEquals(
          await store.consumeRecoveryHash(USER, "nope"),
          false,
        );
        assertEquals(await store.getRecoveryHashes(USER), ["h1"]);
      });

      it("burns a code for exactly one of two concurrent redemptions", async () => {
        await store.setRecoveryHashes(USER, ["h1", "h2"]);
        const results = await Promise.all([
          store.consumeRecoveryHash(USER, "h1"),
          store.consumeRecoveryHash(USER, "h1"),
        ]);
        assertStrictEquals(
          countTrue(results),
          1,
          "a recovery code is single-use — two requests racing one code must " +
            "not both be told they redeemed it",
        );
        assertEquals(await store.getRecoveryHashes(USER), ["h2"]);
      });

      it("burns both codes when two different ones are redeemed concurrently", async () => {
        await store.setRecoveryHashes(USER, ["h1", "h2", "h3"]);
        const results = await Promise.all([
          store.consumeRecoveryHash(USER, "h1"),
          store.consumeRecoveryHash(USER, "h2"),
        ]);
        assertStrictEquals(countTrue(results), 2);
        assertEquals(
          await store.getRecoveryHashes(USER),
          ["h3"],
          "neither deletion may be lost to the other's stale read",
        );
      });
    });
  });
}
