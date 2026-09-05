/**
 * Contract test suite for {@link TokenFlowStore} implementations — the storage
 * behind verification links, password-reset links, and magic links.
 *
 * The load-bearing method is `markConsumed`: it is what makes a link
 * single-use, and only a conditional write survives two requests redeeming one
 * link at the same time. This suite issues those two requests.
 *
 * @example Verify a database-backed store
 * ```ts
 * import { runTokenFlowStoreContractTests } from "@udibo/oauth2/testing/contract";
 * import type { TokenFlowStore } from "@udibo/oauth2/identity";
 *
 * declare function freshTokenFlowStore(): Promise<TokenFlowStore>;
 *
 * runTokenFlowStoreContractTests({
 *   describeName: "DrizzleTokenFlowStore satisfies TokenFlowStore contract",
 *   makeStore: freshTokenFlowStore,
 * });
 * ```
 *
 * @module
 */

import { assert, assertEquals, assertStrictEquals } from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";

import type {
  TokenFlowRecord,
  TokenFlowStore,
} from "../../identity/token-flow.ts";

/** Options for {@link runTokenFlowStoreContractTests}. */
export interface TokenFlowStoreContractOptions {
  /**
   * Returns a fresh, empty store for each test. Isolation is required — a
   * record surviving into the next test makes the single-use checks
   * meaningless.
   */
  makeStore(): Promise<TokenFlowStore> | TokenFlowStore;
  /**
   * Set to `false` when the store deliberately omits the optional
   * {@link TokenFlowStore.deleteBySubject}. The suite then registers an ignored
   * case naming what is not covered — outstanding links stay redeemable until
   * they expire — instead of passing in silence. Defaults to `true`, so a store
   * that meant to implement it and does not fails loudly.
   */
  deleteBySubject?: boolean;
  /**
   * Overrides the name passed to the outer `describe` block. Defaults to
   * `"TokenFlowStore contract"`.
   */
  describeName?: string;
}

const PURPOSE = "password-reset";
const OTHER_PURPOSE = "email-verification";
const SUBJECT = "user-1";
const OTHER_SUBJECT = "user-2";

function countTrue(results: boolean[]): number {
  return results.filter((result) => result).length;
}

function record(
  overrides: Partial<TokenFlowRecord> & { tokenHash: string },
): TokenFlowRecord {
  const now = Date.now();
  return {
    purpose: PURPOSE,
    subject: SUBJECT,
    expiresAt: now + 60_000,
    createdAt: now,
    ...overrides,
  };
}

/**
 * Runs the {@link TokenFlowStore} contract suite. Call it from your own test
 * file — it registers `describe` / `it` blocks the test runner picks up.
 *
 * The concurrency cases redeem one token from two callers at once; a store that
 * reads, awaits, then writes hands the token to both and fails them.
 */
export function runTokenFlowStoreContractTests(
  options: TokenFlowStoreContractOptions,
): void {
  const expectDeleteBySubject = options.deleteBySubject ?? true;

  describe(options.describeName ?? "TokenFlowStore contract", () => {
    let store: TokenFlowStore;

    beforeEach(async () => {
      store = await options.makeStore();
    });

    describe("save / get", () => {
      it("returns null for an unknown token hash", async () => {
        assertStrictEquals(await store.get("no-such-hash"), null);
      });

      it("round-trips every field of a saved record", async () => {
        const saved = record({
          tokenHash: "hash-1",
          data: { email: "user@example.com" },
        });
        await store.save(saved);
        const fetched = await store.get("hash-1");
        assert(fetched !== null, "a saved record must be readable back");
        assertEquals(fetched.purpose, saved.purpose);
        assertEquals(fetched.subject, saved.subject);
        assertEquals(fetched.data, saved.data);
        assertStrictEquals(fetched.expiresAt, saved.expiresAt);
        assertStrictEquals(fetched.createdAt, saved.createdAt);
        assertStrictEquals(fetched.consumedAt, undefined);
      });

      it("returns an expired record rather than hiding it", async () => {
        await store.save(
          record({ tokenHash: "hash-expired", expiresAt: Date.now() - 1000 }),
        );
        const fetched = await store.get("hash-expired");
        assert(
          fetched !== null,
          "expiry is the service's call — it reports `expired` distinctly " +
            "from `invalid`, which it cannot do if the store swallows the row",
        );
      });

      it("keeps records with different hashes independent", async () => {
        await store.save(record({ tokenHash: "hash-1" }));
        await store.save(record({ tokenHash: "hash-2" }));
        assertStrictEquals((await store.get("hash-1"))?.tokenHash, "hash-1");
        assertStrictEquals((await store.get("hash-2"))?.tokenHash, "hash-2");
      });
    });

    describe("markConsumed", () => {
      it("claims a live record and stamps it", async () => {
        await store.save(record({ tokenHash: "hash-1" }));
        const consumedAt = Date.now();
        assertStrictEquals(
          await store.markConsumed("hash-1", consumedAt),
          true,
        );
        assertStrictEquals((await store.get("hash-1"))?.consumedAt, consumedAt);
      });

      it("refuses a record already consumed, keeping the first stamp", async () => {
        await store.save(record({ tokenHash: "hash-1" }));
        const first = Date.now();
        await store.markConsumed("hash-1", first);
        assertStrictEquals(
          await store.markConsumed("hash-1", first + 5_000),
          false,
        );
        assertStrictEquals(
          (await store.get("hash-1"))?.consumedAt,
          first,
          "a losing claim must not overwrite the winner's record",
        );
      });

      it("refuses an unknown token hash", async () => {
        assertStrictEquals(
          await store.markConsumed("no-such-hash", Date.now()),
          false,
        );
      });

      it("claims a token for exactly one of two concurrent redemptions", async () => {
        await store.save(record({ tokenHash: "hash-1" }));
        const now = Date.now();
        const results = await Promise.all([
          store.markConsumed("hash-1", now),
          store.markConsumed("hash-1", now + 1),
        ]);
        assertStrictEquals(
          countTrue(results),
          1,
          "a link is single-use — two requests racing one link must not both " +
            "be told they claimed it",
        );
      });

      it("claims both tokens when two different ones are redeemed concurrently", async () => {
        await store.save(record({ tokenHash: "hash-1" }));
        await store.save(record({ tokenHash: "hash-2" }));
        const now = Date.now();
        const results = await Promise.all([
          store.markConsumed("hash-1", now),
          store.markConsumed("hash-2", now),
        ]);
        assertStrictEquals(countTrue(results), 2);
        assert(
          (await store.get("hash-1"))?.consumedAt !== undefined &&
            (await store.get("hash-2"))?.consumedAt !== undefined,
          "neither stamp may be lost to the other's stale read",
        );
      });
    });

    if (expectDeleteBySubject) {
      describe("deleteBySubject", () => {
        it("is implemented", () => {
          assert(
            typeof store.deleteBySubject === "function",
            "deleteBySubject is optional, but without it " +
              "`TokenFlowService.invalidate` returns false and outstanding " +
              "links stay redeemable until they expire. Implement it, or pass " +
              "`deleteBySubject: false` to record the gap.",
          );
        });

        it("drops the pending tokens for one (purpose, subject)", async () => {
          await store.save(record({ tokenHash: "hash-1" }));
          await store.save(record({ tokenHash: "hash-2" }));
          await store.deleteBySubject!(PURPOSE, SUBJECT);
          assertStrictEquals(await store.get("hash-1"), null);
          assertStrictEquals(await store.get("hash-2"), null);
        });

        it("leaves other subjects and other purposes alone", async () => {
          await store.save(record({ tokenHash: "hash-mine" }));
          await store.save(
            record({ tokenHash: "hash-other-subject", subject: OTHER_SUBJECT }),
          );
          await store.save(
            record({ tokenHash: "hash-other-purpose", purpose: OTHER_PURPOSE }),
          );
          await store.deleteBySubject!(PURPOSE, SUBJECT);
          assertStrictEquals(await store.get("hash-mine"), null);
          assert(
            await store.get("hash-other-subject") !== null,
            "another subject's token must survive",
          );
          assert(
            await store.get("hash-other-purpose") !== null,
            "the same subject's token for another purpose must survive",
          );
        });

        it("is a no-op when the pair has no tokens", async () => {
          await store.save(record({ tokenHash: "hash-1" }));
          await store.deleteBySubject!(PURPOSE, OTHER_SUBJECT);
          assert(await store.get("hash-1") !== null);
        });

        it("keeps an already-consumed record so it still reads as consumed", async () => {
          await store.save(record({ tokenHash: "hash-used" }));
          await store.save(record({ tokenHash: "hash-pending" }));
          assertStrictEquals(
            await store.markConsumed("hash-used", Date.now()),
            true,
          );

          await store.deleteBySubject!(PURPOSE, SUBJECT);

          assertStrictEquals(
            await store.get("hash-pending"),
            null,
            "the pending token must be dropped",
          );
          const used = await store.get("hash-used");
          assert(
            used !== null,
            "a consumed record must survive so inspect() can answer " +
              "`consumed` rather than the generic `invalid`",
          );
          assert(
            used.consumedAt !== undefined,
            "the surviving record must still carry its consumedAt stamp",
          );
        });
      });
    } else {
      it({
        name:
          "deleteBySubject is not implemented — outstanding links stay redeemable until they expire (deleteBySubject: false)",
        ignore: true,
        fn: () => {},
      });
    }
  });
}
