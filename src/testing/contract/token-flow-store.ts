import { assert, beforeEach, describe, expect, it } from "vitest";
import type {
  TokenFlowRecord,
  TokenFlowStore,
} from "../../identity/token-flow.ts";
import { CONCURRENT_CALLERS, race } from "./_race.ts";

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
 * The concurrency cases redeem one token from eight callers at once. A store
 * that reads, awaits, then writes hands the token to more than one of them and
 * fails in practice — a race is probabilistic, so a lucky interleaving can
 * still pass a single run.
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
        expect(await store.get("no-such-hash")).toBe(null);
      });

      it("round-trips every field of a saved record", async () => {
        const saved = record({
          tokenHash: "hash-1",
          data: { email: "user@example.com" },
        });
        await store.save(saved);
        const fetched = await store.get("hash-1");
        assert(fetched !== null, "a saved record must be readable back");
        expect(fetched.purpose).toStrictEqual(saved.purpose);
        expect(fetched.subject).toStrictEqual(saved.subject);
        expect(fetched.data).toStrictEqual(saved.data);
        expect(fetched.expiresAt).toBe(saved.expiresAt);
        expect(fetched.createdAt).toBe(saved.createdAt);
        expect(fetched.consumedAt).toBe(undefined);
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
        expect((await store.get("hash-1"))?.tokenHash).toBe("hash-1");
        expect((await store.get("hash-2"))?.tokenHash).toBe("hash-2");
      });
    });

    describe("markConsumed", () => {
      it("claims a live record and stamps it", async () => {
        await store.save(record({ tokenHash: "hash-1" }));
        const consumedAt = Date.now();
        expect(await store.markConsumed("hash-1", consumedAt)).toBe(true);
        expect((await store.get("hash-1"))?.consumedAt).toBe(consumedAt);
      });

      it("refuses a record already consumed, keeping the first stamp", async () => {
        await store.save(record({ tokenHash: "hash-1" }));
        const first = Date.now();
        await store.markConsumed("hash-1", first);
        expect(await store.markConsumed("hash-1", first + 5_000)).toBe(false);
        expect(
          (await store.get("hash-1"))?.consumedAt,
          "a losing claim must not overwrite the winner's record",
        ).toBe(first);
      });

      it("refuses an unknown token hash", async () => {
        expect(await store.markConsumed("no-such-hash", Date.now())).toBe(
          false,
        );
      });

      it(`claims a token for exactly one of ${CONCURRENT_CALLERS} concurrent redemptions`, async () => {
        await store.save(record({ tokenHash: "hash-1" }));
        const now = Date.now();
        const results = await race((caller) =>
          store.markConsumed("hash-1", now + caller),
        );
        expect(
          countTrue(results),
          "a link is single-use — requests racing one link must not each be " +
            "told they claimed it",
        ).toBe(1);
      });

      it("claims both tokens when two different ones are redeemed concurrently", async () => {
        await store.save(record({ tokenHash: "hash-1" }));
        await store.save(record({ tokenHash: "hash-2" }));
        const now = Date.now();
        const results = await Promise.all([
          store.markConsumed("hash-1", now),
          store.markConsumed("hash-2", now),
        ]);
        expect(countTrue(results)).toBe(2);
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
          expect(await store.get("hash-1")).toBe(null);
          expect(await store.get("hash-2")).toBe(null);
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
          expect(await store.get("hash-mine")).toBe(null);
          assert(
            (await store.get("hash-other-subject")) !== null,
            "another subject's token must survive",
          );
          assert(
            (await store.get("hash-other-purpose")) !== null,
            "the same subject's token for another purpose must survive",
          );
        });

        it("is a no-op when the pair has no tokens", async () => {
          await store.save(record({ tokenHash: "hash-1" }));
          await store.deleteBySubject!(PURPOSE, OTHER_SUBJECT);
          assert((await store.get("hash-1")) !== null);
        });

        it("keeps an already-consumed record so it still reads as consumed", async () => {
          await store.save(record({ tokenHash: "hash-used" }));
          await store.save(record({ tokenHash: "hash-pending" }));
          expect(await store.markConsumed("hash-used", Date.now())).toBe(true);

          await store.deleteBySubject!(PURPOSE, SUBJECT);

          expect(
            await store.get("hash-pending"),
            "the pending token must be dropped",
          ).toBe(null);
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
      it.skip("deleteBySubject is not implemented — outstanding links stay redeemable until they expire (deleteBySubject: false)", () => {});
    }
  });
}
