/**
 * Contract test suite for {@link OtpStore} implementations — the storage behind
 * emailed one-time codes.
 *
 * A six-digit code is guessable online, so the attempt budget is the only thing
 * standing between an attacker and a one-in-a-million draw. `recordAttempt` is
 * what enforces it, and it only enforces it when concurrent guesses cannot
 * share a count — which is what this suite checks. It also checks that a
 * successful `consume` retires the pair's older codes, so a sign-in with the
 * newest code leaves no earlier one redeemable.
 *
 * @example Verify a database-backed store
 * ```ts
 * import { runOtpStoreContractTests } from "@udibo/oauth2/testing/contract";
 * import type { OtpStore } from "@udibo/oauth2/identity";
 *
 * declare function freshOtpStore(): Promise<OtpStore>;
 *
 * runOtpStoreContractTests({
 *   describeName: "DrizzleOtpStore satisfies OtpStore contract",
 *   makeStore: freshOtpStore,
 * });
 * ```
 *
 * @module
 */

import { assert, beforeEach, describe, expect, it } from "vitest";
import {
  EmailOtpService,
  type OtpRecord,
  type OtpStore,
} from "../../identity/otp.ts";
import { CONCURRENT_CALLERS, race } from "./_race.ts";

/** Options for {@link runOtpStoreContractTests}. */
export interface OtpStoreContractOptions {
  /**
   * Returns a fresh, empty store for each test. Isolation is required — an
   * active code left behind by one test makes the `findActive` checks
   * meaningless.
   */
  makeStore(): Promise<OtpStore> | OtpStore;
  /**
   * Set to `true` for a store that keeps at most one active code per
   * `(email, purpose)`, where `create` replaces the pair's code — for example
   * an upsert on a unique `(email, purpose)` index. Such a store conforms: the
   * suite then requires `create` to replace the code, so the replaced code's
   * id no longer consumes, and drops the cases that need two codes active at
   * once. The trade-off is availability: when overlapping requests each send a
   * code and the later send fails, discarding the later code leaves no code
   * the user can enter, where a store keeping several codes leaves the one
   * already delivered. Defaults to `false`; a store that keeps several codes
   * and sets it fails the replacement case.
   */
  oneActiveCode?: boolean;
  /**
   * Overrides the name passed to the outer `describe` block. Defaults to
   * `"OtpStore contract"`.
   */
  describeName?: string;
}

const EMAIL = "user@example.com";
const OTHER_EMAIL = "other@example.com";
const PURPOSE = "signin";
const OTHER_PURPOSE = "step-up";

function record(overrides: Partial<OtpRecord> = {}): OtpRecord {
  const now = Date.now();
  return {
    id: crypto.randomUUID(),
    email: EMAIL,
    purpose: PURPOSE,
    codeHash: "hash",
    expiresAt: now + 600_000,
    attempts: 0,
    maxAttempts: 5,
    createdAt: now,
    ...overrides,
  };
}

/**
 * Runs the {@link OtpStore} contract suite. Call it from your own test file —
 * it registers `describe` / `it` blocks the test runner picks up.
 *
 * Record ids, known and unknown alike, are UUIDs — the ids `EmailOtpService`
 * issues — so a store with a `uuid` id column accepts every one.
 *
 * The concurrency case fires overlapping `recordAttempt` calls and requires
 * each to see a distinct count; a store that reads, awaits, then writes hands
 * the same count to every guess and fails it. The `consume` cases require a
 * successful claim to retire every older active code for the pair, and to
 * leave newer codes, other pairs and — when the claim fails — everything else
 * active. Register a store that keeps one code per pair with
 * `oneActiveCode: true`.
 */
export function runOtpStoreContractTests(
  options: OtpStoreContractOptions,
): void {
  const oneActiveCode = options.oneActiveCode ?? false;
  const manyActiveCodes = !oneActiveCode;

  describe(options.describeName ?? "OtpStore contract", () => {
    let store: OtpStore;

    beforeEach(async () => {
      store = await options.makeStore();
    });

    describe("create / findActive", () => {
      it("returns null when the pair has no code", async () => {
        expect(await store.findActive(EMAIL, PURPOSE)).toBe(null);
      });

      it("round-trips every field of a created record", async () => {
        const created = record({ codeHash: "hash-1", maxAttempts: 3 });
        await store.create(created);
        const found = await store.findActive(EMAIL, PURPOSE);
        assert(found !== null, "a created record must be findable");
        expect(found.id).toBe(created.id);
        expect(found.email).toBe(created.email);
        expect(found.purpose).toBe(created.purpose);
        expect(found.codeHash).toBe(created.codeHash);
        expect(found.expiresAt).toBe(created.expiresAt);
        expect(found.attempts).toBe(0);
        expect(found.maxAttempts).toBe(3);
      });

      it("returns the most recently created active record", async () => {
        const now = Date.now();
        const older = record({ createdAt: now - 1000, codeHash: "old" });
        const newer = record({ createdAt: now, codeHash: "new" });
        await store.create(older);
        await store.create(newer);
        expect(
          (await store.findActive(EMAIL, PURPOSE))?.id,
          "a re-send supersedes the code before it",
        ).toBe(newer.id);
      });

      if (oneActiveCode) {
        it("replaces the pair's active code (oneActiveCode)", async () => {
          const now = Date.now();
          const older = record({ createdAt: now - 1000, codeHash: "old" });
          const newer = record({ createdAt: now, codeHash: "new" });
          await store.create(older);
          await store.create(newer);
          expect(
            await store.consume(older.id),
            "`oneActiveCode: true` declares that a new code replaces the " +
              "pair's code; this store kept the older one active",
          ).toBe(false);
          expect((await store.findActive(EMAIL, PURPOSE))?.id).toBe(newer.id);
        });
        it.skip("a store keeping one code per pair returns the code created last, whatever its createdAt — there is no other code to order it against (oneActiveCode: true)", () => {});
      } else {
        it("returns the greatest createdAt, not the last inserted", async () => {
          const now = Date.now();
          const higher = record({ createdAt: now });
          const lower = record({ createdAt: now - 1000 });
          await store.create(higher);
          await store.create(lower);
          expect(
            (await store.findActive(EMAIL, PURPOSE))?.id,
            "verify consumes the record findActive returns and consume " +
              "retires records created no later than it; ordering by " +
              "insertion under clock drift leaves the other code redeemable",
          ).toBe(higher.id);
        });
      }

      it("returns an expired record rather than hiding it", async () => {
        await store.create(record({ expiresAt: Date.now() - 1000 }));
        assert(
          (await store.findActive(EMAIL, PURPOSE)) !== null,
          "expiry is the service's call — it reports `expired` distinctly " +
            "from `invalid`, which it cannot do if the store swallows the row",
        );
      });

      it("scopes lookups by email and by purpose", async () => {
        await store.create(record());
        expect(await store.findActive(OTHER_EMAIL, PURPOSE)).toBe(null);
        expect(await store.findActive(EMAIL, OTHER_PURPOSE)).toBe(null);
      });
    });

    describe("consume", () => {
      it(`claims an active code for exactly one of ${CONCURRENT_CALLERS} concurrent consumers`, async () => {
        const created = record();
        await store.create(created);
        const results = await race(() => store.consume(created.id));
        expect(
          results.filter((claimed) => claimed).length,
          "a code is single-use — consumers racing one code must not each " +
            "be told they claimed it",
        ).toBe(1);
        expect(await store.consume(crypto.randomUUID())).toBe(false);
      });
      it("takes the record out of the active set", async () => {
        const created = record();
        await store.create(created);
        await store.consume(created.id);
        expect(await store.findActive(EMAIL, PURPOSE)).toBe(null);
      });

      it("retires every older active code for the pair", async () => {
        const now = Date.now();
        const oldest = record({ createdAt: now - 2000 });
        const older = record({ createdAt: now - 1000 });
        const newest = record({ createdAt: now });
        await store.create(oldest);
        await store.create(older);
        await store.create(newest);
        expect(await store.consume(newest.id)).toBe(true);
        expect(
          await store.findActive(EMAIL, PURPOSE),
          "a sign-in with the newest code must end the older codes' window; " +
            "otherwise each stays redeemable until it expires",
        ).toBe(null);
        expect(await store.consume(older.id)).toBe(false);
        expect(await store.consume(oldest.id)).toBe(false);
      });

      if (manyActiveCodes) {
        it("leaves a code newer than the claimed one active", async () => {
          const now = Date.now();
          const claimed = record({ createdAt: now - 1000 });
          const newer = record({ createdAt: now });
          await store.create(claimed);
          await store.create(newer);
          expect(await store.consume(claimed.id)).toBe(true);
          expect(
            (await store.findActive(EMAIL, PURPOSE))?.id,
            "a code a concurrent request minted after the claimed one " +
              "is not older than it and must survive",
          ).toBe(newer.id);
        });

        it("retires nothing when the claim fails", async () => {
          const now = Date.now();
          const older = record({ createdAt: now - 1000 });
          const discarded = record({ createdAt: now });
          await store.create(older);
          await store.create(discarded);
          await store.invalidateById(discarded.id);
          expect(await store.consume(discarded.id)).toBe(false);
          expect(
            (await store.findActive(EMAIL, PURPOSE))?.id,
            "only a successful claim retires older codes; a stale or " +
              "repeated consume must leave the delivered code usable",
          ).toBe(older.id);
        });
      } else {
        it.skip("a store keeping one code per pair has no newer or older code beside the claimed one — a re-send replaces the code a sign-in is verifying, so that sign-in reports invalid and the user enters the new code (oneActiveCode: true)", () => {});
      }

      it("leaves other emails and other purposes active", async () => {
        const claimed = record();
        const otherEmail = record({ email: OTHER_EMAIL });
        const otherPurpose = record({ purpose: OTHER_PURPOSE });
        await store.create(claimed);
        await store.create(otherEmail);
        await store.create(otherPurpose);
        expect(await store.consume(claimed.id)).toBe(true);
        expect((await store.findActive(OTHER_EMAIL, PURPOSE))?.id).toBe(
          otherEmail.id,
        );
        expect((await store.findActive(EMAIL, OTHER_PURPOSE))?.id).toBe(
          otherPurpose.id,
        );
      });

      it("is a no-op for an unknown id", async () => {
        const created = record();
        await store.create(created);
        await store.consume(crypto.randomUUID());
        expect((await store.findActive(EMAIL, PURPOSE))?.id).toBe(created.id);
      });
    });

    describe("invalidateById", () => {
      if (manyActiveCodes) {
        it("deactivates only the named record", async () => {
          const now = Date.now();
          const undelivered = record({ createdAt: now });
          const previous = record({ createdAt: now - 1000 });
          await store.create(previous);
          await store.create(undelivered);
          await store.invalidateById(undelivered.id);
          expect(
            (await store.findActive(EMAIL, PURPOSE))?.id,
            "discarding an undeliverable code must not take a concurrent " +
              "request's code with it",
          ).toBe(previous.id);
        });
      } else {
        it.skip("a store keeping one code per pair has no older code to keep — when overlapping requests each send a code and the later send fails, discarding it leaves no code the user can enter (oneActiveCode: true)", () => {});
      }

      it("leaves a newer code active", async () => {
        const now = Date.now();
        const older = record({ createdAt: now - 1000 });
        const newer = record({ createdAt: now });
        await store.create(older);
        await store.create(newer);
        await store.invalidateById(older.id);
        expect(
          (await store.findActive(EMAIL, PURPOSE))?.id,
          "a slow failed send discards its own code, never the code a " +
            "retry has since delivered",
        ).toBe(newer.id);
      });

      it("is a no-op for an unknown id", async () => {
        const created = record();
        await store.create(created);
        await store.invalidateById(crypto.randomUUID());
        expect((await store.findActive(EMAIL, PURPOSE))?.id).toBe(created.id);
      });
    });

    describe("invalidate", () => {
      it("deactivates every active code for the pair", async () => {
        await store.create(record({ createdAt: Date.now() - 1000 }));
        await store.create(record());
        await store.invalidate(EMAIL, PURPOSE);
        expect(await store.findActive(EMAIL, PURPOSE)).toBe(null);
      });

      it("leaves other emails and other purposes alone", async () => {
        await store.create(record());
        await store.create(record({ email: OTHER_EMAIL }));
        await store.create(record({ purpose: OTHER_PURPOSE }));
        await store.invalidate(EMAIL, PURPOSE);
        assert((await store.findActive(OTHER_EMAIL, PURPOSE)) !== null);
        assert((await store.findActive(EMAIL, OTHER_PURPOSE)) !== null);
      });

      it("is a no-op when the pair has no active code", async () => {
        await store.invalidate(EMAIL, PURPOSE);
        expect(await store.findActive(EMAIL, PURPOSE)).toBe(null);
      });
    });

    describe("recordAttempt", () => {
      it("returns the count after the increment", async () => {
        const created = record();
        await store.create(created);
        expect(await store.recordAttempt(created.id)).toBe(1);
        expect(await store.recordAttempt(created.id)).toBe(2);
        expect(await store.recordAttempt(created.id)).toBe(3);
      });

      it("returns 0 for an unknown id", async () => {
        expect(await store.recordAttempt(crypto.randomUUID())).toBe(0);
      });

      it("counts each record separately", async () => {
        const mine = record();
        const theirs = record({ email: OTHER_EMAIL });
        await store.create(mine);
        await store.create(theirs);
        await store.recordAttempt(mine.id);
        await store.recordAttempt(mine.id);
        expect(await store.recordAttempt(theirs.id)).toBe(1);
      });

      it("gives every concurrent guess its own count", async () => {
        const created = record({ maxAttempts: 5 });
        await store.create(created);
        const counts = await Promise.all(
          Array.from({ length: 5 }, () => store.recordAttempt(created.id)),
        );
        expect(
          [...counts].sort((a, b) => a - b),
          "the guess budget is spent by the returned count — concurrent " +
            "guesses sharing one count spend the budget once and let the " +
            "rest through",
        ).toStrictEqual([1, 2, 3, 4, 5]);
      });
    });

    describe("EmailOtpService over the store", () => {
      it("leaves no older code redeemable after a successful verify", async () => {
        const overlapping = new EmailOtpService({
          store: {
            create: (created) => store.create(created),
            findActive: (email, purpose) => store.findActive(email, purpose),
            recordAttempt: (id) => store.recordAttempt(id),
            consume: (id) => store.consume(id),
            invalidateById: (id) => store.invalidateById(id),
            invalidate: () => Promise.resolve(),
          },
        });
        const codes = new Map<string, string>();
        for (let i = 0; i < 2; i++) {
          await overlapping.request({
            email: EMAIL,
            purpose: PURPOSE,
            onDeliver: (code, _expiresAt, codeId) => {
              codes.set(codeId, code);
            },
          });
        }
        const newest = await store.findActive(EMAIL, PURPOSE);
        assert(newest !== null, "a requested code must be findable");
        const newestCode = codes.get(newest.id);
        const olderCode = [...codes].find(([id]) => id !== newest.id)?.[1];
        assert(newestCode !== undefined && olderCode !== undefined);
        const service = new EmailOtpService({ store });

        expect(
          await service.verify({
            email: EMAIL,
            purpose: PURPOSE,
            code: newestCode,
          }),
        ).toStrictEqual({ status: "success" });
        expect(
          await service.verify({
            email: EMAIL,
            purpose: PURPOSE,
            code: olderCode,
          }),
          "two overlapping requests left two codes; signing in with the " +
            "newest must not leave the older one redeemable",
        ).toStrictEqual({ status: "invalid" });
      });
    });
  });
}
