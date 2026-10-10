import { assert, beforeEach, describe, expect, it } from "vitest";
import type { OtpRecord, OtpStore } from "../../identity/otp.ts";
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
   * Overrides the name passed to the outer `describe` block. Defaults to
   * `"OtpStore contract"`.
   */
  describeName?: string;
}

const EMAIL = "user@example.com";
const OTHER_EMAIL = "other@example.com";
const PURPOSE = "signin";
const OTHER_PURPOSE = "step-up";

let sequence = 0;

function record(overrides: Partial<OtpRecord> = {}): OtpRecord {
  const now = Date.now();
  return {
    id: `otp-${++sequence}`,
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
 * The concurrency case fires overlapping `recordAttempt` calls and requires
 * each to see a distinct count; a store that reads, awaits, then writes hands
 * the same count to every guess and fails it.
 */
export function runOtpStoreContractTests(
  options: OtpStoreContractOptions,
): void {
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
        expect(await store.consume("missing-code")).toBe(false);
      });
      it("takes the record out of the active set", async () => {
        const created = record();
        await store.create(created);
        await store.consume(created.id);
        expect(await store.findActive(EMAIL, PURPOSE)).toBe(null);
      });

      it("leaves an older active code findable", async () => {
        const now = Date.now();
        const older = record({ createdAt: now - 1000 });
        const newer = record({ createdAt: now });
        await store.create(older);
        await store.create(newer);
        await store.consume(newer.id);
        expect((await store.findActive(EMAIL, PURPOSE))?.id).toBe(older.id);
      });

      it("is a no-op for an unknown id", async () => {
        const created = record();
        await store.create(created);
        await store.consume("no-such-id");
        expect((await store.findActive(EMAIL, PURPOSE))?.id).toBe(created.id);
      });
    });

    describe("invalidateById", () => {
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

      it("is a no-op for an unknown id", async () => {
        const created = record();
        await store.create(created);
        await store.invalidateById("no-such-id");
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
        expect(await store.recordAttempt("no-such-id")).toBe(0);
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
  });
}
