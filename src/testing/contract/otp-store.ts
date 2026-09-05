/**
 * Contract test suite for {@link OtpStore} implementations — the storage behind
 * emailed one-time codes.
 *
 * A six-digit code is guessable online, so the attempt budget is the only thing
 * standing between an attacker and a one-in-a-million draw. `recordAttempt` is
 * what enforces it, and it only enforces it when concurrent guesses cannot
 * share a count — which is what this suite checks.
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

import { assert, assertEquals, assertStrictEquals } from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";

import type { OtpRecord, OtpStore } from "../../identity/otp.ts";

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
        assertStrictEquals(await store.findActive(EMAIL, PURPOSE), null);
      });

      it("round-trips every field of a created record", async () => {
        const created = record({ codeHash: "hash-1", maxAttempts: 3 });
        await store.create(created);
        const found = await store.findActive(EMAIL, PURPOSE);
        assert(found !== null, "a created record must be findable");
        assertStrictEquals(found.id, created.id);
        assertStrictEquals(found.email, created.email);
        assertStrictEquals(found.purpose, created.purpose);
        assertStrictEquals(found.codeHash, created.codeHash);
        assertStrictEquals(found.expiresAt, created.expiresAt);
        assertStrictEquals(found.attempts, 0);
        assertStrictEquals(found.maxAttempts, 3);
      });

      it("returns the most recently created active record", async () => {
        const now = Date.now();
        const older = record({ createdAt: now - 1000, codeHash: "old" });
        const newer = record({ createdAt: now, codeHash: "new" });
        await store.create(older);
        await store.create(newer);
        assertStrictEquals(
          (await store.findActive(EMAIL, PURPOSE))?.id,
          newer.id,
          "a re-send supersedes the code before it",
        );
      });

      it("returns an expired record rather than hiding it", async () => {
        await store.create(record({ expiresAt: Date.now() - 1000 }));
        assert(
          await store.findActive(EMAIL, PURPOSE) !== null,
          "expiry is the service's call — it reports `expired` distinctly " +
            "from `invalid`, which it cannot do if the store swallows the row",
        );
      });

      it("scopes lookups by email and by purpose", async () => {
        await store.create(record());
        assertStrictEquals(await store.findActive(OTHER_EMAIL, PURPOSE), null);
        assertStrictEquals(await store.findActive(EMAIL, OTHER_PURPOSE), null);
      });
    });

    describe("consume", () => {
      it("claims an active code only once under concurrency", async () => {
        const created = record();
        await store.create(created);
        const results = await Promise.all([
          store.consume(created.id),
          store.consume(created.id),
        ]);
        assertEquals(results.sort(), [false, true]);
        assertStrictEquals(await store.consume("missing-code"), false);
      });
      it("takes the record out of the active set", async () => {
        const created = record();
        await store.create(created);
        await store.consume(created.id);
        assertStrictEquals(await store.findActive(EMAIL, PURPOSE), null);
      });

      it("leaves an older active code findable", async () => {
        const now = Date.now();
        const older = record({ createdAt: now - 1000 });
        const newer = record({ createdAt: now });
        await store.create(older);
        await store.create(newer);
        await store.consume(newer.id);
        assertStrictEquals(
          (await store.findActive(EMAIL, PURPOSE))?.id,
          older.id,
        );
      });

      it("is a no-op for an unknown id", async () => {
        const created = record();
        await store.create(created);
        await store.consume("no-such-id");
        assertStrictEquals(
          (await store.findActive(EMAIL, PURPOSE))?.id,
          created.id,
        );
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
        assertStrictEquals(
          (await store.findActive(EMAIL, PURPOSE))?.id,
          previous.id,
          "discarding an undeliverable code must not take a concurrent " +
            "request's code with it",
        );
      });

      it("is a no-op for an unknown id", async () => {
        const created = record();
        await store.create(created);
        await store.invalidateById("no-such-id");
        assertStrictEquals(
          (await store.findActive(EMAIL, PURPOSE))?.id,
          created.id,
        );
      });
    });

    describe("invalidate", () => {
      it("deactivates every active code for the pair", async () => {
        await store.create(record({ createdAt: Date.now() - 1000 }));
        await store.create(record());
        await store.invalidate(EMAIL, PURPOSE);
        assertStrictEquals(await store.findActive(EMAIL, PURPOSE), null);
      });

      it("leaves other emails and other purposes alone", async () => {
        await store.create(record());
        await store.create(record({ email: OTHER_EMAIL }));
        await store.create(record({ purpose: OTHER_PURPOSE }));
        await store.invalidate(EMAIL, PURPOSE);
        assert(await store.findActive(OTHER_EMAIL, PURPOSE) !== null);
        assert(await store.findActive(EMAIL, OTHER_PURPOSE) !== null);
      });

      it("is a no-op when the pair has no active code", async () => {
        await store.invalidate(EMAIL, PURPOSE);
        assertStrictEquals(await store.findActive(EMAIL, PURPOSE), null);
      });
    });

    describe("recordAttempt", () => {
      it("returns the count after the increment", async () => {
        const created = record();
        await store.create(created);
        assertStrictEquals(await store.recordAttempt(created.id), 1);
        assertStrictEquals(await store.recordAttempt(created.id), 2);
        assertStrictEquals(await store.recordAttempt(created.id), 3);
      });

      it("returns 0 for an unknown id", async () => {
        assertStrictEquals(await store.recordAttempt("no-such-id"), 0);
      });

      it("counts each record separately", async () => {
        const mine = record();
        const theirs = record({ email: OTHER_EMAIL });
        await store.create(mine);
        await store.create(theirs);
        await store.recordAttempt(mine.id);
        await store.recordAttempt(mine.id);
        assertStrictEquals(await store.recordAttempt(theirs.id), 1);
      });

      it("gives every concurrent guess its own count", async () => {
        const created = record({ maxAttempts: 5 });
        await store.create(created);
        const counts = await Promise.all(
          Array.from({ length: 5 }, () => store.recordAttempt(created.id)),
        );
        assertEquals(
          [...counts].sort((a, b) => a - b),
          [1, 2, 3, 4, 5],
          "the guess budget is spent by the returned count — concurrent " +
            "guesses sharing one count spend the budget once and let the " +
            "rest through",
        );
      });
    });
  });
}
