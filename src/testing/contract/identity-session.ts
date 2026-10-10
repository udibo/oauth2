/**
 * Contract checks for app-owned identity-session revocation and display lists.
 * These are distinct from the Hono BFF SessionStore contract.
 * @module
 */

import { afterEach, assert, beforeEach, describe, expect, it } from "vitest";
import type {
  ListableSessionService,
  RevocableSessionService,
  SessionSummary,
} from "../../identity/session.ts";

/** Session states the application translates into its own storage fields. */
export type IdentitySessionContractState =
  | "live"
  | "revoked"
  | "expired"
  | "idle-timed-out";

/** Isolated revocation implementation and app-owned session setup helpers. */
export interface RevocableSessionServiceContractFixture {
  /** Implementation under test. */
  service: RevocableSessionService;
  /** Two distinct existing owners, using your application's valid user-id format. */
  userId: string;
  /** Existing owner whose sessions must survive operations on userId. */
  otherUserId: string;
  /** Stable, distinct app-valid non-secret session ids for sequences 1 through 7 and 99. */
  sessionId(sequence: number): string;
  /** Seed one unique session with the indicated owner and state. */
  addSession(
    userId: string,
    summary: SessionSummary,
    state: IdentitySessionContractState,
  ): Promise<void>;
  /** Whether the application would still accept this session after revocation returns. */
  isLive(sessionId: string): Promise<boolean>;
  /** Release resources and remove this test's records. */
  dispose?(): Promise<void> | void;
}

/** Options for runRevocableSessionServiceContractTests. */
export interface RevocableSessionServiceContractOptions {
  /** Create a fresh empty fixture for each test. */
  makeFixture():
    | RevocableSessionServiceContractFixture
    | Promise<RevocableSessionServiceContractFixture>;
  /** Override the outer suite name. */
  describeName?: string;
}

/** Fixture for a store that exposes authoritative session display lists. */
export interface ListableSessionServiceContractFixture extends RevocableSessionServiceContractFixture {
  /** Both listing and immediate revocation must address the same stored sessions. */
  service: RevocableSessionService & ListableSessionService;
}

/** Options for runListableSessionServiceContractTests. */
export interface ListableSessionServiceContractOptions {
  /** Create a fresh empty fixture; translate ended states into your expiry and idle policy. */
  makeFixture():
    | ListableSessionServiceContractFixture
    | Promise<ListableSessionServiceContractFixture>;
  /** Override the outer suite name. */
  describeName?: string;
}

function summary(id: string, lastSeenAt = Date.now() - 30_000): SessionSummary {
  return {
    id,
    createdAt: new Date(Date.now() - 60_000),
    lastSeenAt: new Date(lastSeenAt),
  };
}

/**
 * Register checks for user-scoped, immediately effective session revocation.
 * The count checks seed live sessions only; they impose no retention policy on
 * ended rows. Concurrent calls are drained before fixture cleanup. Their
 * counts must reflect sessions actually revoked rather than double-counting
 * the same live sessions. This tests observed interleavings, not all races.
 */
export function runRevocableSessionServiceContractTests(
  options: RevocableSessionServiceContractOptions,
): void {
  describe(options.describeName ?? "RevocableSessionService contract", () => {
    let fixture: RevocableSessionServiceContractFixture;
    beforeEach(async () => {
      fixture = await options.makeFixture();
      assert(
        fixture.userId !== fixture.otherUserId,
        "session fixture owners must be distinct",
      );
    });
    afterEach(async () => {
      await fixture?.dispose?.();
    });
    async function seed(): Promise<void> {
      for (const id of [
        fixture.sessionId(1),
        fixture.sessionId(2),
        fixture.sessionId(3),
      ]) {
        await fixture.addSession(fixture.userId, summary(id), "live");
      }
      await fixture.addSession(
        fixture.otherUserId,
        summary(fixture.sessionId(4)),
        "live",
      );
    }
    it("reports zero for users without sessions", async () => {
      expect(
        await fixture.service.revokeAllByUser(fixture.userId),
      ).toStrictEqual(0);
      expect(
        await fixture.service.revokeOthers(
          fixture.userId,
          fixture.sessionId(99),
        ),
      ).toStrictEqual(0);
    });
    it("revokes all of the selected user's sessions immediately and only once", async () => {
      await seed();
      expect(
        await fixture.service.revokeAllByUser(fixture.userId),
      ).toStrictEqual(3);
      for (const id of [
        fixture.sessionId(1),
        fixture.sessionId(2),
        fixture.sessionId(3),
      ]) {
        expect(await fixture.isLive(id)).toBe(false);
      }
      expect(await fixture.isLive(fixture.sessionId(4))).toBe(true);
      expect(
        await fixture.service.revokeAllByUser(fixture.userId),
      ).toStrictEqual(0);
    });
    it("keeps only the selected current session and preserves another user's sessions", async () => {
      await seed();
      expect(
        await fixture.service.revokeOthers(
          fixture.userId,
          fixture.sessionId(2),
        ),
      ).toStrictEqual(2);
      expect(await fixture.isLive(fixture.sessionId(1))).toBe(false);
      expect(await fixture.isLive(fixture.sessionId(3))).toBe(false);
      expect(await fixture.isLive(fixture.sessionId(2))).toBe(true);
      expect(await fixture.isLive(fixture.sessionId(4))).toBe(true);
      expect(
        await fixture.service.revokeOthers(
          fixture.userId,
          fixture.sessionId(2),
        ),
      ).toStrictEqual(0);
    });
    it("a foreign keepSessionId cannot exempt the selected user's sessions", async () => {
      await seed();
      expect(
        await fixture.service.revokeOthers(
          fixture.userId,
          fixture.sessionId(4),
        ),
      ).toStrictEqual(3);
      for (const id of [
        fixture.sessionId(1),
        fixture.sessionId(2),
        fixture.sessionId(3),
      ]) {
        expect(await fixture.isLive(id)).toBe(false);
      }
      expect(await fixture.isLive(fixture.sessionId(4))).toBe(true);
    });
    it("does not double-count concurrent revocations", async () => {
      await seed();
      const results = await Promise.allSettled(
        Array.from({ length: 8 }, () =>
          fixture.service.revokeAllByUser(fixture.userId),
        ),
      );
      const counts = results.map((result) => {
        if (result.status === "rejected") throw result.reason;
        return result.value;
      });
      expect(
        counts.reduce((sum, count) => sum + count, 0),
        "concurrent revocation counts must not count a live session twice",
      ).toStrictEqual(3);
      for (const id of [
        fixture.sessionId(1),
        fixture.sessionId(2),
        fixture.sessionId(3),
      ]) {
        expect(await fixture.isLive(id)).toBe(false);
      }
      expect(await fixture.isLive(fixture.sessionId(4))).toBe(true);
    });
  });
}

/**
 * Register checks for user-scoped, newest-activity-first session display lists.
 * Verifies base timestamps and only the documented display keys, excluding
 * token material and secrets. Optional coarse client metadata may be omitted.
 * Run the separate revocation suite as well to verify its complete contract.
 */
export function runListableSessionServiceContractTests(
  options: ListableSessionServiceContractOptions,
): void {
  describe(options.describeName ?? "ListableSessionService contract", () => {
    let fixture: ListableSessionServiceContractFixture;
    beforeEach(async () => {
      fixture = await options.makeFixture();
      assert(
        fixture.userId !== fixture.otherUserId,
        "session fixture owners must be distinct",
      );
    });
    afterEach(async () => {
      await fixture?.dispose?.();
    });
    it("returns an empty list for a user without live sessions", async () => {
      expect(await fixture.service.listByUser(fixture.userId)).toStrictEqual(
        [],
      );
    });
    it("lists only the owner's live sessions in most-recently-active order", async () => {
      const oldest = summary(fixture.sessionId(1));
      const newest = {
        ...summary(fixture.sessionId(2), Date.now() - 1_000),
        userAgent: "contract-browser",
        location: "Example City, US",
      };
      const middle = summary(fixture.sessionId(3), Date.now() - 2_000);
      for (const value of [oldest, newest, middle]) {
        await fixture.addSession(fixture.userId, value, "live");
      }
      for (const [index, state] of (
        ["revoked", "expired", "idle-timed-out"] as const
      ).entries()) {
        await fixture.addSession(
          fixture.userId,
          summary(fixture.sessionId(index + 5)),
          state,
        );
      }
      await fixture.addSession(
        fixture.otherUserId,
        summary(fixture.sessionId(4)),
        "live",
      );
      const rows = await fixture.service.listByUser(fixture.userId);
      expect(
        rows.map((row) => row.id),
        "lists must exclude foreign and ended sessions and sort by last activity",
      ).toStrictEqual([
        fixture.sessionId(2),
        fixture.sessionId(3),
        fixture.sessionId(1),
      ]);
      const expectedRows: SessionSummary[] = [newest, middle, oldest];
      for (const [index, expected] of expectedRows.entries()) {
        const row = rows[index];
        assert.exists(row);
        expect(row.createdAt).toStrictEqual(expected.createdAt);
        expect(row.lastSeenAt).toStrictEqual(expected.lastSeenAt);
        expect(
          Object.keys(row).filter(
            (key) =>
              ![
                "id",
                "createdAt",
                "lastSeenAt",
                "userAgent",
                "location",
              ].includes(key),
          ),
          "session summaries must not expose secret/hash or token material",
        ).toStrictEqual([]);
        if (row.userAgent !== undefined) {
          expect(row.userAgent).toStrictEqual(expected.userAgent);
        }
        if (row.location !== undefined) {
          expect(row.location).toStrictEqual(expected.location);
        }
      }
      expect(
        (await fixture.service.listByUser(fixture.otherUserId)).map(
          (row) => row.id,
        ),
      ).toStrictEqual([fixture.sessionId(4)]);
    });
    it("removes revoked sessions from the authoritative list immediately", async () => {
      await fixture.addSession(
        fixture.userId,
        summary(fixture.sessionId(1)),
        "live",
      );
      await fixture.addSession(
        fixture.userId,
        summary(fixture.sessionId(2)),
        "live",
      );
      await fixture.addSession(
        fixture.otherUserId,
        summary(fixture.sessionId(4)),
        "live",
      );
      expect(
        await fixture.service.revokeOthers(
          fixture.userId,
          fixture.sessionId(1),
        ),
      ).toStrictEqual(1);
      expect(
        (await fixture.service.listByUser(fixture.userId)).map((row) => row.id),
      ).toStrictEqual([fixture.sessionId(1)]);
      expect(await fixture.isLive(fixture.sessionId(2))).toBe(false);
      expect(
        await fixture.service.revokeAllByUser(fixture.userId),
      ).toStrictEqual(1);
      expect(await fixture.service.listByUser(fixture.userId)).toStrictEqual(
        [],
      );
      expect(
        (await fixture.service.listByUser(fixture.otherUserId)).map(
          (row) => row.id,
        ),
      ).toStrictEqual([fixture.sessionId(4)]);
    });
  });
}
