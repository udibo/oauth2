import { assert, assertEquals, assertFalse } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  isRecentlyAuthenticated,
  type ListableSessionService,
  type RevocableSessionService,
  type SessionSummary,
  supportsSessionListing,
} from "./session.ts";

describe("isRecentlyAuthenticated", () => {
  const NOW = 1_000_000;
  const FIVE_MIN = 5 * 60_000;

  it("is true within the window, false past it", () => {
    assertEquals(isRecentlyAuthenticated(NOW - 60_000, FIVE_MIN, NOW), true);
    assertEquals(isRecentlyAuthenticated(NOW - FIVE_MIN, FIVE_MIN, NOW), true);
    assertEquals(
      isRecentlyAuthenticated(NOW - FIVE_MIN - 1, FIVE_MIN, NOW),
      false,
    );
  });

  it("treats a missing/zero timestamp as not recent", () => {
    assertEquals(isRecentlyAuthenticated(0, FIVE_MIN, NOW), false);
  });
});

describe("RevocableSessionService (contract shape)", () => {
  it("a minimal in-memory implementation satisfies the contract", async () => {
    const byUser = new Map<string, Set<string>>();
    const link = (u: string, s: string) =>
      (byUser.get(u) ?? byUser.set(u, new Set()).get(u)!).add(s);
    link("u1", "s1");
    link("u1", "s2");
    link("u2", "s3");

    const service: RevocableSessionService = {
      revokeOthers(userId, keep) {
        const set = byUser.get(userId) ?? new Set();
        let n = 0;
        for (const id of [...set]) {
          if (id !== keep) {
            set.delete(id);
            n++;
          }
        }
        return Promise.resolve(n);
      },
      revokeAllByUser(userId) {
        const n = byUser.get(userId)?.size ?? 0;
        byUser.delete(userId);
        return Promise.resolve(n);
      },
    };

    assertEquals(await service.revokeOthers("u1", "s1"), 1);
    assertEquals([...(byUser.get("u1") ?? [])], ["s1"]);
    assertEquals(await service.revokeAllByUser("u2"), 1);
    assertEquals(byUser.has("u2"), false);
  });
});

describe("ListableSessionService (contract shape)", () => {
  const NOW = 1_000_000;
  const summariesByUser: Record<string, SessionSummary[]> = {
    u1: [
      { id: "s2", createdAt: new Date(NOW - 1_000), lastSeenAt: new Date(NOW) },
      {
        id: "s1",
        createdAt: new Date(NOW - 10_000),
        lastSeenAt: new Date(NOW - 5_000),
        userAgent: "Mozilla/5.0",
        location: "San Francisco, US",
      },
    ],
  };

  const listable: RevocableSessionService & ListableSessionService = {
    revokeAllByUser: () => Promise.resolve(0),
    revokeOthers: () => Promise.resolve(0),
    listByUser: (userId) => Promise.resolve(summariesByUser[userId] ?? []),
  };

  it("a listing implementation satisfies the contract", async () => {
    const rows = await listable.listByUser("u1");
    assertEquals(rows.map((row) => row.id), ["s2", "s1"]);
    assertEquals(rows[1].userAgent, "Mozilla/5.0");
    assertEquals(rows[1].location, "San Francisco, US");
    assertEquals(await listable.listByUser("nobody"), []);
  });

  it("supportsSessionListing narrows a store that opts in", () => {
    assert(supportsSessionListing(listable));
  });

  it("supportsSessionListing rejects a revoke-only store", () => {
    const revokeOnly: RevocableSessionService = {
      revokeAllByUser: () => Promise.resolve(0),
      revokeOthers: () => Promise.resolve(0),
    };
    assertFalse(supportsSessionListing(revokeOnly));
  });
});
