import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { AccountLockout } from "./lockout.ts";

describe("AccountLockout", () => {
  it("locks after the consecutive-failure threshold", async () => {
    const lockout = new AccountLockout({
      maxAttempts: 3,
      lockDurationMs: 60_000,
    });
    const now = 1_000_000;

    assertEquals(
      (await lockout.recordFailure("u1", now)).locked,
      false,
    );
    assertEquals((await lockout.recordFailure("u1", now)).locked, false);
    const third = await lockout.recordFailure("u1", now);
    assertEquals(third.locked, true);
    assertEquals(third.justLocked, true);
    assertEquals(third.failures, 3);
    assertEquals(third.lockedUntil, now + 60_000);

    const status = await lockout.status("u1", now + 1);
    assertEquals(status.locked, true);
    assertEquals(status.lockedUntil, now + 60_000);
  });

  it("an expired lock reads unlocked and a new failure starts fresh", async () => {
    const lockout = new AccountLockout({
      maxAttempts: 2,
      lockDurationMs: 1_000,
    });
    const now = 1_000_000;
    await lockout.recordFailure("u1", now);
    await lockout.recordFailure("u1", now);
    assertEquals((await lockout.status("u1", now + 500)).locked, true);
    assertEquals((await lockout.status("u1", now + 1_001)).locked, false);

    const fresh = await lockout.recordFailure("u1", now + 2_000);
    assertEquals(fresh.failures, 1);
    assertEquals(fresh.locked, false);
  });

  it("failures during an active lock keep it locked without re-triggering", async () => {
    const lockout = new AccountLockout({
      maxAttempts: 2,
      lockDurationMs: 60_000,
    });
    const now = 1_000_000;
    await lockout.recordFailure("u1", now);
    await lockout.recordFailure("u1", now);

    const during = await lockout.recordFailure("u1", now + 10);
    assertEquals(during.locked, true);
    assertEquals(during.justLocked, false);
    assertEquals(during.lockedUntil, now + 60_000);
  });

  it("reset clears failures and any lock", async () => {
    const lockout = new AccountLockout({
      maxAttempts: 2,
      lockDurationMs: 60_000,
    });
    await lockout.recordFailure("u1");
    await lockout.recordFailure("u1");
    await lockout.reset("u1");

    const status = await lockout.status("u1");
    assertEquals(status.locked, false);
    assertEquals(status.failures, 0);
    assertEquals(status.lockedUntil, undefined);
  });

  it("tracks accounts independently", async () => {
    const lockout = new AccountLockout({
      maxAttempts: 2,
      lockDurationMs: 60_000,
    });
    await lockout.recordFailure("u1");
    await lockout.recordFailure("u1");
    assertEquals((await lockout.status("u1")).locked, true);
    assertEquals((await lockout.status("u2")).locked, false);
  });

  it("concurrent failures neither lose counts nor double-report justLocked", async () => {
    const lockout = new AccountLockout({
      maxAttempts: 5,
      lockDurationMs: 60_000,
    });
    const now = 1_000_000;

    const results = await Promise.all(
      Array.from({ length: 8 }, () => lockout.recordFailure("u1", now)),
    );

    const failures = results.map((r) => r.failures).sort((a, b) => a - b);
    assertEquals(failures, [1, 2, 3, 4, 5, 6, 7, 8]);
    assertEquals(results.filter((r) => r.justLocked).length, 1);
    assertEquals((await lockout.status("u1", now + 1)).locked, true);
  });
});
