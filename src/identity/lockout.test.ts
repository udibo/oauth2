import { describe, expect, it } from "vitest";
import { AccountLockout } from "./lockout.ts";

describe("AccountLockout", () => {
  it("locks after the consecutive-failure threshold", async () => {
    const lockout = new AccountLockout({
      maxAttempts: 3,
      lockDurationMs: 60_000,
    });
    const now = 1_000_000;

    expect((await lockout.recordFailure("u1", now)).locked).toStrictEqual(
      false,
    );
    expect((await lockout.recordFailure("u1", now)).locked).toStrictEqual(
      false,
    );
    const third = await lockout.recordFailure("u1", now);
    expect(third.locked).toStrictEqual(true);
    expect(third.justLocked).toStrictEqual(true);
    expect(third.failures).toStrictEqual(3);
    expect(third.lockedUntil).toStrictEqual(now + 60_000);

    const status = await lockout.status("u1", now + 1);
    expect(status.locked).toStrictEqual(true);
    expect(status.lockedUntil).toStrictEqual(now + 60_000);
  });

  it("an expired lock reads unlocked and a new failure starts fresh", async () => {
    const lockout = new AccountLockout({
      maxAttempts: 2,
      lockDurationMs: 1_000,
    });
    const now = 1_000_000;
    await lockout.recordFailure("u1", now);
    await lockout.recordFailure("u1", now);
    expect((await lockout.status("u1", now + 500)).locked).toStrictEqual(true);
    expect((await lockout.status("u1", now + 1_001)).locked).toStrictEqual(
      false,
    );

    const fresh = await lockout.recordFailure("u1", now + 2_000);
    expect(fresh.failures).toStrictEqual(1);
    expect(fresh.locked).toStrictEqual(false);
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
    expect(during.locked).toStrictEqual(true);
    expect(during.justLocked).toStrictEqual(false);
    expect(during.lockedUntil).toStrictEqual(now + 60_000);
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
    expect(status.locked).toStrictEqual(false);
    expect(status.failures).toStrictEqual(0);
    expect(status.lockedUntil).toStrictEqual(undefined);
  });

  it("tracks accounts independently", async () => {
    const lockout = new AccountLockout({
      maxAttempts: 2,
      lockDurationMs: 60_000,
    });
    await lockout.recordFailure("u1");
    await lockout.recordFailure("u1");
    expect((await lockout.status("u1")).locked).toStrictEqual(true);
    expect((await lockout.status("u2")).locked).toStrictEqual(false);
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
    expect(failures).toStrictEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(results.filter((r) => r.justLocked).length).toStrictEqual(1);
    expect((await lockout.status("u1", now + 1)).locked).toStrictEqual(true);
  });
});
