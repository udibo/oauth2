import { describe, expect, it } from "vitest";
import {
  AccountLockout,
  type AccountLockoutOptions,
  type LockoutRecord,
  type LockoutStore,
  MemoryLockoutStore,
} from "./lockout.ts";

interface HeldLockWrite {
  store: LockoutStore;
  reached: Promise<void>;
  release(): void;
}

function holdLockWrites(inner: MemoryLockoutStore): HeldLockWrite {
  const reached = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const held = async <T>(write: () => Promise<T>): Promise<T> => {
    reached.resolve();
    await release.promise;
    return write();
  };
  return {
    store: {
      get: (userId, now) => inner.get(userId, now),
      increment: (userId, now) => inner.increment(userId, now),
      clear: (userId) => inner.clear(userId),
      set: (userId, record) => held(() => inner.set(userId, record)),
      lock: (userId, record, now) =>
        held(() => inner.lock(userId, record, now)),
    },
    reached: reached.promise,
    release: () => release.resolve(),
  };
}

function withoutLock(inner: MemoryLockoutStore): LockoutStore {
  return {
    get: (userId, now) => inner.get(userId, now),
    increment: (userId, now) => inner.increment(userId, now),
    set: (userId, record: LockoutRecord) => inner.set(userId, record),
    clear: (userId) => inner.clear(userId),
  };
}

describe("AccountLockout", () => {
  it("locks after the consecutive-failure threshold", async () => {
    const lockout = new AccountLockout({
      maxAttempts: 3,
      lockDurationMs: 60_000,
      store: new MemoryLockoutStore(),
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
      store: new MemoryLockoutStore(),
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
      store: new MemoryLockoutStore(),
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
      store: new MemoryLockoutStore(),
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
      store: new MemoryLockoutStore(),
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
      store: new MemoryLockoutStore(),
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

  it("admits exactly maxAttempts of any number of concurrent reservations", async () => {
    const lockout = new AccountLockout({
      maxAttempts: 3,
      lockDurationMs: 60_000,
      store: new MemoryLockoutStore(),
    });
    const now = 1_000_000;

    const results = await Promise.all(
      Array.from({ length: 10 }, () => lockout.reserveAttempt("u1", now)),
    );

    const admitted = results
      .filter((r) => !r.locked || r.justLocked)
      .map((r) => r.failures)
      .sort((a, b) => a - b);
    expect(admitted).toStrictEqual([1, 2, 3]);
    expect(results.filter((r) => r.justLocked).length).toStrictEqual(1);
    expect((await lockout.status("u1", now + 1)).locked).toStrictEqual(true);
  });

  it("refuses a reservation against an active lock without moving it", async () => {
    const store = new MemoryLockoutStore();
    const lockout = new AccountLockout({
      maxAttempts: 2,
      lockDurationMs: 60_000,
      store,
    });
    const now = 1_000_000;
    await lockout.reserveAttempt("u1", now);
    await lockout.reserveAttempt("u1", now);

    const refused = await lockout.reserveAttempt("u1", now + 5_000);

    expect(refused).toStrictEqual({
      failures: 3,
      locked: true,
      justLocked: false,
      lockedUntil: now + 60_000,
    });
  });

  it("does not re-lock an account reset while an over-budget attempt was locking it", async () => {
    const inner = new MemoryLockoutStore();
    const { store, reached, release } = holdLockWrites(inner);
    const lockout = new AccountLockout({
      maxAttempts: 3,
      lockDurationMs: 60_000,
      store,
    });
    const now = 1_000_000;
    for (let i = 0; i < 3; i++) await inner.increment("u1", now);

    const overBudget = lockout.reserveAttempt("u1", now);
    await reached;
    await lockout.reset("u1");
    release();

    expect(
      await overBudget,
      "the attempt is counted again against the record the reset left",
    ).toStrictEqual({ failures: 1, locked: false, justLocked: false });
    expect(
      await lockout.status("u1", now + 1),
      "a lock computed before the reset must not land after it",
    ).toStrictEqual({ locked: false, failures: 1, lockedUntil: undefined });
  });

  it("reports no new lock when a reset lands before the threshold attempt's lock", async () => {
    const inner = new MemoryLockoutStore();
    const { store, reached, release } = holdLockWrites(inner);
    const lockout = new AccountLockout({
      maxAttempts: 3,
      lockDurationMs: 60_000,
      store,
    });
    const now = 1_000_000;
    for (let i = 0; i < 2; i++) await inner.increment("u1", now);

    const threshold = lockout.reserveAttempt("u1", now);
    await reached;
    await lockout.reset("u1");
    release();

    expect(
      (await threshold).justLocked,
      "the lockout event fires only for a lock that exists",
    ).toStrictEqual(false);
    expect((await lockout.status("u1", now + 1)).locked).toStrictEqual(false);
  });

  it("admits the attempt unlocked, without a lock, when its recount's lock is refused too", async () => {
    const inner = new MemoryLockoutStore();
    let increments = 0;
    const store: LockoutStore = {
      get: (userId, now) => inner.get(userId, now),
      increment: (userId, now) => {
        increments++;
        return inner.increment(userId, now);
      },
      set: (userId, record) => inner.set(userId, record),
      clear: (userId) => inner.clear(userId),
      lock: () => Promise.resolve(false),
    };
    const lockout = new AccountLockout({
      maxAttempts: 2,
      lockDurationMs: 60_000,
      store,
    });
    const now = 1_000_000;
    await inner.increment("u1", now);

    const attempt = await lockout.reserveAttempt("u1", now);

    expect(
      increments,
      "a refused lock is retried against one fresh count, never looped",
    ).toBe(2);
    expect(
      attempt,
      "with no lock written, the attempt reports the state the store holds",
    ).toStrictEqual({ failures: 3, locked: false, justLocked: false });
    expect((await lockout.status("u1", now)).locked).toBe(false);
  });

  it("locks through set when the store has no conditional lock", async () => {
    const inner = new MemoryLockoutStore();
    const lockout = new AccountLockout({
      maxAttempts: 2,
      lockDurationMs: 60_000,
      store: withoutLock(inner),
    });
    const now = 1_000_000;

    await lockout.reserveAttempt("u1", now);
    const second = await lockout.reserveAttempt("u1", now);

    expect(second).toStrictEqual({
      failures: 2,
      locked: true,
      justLocked: true,
      lockedUntil: now + 60_000,
    });
    expect(await inner.get("u1", now)).toStrictEqual({
      failures: 2,
      lockedUntil: now + 60_000,
    });
  });

  it("two instances sharing a store agree on failures and the lock", async () => {
    const store = new MemoryLockoutStore();
    const first = new AccountLockout({
      maxAttempts: 3,
      lockDurationMs: 60_000,
      store,
    });
    const second = new AccountLockout({
      maxAttempts: 3,
      lockDurationMs: 60_000,
      store,
    });
    const now = 1_000_000;

    await first.recordFailure("u1", now);
    await second.recordFailure("u1", now);
    const third = await first.recordFailure("u1", now);

    expect(third.justLocked).toBe(true);
    expect(await second.status("u1", now + 1)).toStrictEqual({
      locked: true,
      failures: 3,
      lockedUntil: now + 60_000,
    });

    await second.reset("u1");
    expect(await first.status("u1", now + 1)).toStrictEqual({
      locked: false,
      failures: 0,
    });
  });

  it("requires a store, naming the option and the choices", () => {
    expect(
      () =>
        // @ts-expect-error store is required
        new AccountLockout({ maxAttempts: 3 }),
    ).toThrow(
      new TypeError(
        "AccountLockout requires options.store. Pass a LockoutStore over " +
          "storage every instance shares, such as columns on your users " +
          "table, or MemoryLockoutStore for a single process, tests and " +
          "local development.",
      ),
    );
  });

  it("requires options at all", () => {
    expect(
      () =>
        // @ts-expect-error options are required
        new AccountLockout(),
    ).toThrow(/AccountLockout requires options\.store/);
    expect(
      () => new AccountLockout(undefined as unknown as AccountLockoutOptions),
    ).toThrow(TypeError);
  });
});

describe("AccountLockout.releaseAttempt", () => {
  const now = 1_000_000;

  function lockoutOver(store: LockoutStore): AccountLockout {
    return new AccountLockout({
      maxAttempts: 3,
      lockDurationMs: 60_000,
      store,
    });
  }

  it("takes back one reserved attempt", async () => {
    const lockout = lockoutOver(new MemoryLockoutStore());
    await lockout.reserveAttempt("u1", now);
    await lockout.reserveAttempt("u1", now);

    expect(await lockout.releaseAttempt("u1", now)).toStrictEqual(true);

    expect(await lockout.status("u1", now)).toStrictEqual({
      locked: false,
      failures: 1,
      lockedUntil: undefined,
    });
  });

  it("drops the lock the released attempt's count created", async () => {
    const lockout = lockoutOver(new MemoryLockoutStore());
    for (let i = 0; i < 3; i++) await lockout.reserveAttempt("u1", now);
    expect((await lockout.status("u1", now)).locked).toStrictEqual(true);

    await lockout.releaseAttempt("u1", now);

    expect(await lockout.status("u1", now)).toStrictEqual({
      locked: false,
      failures: 2,
      lockedUntil: undefined,
    });
    expect(
      (await lockout.reserveAttempt("u1", now)).justLocked,
      "the next counted attempt reaches the threshold again and announces it",
    ).toStrictEqual(true);
  });

  it("keeps a lock the remaining attempts still reach", async () => {
    const lockout = lockoutOver(new MemoryLockoutStore());
    for (let i = 0; i < 4; i++) await lockout.reserveAttempt("u1", now);

    await lockout.releaseAttempt("u1", now);

    expect(await lockout.status("u1", now)).toStrictEqual({
      locked: true,
      failures: 3,
      lockedUntil: now + 60_000,
    });
  });

  it("leaves an account with no record untouched", async () => {
    const store = new MemoryLockoutStore();
    const lockout = lockoutOver(store);

    expect(await lockout.releaseAttempt("u1", now)).toStrictEqual(true);

    expect(await store.get("u1", now)).toBe(undefined);
  });

  it("resolves false and keeps the attempt counted when the store cannot release", async () => {
    const lockout = lockoutOver(withoutLock(new MemoryLockoutStore()));
    await lockout.reserveAttempt("u1", now);

    expect(await lockout.releaseAttempt("u1", now)).toStrictEqual(false);

    expect((await lockout.status("u1", now)).failures).toStrictEqual(1);
  });
});

describe("MemoryLockoutStore", () => {
  const now = 1_000_000;
  const hour = 60 * 60_000;

  it("drops a record idle past its TTL", async () => {
    const store = new MemoryLockoutStore({ ttlMs: hour });
    await store.increment("u1", now);
    await store.increment("u1", now + 10);

    expect(await store.get("u1", now + hour + 9)).toStrictEqual({
      failures: 2,
    });
    expect(await store.get("u1", now + hour + 10)).toStrictEqual(undefined);
    expect(store.size).toBe(0);
  });

  it("starts a fresh count when a failure arrives after the TTL", async () => {
    const store = new MemoryLockoutStore({ ttlMs: hour });
    await store.increment("u1", now);
    await store.increment("u1", now);

    expect(await store.increment("u1", now + hour)).toStrictEqual({
      failures: 1,
    });
  });

  it("keeps a record past its TTL while its lock is active", async () => {
    const store = new MemoryLockoutStore({ ttlMs: hour });
    const lockout = new AccountLockout({
      maxAttempts: 2,
      lockDurationMs: 3 * hour,
      store,
    });
    await lockout.recordFailure("u1", now);
    await lockout.recordFailure("u1", now);

    expect((await lockout.status("u1", now + 2 * hour)).locked).toBe(true);
    expect((await lockout.recordFailure("u1", now + 2 * hour)).locked).toBe(
      true,
    );
    expect(await store.get("u1", now + 4 * hour)).toStrictEqual(undefined);
  });

  it("defaults to a 24-hour TTL", async () => {
    const store = new MemoryLockoutStore();
    await store.increment("u1", now);

    expect(await store.get("u1", now + 24 * hour - 1)).toStrictEqual({
      failures: 1,
    });
    expect(await store.get("u1", now + 24 * hour)).toStrictEqual(undefined);
  });

  it("sweeps expired records as failures accumulate", async () => {
    const store = new MemoryLockoutStore({ ttlMs: hour });
    for (let i = 0; i < 50; i++) await store.increment(`idle:${i}`, now);
    expect(store.size).toBe(50);

    for (let i = 0; i < 1_000; i++) {
      await store.increment("active", now + 2 * hour);
    }
    expect(store.size).toBe(1);
  });

  it("holds at most maxEntries records", async () => {
    const store = new MemoryLockoutStore({ maxEntries: 100 });
    for (let i = 0; i < 1_000; i++) await store.increment(`u${i}`, now + i);

    expect(store.size).toBe(100);
    expect(await store.get("u999", now + 1_000)).toStrictEqual({
      failures: 1,
    });
  });

  it("defaults to a 10,000-record cap", async () => {
    const store = new MemoryLockoutStore();
    for (let i = 0; i < 10_050; i++) await store.increment(`u${i}`, now);

    expect(store.size).toBe(10_000);
  });

  it("reclaims expired records at capacity before evicting live ones", async () => {
    const store = new MemoryLockoutStore({ ttlMs: hour, maxEntries: 3 });
    for (let i = 0; i < 3; i++) await store.increment("expired", now);
    await store.increment("live-a", now + hour - 1);
    await store.increment("live-b", now + hour - 1);

    await store.increment("new", now + hour);

    expect(await store.get("expired", now + hour)).toStrictEqual(undefined);
    expect(await store.get("live-a", now + hour)).toStrictEqual({
      failures: 1,
    });
    expect(await store.get("live-b", now + hour)).toStrictEqual({
      failures: 1,
    });
  });

  it("evicts the record with the fewest failures before one closer to locking", async () => {
    const store = new MemoryLockoutStore({ maxEntries: 2 });
    await store.increment("warm", now);
    await store.increment("warm", now);
    await store.increment("cold", now + 1);

    await store.increment("new", now + 2);

    expect(await store.get("warm", now + 2)).toStrictEqual({ failures: 2 });
    expect(await store.get("cold", now + 2)).toStrictEqual(undefined);
  });

  it("evicts an unlocked record before a locked one", async () => {
    const store = new MemoryLockoutStore({ maxEntries: 2 });
    const lockout = new AccountLockout({
      maxAttempts: 2,
      lockDurationMs: hour,
      store,
    });
    await lockout.recordFailure("locked", now);
    await lockout.recordFailure("locked", now);
    for (let i = 0; i < 5; i++) await store.increment("busy", now);

    await store.increment("new", now + 1);

    expect((await lockout.status("locked", now + 1)).locked).toBe(true);
    expect(await store.get("busy", now + 1)).toStrictEqual(undefined);
  });

  it("evicts the longest-idle record among those with equal failures", async () => {
    const store = new MemoryLockoutStore({ maxEntries: 2 });
    await store.increment("idle", now);
    await store.increment("recent", now + 10);

    await store.increment("new", now + 20);

    expect(await store.get("idle", now + 20)).toStrictEqual(undefined);
    expect(await store.get("recent", now + 20)).toStrictEqual({ failures: 1 });
  });

  it("evicts the lock that ends soonest once only locked records remain", async () => {
    const store = new MemoryLockoutStore({ maxEntries: 2 });
    const lockout = new AccountLockout({
      maxAttempts: 1,
      lockDurationMs: hour,
      store,
    });
    await lockout.recordFailure("ends-first", now);
    await lockout.recordFailure("ends-last", now + 10);

    await store.increment("new", now + 20);

    expect((await lockout.status("ends-first", now + 20)).locked).toBe(false);
    expect(await lockout.status("ends-last", now + 20)).toStrictEqual({
      locked: true,
      failures: 1,
      lockedUntil: now + 10 + hour,
    });
  });

  it("keeps a lock through a flood of failures against other accounts", async () => {
    const store = new MemoryLockoutStore({ maxEntries: 100 });
    const lockout = new AccountLockout({
      maxAttempts: 3,
      lockDurationMs: hour,
      store,
    });
    for (let i = 0; i < 3; i++) await lockout.recordFailure("victim", now);

    for (let i = 0; i < 5_000; i++) {
      await lockout.recordFailure(`other-${i}`, now + 1);
    }

    expect((await lockout.status("victim", now + 2)).locked).toBe(true);
    expect(store.size).toBe(100);
  });

  it("rejects a cap or TTL that is not a positive number", () => {
    expect(() => new MemoryLockoutStore({ maxEntries: 0 })).toThrow(RangeError);
    expect(() => new MemoryLockoutStore({ maxEntries: 1.5 })).toThrow(
      RangeError,
    );
    expect(() => new MemoryLockoutStore({ ttlMs: 0 })).toThrow(RangeError);
    expect(() => new MemoryLockoutStore({ ttlMs: Number.NaN })).toThrow(
      RangeError,
    );
    expect(
      () => new MemoryLockoutStore({ maxEntries: Infinity, ttlMs: Infinity }),
    ).not.toThrow();
  });
});
