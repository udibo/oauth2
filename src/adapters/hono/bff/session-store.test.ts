import { assert, describe, expect, it, vi } from "vitest";
import { FakeTime } from "../../../_test_fake-time.ts";
import { rejection, thrown } from "../../../_test_assert.ts";
import { InvalidGrantError } from "../../../errors.ts";
import { sealJson } from "../../../utils/crypto.ts";
import {
  AUTH_REQUEST_COOKIE_KEY_INFO,
  deriveCookieKey,
  SESSION_COOKIE_KEY_INFO,
} from "./_cookie-keys.ts";
import {
  DEFAULT_SESSION_MAX_AGE_MS,
  EncryptedCookieSessionStore,
  MemorySessionStore,
  type RefreshLease,
  type SessionData,
  sessionStoreMaxAgeMs,
} from "./session-store.ts";

function makeSessionData(overrides: Partial<SessionData> = {}): SessionData {
  const now = Date.now();
  return {
    tokens: { accessToken: "abc", tokenType: "Bearer", scope: "read" },
    refreshToken: "r1",
    user: { sub: "u1" },
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

describe("EncryptedCookieSessionStore secret rotation", () => {
  it("seals under the current secret and reads back", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const store = new EncryptedCookieSessionStore({ secret });
    const data = makeSessionData();
    expect(await store.read(await store.create(data))).toStrictEqual(data);
  });

  it("reads a cookie sealed under any secret in the list", async () => {
    const current = crypto.getRandomValues(new Uint8Array(32));
    const previous = crypto.getRandomValues(new Uint8Array(32));
    const data = makeSessionData();

    const previousOnly = new EncryptedCookieSessionStore({ secret: previous });
    const cookieUnderPrevious = await previousOnly.create(data);

    const rotated = new EncryptedCookieSessionStore({
      secret: [current, previous],
    });
    expect(await rotated.read(cookieUnderPrevious)).toStrictEqual(data);
  });

  it("seals new cookies under the first secret during a rotation", async () => {
    const current = crypto.getRandomValues(new Uint8Array(32));
    const previous = crypto.getRandomValues(new Uint8Array(32));
    const data = makeSessionData();

    const rotated = new EncryptedCookieSessionStore({
      secret: [current, previous],
    });
    const freshCookie = await rotated.create(data);

    const currentOnly = new EncryptedCookieSessionStore({ secret: current });
    expect(await currentOnly.read(freshCookie)).toStrictEqual(data);
  });

  it("keeps an old cookie readable while its secret stays in the list, and drops it once removed", async () => {
    const current = crypto.getRandomValues(new Uint8Array(32));
    const previous = crypto.getRandomValues(new Uint8Array(32));
    const data = makeSessionData();

    const previousOnly = new EncryptedCookieSessionStore({ secret: previous });
    const oldCookie = await previousOnly.create(data);

    const duringGraceWindow = new EncryptedCookieSessionStore({
      secret: [current, previous],
    });
    expect(await duringGraceWindow.read(oldCookie)).toStrictEqual(data);

    const afterGraceWindow = new EncryptedCookieSessionStore({
      secret: current,
    });
    expect(await afterGraceWindow.read(oldCookie)).toBe(null);
  });

  it("returns null for a cookie sealed under an unknown secret", async () => {
    const data = makeSessionData();
    const sealer = new EncryptedCookieSessionStore({
      secret: crypto.getRandomValues(new Uint8Array(32)),
    });
    const cookie = await sealer.create(data);

    const reader = new EncryptedCookieSessionStore({
      secret: crypto.getRandomValues(new Uint8Array(32)),
    });
    expect(await reader.read(cookie)).toBe(null);
  });

  it("returns null for tampered or malformed cookies", async () => {
    const store = new EncryptedCookieSessionStore({
      secret: new Uint8Array(32),
    });
    expect(await store.read("not-a-real-cookie")).toBe(null);
  });

  it("rejects a secret shorter than 16 bytes on first use", async () => {
    const store = new EncryptedCookieSessionStore({
      secret: new Uint8Array(15),
    });
    await rejection(
      store.create(makeSessionData()),
      Error,
      /at least 16 bytes/,
    );
  });

  it("accepts a secret of exactly 16 bytes", async () => {
    const store = new EncryptedCookieSessionStore({ secret: "x".repeat(16) });
    const data = makeSessionData();
    expect(await store.read(await store.create(data))).toStrictEqual(data);
  });

  it("throws when the secret list is empty", () => {
    thrown(
      () => new EncryptedCookieSessionStore({ secret: [] }),
      Error,
      "secret must not be an empty list.",
    );
  });

  it("starts no key derivation until an operation needs the key", async () => {
    using deriveKey = vi.spyOn(crypto.subtle, "deriveKey");
    const store = new EncryptedCookieSessionStore({
      secret: [
        crypto.getRandomValues(new Uint8Array(32)),
        crypto.getRandomValues(new Uint8Array(32)),
      ],
    });
    expect(deriveKey).toHaveBeenCalledTimes(0);

    const cookie = await store.create(makeSessionData());
    expect(deriveKey).toHaveBeenCalledTimes(1);

    await store.read(cookie);
    expect(deriveKey).toHaveBeenCalledTimes(1);
  });
});

describe("EncryptedCookieSessionStore bounded lifetime", () => {
  it("reads a fresh cookie when a max age is configured", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const store = new EncryptedCookieSessionStore({ secret, maxAgeMs: 60_000 });
    const data = makeSessionData();
    expect(await store.read(await store.create(data))).toStrictEqual(data);
  });

  it("returns null once a cookie is older than the max age", async () => {
    using time = new FakeTime(1_700_000_000_000);
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const store = new EncryptedCookieSessionStore({ secret, maxAgeMs: 60_000 });
    const cookie = await store.create(makeSessionData());

    time.tick(59_999);
    expect((await store.read(cookie))?.tokens.accessToken).toStrictEqual("abc");

    time.tick(2);
    expect(await store.read(cookie)).toBe(null);
  });

  it("bounds a store built without maxAgeMs by the 14-day default", async () => {
    using time = new FakeTime(1_700_000_000_000);
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const store = new EncryptedCookieSessionStore({ secret });
    expect(store.maxAgeMs).toBe(DEFAULT_SESSION_MAX_AGE_MS);
    const cookie = await store.create(makeSessionData());

    time.tick(DEFAULT_SESSION_MAX_AGE_MS - 1);
    expect((await store.read(cookie))?.tokens.accessToken).toStrictEqual("abc");

    time.tick(2);
    expect(await store.read(cookie)).toBe(null);
  });

  it("refuses a non-positive maxAgeMs instead of silently never expiring", () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    thrown(
      () => new EncryptedCookieSessionStore({ secret, maxAgeMs: 0 }),
      Error,
      "maxAgeMs must be a positive number of milliseconds",
    );
  });

  it("reports its bound so a BFF can check its cookie outlives it", () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const store = new EncryptedCookieSessionStore({ secret, maxAgeMs: 60_000 });
    expect(sessionStoreMaxAgeMs(store)).toBe(60_000);
    expect(sessionStoreMaxAgeMs(new MemorySessionStore())).toBe(undefined);
  });
});

describe("EncryptedCookieSessionStore cookie shape", () => {
  it("refuses an authentic payload sealed without the seal-time envelope", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveCookieKey(secret, SESSION_COOKIE_KEY_INFO);
    const store = new EncryptedCookieSessionStore({ secret });
    const data = makeSessionData();
    const payloads: unknown[] = [
      data,
      { issuedAt: String(Date.now()), data },
      { issuedAt: Date.now(), data: null },
      { issuedAt: Date.now() },
      [{ issuedAt: Date.now(), data }],
      "session",
      42,
      null,
    ];
    for (const payload of payloads) {
      expect(
        await store.read(await sealJson(key, payload)),
        JSON.stringify(payload),
      ).toBe(null);
    }
  });

  it("reads nothing sealed under the pending-sign-in key of the same secret", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const store = new EncryptedCookieSessionStore({ secret });
    const sealed = await sealJson(
      await deriveCookieKey(secret, AUTH_REQUEST_COOKIE_KEY_INFO),
      { issuedAt: Date.now(), data: makeSessionData() },
    );
    expect(await store.read(sealed)).toBe(null);
  });

  it("reads nothing from a cookie sealed under the secret's bare SHA-256", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const store = new EncryptedCookieSessionStore({ secret });
    const bareSha256Key = await crypto.subtle.importKey(
      "raw",
      await crypto.subtle.digest("SHA-256", secret),
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
    const sealed = await sealJson(bareSha256Key, {
      issuedAt: Date.now(),
      data: makeSessionData(),
    });
    expect(await store.read(sealed)).toBe(null);
  });
});

describe("MemorySessionStore", () => {
  it("separates sessions by cookie value", async () => {
    const store = new MemorySessionStore();
    const a = await store.create(
      makeSessionData({
        tokens: { accessToken: "a", tokenType: "Bearer" },
      }),
    );
    const b = await store.create(
      makeSessionData({
        tokens: { accessToken: "b", tokenType: "Bearer" },
      }),
    );

    expect(a).not.toBe(b);
    expect((await store.read(a))?.tokens.accessToken).toBe("a");
    expect((await store.read(b))?.tokens.accessToken).toBe("b");

    await store.destroy(a);
    expect(await store.read(a)).toBe(null);
    expect((await store.read(b))?.tokens.accessToken).toBe("b");
  });
});

describe("MemorySessionStore refresh lease", () => {
  const LEASE_MS = 300;

  function leaseOf(lease: RefreshLease | undefined): RefreshLease {
    assert(lease !== undefined, "MemorySessionStore must pass a lease");
    return lease;
  }

  it("refuses a lease setting that is not a positive number of milliseconds a timer can hold", () => {
    for (const bad of [0, -1, Number.NaN, Infinity, 2 ** 31, 1e10]) {
      thrown(
        () => new MemorySessionStore({ refreshLeaseMs: bad }),
        RangeError,
        "refreshLeaseMs",
      );
      thrown(
        () => new MemorySessionStore({ refreshLockWaitMs: bad }),
        RangeError,
        "refreshLockWaitMs",
      );
    }
  });

  it("renews a lease at the longest setting on its own schedule, not every millisecond", async () => {
    using time = new FakeTime();
    const leaseMs = 2 ** 31 - 1;
    const store = new MemorySessionStore({
      refreshLeaseMs: leaseMs,
      refreshLockWaitMs: leaseMs,
    });
    const value = await store.create(makeSessionData());
    const release = Promise.withResolvers<void>();
    using setIntervalSpy = vi.spyOn(globalThis, "setInterval");
    const holder = store.withRefreshLock(value, () => release.promise);
    await time.tickAsync(0);

    const delays = setIntervalSpy.mock.calls.map(([, delay]) => delay);
    expect(delays).toStrictEqual([leaseMs / 3]);
    release.resolve();
    await holder;
  });

  it("loses a lease that lapsed: another call takes the lock, and the lapsed lease can neither write nor destroy", async () => {
    using time = new FakeTime();
    const store = new MemorySessionStore({ refreshLeaseMs: LEASE_MS });
    const value = await store.create(makeSessionData({ refreshToken: "r1" }));
    const stalled = Promise.withResolvers<void>();
    const holding = Promise.withResolvers<void>();

    const lapsed = store.withRefreshLock(value, async (given) => {
      const lease = leaseOf(given);
      holding.resolve();
      await stalled.promise;
      return {
        write: await rejection(
          lease.update(makeSessionData({ refreshToken: "lapsed" })),
        ),
        destroyed: await lease.destroy("r2"),
      };
    });
    await time.settle(holding.promise);
    const takeover = store.withRefreshLock(value, (given) =>
      leaseOf(given).update(makeSessionData({ refreshToken: "r2" })),
    );
    vi.setSystemTime(time.now + 3 * LEASE_MS);

    expect(await time.settle(takeover)).toBe(value);
    stalled.resolve();
    const outcome = await time.settle(lapsed);

    expect(
      outcome.write,
      "a holder whose lease lapsed overwrote the refresh of the call that took it",
    ).toBeInstanceOf(InvalidGrantError);
    expect(
      outcome.destroyed,
      "a holder whose lease lapsed ended the session the next holder refreshed",
    ).toBe(false);
    expect((await store.read(value))?.refreshToken).toBe("r2");
    expect(vi.getTimerCount(), "a settled lease left a timer running").toBe(0);
  });

  it("renews a running refresh's lease, so a waiter gives up instead of taking it", async () => {
    using time = new FakeTime();
    const store = new MemorySessionStore({
      refreshLeaseMs: LEASE_MS,
      refreshLockWaitMs: 2 * LEASE_MS,
    });
    const value = await store.create(makeSessionData({ refreshToken: "r1" }));
    const exchange = Promise.withResolvers<void>();
    const holding = Promise.withResolvers<void>();
    const holder = store.withRefreshLock(value, async (given) => {
      holding.resolve();
      await exchange.promise;
      return await leaseOf(given).update(
        makeSessionData({ refreshToken: "r2" }),
      );
    });
    await time.settle(holding.promise);

    const waiter = store
      .withRefreshLock(value, () => Promise.resolve("the waiter took the lock"))
      .catch((error: unknown) => error);
    const waited = await time.settle(waiter);
    await time.tickAsync(5 * LEASE_MS);
    exchange.resolve();

    expect(
      waited,
      "the waiter took the lock from a holder whose refresh was still running",
    ).toBeInstanceOf(Error);
    expect(await time.settle(holder)).toBe(value);
    expect((await store.read(value))?.refreshToken).toBe("r2");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("hands the lock to a waiting call as soon as the holder releases it", async () => {
    using time = new FakeTime();
    const store = new MemorySessionStore({ refreshLeaseMs: LEASE_MS });
    const value = await store.create(makeSessionData());
    const release = Promise.withResolvers<void>();
    const holder = store.withRefreshLock(value, () => release.promise);
    const waiter = store.withRefreshLock(value, () =>
      Promise.resolve(time.now),
    );
    await time.tickAsync(LEASE_MS / 2);
    const releasedAt = time.now;
    release.resolve();

    await holder;
    expect(await waiter).toBe(releasedAt);
  });
});
