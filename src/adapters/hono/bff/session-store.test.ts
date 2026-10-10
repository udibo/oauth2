import { describe, expect, it, vi } from "vitest";
import { FakeTime } from "../../../_test_fake-time.ts";
import { thrown } from "../../../_test_assert.ts";
import { deriveAesKey, sealJson } from "../../../utils/crypto.ts";
import {
  DEFAULT_SESSION_MAX_AGE_MS,
  EncryptedCookieSessionStore,
  MemorySessionStore,
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

  it("throws when the secret list is empty", () => {
    thrown(
      () => new EncryptedCookieSessionStore({ secret: [] }),
      Error,
      "secret must not be an empty list.",
    );
  });

  it("starts no key derivation until an operation needs the key", async () => {
    using digest = vi.spyOn(crypto.subtle, "digest");
    const store = new EncryptedCookieSessionStore({
      secret: [
        crypto.getRandomValues(new Uint8Array(32)),
        crypto.getRandomValues(new Uint8Array(32)),
      ],
    });
    expect(digest).toHaveBeenCalledTimes(0);

    const cookie = await store.create(makeSessionData());
    expect(digest).toHaveBeenCalledTimes(1);

    await store.read(cookie);
    expect(digest).toHaveBeenCalledTimes(1);
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

describe("EncryptedCookieSessionStore legacy payload compatibility", () => {
  it("reads a pre-rotation payload sealed without an issuedAt envelope", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const data = makeSessionData();
    const legacyCookie = await sealJson(await deriveAesKey(secret), data);

    const store = new EncryptedCookieSessionStore({ secret });
    expect(await store.read(legacyCookie)).toStrictEqual(data);
  });

  it("bounds a legacy payload by its updatedAt when a max age is set", async () => {
    using _time = new FakeTime(1_700_000_000_000);
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const staleData = makeSessionData({
      createdAt: Date.now() - 120_000,
      updatedAt: Date.now() - 120_000,
    });
    const legacyCookie = await sealJson(await deriveAesKey(secret), staleData);

    const store = new EncryptedCookieSessionStore({ secret, maxAgeMs: 60_000 });
    expect(await store.read(legacyCookie)).toBe(null);
  });

  it("accepts a recent legacy payload within the max age", async () => {
    using _time = new FakeTime(1_700_000_000_000);
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const recentData = makeSessionData({
      createdAt: Date.now() - 10_000,
      updatedAt: Date.now() - 10_000,
    });
    const legacyCookie = await sealJson(await deriveAesKey(secret), recentData);

    const store = new EncryptedCookieSessionStore({ secret, maxAgeMs: 60_000 });
    expect(await store.read(legacyCookie)).toStrictEqual(recentData);
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
