import { describe, expect, it } from "vitest";
import { FakeTime } from "../_test_fake-time.ts";
import { MemoryAuthRequestStorage } from "./storage.ts";

const TEN_MINUTES = 10 * 60 * 1000;

describe("MemoryAuthRequestStorage", () => {
  it("prunes records past the TTL when a new one is written", () => {
    using time = new FakeTime();
    const storage = new MemoryAuthRequestStorage();
    storage.set("abandoned", { codeVerifier: "v1", createdAt: Date.now() });

    time.tick(TEN_MINUTES + 1);
    storage.set("fresh", { codeVerifier: "v2", createdAt: Date.now() });

    expect(storage.get("abandoned")).toBe(null);
    expect(storage.get("fresh")?.codeVerifier).toStrictEqual("v2");
  });

  it("keeps records still inside the TTL when a new one is written", () => {
    using time = new FakeTime();
    const storage = new MemoryAuthRequestStorage();
    storage.set("pending", { codeVerifier: "v1", createdAt: Date.now() });

    time.tick(TEN_MINUTES);
    storage.set("fresh", { codeVerifier: "v2", createdAt: Date.now() });

    expect(storage.get("pending")?.codeVerifier).toStrictEqual("v1");
  });

  it("honours a configured TTL", () => {
    using time = new FakeTime();
    const storage = new MemoryAuthRequestStorage({ ttlMs: 1000 });
    storage.set("abandoned", { codeVerifier: "v1", createdAt: Date.now() });

    time.tick(1001);
    storage.set("fresh", { codeVerifier: "v2", createdAt: Date.now() });

    expect(storage.get("abandoned")).toBe(null);
  });

  it("never prunes with an infinite TTL", () => {
    using time = new FakeTime();
    const storage = new MemoryAuthRequestStorage({ ttlMs: Infinity });
    storage.set("pending", { codeVerifier: "v1", createdAt: Date.now() });

    time.tick(365 * 24 * 60 * 60 * 1000);
    storage.set("fresh", { codeVerifier: "v2", createdAt: Date.now() });

    expect(storage.get("pending")?.codeVerifier).toStrictEqual("v1");
  });

  it("visits only the expired prefix and the first fresh record when pruning", () => {
    using time = new FakeTime();
    const storage = new MemoryAuthRequestStorage();
    let visits = 0;
    const countedRecord = (codeVerifier: string) => {
      const createdAt = Date.now();
      return {
        codeVerifier,
        get createdAt() {
          visits++;
          return createdAt;
        },
      };
    };
    storage.set("expired-1", countedRecord("v1"));
    storage.set("expired-2", countedRecord("v2"));
    time.tick(TEN_MINUTES + 1);
    for (let i = 0; i < 100; i++) storage.set(`fresh-${i}`, countedRecord("v"));

    visits = 0;
    storage.set("next", { codeVerifier: "v", createdAt: Date.now() });

    expect(visits).toStrictEqual(1);
    expect(storage.get("expired-1")).toBe(null);
    expect(storage.get("expired-2")).toBe(null);
  });

  it("prunes a record rewritten under an existing state by its newest write", () => {
    using time = new FakeTime();
    const storage = new MemoryAuthRequestStorage();
    storage.set("rewritten", { codeVerifier: "v1", createdAt: Date.now() });
    storage.set("abandoned", { codeVerifier: "v2", createdAt: Date.now() });

    time.tick(60_000);
    storage.set("rewritten", { codeVerifier: "v3", createdAt: Date.now() });
    time.tick(TEN_MINUTES - 60_000 + 1);
    storage.set("fresh", { codeVerifier: "v4", createdAt: Date.now() });

    expect(storage.get("abandoned")).toBe(null);
    expect(storage.get("rewritten")?.codeVerifier).toStrictEqual("v3");
  });

  it("keeps at most maxEntries records under a burst, evicting the oldest write first", () => {
    const storage = new MemoryAuthRequestStorage({ maxEntries: 3 });
    for (let i = 0; i < 20; i++) {
      storage.set(`state-${i}`, {
        codeVerifier: `v${i}`,
        createdAt: Date.now(),
      });
    }

    const kept = Array.from({ length: 20 }, (_, i) => `state-${i}`).filter(
      (state) => storage.get(state) !== null,
    );
    expect(kept).toStrictEqual(["state-17", "state-18", "state-19"]);
  });

  it("caps the store at 1000 records by default", () => {
    const storage = new MemoryAuthRequestStorage();
    for (let i = 0; i <= 1000; i++) {
      storage.set(`state-${i}`, { codeVerifier: "v", createdAt: Date.now() });
    }

    expect(storage.get("state-0")).toBe(null);
    expect(storage.get("state-1")?.codeVerifier).toStrictEqual("v");
    expect(storage.get("state-1000")?.codeVerifier).toStrictEqual("v");
  });

  it("evicts nothing when a write replaces a record already at the cap", () => {
    const storage = new MemoryAuthRequestStorage({ maxEntries: 2 });
    storage.set("a", { codeVerifier: "v1", createdAt: Date.now() });
    storage.set("b", { codeVerifier: "v2", createdAt: Date.now() });
    storage.set("a", { codeVerifier: "v3", createdAt: Date.now() });

    expect(storage.get("a")?.codeVerifier).toStrictEqual("v3");
    expect(storage.get("b")?.codeVerifier).toStrictEqual("v2");
  });

  it("counts a rewritten record as the newest when choosing what to evict", () => {
    const storage = new MemoryAuthRequestStorage({ maxEntries: 2 });
    storage.set("a", { codeVerifier: "v1", createdAt: Date.now() });
    storage.set("b", { codeVerifier: "v2", createdAt: Date.now() });
    storage.set("a", { codeVerifier: "v3", createdAt: Date.now() });
    storage.set("c", { codeVerifier: "v4", createdAt: Date.now() });

    expect(storage.get("b")).toBe(null);
    expect(storage.get("a")?.codeVerifier).toStrictEqual("v3");
    expect(storage.get("c")?.codeVerifier).toStrictEqual("v4");
  });

  it("never evicts by count with an infinite maxEntries", () => {
    const storage = new MemoryAuthRequestStorage({ maxEntries: Infinity });
    for (let i = 0; i <= 1000; i++) {
      storage.set(`state-${i}`, { codeVerifier: "v", createdAt: Date.now() });
    }

    expect(storage.get("state-0")?.codeVerifier).toStrictEqual("v");
  });

  it("refuses a maxEntries that is not a positive integer", () => {
    for (const maxEntries of [0, -1, 1.5, Number.NaN]) {
      expect(
        () => new MemoryAuthRequestStorage({ maxEntries }),
        `maxEntries ${maxEntries}`,
      ).toThrow(RangeError);
    }
  });

  it("take returns a record once and removes it", () => {
    const storage = new MemoryAuthRequestStorage();
    storage.set("state-1", { codeVerifier: "v1", createdAt: Date.now() });

    expect(storage.take("state-1")?.codeVerifier).toStrictEqual("v1");
    expect(storage.take("state-1")).toBe(null);
    expect(storage.get("state-1")).toBe(null);
  });
});
