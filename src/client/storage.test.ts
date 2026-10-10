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

  it("take returns a record once and removes it", () => {
    const storage = new MemoryAuthRequestStorage();
    storage.set("state-1", { codeVerifier: "v1", createdAt: Date.now() });

    expect(storage.take("state-1")?.codeVerifier).toStrictEqual("v1");
    expect(storage.take("state-1")).toBe(null);
    expect(storage.get("state-1")).toBe(null);
  });
});
