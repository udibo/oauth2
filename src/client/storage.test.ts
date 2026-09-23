import { assertEquals, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { FakeTime } from "@std/testing/time";

import { MemoryAuthRequestStorage } from "./storage.ts";

const TEN_MINUTES = 10 * 60 * 1000;

describe("MemoryAuthRequestStorage", () => {
  it("prunes records past the TTL when a new one is written", () => {
    using time = new FakeTime();
    const storage = new MemoryAuthRequestStorage();
    storage.set("abandoned", { codeVerifier: "v1", createdAt: Date.now() });

    time.tick(TEN_MINUTES + 1);
    storage.set("fresh", { codeVerifier: "v2", createdAt: Date.now() });

    assertStrictEquals(storage.get("abandoned"), null);
    assertEquals(storage.get("fresh")?.codeVerifier, "v2");
  });

  it("keeps records still inside the TTL when a new one is written", () => {
    using time = new FakeTime();
    const storage = new MemoryAuthRequestStorage();
    storage.set("pending", { codeVerifier: "v1", createdAt: Date.now() });

    time.tick(TEN_MINUTES);
    storage.set("fresh", { codeVerifier: "v2", createdAt: Date.now() });

    assertEquals(storage.get("pending")?.codeVerifier, "v1");
  });

  it("honours a configured TTL", () => {
    using time = new FakeTime();
    const storage = new MemoryAuthRequestStorage({ ttlMs: 1000 });
    storage.set("abandoned", { codeVerifier: "v1", createdAt: Date.now() });

    time.tick(1001);
    storage.set("fresh", { codeVerifier: "v2", createdAt: Date.now() });

    assertStrictEquals(storage.get("abandoned"), null);
  });

  it("never prunes with an infinite TTL", () => {
    using time = new FakeTime();
    const storage = new MemoryAuthRequestStorage({ ttlMs: Infinity });
    storage.set("pending", { codeVerifier: "v1", createdAt: Date.now() });

    time.tick(365 * 24 * 60 * 60 * 1000);
    storage.set("fresh", { codeVerifier: "v2", createdAt: Date.now() });

    assertEquals(storage.get("pending")?.codeVerifier, "v1");
  });

  it("take returns a record once and removes it", () => {
    const storage = new MemoryAuthRequestStorage();
    storage.set("state-1", { codeVerifier: "v1", createdAt: Date.now() });

    assertEquals(storage.take("state-1")?.codeVerifier, "v1");
    assertStrictEquals(storage.take("state-1"), null);
    assertStrictEquals(storage.get("state-1"), null);
  });
});
