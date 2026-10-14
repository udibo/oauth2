import { describe, expect, it } from "vitest";

import { FakeTime } from "../../../_test_fake-time.ts";
import { RotatedCookies } from "./_rotated-cookies.ts";

describe("RotatedCookies", () => {
  it("leads a replaced cookie to the one that replaced it", async () => {
    const memo = new RotatedCookies(10_000, 10);
    await memo.remember("c0", "c1");

    expect(await memo.successor("c0")).toBe("c1");
    expect(await memo.successor("c1")).toBe(undefined);
  });

  it("forgets a replacement once its window has passed", async () => {
    using time = new FakeTime();
    const memo = new RotatedCookies(10_000, 10);
    await memo.remember("c0", "c1");

    time.tick(9_999);
    expect(await memo.successor("c0")).toBe("c1");
    time.tick(1);
    expect(await memo.successor("c0")).toBe(undefined);
  });

  it("drops the oldest replacement beyond maxEntries", async () => {
    const memo = new RotatedCookies(10_000, 2);
    await memo.remember("a0", "a1");
    await memo.remember("b0", "b1");
    await memo.remember("c0", "c1");

    expect(await memo.successor("a0")).toBe(undefined);
    expect(await memo.successor("b0")).toBe("b1");
    expect(await memo.successor("c0")).toBe("c1");
  });

  it("forgets the whole chain a cookie belongs to, from either end", async () => {
    for (const ended of ["c0", "c1", "c2"]) {
      const memo = new RotatedCookies(10_000, 10);
      await memo.remember("c0", "c1");
      await memo.remember("c1", "c2");
      await memo.remember("other0", "other1");

      await memo.forget(ended);

      expect(await memo.successor("c0"), ended).toBe(undefined);
      expect(await memo.successor("c1"), ended).toBe(undefined);
      expect(await memo.successor("other0"), ended).toBe("other1");
    }
  });
});
