import { describe, expect, it } from "vitest";
import { constantTimeEqual } from "./_constant-time.ts";

describe("constantTimeEqual", () => {
  it("is true for equal bytes, including two empty arrays", () => {
    expect(constantTimeEqual(new Uint8Array(), new Uint8Array())).toBe(true);
    expect(
      constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])),
    ).toBe(true);
  });

  it("is false when any single byte differs, wherever it is", () => {
    const base = crypto.getRandomValues(new Uint8Array(32));
    for (let index = 0; index < base.length; index++) {
      const other = base.slice();
      other[index] = other[index]! ^ 0x01;
      expect(constantTimeEqual(base, other), `byte ${index}`).toBe(false);
    }
  });

  it("is false for different lengths, even when one is a prefix of the other", () => {
    expect(
      constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0])),
    ).toBe(false);
  });

  it("compares the viewed bytes of a subarray, not its backing buffer", () => {
    const backing = new Uint8Array([9, 1, 2, 3, 9]);
    expect(
      constantTimeEqual(backing.subarray(1, 4), new Uint8Array([1, 2, 3])),
    ).toBe(true);
  });
});
