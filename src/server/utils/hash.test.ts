import { describe, expect, it } from "vitest";
import { sha256Hash } from "./hash.ts";

describe("sha256Hash", () => {
  it("should generate consistent hash for same input", async () => {
    const hash1 = await sha256Hash("test-value");
    const hash2 = await sha256Hash("test-value");
    expect(hash1).toBe(hash2);
  });

  it("should generate different hashes for different inputs", async () => {
    const hash1 = await sha256Hash("value-1");
    const hash2 = await sha256Hash("value-2");
    expect(hash1).not.toBe(hash2);
  });

  it("should generate 64 character hex string (256 bits)", async () => {
    const hash = await sha256Hash("test-value");
    expect(hash.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(hash)).toBe(true);
  });

  it("should hash a UUID", async () => {
    const uuid = crypto.randomUUID();
    const hash = await sha256Hash(uuid);
    expect(hash.length).toBe(64);
    expect(hash).not.toBe(uuid);
  });
});
