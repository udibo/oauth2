import { assertNotStrictEquals, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { sha256Hash } from "./hash.ts";

describe("sha256Hash", () => {
  it("should generate consistent hash for same input", async () => {
    const hash1 = await sha256Hash("test-value");
    const hash2 = await sha256Hash("test-value");
    assertStrictEquals(hash1, hash2);
  });

  it("should generate different hashes for different inputs", async () => {
    const hash1 = await sha256Hash("value-1");
    const hash2 = await sha256Hash("value-2");
    assertNotStrictEquals(hash1, hash2);
  });

  it("should generate 64 character hex string (256 bits)", async () => {
    const hash = await sha256Hash("test-value");
    assertStrictEquals(hash.length, 64);
    assertStrictEquals(/^[0-9a-f]+$/.test(hash), true);
  });

  it("should hash a UUID", async () => {
    const uuid = crypto.randomUUID();
    const hash = await sha256Hash(uuid);
    assertStrictEquals(hash.length, 64);
    assertNotStrictEquals(hash, uuid);
  });
});
