import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  base64urlDecode,
  base64urlEncode,
  deriveAesKey,
  deriveSealKey,
  randomToken,
  seal,
  sealJson,
  timingSafeEqualString,
  unseal,
  unsealJson,
} from "./crypto.ts";
import { timingSafeMatchIndex } from "./_timing-safe.ts";

const SECRET = "a-high-entropy-secret-of-at-least-32-bytes!!";

describe("base64url", () => {
  it("round-trips arbitrary bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 255, 65, 66]);
    assertEquals(base64urlDecode(base64urlEncode(bytes)), bytes);
  });

  it("is URL-safe (no +, /, =)", () => {
    const enc = base64urlEncode(new Uint8Array([251, 255, 191, 254]));
    assertEquals(/[+/=]/.test(enc), false);
  });

  it("decodes an unpadded base64url string", () => {
    assertEquals(
      new TextDecoder().decode(base64urlDecode("eyJzdWIiOiIxMjMifQ")),
      '{"sub":"123"}',
    );
  });

  it("round-trips every remainder length without padding", () => {
    for (let length = 0; length <= 8; length++) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      const encoded = base64urlEncode(bytes);
      assertEquals(encoded.includes("="), false);
      assertEquals(base64urlDecode(encoded), bytes);
    }
  });

  it("still decodes a padded value", () => {
    assertEquals(base64urlDecode("-_8="), new Uint8Array([251, 255]));
    assertEquals(base64urlDecode("-_8"), new Uint8Array([251, 255]));
  });

  it("decodes UTF-8 claims without corrupting non-ASCII", () => {
    const claims = { name: "Ünïcødé ☃" };
    const encoded = base64urlEncode(
      new TextEncoder().encode(JSON.stringify(claims)),
    );
    assertEquals(
      JSON.parse(new TextDecoder().decode(base64urlDecode(encoded))),
      claims,
    );
  });

  it("rejects the standard base64 alphabet and whitespace", () => {
    assertThrows(() => base64urlDecode("a+b/"), TypeError);
    assertThrows(() => base64urlDecode(" QQ "), TypeError);
  });

  it("rejects a truncated value with a RangeError, not a TypeError", () => {
    assertThrows(() => base64urlDecode("a"), RangeError);
    assertThrows(() => base64urlDecode("abcde"), RangeError);
  });
});

describe("randomToken", () => {
  it("defaults to 32 bytes, encoded as 43 unpadded characters", () => {
    const token = randomToken();
    assertEquals(token.length, 43);
    assertEquals(base64urlDecode(token).length, 32);
  });

  it("uses only URL-safe characters", () => {
    for (let i = 0; i < 50; i++) {
      assertEquals(/^[A-Za-z0-9_-]+$/.test(randomToken()), true);
    }
  });

  it("honors a custom byte count", () => {
    assertEquals(base64urlDecode(randomToken(16)).length, 16);
    assertEquals(randomToken(16).length, 22);
    assertEquals(randomToken(64).length, 86);
  });

  it("does not repeat across calls", () => {
    const tokens = new Set(Array.from({ length: 500 }, () => randomToken()));
    assertEquals(tokens.size, 500);
  });
});

describe("deriveAesKey + seal/unseal", () => {
  it("round-trips bytes", async () => {
    const key = await deriveAesKey(SECRET);
    const data = new TextEncoder().encode("hello tokens");
    const opened = await unseal(key, await seal(key, data));
    assertEquals(opened, data);
  });

  it("returns null on a tampered ciphertext", async () => {
    const key = await deriveAesKey(SECRET);
    const sealed = await seal(key, new TextEncoder().encode("x"));
    const bytes = base64urlDecode(sealed);
    bytes[bytes.length - 1] ^= 0xff;
    assertEquals(await unseal(key, base64urlEncode(bytes)), null);
  });

  it("returns null with the wrong key", async () => {
    const a = await deriveAesKey(SECRET);
    const b = await deriveAesKey(`${SECRET}-different`);
    const sealed = await seal(a, new TextEncoder().encode("x"));
    assertEquals(await unseal(b, sealed), null);
  });

  it("rejects a too-short secret", async () => {
    let threw = false;
    try {
      await deriveAesKey("short");
    } catch {
      threw = true;
    }
    assertEquals(threw, true);
  });

  it("returns null for a value too short to hold an IV", async () => {
    const key = await deriveAesKey(SECRET);
    assertEquals(await unseal(key, base64urlEncode(new Uint8Array(5))), null);
  });
});

describe("deriveSealKey (HKDF) domain separation", () => {
  it("keys with different info labels cannot unseal each other's data", async () => {
    const a = await deriveSealKey(SECRET, "purpose-a");
    const b = await deriveSealKey(SECRET, "purpose-b");
    const sealed = await seal(a, new TextEncoder().encode("secret"));
    assertEquals(await unseal(b, sealed), null);
  });

  it("the HKDF key is independent of the SHA-256-derived key", async () => {
    const sealKey = await deriveSealKey(SECRET, "udibo:bff-session-tokens:v1");
    const hashKey = await deriveAesKey(SECRET);
    const sealed = await seal(sealKey, new TextEncoder().encode("token"));
    assertEquals(await unseal(hashKey, sealed), null);
  });

  it("same secret + same info round-trips", async () => {
    const data = new TextEncoder().encode("stable");
    const k1 = await deriveSealKey(SECRET, "same");
    const sealed = await seal(k1, data);
    const k2 = await deriveSealKey(SECRET, "same");
    assertEquals(await unseal(k2, sealed), data);
  });
});

describe("sealJson / unsealJson", () => {
  it("round-trips a JSON value", async () => {
    const key = await deriveSealKey(SECRET, "json");
    const value = { accessToken: "at", refreshToken: "rt", n: 7 };
    assertEquals(await unsealJson(key, await sealJson(key, value)), value);
  });

  it("returns null when it can't be unsealed", async () => {
    const key = await deriveSealKey(SECRET, "json");
    assertEquals(await unsealJson(key, "not-a-valid-sealed-value"), null);
  });

  it("returns null when the bytes decrypt but aren't JSON", async () => {
    const key = await deriveSealKey(SECRET, "json");
    const sealed = await seal(
      key,
      new TextEncoder().encode("definitely not json"),
    );
    assertEquals(await unsealJson(key, sealed), null);
  });
});

function coercible(value: string): string {
  return { toString: () => value } as unknown as string;
}

function countingCandidates(
  values: string[],
): { candidates: string[]; reads: () => number } {
  let reads = 0;
  const candidates = values.slice();
  for (let index = 0; index < values.length; index++) {
    Object.defineProperty(candidates, index, {
      configurable: true,
      get: () => {
        reads++;
        return values[index];
      },
    });
  }
  return { candidates, reads: () => reads };
}

describe("timingSafeEqualString", () => {
  it("is true for equal strings", () => {
    assertEquals(timingSafeEqualString("hunter2", "hunter2"), true);
  });

  it("is false for different strings of the same length", () => {
    assertEquals(timingSafeEqualString("hunter2", "hunter3"), false);
    assertEquals(timingSafeEqualString("hunter2", "xunter2"), false);
  });

  it("is false when the lengths differ", () => {
    assertEquals(timingSafeEqualString("hunter2", "hunter22"), false);
    assertEquals(timingSafeEqualString("", "h"), false);
  });

  it("is true for two empty strings", () => {
    assertEquals(timingSafeEqualString("", ""), true);
  });

  it("decides equality from the encoded bytes, not JavaScript string identity", () => {
    assertEquals(
      timingSafeEqualString(coercible("hunter2"), coercible("hunter2")),
      true,
    );
    assertEquals(
      timingSafeEqualString(coercible("hunter2"), coercible("hunter3")),
      false,
    );
  });

  it("compares non-ASCII values by their UTF-8 bytes", () => {
    assertEquals(timingSafeEqualString("café ☃", "café ☃"), true);
    assertEquals(timingSafeEqualString("café ☃", "café ☂"), false);
  });
});

describe("timingSafeMatchIndex", () => {
  it("returns the index of the matching candidate", () => {
    assertEquals(timingSafeMatchIndex(["a", "b", "c"], "b"), 1);
  });

  it("returns undefined when no candidate matches", () => {
    assertEquals(timingSafeMatchIndex(["a", "b", "c"], "d"), undefined);
  });

  it("returns undefined for an empty candidate list", () => {
    assertEquals(timingSafeMatchIndex([], "a"), undefined);
  });

  it("returns the last matching candidate so a duplicate resolves to the preferred entry", () => {
    assertEquals(timingSafeMatchIndex(["secret", "b", "secret"], "secret"), 2);
  });

  it("reads every candidate after the first one matches", () => {
    const { candidates, reads } = countingCandidates(["a", "b", "c"]);
    assertEquals(timingSafeMatchIndex(candidates, "a"), 0);
    assertEquals(reads(), 3);
  });

  it("reads every candidate when none matches", () => {
    const { candidates, reads } = countingCandidates(["a", "b", "c"]);
    assertEquals(timingSafeMatchIndex(candidates, "d"), undefined);
    assertEquals(reads(), 3);
  });

  it("reads every candidate after a match in the middle", () => {
    const { candidates, reads } = countingCandidates(["a", "b", "c", "d"]);
    assertEquals(timingSafeMatchIndex(candidates, "b"), 1);
    assertEquals(reads(), 4);
  });

  it("compares each candidate with the constant-time comparison, not JavaScript equality", () => {
    const candidates = ["a", "secret", "c"].map(coercible);
    assertEquals(timingSafeMatchIndex(candidates, "secret"), 1);
  });
});
