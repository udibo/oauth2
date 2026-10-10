import { describe, expect, it } from "vitest";
import { thrown } from "../_test_assert.ts";
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
    expect(base64urlDecode(base64urlEncode(bytes))).toStrictEqual(bytes);
  });

  it("is URL-safe (no +, /, =)", () => {
    const enc = base64urlEncode(new Uint8Array([251, 255, 191, 254]));
    expect(/[+/=]/.test(enc)).toStrictEqual(false);
  });

  it("decodes an unpadded base64url string", () => {
    expect(
      new TextDecoder().decode(base64urlDecode("eyJzdWIiOiIxMjMifQ")),
    ).toStrictEqual('{"sub":"123"}');
  });

  it("round-trips every remainder length without padding", () => {
    for (let length = 0; length <= 8; length++) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      const encoded = base64urlEncode(bytes);
      expect(encoded.includes("=")).toStrictEqual(false);
      expect(base64urlDecode(encoded)).toStrictEqual(bytes);
    }
  });

  it("still decodes a padded value", () => {
    expect(base64urlDecode("-_8=")).toStrictEqual(new Uint8Array([251, 255]));
    expect(base64urlDecode("-_8")).toStrictEqual(new Uint8Array([251, 255]));
  });

  it("decodes UTF-8 claims without corrupting non-ASCII", () => {
    const claims = { name: "Ünïcødé ☃" };
    const encoded = base64urlEncode(
      new TextEncoder().encode(JSON.stringify(claims)),
    );
    expect(
      JSON.parse(new TextDecoder().decode(base64urlDecode(encoded))),
    ).toStrictEqual(claims);
  });

  it("rejects the standard base64 alphabet and whitespace", () => {
    thrown(() => base64urlDecode("a+b/"), TypeError);
    thrown(() => base64urlDecode(" QQ "), TypeError);
  });

  it("rejects a truncated value with a RangeError, not a TypeError", () => {
    thrown(() => base64urlDecode("a"), RangeError);
    thrown(() => base64urlDecode("abcde"), RangeError);
  });
});

describe("randomToken", () => {
  it("defaults to 32 bytes, encoded as 43 unpadded characters", () => {
    const token = randomToken();
    expect(token.length).toStrictEqual(43);
    expect(base64urlDecode(token).length).toStrictEqual(32);
  });

  it("uses only URL-safe characters", () => {
    for (let i = 0; i < 50; i++) {
      expect(/^[A-Za-z0-9_-]+$/.test(randomToken())).toStrictEqual(true);
    }
  });

  it("honors a custom byte count", () => {
    expect(base64urlDecode(randomToken(16)).length).toStrictEqual(16);
    expect(randomToken(16).length).toStrictEqual(22);
    expect(randomToken(64).length).toStrictEqual(86);
  });

  it("does not repeat across calls", () => {
    const tokens = new Set(Array.from({ length: 500 }, () => randomToken()));
    expect(tokens.size).toStrictEqual(500);
  });
});

describe("deriveAesKey + seal/unseal", () => {
  it("round-trips bytes", async () => {
    const key = await deriveAesKey(SECRET);
    const data = new TextEncoder().encode("hello tokens");
    const opened = await unseal(key, await seal(key, data));
    expect(opened).toStrictEqual(data);
  });

  it("returns null on a tampered ciphertext", async () => {
    const key = await deriveAesKey(SECRET);
    const sealed = await seal(key, new TextEncoder().encode("x"));
    const bytes = base64urlDecode(sealed);
    bytes[bytes.length - 1] ^= 0xff;
    expect(await unseal(key, base64urlEncode(bytes))).toStrictEqual(null);
  });

  it("returns null with the wrong key", async () => {
    const a = await deriveAesKey(SECRET);
    const b = await deriveAesKey(`${SECRET}-different`);
    const sealed = await seal(a, new TextEncoder().encode("x"));
    expect(await unseal(b, sealed)).toStrictEqual(null);
  });

  it("rejects a too-short secret", async () => {
    let threw = false;
    try {
      await deriveAesKey("short");
    } catch {
      threw = true;
    }
    expect(threw).toStrictEqual(true);
  });

  it("returns null for a value too short to hold an IV", async () => {
    const key = await deriveAesKey(SECRET);
    expect(await unseal(key, base64urlEncode(new Uint8Array(5)))).toStrictEqual(
      null,
    );
  });
});

describe("deriveSealKey (HKDF) domain separation", () => {
  it("keys with different info labels cannot unseal each other's data", async () => {
    const a = await deriveSealKey(SECRET, "purpose-a");
    const b = await deriveSealKey(SECRET, "purpose-b");
    const sealed = await seal(a, new TextEncoder().encode("secret"));
    expect(await unseal(b, sealed)).toStrictEqual(null);
  });

  it("the HKDF key is independent of the SHA-256-derived key", async () => {
    const sealKey = await deriveSealKey(SECRET, "udibo:bff-session-tokens:v1");
    const hashKey = await deriveAesKey(SECRET);
    const sealed = await seal(sealKey, new TextEncoder().encode("token"));
    expect(await unseal(hashKey, sealed)).toStrictEqual(null);
  });

  it("same secret + same info round-trips", async () => {
    const data = new TextEncoder().encode("stable");
    const k1 = await deriveSealKey(SECRET, "same");
    const sealed = await seal(k1, data);
    const k2 = await deriveSealKey(SECRET, "same");
    expect(await unseal(k2, sealed)).toStrictEqual(data);
  });
});

describe("sealJson / unsealJson", () => {
  it("round-trips a JSON value", async () => {
    const key = await deriveSealKey(SECRET, "json");
    const value = { accessToken: "at", refreshToken: "rt", n: 7 };
    expect(await unsealJson(key, await sealJson(key, value))).toStrictEqual(
      value,
    );
  });

  it("returns null when it can't be unsealed", async () => {
    const key = await deriveSealKey(SECRET, "json");
    expect(await unsealJson(key, "not-a-valid-sealed-value")).toStrictEqual(
      null,
    );
  });

  it("returns null when the bytes decrypt but aren't JSON", async () => {
    const key = await deriveSealKey(SECRET, "json");
    const sealed = await seal(
      key,
      new TextEncoder().encode("definitely not json"),
    );
    expect(await unsealJson(key, sealed)).toStrictEqual(null);
  });
});

function coercible(value: string): string {
  return { toString: () => value } as unknown as string;
}

function countingCandidates(values: string[]): {
  candidates: string[];
  reads: () => number;
} {
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
    expect(timingSafeEqualString("hunter2", "hunter2")).toStrictEqual(true);
  });

  it("is false for different strings of the same length", () => {
    expect(timingSafeEqualString("hunter2", "hunter3")).toStrictEqual(false);
    expect(timingSafeEqualString("hunter2", "xunter2")).toStrictEqual(false);
  });

  it("is false when the lengths differ", () => {
    expect(timingSafeEqualString("hunter2", "hunter22")).toStrictEqual(false);
    expect(timingSafeEqualString("", "h")).toStrictEqual(false);
  });

  it("is true for two empty strings", () => {
    expect(timingSafeEqualString("", "")).toStrictEqual(true);
  });

  it("decides equality from the encoded bytes, not JavaScript string identity", () => {
    expect(
      timingSafeEqualString(coercible("hunter2"), coercible("hunter2")),
    ).toStrictEqual(true);
    expect(
      timingSafeEqualString(coercible("hunter2"), coercible("hunter3")),
    ).toStrictEqual(false);
  });

  it("compares non-ASCII values by their UTF-8 bytes", () => {
    expect(timingSafeEqualString("café ☃", "café ☃")).toStrictEqual(true);
    expect(timingSafeEqualString("café ☃", "café ☂")).toStrictEqual(false);
  });
});

describe("timingSafeMatchIndex", () => {
  it("returns the index of the matching candidate", () => {
    expect(timingSafeMatchIndex(["a", "b", "c"], "b")).toStrictEqual(1);
  });

  it("returns undefined when no candidate matches", () => {
    expect(timingSafeMatchIndex(["a", "b", "c"], "d")).toStrictEqual(undefined);
  });

  it("returns undefined for an empty candidate list", () => {
    expect(timingSafeMatchIndex([], "a")).toStrictEqual(undefined);
  });

  it("returns the last matching candidate so a duplicate resolves to the preferred entry", () => {
    expect(
      timingSafeMatchIndex(["secret", "b", "secret"], "secret"),
    ).toStrictEqual(2);
  });

  it("reads every candidate after the first one matches", () => {
    const { candidates, reads } = countingCandidates(["a", "b", "c"]);
    expect(timingSafeMatchIndex(candidates, "a")).toStrictEqual(0);
    expect(reads()).toStrictEqual(3);
  });

  it("reads every candidate when none matches", () => {
    const { candidates, reads } = countingCandidates(["a", "b", "c"]);
    expect(timingSafeMatchIndex(candidates, "d")).toStrictEqual(undefined);
    expect(reads()).toStrictEqual(3);
  });

  it("reads every candidate after a match in the middle", () => {
    const { candidates, reads } = countingCandidates(["a", "b", "c", "d"]);
    expect(timingSafeMatchIndex(candidates, "b")).toStrictEqual(1);
    expect(reads()).toStrictEqual(4);
  });

  it("compares each candidate with the constant-time comparison, not JavaScript equality", () => {
    const candidates = ["a", "secret", "c"].map(coercible);
    expect(timingSafeMatchIndex(candidates, "secret")).toStrictEqual(1);
  });
});
