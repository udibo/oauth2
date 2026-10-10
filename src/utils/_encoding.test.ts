import { describe, expect, it } from "vitest";
import {
  decodeBase32,
  decodeBase64,
  decodeBase64Url,
  encodeBase32,
  encodeBase64,
  encodeBase64Url,
  encodeHex,
} from "./_encoding.ts";

const encoder = new TextEncoder();

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

describe("base64", () => {
  it("encodes the RFC 4648 section 10 vectors", () => {
    const vectors: [string, string][] = [
      ["", ""],
      ["f", "Zg=="],
      ["fo", "Zm8="],
      ["foo", "Zm9v"],
      ["foob", "Zm9vYg=="],
      ["fooba", "Zm9vYmE="],
      ["foobar", "Zm9vYmFy"],
    ];
    for (const [text, encoded] of vectors) {
      expect(encodeBase64(encoder.encode(text))).toBe(encoded);
      expect(decodeBase64(encoded)).toStrictEqual(encoder.encode(text));
    }
  });

  it("agrees with Buffer for every length from 0 to 64 bytes", () => {
    for (let length = 0; length <= 64; length++) {
      const bytes = randomBytes(length);
      const expected = Buffer.from(bytes).toString("base64");
      expect(encodeBase64(bytes)).toBe(expected);
      expect(decodeBase64(expected)).toStrictEqual(bytes);
      expect(decodeBase64(expected.replace(/=+$/, ""))).toStrictEqual(bytes);
    }
  });

  it("uses the standard alphabet's plus and slash", () => {
    expect(encodeBase64(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe("+/+/");
    expect(decodeBase64("+/+/")).toStrictEqual(
      new Uint8Array([0xfb, 0xff, 0xbf]),
    );
  });

  it("rejects characters outside the alphabet with a TypeError", () => {
    for (const invalid of ["Zm!v", "Zm 9", "Zm-_", "Z=m9", "AB=C"]) {
      expect(() => decodeBase64(invalid), invalid).toThrow(TypeError);
    }
  });

  it("rejects a length that leaves a remainder of 1 with a RangeError", () => {
    for (const truncated of ["Z", "Zm9vY", "Zm9vYmFyZ"]) {
      expect(() => decodeBase64(truncated), truncated).toThrow(RangeError);
    }
  });
});

describe("base64url", () => {
  it("agrees with Buffer's unpadded base64url for every length from 0 to 64 bytes", () => {
    for (let length = 0; length <= 64; length++) {
      const bytes = randomBytes(length);
      const expected = Buffer.from(bytes).toString("base64url");
      expect(encodeBase64Url(bytes)).toBe(expected);
      expect(decodeBase64Url(expected)).toStrictEqual(bytes);
    }
  });

  it("uses dash and underscore, never plus, slash or padding", () => {
    expect(encodeBase64Url(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe("-_-_");
    expect(encodeBase64Url(new Uint8Array([0xfb]))).toBe("-w");
  });

  it("accepts optional padding", () => {
    expect(decodeBase64Url("Zg==")).toStrictEqual(encoder.encode("f"));
    expect(decodeBase64Url("Zg")).toStrictEqual(encoder.encode("f"));
  });

  it("rejects the standard alphabet and whitespace with a TypeError", () => {
    for (const invalid of ["+/+/", "Zm 9", "Zm9\n", "Zg=x"]) {
      expect(() => decodeBase64Url(invalid), invalid).toThrow(TypeError);
    }
  });

  it("rejects a length that leaves a remainder of 1 with a RangeError", () => {
    expect(() => decodeBase64Url("Zm9vY")).toThrow(RangeError);
  });
});

describe("base32", () => {
  it("encodes the RFC 4648 section 10 vectors", () => {
    const vectors: [string, string][] = [
      ["", ""],
      ["f", "MY======"],
      ["fo", "MZXQ===="],
      ["foo", "MZXW6==="],
      ["foob", "MZXW6YQ="],
      ["fooba", "MZXW6YTB"],
      ["foobar", "MZXW6YTBOI======"],
    ];
    for (const [text, encoded] of vectors) {
      expect(encodeBase32(encoder.encode(text))).toBe(encoded);
      expect(decodeBase32(encoded)).toStrictEqual(encoder.encode(text));
    }
  });

  it("round-trips random secrets of every length from 0 to 40 bytes", () => {
    for (let length = 0; length <= 40; length++) {
      const bytes = randomBytes(length);
      expect(decodeBase32(encodeBase32(bytes))).toStrictEqual(bytes);
    }
  });

  it("rejects an unpadded length with a TypeError", () => {
    expect(() => decodeBase32("MZXW6YQ")).toThrow(TypeError);
  });

  it("rejects characters outside the alphabet with a TypeError", () => {
    for (const invalid of ["MZXW6Y1=", "mzxw6yq=", "MZXW6Y!="]) {
      expect(() => decodeBase32(invalid), invalid).toThrow(TypeError);
    }
  });

  it("rejects a length no encoding can produce with a RangeError", () => {
    for (const impossible of ["MZX=====", "MZXW6Y=="]) {
      expect(() => decodeBase32(impossible), impossible).toThrow(RangeError);
    }
  });
});

describe("encodeHex", () => {
  it("agrees with Buffer and accepts an ArrayBuffer", () => {
    for (let length = 0; length <= 64; length++) {
      const bytes = randomBytes(length);
      const expected = Buffer.from(bytes).toString("hex");
      expect(encodeHex(bytes)).toBe(expected);
      expect(encodeHex(bytes.buffer as ArrayBuffer)).toBe(expected);
    }
  });

  it("pads each byte to two lowercase digits", () => {
    expect(encodeHex(new Uint8Array([0, 1, 15, 16, 171, 255]))).toBe(
      "00010f10abff",
    );
  });
});
