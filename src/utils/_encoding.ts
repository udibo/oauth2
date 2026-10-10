/**
 * Internal binary-to-text codecs shared by the modules that run in both
 * browsers and servers.
 *
 * @module
 */

const BASE64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64URL =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const lookup = (alphabet: string): Map<string, number> =>
  new Map([...alphabet].map((char, index) => [char, index]));

const BASE64_LOOKUP = lookup(BASE64);
const BASE64URL_LOOKUP = lookup(BASE64URL);
const BASE32_LOOKUP = lookup(BASE32);

const HEX = Array.from({ length: 256 }, (_, byte) =>
  byte.toString(16).padStart(2, "0"),
);

/** Lowercase hexadecimal encoding of `bytes`. */
export function encodeHex(bytes: Uint8Array | ArrayBuffer): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (const byte of view) out += HEX[byte];
  return out;
}

function encodeBits(
  bytes: Uint8Array,
  alphabet: string,
  bitsPerChar: number,
): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  const mask = (1 << bitsPerChar) - 1;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= bitsPerChar) {
      bits -= bitsPerChar;
      out += alphabet[(buffer >> bits) & mask];
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += alphabet[(buffer << (bitsPerChar - bits)) & mask];
  return out;
}

function pad(encoded: string, multiple: number): string {
  return (
    encoded + "=".repeat((multiple - (encoded.length % multiple)) % multiple)
  );
}

function decodeBits(
  input: string,
  table: Map<string, number>,
  bitsPerChar: number,
  name: string,
  paddingWindow: number,
  invalidRemainders: readonly number[],
): Uint8Array {
  let text = input;
  for (let x = Math.max(0, text.length - paddingWindow); x < text.length; ++x) {
    if (text[x] === "=") {
      for (let y = x + 1; y < text.length; ++y) {
        if (text[y] !== "=") {
          throw new TypeError(
            `Cannot decode input as ${name}: Invalid character (${text[y]})`,
          );
        }
      }
      text = text.slice(0, x);
      break;
    }
  }
  const modulus = name === "base32" ? 8 : 4;
  if (invalidRemainders.includes(text.length % modulus)) {
    throw new RangeError(
      `Cannot decode input as ${name}: Length (${text.length}), excluding ` +
        `padding, must not have a remainder of ${invalidRemainders.join(
          ", ",
        )} when divided by ${modulus}`,
    );
  }
  const out = new Uint8Array(Math.floor((text.length * bitsPerChar) / 8));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of text) {
    const value = table.get(char);
    if (value === undefined) {
      throw new TypeError(
        `Cannot decode input as ${name}: Invalid character (${char})`,
      );
    }
    buffer = (buffer << bitsPerChar) | value;
    bits += bitsPerChar;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (buffer >> bits) & 0xff;
      buffer &= (1 << bits) - 1;
    }
  }
  return out;
}

/** Standard-alphabet base64 with `=` padding. */
export function encodeBase64(bytes: Uint8Array): string {
  return pad(encodeBits(bytes, BASE64, 6), 4);
}

/**
 * Decodes standard-alphabet base64, padded or not.
 *
 * @throws {TypeError} on a character outside the alphabet.
 * @throws {RangeError} on a length that leaves a remainder of 1 when divided
 * by 4.
 */
export function decodeBase64(input: string): Uint8Array {
  return decodeBits(input, BASE64_LOOKUP, 6, "base64", 2, [1]);
}

/** URL-safe base64 without padding. */
export function encodeBase64Url(bytes: Uint8Array): string {
  return encodeBits(bytes, BASE64URL, 6);
}

/**
 * Decodes URL-safe base64, padded or not.
 *
 * @throws {TypeError} on a character outside the alphabet.
 * @throws {RangeError} on a length that leaves a remainder of 1 when divided
 * by 4.
 */
export function decodeBase64Url(input: string): Uint8Array {
  return decodeBits(input, BASE64URL_LOOKUP, 6, "base64", 2, [1]);
}

/** RFC 4648 base32 with `=` padding. */
export function encodeBase32(bytes: Uint8Array): string {
  return pad(encodeBits(bytes, BASE32, 5), 8);
}

/**
 * Decodes RFC 4648 base32. The input length must be a multiple of 8,
 * counting padding.
 *
 * @throws {TypeError} on a character outside the alphabet or an unpadded
 * length.
 * @throws {RangeError} on a length no encoding can produce.
 */
export function decodeBase32(input: string): Uint8Array {
  if (input.length % 8 !== 0) {
    throw new TypeError(
      `Invalid base32 string: length (${input.length}) must be a multiple of 8`,
    );
  }
  return decodeBits(input, BASE32_LOOKUP, 5, "base32", 6, [1, 3, 6]);
}
