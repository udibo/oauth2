/**
 * Authenticated-encryption (AES-256-GCM) and key-derivation helpers for sealing
 * session and token data at rest or in a cookie.
 *
 * Two key-derivation paths, for two different threat models:
 *
 * - {@link deriveAesKey} hashes a single **server-held** secret (SHA-256) into
 *   an AES-256-GCM key. Use this for a stateless cookie sealed under one
 *   configured secret (see `EncryptedCookieSessionStore`), where the secret is
 *   never persisted.
 *
 * - {@link deriveSealKey} uses **HKDF** with a domain-separating `info` label so
 *   a high-entropy *per-session* secret yields an encryption key that is
 *   independent of any other value derived from the same secret. This is what
 *   makes "the cookie value is both the lookup credential **and** the decryption
 *   key" safe: a database can store `sha256(secret)` as a lookup hash while the
 *   sealing key is `HKDF(secret, info)`, and knowing the stored hash never
 *   reveals the key. Always pass a distinct `info` per purpose.
 *
 * {@link seal}/{@link unseal} use AES-256-GCM (an AEAD), so tampered ciphertext
 * fails to unseal (returns `null`) rather than decrypting to garbage.
 *
 * @module
 */

import { timingSafeEqual } from "@std/crypto/timing-safe-equal";
import { decodeBase64Url, encodeBase64Url } from "@std/encoding/base64url";

import { sha256Hash } from "../server/utils/hash.ts";
import { toArrayBuffer } from "./_buffer.ts";

export { sha256Hash };
export { toArrayBuffer };

function toBytes(secret: string | Uint8Array): Uint8Array {
  return typeof secret === "string" ? new TextEncoder().encode(secret) : secret;
}

/** Constant-time string equality (length difference short-circuits to false). */
export function timingSafeEqualString(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  if (aBytes.byteLength !== bBytes.byteLength) return false;
  return timingSafeEqual(aBytes, bBytes);
}

/** URL-safe base64 encode (no padding). */
export function base64urlEncode(bytes: Uint8Array): string {
  return encodeBase64Url(bytes);
}

/**
 * URL-safe base64 decode. Padding is optional, so JWS/JWT segments — which
 * carry none — decode as-is. Only the URL-safe alphabet is accepted.
 *
 * @throws {TypeError} on a character outside the URL-safe alphabet — including
 * the standard alphabet's `+` and `/`, and whitespace.
 * @throws {RangeError} on a truncated value (a length that leaves a remainder
 * of 1 when divided by 4, which no encoding can produce).
 */
export function base64urlDecode(value: string): Uint8Array {
  return decodeBase64Url(value);
}

/**
 * Mint a cryptographically random, URL-safe token: `base64url` of `bytes`
 * random bytes, unpadded, so it drops into a URL, a link in an email, or a
 * cookie value with no further escaping.
 *
 * This is the primitive behind session secrets, verification / password-reset
 * links, and download tokens. The token is a bearer credential: hand it out
 * once and persist only a hash of it ({@link sha256Hash}, from this module).
 * The default 32 bytes (256 bits, 43 characters) is what every such credential
 * should use; shrink it only for values that don't authorize anything.
 *
 * @param bytes How many random bytes to draw. Defaults to 32.
 * @returns The unpadded base64url encoding of those bytes.
 *
 * @example
 * ```ts
 * randomToken();    // 43 chars, e.g. "kQ7…" — a reset-link token
 * randomToken(16);  // 22 chars — a non-credential correlation id
 * ```
 */
export function randomToken(bytes = 32): string {
  return base64urlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

/**
 * Derive an AES-256-GCM key from a single server-held secret via SHA-256.
 *
 * Suitable when the secret is a long-lived configuration value that is never
 * stored alongside the ciphertext. Do **not** use this when a hash of the same
 * secret is persisted (e.g. as a lookup key) — use {@link deriveSealKey} so the
 * sealing key is independent of that stored hash.
 *
 * @throws if the secret has fewer than 16 bytes of entropy (32+ recommended).
 */
export async function deriveAesKey(
  secret: string | Uint8Array,
): Promise<CryptoKey> {
  const raw = toBytes(secret);
  if (raw.byteLength < 16) {
    throw new Error(
      "secret must be at least 16 bytes; 32+ bytes of entropy is recommended.",
    );
  }
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(raw));
  return await crypto.subtle.importKey(
    "raw",
    digest,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Derive an AES-256-GCM sealing key from a high-entropy secret via HKDF-SHA-256
 * with a domain-separating `info` label.
 *
 * Keys derived with different `info` values (or different from `sha256(secret)`)
 * are independent, so the same secret can safely back both a stored lookup hash
 * and a never-stored sealing key. Pass a stable, unique `info` per purpose, e.g.
 * `"udibo:bff-session-tokens:v1"`.
 */
export async function deriveSealKey(
  secret: string | Uint8Array,
  info: string,
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(toBytes(secret)),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(info),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Seal bytes with AES-256-GCM; returns `base64url(iv ‖ ciphertext+tag)`. */
export async function seal(
  key: CryptoKey,
  plaintext: Uint8Array,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      toArrayBuffer(plaintext),
    ),
  );
  const packed = new Uint8Array(iv.length + ciphertext.length);
  packed.set(iv, 0);
  packed.set(ciphertext, iv.length);
  return base64urlEncode(packed);
}

/**
 * Unseal an AES-256-GCM value produced by {@link seal}. Returns `null` on a
 * malformed input, a wrong key, or tampering (the AEAD tag fails); it never
 * throws.
 */
export async function unseal(
  key: CryptoKey,
  sealed: string,
): Promise<Uint8Array | null> {
  try {
    const bytes = base64urlDecode(sealed);
    if (bytes.length < 13) return null;
    const iv = bytes.slice(0, 12);
    const ciphertext = bytes.slice(12);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      toArrayBuffer(ciphertext),
    );
    return new Uint8Array(plaintext);
  } catch {
    return null;
  }
}

/** Seal a JSON-serializable value. */
export async function sealJson(
  key: CryptoKey,
  value: unknown,
): Promise<string> {
  return await seal(key, new TextEncoder().encode(JSON.stringify(value)));
}

/** Unseal a value sealed by {@link sealJson}, or `null` if it can't be unsealed. */
export async function unsealJson<T>(
  key: CryptoKey,
  sealed: string,
): Promise<T | null> {
  const bytes = await unseal(key, sealed);
  if (!bytes) return null;
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as T;
  } catch {
    return null;
  }
}
