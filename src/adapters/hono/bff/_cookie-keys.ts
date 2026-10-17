/**
 * The AES-256-GCM keys the BFF's encrypted-cookie stores seal under.
 *
 * @module
 */

import { deriveSealKey } from "../../../utils/crypto.ts";

/** HKDF `info` label for `EncryptedCookieSessionStore`'s key. */
export const SESSION_COOKIE_KEY_INFO = "udibo:oauth2:bff:session-cookie:v1";

/** HKDF `info` label for `EncryptedCookieAuthRequestStorage`'s key. */
export const AUTH_REQUEST_COOKIE_KEY_INFO =
  "udibo:oauth2:bff:auth-request-cookie:v1";

const MIN_SECRET_BYTES = 16;

/**
 * Derives a cookie store's key from its configured secret with HKDF-SHA-256
 * under the store's own `info` label, so one secret given to two stores yields
 * independent keys.
 *
 * @throws {Error} When the secret is shorter than 16 bytes.
 */
export async function deriveCookieKey(
  secret: string | Uint8Array,
  info: string,
): Promise<CryptoKey> {
  const bytes =
    typeof secret === "string" ? new TextEncoder().encode(secret) : secret;
  if (bytes.byteLength < MIN_SECRET_BYTES) {
    throw new Error(
      "secret must be at least 16 bytes; 32+ bytes of entropy is recommended.",
    );
  }
  return await deriveSealKey(bytes, info);
}
