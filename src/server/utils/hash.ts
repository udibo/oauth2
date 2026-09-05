/**
 * Hashing utilities for secure token and secret storage.
 * @module
 */

import { encodeHex } from "@std/encoding/hex";

/** Hashes a high-entropy string (UUID, token, secret) using SHA-256. */
export async function sha256Hash(value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return encodeHex(hash);
}
