/**
 * Recovery-code primitives for MFA — the single-use fallback a user redeems
 * when their authenticator is unavailable.
 *
 * Codes are generated from a Crockford-style alphabet (no `I`, `L`, `O`, or
 * `U`, so nothing reads ambiguously off paper) as two 8-character groups —
 * 80 bits of entropy per code. Only SHA-256 hashes are meant to be stored:
 * at 80 bits an unsalted fast hash is sufficient — even a full offline
 * keyspace sweep is infeasible, so a leaked hash table stays unbroken and the
 * deterministic hash doubles as an exact-match storage key for atomic
 * burn-on-use. Online guessing should be rate-limited like any credential.
 * Verification is constant-time against every stored hash and reports which
 * one matched so the app can delete ("burn") it — **single use is the app's
 * storage responsibility**.
 *
 * @module
 */

import { sha256Hash } from "../../server/utils/hash.ts";
import { timingSafeMatchIndex } from "../../utils/_timing-safe.ts";

const RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DEFAULT_COUNT = 10;

/**
 * The length of a normalized recovery code (separators stripped). A submitted
 * value of any other length cannot be a recovery code, so callers can skip
 * hashing and storage lookups for it.
 */
export const RECOVERY_CODE_LENGTH = 16;

/**
 * Normalize a recovery code to its canonical stored form: uppercase with
 * separators (anything non-alphanumeric) stripped. Hashing and verification
 * apply this automatically, so users can submit codes in any case and with or
 * without the display hyphens.
 */
export function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replaceAll(/[^0-9A-Z]/g, "");
}

/**
 * Hash a recovery code for storage: hex-encoded SHA-256 of the normalized
 * code, the same stored-hash format the package's other high-entropy
 * credentials use. Fast on purpose — see the module doc for why the code's
 * entropy makes a slow hash unnecessary. Store only the hash; the plaintext
 * code is shown to the user once at generation time.
 */
export function hashRecoveryCode(code: string): Promise<string> {
  return sha256Hash(normalizeRecoveryCode(code));
}

/** Options for {@link generateRecoveryCodes}. */
export interface GenerateRecoveryCodesOptions {
  /** How many codes to generate. Defaults to `10`. */
  count?: number;
}

/** A freshly generated recovery-code set (see {@link generateRecoveryCodes}). */
export interface GeneratedRecoveryCodes {
  /**
   * The plaintext codes, e.g. `"4Q7MB2XW-9ZHT3KVR"`. Show them to the user
   * exactly once; they are not recoverable afterwards.
   */
  codes: string[];
  /**
   * The hash of each code, index-aligned with `codes` — persist these (see
   * {@link hashRecoveryCode}).
   */
  hashes: string[];
}

/**
 * Generate a set of single-use recovery codes plus the hashes to store.
 * Persist `hashes`, display `codes` once, and delete a hash when
 * {@link verifyRecoveryCode} reports its index matched.
 *
 * @example Issue codes on MFA enrollment
 * ```ts
 * const { codes, hashes } = await generateRecoveryCodes();
 * await store.setRecoveryHashes(user.id, hashes);
 * // display `codes` to the user exactly once
 * ```
 */
export async function generateRecoveryCodes(
  options?: GenerateRecoveryCodesOptions,
): Promise<GeneratedRecoveryCodes> {
  const count = options?.count ?? DEFAULT_COUNT;
  const bytes = crypto.getRandomValues(
    new Uint8Array(count * RECOVERY_CODE_LENGTH),
  );
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = Array.from(
      bytes.subarray(i * RECOVERY_CODE_LENGTH, (i + 1) * RECOVERY_CODE_LENGTH),
      (byte) => RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length],
    ).join("");
    codes.push(`${raw.slice(0, 8)}-${raw.slice(8)}`);
  }
  const hashes = await Promise.all(codes.map(hashRecoveryCode));
  return { codes, hashes };
}

/** Options for {@link verifyRecoveryCode}. */
export interface VerifyRecoveryCodeOptions {
  /** The code the user submitted (any case, separators optional). */
  code: string;
  /** The stored hashes for the user's unused codes. */
  hashes: string[];
}

/** The outcome of {@link verifyRecoveryCode}. */
export type RecoveryCodeVerification =
  | { valid: false }
  | {
    valid: true;
    /**
     * The index of the matching hash. Burn it with an atomic delete-by-value
     * (a conditional `DELETE` on the hash, never read-filter-write) so the
     * code cannot be redeemed again — the library does not do this for you at
     * this level ({@link MfaService} does, atomically).
     */
    index: number;
  };

/**
 * Check a submitted recovery code against the stored hashes. Comparison is
 * constant-time and every hash is checked even after a match, so timing does
 * not reveal whether or where a match occurred. On success the caller must
 * burn the matched hash (see {@link RecoveryCodeVerification}).
 */
export async function verifyRecoveryCode(
  options: VerifyRecoveryCodeOptions,
): Promise<RecoveryCodeVerification> {
  const submitted = await hashRecoveryCode(options.code);
  const index = timingSafeMatchIndex(options.hashes, submitted);
  return index === undefined ? { valid: false } : { valid: true, index };
}
