/**
 * Password-hash import primitives — the migration on-ramp for apps moving off
 * another auth system without forcing a password reset.
 *
 * The model is **upgrade-on-login**: keep each imported user's existing
 * (foreign-format) password hash, verify it on their first sign-in, and — on a
 * match — transparently rehash the password into this package's native format
 * ({@link PasswordIdentityService}, PBKDF2-SHA-256) and store that. The foreign
 * hash is then cleared. Users never see a reset; the migration completes one
 * login at a time. Wire it via {@link IdentityService}'s `legacyVerifiers`
 * option plus the optional `getLegacyCredential`/`clearLegacyCredential` store
 * hooks, plus atomic `replaceCredential` for upgrade writes.
 *
 * **Which algorithms ship built-in vs. bring-your-own (BYO).** The package's
 * hard constraint is zero new runtime dependencies — Web Crypto only. So the
 * only built-in verifier is {@link pbkdf2Verifier} (PBKDF2 is a Web Crypto
 * primitive). **bcrypt, argon2, and scrypt cannot be implemented dep-free** —
 * bcrypt and argon2 have no Web Crypto primitive, and scrypt is not exposed by
 * Web Crypto or `@std/crypto`. Those are **BYO**: you implement the
 * {@link LegacyPasswordVerifier} seam with your app's own bcrypt/argon2/scrypt
 * dependency and pass it in. {@link parsePhc} is provided to parse the PHC /
 * modular-crypt strings those algorithms store, so a BYO verifier is a few
 * lines. See the migration guide for worked bcrypt/argon2 examples.
 *
 * @module
 */

import { decodeBase64 } from "@std/encoding";
import { timingSafeEqual } from "@std/crypto/timing-safe-equal";

/**
 * A verifier for one foreign password-hash format, used during
 * upgrade-on-login. Connectors identify the formats they handle by sniffing the
 * stored hash string in {@link LegacyPasswordVerifier.canVerify}; the first
 * verifier in {@link IdentityService}'s `legacyVerifiers` list whose `canVerify`
 * returns `true` is asked to {@link LegacyPasswordVerifier.verify} the password.
 *
 * Implement this to bring your own bcrypt/argon2/scrypt verifier (using your
 * app's dependency) — the package only ships {@link pbkdf2Verifier} built-in.
 *
 * @example Bring-your-own bcrypt (app adds an `npm:bcryptjs` dependency)
 * ```ts
 * import { compare } from "bcryptjs";
 * import type { LegacyPasswordVerifier } from "@udibo/oauth2/identity/migration";
 *
 * const bcryptVerifier: LegacyPasswordVerifier = {
 *   id: "bcrypt",
 *   canVerify: (phc) => /^\$2[aby]?\$/.test(phc),
 *   verify: (password, phc) => compare(password, phc),
 * };
 * ```
 */
export interface LegacyPasswordVerifier {
  /**
   * Stable identifier for this format (e.g. `"bcrypt"`, `"argon2id"`,
   * `"pbkdf2"`). Surfaced on the `password.upgraded` audit event so you can see
   * which format a migrated user came from.
   */
  readonly id: string;
  /**
   * Cheap, synchronous sniff of whether this verifier recognizes `phc` (its
   * prefix/shape). Must not throw — return `false` for anything unrecognized or
   * malformed. Selection stops at the first verifier that returns `true`.
   */
  canVerify(phc: string): boolean;
  /**
   * Verify `password` against the stored foreign hash `phc`. Called only when
   * {@link LegacyPasswordVerifier.canVerify} returned `true`. Resolve `false`
   * (never throw) on a mismatch or a malformed hash. Use a constant-time
   * comparison.
   */
  verify(password: string, phc: string): Promise<boolean>;
}

/**
 * The first verifier in `verifiers` (in order) whose `canVerify` accepts `phc`,
 * or `undefined` if none do. A verifier that throws from `canVerify` is skipped
 * rather than propagated, so one misbehaving connector can't break selection.
 */
export function findLegacyVerifier(
  verifiers: readonly LegacyPasswordVerifier[],
  phc: string,
): LegacyPasswordVerifier | undefined {
  return verifiers.find((verifier) => {
    try {
      return verifier.canVerify(phc);
    } catch {
      return false;
    }
  });
}

/**
 * Verify `password` against a stored foreign hash `phc` using the first matching
 * verifier in `verifiers`. Resolves `false` when no verifier recognizes `phc` or
 * the matched verifier rejects the password. Useful for a bulk-import
 * dry-run/validation pass; {@link IdentityService.signIn} uses the same
 * selection internally for upgrade-on-login.
 */
export async function verifyLegacyPassword(
  verifiers: readonly LegacyPasswordVerifier[],
  password: string,
  phc: string,
): Promise<boolean> {
  const verifier = findLegacyVerifier(verifiers, phc);
  if (!verifier) return false;
  try {
    return await verifier.verify(password, phc);
  } catch {
    return false;
  }
}

/**
 * A parsed PHC / modular-crypt string ({@link parsePhc}). The salt and hash
 * segments are decoded from base64 (the PHC "B64" alphabet, padding optional).
 */
export interface PhcHash {
  /** Algorithm identifier, e.g. `"argon2id"`, `"scrypt"`, `"pbkdf2-sha256"`. */
  id: string;
  /** The `v=` version field, if present (e.g. argon2's `19`). */
  version?: number;
  /** The comma-separated `k=v` parameter field, e.g. argon2's `{ m, t, p }`. */
  params: Record<string, string>;
  /** Decoded salt bytes, if a salt segment was present. */
  salt?: Uint8Array;
  /** Decoded hash/checksum bytes, if a hash segment was present. */
  hash?: Uint8Array;
}

function decodeB64(segment: string): Uint8Array {
  const padded = segment + "=".repeat((4 - (segment.length % 4)) % 4);
  return decodeBase64(padded);
}

/**
 * Parse a PHC / modular-crypt string (`$id[$v=n][$k=v,...]$salt$hash`) into its
 * parts. Returns `null` for anything that isn't a `$`-led PHC string. Salt and
 * hash are decoded as base64 (padding optional). This is the parsing helper for
 * writing a bring-your-own argon2/scrypt {@link LegacyPasswordVerifier}: parse
 * the stored string, feed `params`/`salt`/`hash` to your KDF dependency, and
 * constant-time compare.
 *
 * @example
 * ```ts
 * const parsed = parsePhc("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaA");
 * parsed?.id;            // "argon2id"
 * parsed?.version;       // 19
 * parsed?.params.m;      // "65536"
 * ```
 */
export function parsePhc(phc: string): PhcHash | null {
  if (typeof phc !== "string" || !phc.startsWith("$")) return null;
  const fields = phc.split("$").slice(1);
  if (fields.length === 0 || fields[0] === "") return null;
  const id = fields[0];
  let version: number | undefined;
  const params: Record<string, string> = {};
  const rest = fields.slice(1);
  let index = 0;
  if (rest[index]?.startsWith("v=")) {
    version = Number(rest[index].slice(2));
    index++;
  }
  if (rest[index] && rest[index].includes("=")) {
    for (const pair of rest[index].split(",")) {
      const eq = pair.indexOf("=");
      if (eq === -1) continue;
      params[pair.slice(0, eq)] = pair.slice(eq + 1);
    }
    index++;
  }
  const saltSegment = rest[index++];
  const hashSegment = rest[index];
  const result: PhcHash = { id, params };
  if (version !== undefined) result.version = version;
  try {
    if (saltSegment) result.salt = decodeB64(saltSegment);
    if (hashSegment) result.hash = decodeB64(hashSegment);
  } catch {
    return null;
  }
  return result;
}

/** Options for {@link pbkdf2Verifier}. */
export interface Pbkdf2VerifierOptions {
  /** Verifier id surfaced on the `password.upgraded` event. Defaults to `"pbkdf2"`. */
  id?: string;
}

const PBKDF2_DIGEST: Record<string, string> = {
  sha1: "SHA-1",
  sha256: "SHA-256",
  sha512: "SHA-512",
};

interface Pbkdf2Parsed {
  digest: string;
  iterations: number;
  salt: Uint8Array;
  expected: Uint8Array;
}

const encoder = new TextEncoder();

/**
 * Reject an imported hash whose derived-key segment is implausibly short: a
 * 0-byte checksum would make `deriveBits(0)` compare empty-to-empty and turn
 * any password into a match on a runtime where that returns an empty buffer.
 */
const MIN_HASH_BYTES = 16;
const MAX_PBKDF2_ITERATIONS = 1_000_000;

function parseDjango(phc: string): Pbkdf2Parsed | null {
  const parts = phc.split("$");
  if (parts.length !== 4) return null;
  const [algorithm, iterationsRaw, salt, hashB64] = parts;
  const digestName = algorithm.slice("pbkdf2_".length);
  const digest = PBKDF2_DIGEST[digestName];
  if (!digest) return null;
  const iterations = Number(iterationsRaw);
  if (!Number.isInteger(iterations) || iterations < 1) return null;
  try {
    return {
      digest,
      iterations,
      salt: encoder.encode(salt),
      expected: decodeBase64(hashB64),
    };
  } catch {
    return null;
  }
}

function parsePhcPbkdf2(phc: string): Pbkdf2Parsed | null {
  const parsed = parsePhc(phc);
  if (!parsed || !parsed.salt || !parsed.hash) return null;
  const digestName = parsed.id.slice("pbkdf2-".length);
  const digest = PBKDF2_DIGEST[digestName];
  if (!digest) return null;
  const iterations = Number(parsed.params.i ?? parsed.params.rounds);
  if (!Number.isInteger(iterations) || iterations < 1) return null;
  return { digest, iterations, salt: parsed.salt, expected: parsed.hash };
}

function parsePbkdf2(phc: string): Pbkdf2Parsed | null {
  const parsed = phc.startsWith("pbkdf2_")
    ? parseDjango(phc)
    : phc.startsWith("$pbkdf2-")
    ? parsePhcPbkdf2(phc)
    : null;
  if (!parsed) return null;
  if (parsed.iterations > MAX_PBKDF2_ITERATIONS) return null;
  if (parsed.expected.length < MIN_HASH_BYTES) return null;
  return parsed;
}

/**
 * Built-in {@link LegacyPasswordVerifier} for PBKDF2 hashes — the only family
 * this package can verify dep-free (PBKDF2 is a Web Crypto primitive). Handles
 * two common encodings, auto-detected:
 *
 * - **Django** — `pbkdf2_<digest>$<iterations>$<salt>$<base64 hash>`, where the
 *   salt is used as raw UTF-8 bytes and the hash is standard base64. This is
 *   Django's `PBKDF2PasswordHasher` output.
 * - **PHC** — `$pbkdf2-<digest>$i=<iterations>$<base64 salt>$<base64 hash>`,
 *   with base64 (padding optional) salt and hash.
 *
 * `<digest>` is one of `sha1`, `sha256`, `sha512`. The derived-key length is
 * taken from the stored hash. Comparison is constant-time. On a match,
 * {@link IdentityService} rehashes into its native PBKDF2 format and clears the
 * imported hash.
 *
 * A hash outside the accepted bounds is declined rather than verified —
 * `canVerify` returns `false` and `verify` resolves `false`, which reads to your
 * app as a wrong password. The bounds are more than 1,000,000 iterations and a
 * stored checksum shorter than 16 bytes.
 *
 * @example
 * ```ts
 * import { IdentityService } from "@udibo/oauth2/identity";
 * import { pbkdf2Verifier } from "@udibo/oauth2/identity/migration";
 *
 * const identity = new IdentityService({
 *   users: store, // implements getLegacyCredential/clearLegacyCredential
 *   legacyVerifiers: [pbkdf2Verifier()],
 * });
 * ```
 */
export function pbkdf2Verifier(
  options: Pbkdf2VerifierOptions = {},
): LegacyPasswordVerifier {
  const id = options.id ?? "pbkdf2";
  return {
    id,
    canVerify(phc: string): boolean {
      return parsePbkdf2(phc) !== null;
    },
    async verify(password: string, phc: string): Promise<boolean> {
      const parsed = parsePbkdf2(phc);
      if (!parsed) return false;
      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"],
      );
      const bits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: new Uint8Array(parsed.salt),
          iterations: parsed.iterations,
          hash: parsed.digest,
        },
        key,
        parsed.expected.length * 8,
      );
      const derived = new Uint8Array(bits);
      if (derived.length !== parsed.expected.length) return false;
      return timingSafeEqual(derived, parsed.expected);
    },
  };
}
