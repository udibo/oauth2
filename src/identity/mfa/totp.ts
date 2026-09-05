/**
 * TOTP primitives (RFC 6238 over RFC 4226 HOTP) built on Web Crypto — no
 * dependencies beyond `@std`. Generate a secret, render the `otpauth://` URI an
 * authenticator app scans, and verify submitted codes with a constant-time
 * comparison.
 *
 * Verification returns the matched time-step counter so the caller can enforce
 * single use: persist the last accepted step per user and reject any code whose
 * `matchedStep` is `<=` the stored value (see {@link verifyTotpCode}). The
 * package owns the math; replay state, like all storage, stays app-owned.
 *
 * @module
 */

import { decodeBase32, encodeBase32 } from "@std/encoding/base32";

import { toArrayBuffer } from "../../utils/_buffer.ts";
import { timingSafeMatchIndex } from "../../utils/_timing-safe.ts";

/**
 * The HMAC hash a TOTP credential uses. `"SHA-1"` is the RFC default and what
 * authenticator apps universally support; prefer it unless you control the
 * client. Some authenticators silently ignore the `algorithm` URI parameter and
 * always use SHA-1, so a non-default choice can produce codes that never match.
 */
export type TotpAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";

const DEFAULT_DIGITS = 6;
const DEFAULT_PERIOD_SECONDS = 30;
const DEFAULT_ALGORITHM: TotpAlgorithm = "SHA-1";
const DEFAULT_WINDOWS = 1;

function normalizeTotpSecret(base32: string): string {
  return base32.toUpperCase().replaceAll(/[\s=]/g, "");
}

/**
 * Assert that TOTP parameters are usable: `digits` and `periodSeconds` must be
 * positive integers and `windows` a non-negative integer. Every TOTP entry
 * point applies this, so a corrupted or miswired configuration fails loudly
 * instead of silently rejecting every code.
 *
 * @throws {TypeError} on the first invalid value.
 */
export function validateTotpParams(
  params: { digits?: number; periodSeconds?: number; windows?: number },
): void {
  const { digits, periodSeconds, windows } = params;
  if (digits !== undefined && (!Number.isInteger(digits) || digits <= 0)) {
    throw new TypeError("totp digits must be a positive integer");
  }
  if (
    periodSeconds !== undefined &&
    (!Number.isInteger(periodSeconds) || periodSeconds <= 0)
  ) {
    throw new TypeError("totp period must be a positive integer");
  }
  if (windows !== undefined && (!Number.isInteger(windows) || windows < 0)) {
    throw new TypeError("totp windows must be a non-negative integer");
  }
}

/**
 * Decode a base32 TOTP secret into raw key bytes. Tolerates lowercase,
 * whitespace, and missing `=` padding (authenticator conventions vary).
 *
 * @throws {TypeError} if the value is not valid RFC 4648 base32.
 */
export function decodeTotpSecret(base32: string): Uint8Array {
  const normalized = normalizeTotpSecret(base32);
  const padded = normalized.padEnd(
    normalized.length + ((8 - (normalized.length % 8)) % 8),
    "=",
  );
  return decodeBase32(padded);
}

/** A freshly generated TOTP secret, in both raw and shareable forms. */
export interface GeneratedTotpSecret {
  /** The raw 20-byte (160-bit) secret key. */
  secret: Uint8Array;
  /**
   * The secret encoded as unpadded RFC 4648 base32 — the form authenticator
   * apps accept for manual entry and the `otpauth://` URI carries.
   */
  base32: string;
}

/**
 * Generate a random 160-bit TOTP secret (the RFC 4226 recommended size and
 * what authenticator apps expect). Store it encrypted at rest — it is a
 * symmetric key, not a hash: anyone who reads it can mint valid codes.
 *
 * @example Enroll a user
 * ```ts
 * const { base32 } = generateTotpSecret();
 * const uri = buildOtpauthUri({
 *   secret: base32,
 *   issuer: "Example",
 *   accountName: "user@example.com",
 * });
 * // render `uri` as a QR code; store `base32` encrypted
 * ```
 */
export function generateTotpSecret(): GeneratedTotpSecret {
  const secret = crypto.getRandomValues(new Uint8Array(20));
  return { secret, base32: encodeBase32(secret).replaceAll("=", "") };
}

/** Options for {@link buildOtpauthUri}. */
export interface OtpauthUriOptions {
  /** The base32-encoded TOTP secret (from {@link generateTotpSecret}). */
  secret: string;
  /** The service name shown in the authenticator app (e.g. `"Udibo"`). */
  issuer: string;
  /** The account label shown under the issuer (typically the user's email). */
  accountName: string;
  /** Code length. Defaults to `6`. */
  digits?: number;
  /** Time-step length in seconds. Defaults to `30`. */
  periodSeconds?: number;
  /** HMAC hash. Defaults to `"SHA-1"` (see {@link TotpAlgorithm}). */
  algorithm?: TotpAlgorithm;
}

/**
 * Build the `otpauth://totp/...` provisioning URI an enrollment screen renders
 * as a QR code. Follows the de-facto Google Authenticator format: the issuer
 * appears both as the URI-encoded label prefix (`Issuer:account`) and as the
 * `issuer` query parameter, so apps that read either convention group the
 * entry correctly.
 *
 * @throws {TypeError} if the secret is not base32 or `digits`/`periodSeconds`
 * are not positive integers, so a corrupted value cannot inject URI parameters.
 */
export function buildOtpauthUri(options: OtpauthUriOptions): string {
  validateTotpParams(options);
  const digits = options.digits ?? DEFAULT_DIGITS;
  const periodSeconds = options.periodSeconds ?? DEFAULT_PERIOD_SECONDS;
  const algorithm = options.algorithm ?? DEFAULT_ALGORITHM;
  const secret = normalizeTotpSecret(options.secret);
  if (!/^[A-Z2-7]+$/.test(secret)) {
    throw new TypeError("otpauth secret must be base32");
  }
  const label = `${encodeURIComponent(options.issuer)}:${
    encodeURIComponent(options.accountName)
  }`;
  const query = [
    `secret=${secret}`,
    `issuer=${encodeURIComponent(options.issuer)}`,
    `algorithm=${algorithm.replaceAll("-", "")}`,
    `digits=${digits}`,
    `period=${periodSeconds}`,
  ].join("&");
  return `otpauth://totp/${label}?${query}`;
}

function importHotpKey(
  key: Uint8Array,
  algorithm: TotpAlgorithm,
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer(key),
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"],
  );
}

async function hotp(
  hmacKey: CryptoKey,
  counter: number,
  digits: number,
): Promise<string> {
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(counter));
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", hmacKey, message),
  );
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    mac[offset + 3];
  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

function toKeyBytes(secret: string | Uint8Array): Uint8Array {
  return typeof secret === "string" ? decodeTotpSecret(secret) : secret;
}

function timeStep(timestamp: number, periodSeconds: number): number {
  return Math.floor(timestamp / 1000 / periodSeconds);
}

/** Options for {@link generateTotpCode}. */
export interface GenerateTotpCodeOptions {
  /** The TOTP secret, as base32 or raw key bytes. */
  secret: string | Uint8Array;
  /** Epoch milliseconds to generate the code for. Defaults to `Date.now()`. */
  timestamp?: number;
  /** Code length. Defaults to `6`. */
  digits?: number;
  /** Time-step length in seconds. Defaults to `30`. */
  periodSeconds?: number;
  /** HMAC hash. Defaults to `"SHA-1"` (see {@link TotpAlgorithm}). */
  algorithm?: TotpAlgorithm;
}

/**
 * Compute the TOTP code for a moment in time — what an authenticator app
 * displays. Exported for tests and for tooling that needs to mint codes (e.g.
 * an enrollment simulator); server-side verification should go through
 * {@link verifyTotpCode}, which also handles the clock-skew window and
 * constant-time comparison.
 *
 * @example Mint the current code in a test
 * ```ts
 * const code = await generateTotpCode({ secret: base32 });
 * ```
 *
 * @throws {TypeError} if `digits` or `periodSeconds` is not a positive
 * integer, or the secret is not valid base32.
 */
export async function generateTotpCode(
  options: GenerateTotpCodeOptions,
): Promise<string> {
  validateTotpParams(options);
  const algorithm = options.algorithm ?? DEFAULT_ALGORITHM;
  const hmacKey = await importHotpKey(toKeyBytes(options.secret), algorithm);
  return await hotp(
    hmacKey,
    timeStep(
      options.timestamp ?? Date.now(),
      options.periodSeconds ?? DEFAULT_PERIOD_SECONDS,
    ),
    options.digits ?? DEFAULT_DIGITS,
  );
}

/** Options for {@link verifyTotpCode}. */
export interface VerifyTotpCodeOptions {
  /** The TOTP secret, as base32 or raw key bytes. */
  secret: string | Uint8Array;
  /**
   * The code the user submitted. Whitespace is stripped before checking, so
   * a code pasted in the spaced groups authenticator apps display verifies.
   */
  code: string;
  /** Epoch milliseconds to verify against. Defaults to `Date.now()`. */
  timestamp?: number;
  /**
   * How many time steps of clock skew to accept on each side of the current
   * step. Defaults to `1` (accepts the previous, current, and next step —
   * ±30 seconds at the default period). Keep it small: every extra window
   * widens the guessing surface.
   */
  windows?: number;
  /** Code length. Defaults to `6`. */
  digits?: number;
  /** Time-step length in seconds. Defaults to `30`. */
  periodSeconds?: number;
  /** HMAC hash. Defaults to `"SHA-1"` (see {@link TotpAlgorithm}). */
  algorithm?: TotpAlgorithm;
}

/** The outcome of {@link verifyTotpCode}. */
export type TotpVerification =
  | { valid: false }
  | {
    valid: true;
    /**
     * The time-step counter the code matched. Persist the highest accepted
     * step per user and reject codes with `matchedStep <= lastStep` — that is
     * what makes each code single-use.
     */
    matchedStep: number;
  };

/**
 * Verify a submitted TOTP code against the secret, accepting `windows` steps
 * of clock skew on either side. Code comparison is constant-time, and every
 * candidate step is checked even after a match, so timing does not reveal
 * which step (if any) matched. When adjacent steps happen to produce the same
 * code, the newest step wins, so the replay guard below never rejects a fresh
 * code over a stale tie.
 *
 * **Replay protection is the caller's half of the contract:** a valid result
 * includes `matchedStep`; store the last accepted step and reject any code
 * whose `matchedStep` is `<=` that value ({@link MfaService} in this module
 * does this for you). Without it, a code stays valid for the whole skew
 * window and can be replayed.
 *
 * @example Verify with replay rejection
 * ```ts
 * const result = await verifyTotpCode({ secret, code });
 * if (result.valid && result.matchedStep > lastAcceptedStep) {
 *   lastAcceptedStep = result.matchedStep; // persist atomically
 *   // accepted
 * }
 * ```
 *
 * @throws {TypeError} if `digits`/`periodSeconds` is not a positive integer,
 * `windows` is not a non-negative integer, or the secret is not valid base32.
 */
export async function verifyTotpCode(
  options: VerifyTotpCodeOptions,
): Promise<TotpVerification> {
  validateTotpParams(options);
  const digits = options.digits ?? DEFAULT_DIGITS;
  const periodSeconds = options.periodSeconds ?? DEFAULT_PERIOD_SECONDS;
  const algorithm = options.algorithm ?? DEFAULT_ALGORITHM;
  const windows = options.windows ?? DEFAULT_WINDOWS;
  const code = options.code.replaceAll(/\s/g, "");
  if (!/^\d+$/.test(code) || code.length !== digits) {
    return { valid: false };
  }
  const hmacKey = await importHotpKey(toKeyBytes(options.secret), algorithm);
  const step = timeStep(options.timestamp ?? Date.now(), periodSeconds);
  const candidates: number[] = [];
  for (let offset = -windows; offset <= windows; offset++) {
    if (step + offset >= 0) candidates.push(step + offset);
  }
  const expected = await Promise.all(
    candidates.map((candidate) => hotp(hmacKey, candidate, digits)),
  );
  const index = timingSafeMatchIndex(expected, code);
  return index === undefined
    ? { valid: false }
    : { valid: true, matchedStep: candidates[index] };
}
