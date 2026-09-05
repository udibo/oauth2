/**
 * Password hashing primitive for the identity self-service layer.
 *
 * Promotes the package's internal PBKDF2 helpers (previously reachable only via
 * a relative import) to a public, documented service so apps stop hand-rolling
 * password crypto — the single riskiest thing to reinvent. The built-in
 * algorithm is PBKDF2-SHA-256 at {@link DEFAULT_PBKDF2_ITERATIONS} iterations
 * with a constant-time verify. Want argon2 or scrypt instead? Implement
 * {@link PasswordHasherLike} with your own dependency and pass it wherever a
 * hasher is accepted — nothing in the package requires the concrete class.
 *
 * **Storage is yours.** Persist the whole {@link PasswordCredential} — including
 * its `params` — on your user record and pass it back to
 * {@link PasswordIdentityService.verify}. The package owns the crypto, not the
 * database (the same thin-seam philosophy as `SessionStore`).
 *
 * @module
 */

import { encodeHex } from "@std/encoding";
import { timingSafeEqual } from "@std/crypto/timing-safe-equal";

/**
 * Generates a cryptographically random salt for password hashing.
 *
 * @param length The number of bytes of randomness
 * @returns The hex-encoded salt, twice `length` characters long
 */
export function generateSalt(length = 16): string {
  const salt = new Uint8Array(length);
  crypto.getRandomValues(salt);
  return encodeHex(salt);
}

const encoder = new TextEncoder();

/**
 * The PBKDF2-SHA-256 iteration count new credentials are minted at, matching
 * current OWASP guidance. Raise it with `new PasswordIdentityService({
 * iterations })` as hardware improves; stored credentials record what they were
 * hashed with, so raising it only triggers a rehash on the owner's next sign-in.
 */
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

/**
 * The iteration count a {@link PasswordCredential} with no `params` is assumed
 * to have been hashed at — the package's original default. Credentials minted
 * before `params` existed keep verifying against this, and
 * {@link PasswordIdentityService.needsRehash} reports them as due for an
 * upgrade.
 */
export const LEGACY_PBKDF2_ITERATIONS = 100_000;

/** The algorithm identifier {@link PasswordIdentityService} records and accepts. */
export const PBKDF2_SHA256 = "pbkdf2-sha256";

/**
 * The work factor a stored credential was produced with, so a credential is
 * self-describing and a later default change can tell old hashes from new.
 */
export interface PasswordHashParams {
  /** Algorithm identifier; {@link PasswordIdentityService} only mints {@link PBKDF2_SHA256}. */
  algorithm: string;
  /** Iteration count the hash was derived with. */
  iterations: number;
}

/**
 * A stored password credential: the hash, the salt it used, and (for
 * credentials minted since `params` existed) the work factor behind it.
 *
 * Persist all three fields. A credential with no `params` is interpreted as
 * PBKDF2-SHA-256 at {@link LEGACY_PBKDF2_ITERATIONS}.
 */
export interface PasswordCredential {
  /** Hex-encoded PBKDF2-SHA-256 digest. */
  hash: string;
  /** Hex-encoded random salt. */
  salt: string;
  /** Algorithm and work factor used; absent means the legacy default. */
  params?: PasswordHashParams;
}

/**
 * The password-hasher seam. {@link PasswordIdentityService} is the built-in
 * PBKDF2 implementation; implement this yourself to plug in argon2, scrypt, or
 * a hardware-backed hasher, and pass it as `IdentityService`'s `passwords`
 * option.
 *
 * Implement the optional `needsRehash` to get rehash-on-successful-sign-in: the
 * identity flows call it after a password verifies and, when it returns `true`,
 * re-hash the just-verified password and persist the result.
 */
export interface PasswordHasherLike {
  /** Hashes a new password into a credential to store. */
  hash(password: string): Promise<PasswordCredential>;
  /** Constant-time verify of a password against a stored credential. */
  verify(password: string, credential: PasswordCredential): Promise<boolean>;
  /**
   * Whether a stored credential is weaker than what this hasher mints today.
   * Only consulted for a credential that has just verified. Omit to opt out of
   * rehash-on-sign-in.
   */
  needsRehash?(credential: PasswordCredential): boolean;
}

/**
 * Hashes a password with salt using PBKDF2-SHA-256.
 *
 * Pass the same `iterations` to {@link verifyPassword} that you hashed with —
 * a mismatch simply fails to verify. Prefer {@link PasswordIdentityService},
 * which records the work factor on the credential so you never have to track it.
 *
 * @param password The password to hash
 * @param salt The salt to use, from {@link generateSalt}
 * @param iterations PBKDF2 iterations; defaults to {@link DEFAULT_PBKDF2_ITERATIONS}
 * @returns The hex-encoded 256-bit digest
 */
export async function hashPassword(
  password: string,
  salt: string,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"],
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );
  return encodeHex(new Uint8Array(derivedBits, 0, 32));
}

/**
 * Verifies a password against a stored hash in constant time.
 *
 * @param password The password to verify
 * @param salt The salt used for the hash
 * @param hash The stored hash to compare against
 * @param iterations The iterations the stored hash was derived with; defaults to {@link DEFAULT_PBKDF2_ITERATIONS}
 * @returns Whether the password reproduces the stored hash
 */
export async function verifyPassword(
  password: string,
  salt: string,
  hash: string,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
): Promise<boolean> {
  const computedHash = await hashPassword(password, salt, iterations);
  // Both are fixed-width hex digests, so length carries no secret.
  if (computedHash.length !== hash.length) return false;
  return timingSafeEqual(encoder.encode(computedHash), encoder.encode(hash));
}

/** Options for {@link PasswordIdentityService}. */
export interface PasswordIdentityServiceOptions {
  /**
   * PBKDF2 iterations new credentials are minted at. Defaults to
   * {@link DEFAULT_PBKDF2_ITERATIONS}. Raising it costs login latency (roughly
   * linear) and makes every older credential report `needsRehash`.
   */
  iterations?: number;
}

/**
 * Hashes and verifies passwords (PBKDF2-SHA-256, constant-time verify).
 * Construct once and reuse.
 *
 * Verification reads the work factor off the credential, so credentials minted
 * under an older default keep verifying; {@link needsRehash} tells you when one
 * is due for an upgrade (`IdentityService` does this for you on sign-in).
 *
 * @example
 * ```ts
 * import {
 *   type IdentityUserStore,
 *   PasswordIdentityService,
 * } from "@udibo/oauth2/identity";
 *
 * interface User { id: string }
 *
 * declare const store: IdentityUserStore<User>;
 * declare const userId: string;
 *
 * const passwords = new PasswordIdentityService();
 * const credential = await passwords.hash("hunter2");   // { hash, salt, params }
 * // …store credential on the user…
 * const ok = await passwords.verify("hunter2", credential);
 * if (ok && passwords.needsRehash(credential)) {
 *   await store.setCredential(userId, await passwords.hash("hunter2"));
 * }
 * ```
 */
export class PasswordIdentityService implements PasswordHasherLike {
  readonly #iterations: number;

  /** Applies the iteration default; construct with no arguments for it. */
  constructor(options: PasswordIdentityServiceOptions = {}) {
    this.#iterations = options.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  }

  /** The PBKDF2 iteration count this instance mints new credentials at. */
  get iterations(): number {
    return this.#iterations;
  }

  /** Hashes a new password, generating a fresh random salt. */
  async hash(password: string): Promise<PasswordCredential> {
    const salt = generateSalt();
    return {
      salt,
      hash: await hashPassword(password, salt, this.#iterations),
      params: { algorithm: PBKDF2_SHA256, iterations: this.#iterations },
    };
  }

  /**
   * Constant-time verify of a password against a stored credential, using the
   * credential's own recorded work factor. Resolves `false` for a credential
   * recorded under an algorithm this service does not implement.
   */
  verify(password: string, credential: PasswordCredential): Promise<boolean> {
    const params = credential.params;
    if (params && params.algorithm !== PBKDF2_SHA256) {
      return Promise.resolve(false);
    }
    return verifyPassword(
      password,
      credential.salt,
      credential.hash,
      params?.iterations ?? LEGACY_PBKDF2_ITERATIONS,
    );
  }

  /**
   * Whether the credential was produced with a weaker configuration than this
   * service mints today — call it after a successful {@link verify} and, when
   * `true`, re-hash the verified password and persist the new credential.
   */
  needsRehash(credential: PasswordCredential): boolean {
    const params = credential.params;
    if (!params) return LEGACY_PBKDF2_ITERATIONS < this.#iterations;
    return params.algorithm !== PBKDF2_SHA256 ||
      params.iterations < this.#iterations;
  }
}
