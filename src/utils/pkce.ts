/**
 * PKCE (Proof Key for Code Exchange) utilities for OAuth2.
 *
 * Implements RFC 7636 for preventing authorization code interception attacks.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7636
 * @module
 */

import { encodeBase64Url } from "@std/encoding/base64url";

/**
 * A challenge method used for PKCE.
 * Transforms a verifier into a challenge.
 */
export type ChallengeMethod = (verifier: string) => Promise<string>;

/** The allowed PKCE code challenge methods. */
export interface ChallengeMethods {
  /** Maps a `code_challenge_method` name (e.g. `"S256"`) to its transform. */
  [key: string]: ChallengeMethod;
}

/**
 * Minimum length for code verifier per RFC 7636 Section 4.1.
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
 */
export const CODE_VERIFIER_MIN_LENGTH = 43;

/**
 * Maximum length for code verifier per RFC 7636 Section 4.1.
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
 */
export const CODE_VERIFIER_MAX_LENGTH = 128;

/**
 * Pattern for valid code verifier characters per RFC 7636 Section 4.1.
 * Allowed characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
 */
export const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]+$/;

/**
 * The default allowed PKCE code challenge methods.
 *
 * Per RFC 7636 and OAuth 2.1, clients SHOULD use the S256 method.
 * The "plain" method is NOT included by default as it provides
 * weaker security guarantees.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.1
 */
export const challengeMethods: ChallengeMethods = {
  S256: async (verifier: string): Promise<string> => {
    const data = new TextEncoder().encode(verifier);
    const buffer = await crypto.subtle.digest("SHA-256", data);
    return encodeBase64Url(new Uint8Array(buffer));
  },
};

/**
 * Validates a code verifier per RFC 7636 Section 4.1.
 *
 * The code verifier must:
 * - Be between 43 and 128 characters long
 * - Contain only unreserved characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 *
 * @param verifier The code verifier to validate
 * @returns true if the verifier is valid
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
 */
export function validateCodeVerifier(verifier: string): boolean {
  if (
    verifier.length < CODE_VERIFIER_MIN_LENGTH ||
    verifier.length > CODE_VERIFIER_MAX_LENGTH
  ) {
    return false;
  }
  return CODE_VERIFIER_PATTERN.test(verifier);
}

/**
 * Generates a random code verifier with a minimum of 256 bits of entropy.
 *
 * This is done by generating a random 32-octet sequence then base64url encoding it
 * to produce a 43 character URL-safe string.
 *
 * @returns A cryptographically random code verifier
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-7.1
 */
export function generateCodeVerifier(): string {
  const sequence = new Uint8Array(32);
  crypto.getRandomValues(sequence);
  return encodeBase64Url(sequence);
}

/**
 * Generates a code challenge from a code verifier using the S256 method.
 *
 * The S256 challenge is: BASE64URL(SHA256(ASCII(code_verifier)))
 *
 * @param verifier The code verifier to transform
 * @returns The code challenge
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  return await challengeMethods.S256(verifier);
}

/**
 * Validates a `code_challenge` per RFC 7636 Section 4.2, for the challenge
 * methods whose output shape that section fixes.
 *
 * `S256` and `plain` are the only methods the PKCE registry defines, and both
 * produce a challenge drawn from the same 43-128 unreserved characters as a
 * code verifier, so an authorization endpoint can reject a malformed challenge
 * before it is ever stored. Any other `method` — one a server registered in its
 * own {@link ChallengeMethods} map — may legitimately produce any shape, so
 * this returns `true` for it rather than imposing a format its author never
 * agreed to. Check the name is allowed with {@linkcode getChallengeMethod}
 * first; this answers only for the format.
 *
 * @param challenge The client-supplied `code_challenge`
 * @param method The client-supplied `code_challenge_method`; defaults to `S256`
 * @returns true when the challenge is acceptable for that method
 * @example
 * ```ts
 * validateCodeChallenge("a".repeat(43));                 // → true
 * validateCodeChallenge("short");                        // → false
 * validateCodeChallenge("short", "custom-method");       // → true
 * ```
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
 */
export function validateCodeChallenge(
  challenge: string,
  method?: string | null,
): boolean {
  const name = method ?? "S256";
  if (name !== "S256" && name !== "plain") return true;
  return validateCodeVerifier(challenge);
}

/**
 * Resolves a client-supplied `code_challenge_method` name against the methods
 * a server allows.
 *
 * Reach for this instead of indexing a {@link ChallengeMethods} map directly.
 * The name comes off the wire, and a map written as a plain object literal
 * also inherits `toString`, `valueOf`, `constructor` and friends from
 * `Object.prototype` — a bare lookup hands those back as if the server had
 * allowed them, which downgrades PKCE to a value any verifier satisfies. Only
 * own, callable properties of `methods` resolve here; every other name is
 * `undefined`, including names inherited from a prototype.
 *
 * @param methods The challenge methods the server allows
 * @param method The client-supplied method name; defaults to `S256`
 * @returns The transform for that method, or `undefined` when it is not allowed
 * @example
 * ```ts
 * getChallengeMethod(challengeMethods, "S256");       // → the S256 transform
 * getChallengeMethod(challengeMethods);               // → the S256 transform
 * getChallengeMethod(challengeMethods, "toString");   // → undefined
 * getChallengeMethod(challengeMethods, "__proto__");  // → undefined
 * ```
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
 */
export function getChallengeMethod(
  methods: ChallengeMethods,
  method?: string | null,
): ChallengeMethod | undefined {
  const name = method ?? "S256";
  if (!Object.hasOwn(methods, name)) return undefined;
  const challengeMethod = methods[name];
  return typeof challengeMethod === "function" ? challengeMethod : undefined;
}

/**
 * Verifies that a code verifier matches a code challenge.
 *
 * Fails closed against the default {@link challengeMethods} map only: a
 * `method` that map does not hold — `"plain"`, a name inherited from
 * `Object.prototype` such as `"toString"`, or one registered on a grant via
 * its own `challengeMethods` — resolves `false` rather than throwing, so it is
 * indistinguishable from a mismatched verifier.
 *
 * @param verifier The code verifier provided by the client
 * @param challenge The code challenge stored from the authorization request
 * @param method The challenge method used (defaults to S256)
 * @returns true if the verifier matches the challenge
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
 */
export async function verifyCodeChallenge(
  verifier: string,
  challenge: string,
  method = "S256",
): Promise<boolean> {
  const challengeMethod = getChallengeMethod(challengeMethods, method);
  if (!challengeMethod) return false;
  const expected = await challengeMethod(verifier);
  return expected === challenge;
}

/**
 * Generates a random state parameter for CSRF protection.
 *
 * @returns A random UUID to use as the state parameter
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
 */
export function generateState(): string {
  return crypto.randomUUID();
}
