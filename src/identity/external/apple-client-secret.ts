/**
 * Sign in with Apple client-secret generation. Apple's "client secret" is not a
 * static string but a short-lived ES256 JWT the app signs from its `.p8`
 * private key — {@link generateAppleClientSecret} builds one,
 * {@link createAppleClientSecretFactory} caches and renews it before expiry.
 *
 * @module
 */

import { decodeBase64 } from "@std/encoding/base64";

import { toArrayBuffer } from "../../utils/_buffer.ts";
import { base64urlEncode } from "../../utils/crypto.ts";
import { ExternalAuthError } from "./errors.ts";

/** Apple's audience for the client-secret JWT. */
export const APPLE_AUDIENCE = "https://appleid.apple.com";

/** Apple's hard cap on the client secret's lifetime: 6 months, in seconds. */
export const APPLE_CLIENT_SECRET_MAX_TTL_SECONDS = 15777000;

/** Default client-secret lifetime: ~180 days, comfortably under Apple's cap. */
export const DEFAULT_APPLE_CLIENT_SECRET_TTL_SECONDS = 15552000;

/** The Apple developer key material a client secret is signed from. */
export interface AppleClientSecretOptions {
  /**
   * The 10-character Apple Team ID (`iss`). Found top-right in the Apple
   * Developer account membership page — not the App ID.
   */
  teamId: string;
  /**
   * The Key ID (`kid`) of the `.p8` signing key, from Certificates,
   * Identifiers & Profiles → Keys.
   */
  keyId: string;
  /**
   * The Services ID (`sub`), i.e. the client id the token is for — the
   * identifier configured for "Sign in with Apple" on the web, not the app's
   * bundle id.
   */
  clientId: string;
  /**
   * The PKCS#8 PEM contents of the `.p8` private key downloaded from Apple
   * (downloadable once). Both the full `-----BEGIN PRIVATE KEY-----` block and
   * the bare base64 body are accepted.
   */
  privateKey: string;
  /**
   * Lifetime of the generated secret in seconds. Defaults to
   * {@link DEFAULT_APPLE_CLIENT_SECRET_TTL_SECONDS}; must not exceed
   * {@link APPLE_CLIENT_SECRET_MAX_TTL_SECONDS}.
   */
  expiresInSeconds?: number;
  /** Provider id used in error messages. Defaults to `"apple"`. */
  providerId?: string;
}

const encoder = new TextEncoder();
const ES256_IMPORT = { name: "ECDSA", namedCurve: "P-256" } as const;
const ES256_SIGN = { name: "ECDSA", hash: "SHA-256" } as const;

function configError(providerId: string, message: string): ExternalAuthError {
  return new ExternalAuthError(providerId, "configuration", message);
}

function requireNonEmpty(
  providerId: string,
  value: string,
  field: string,
): string {
  const trimmed = value?.trim?.() ?? "";
  if (!trimmed) {
    throw configError(
      providerId,
      `Apple ${field} is empty — set it from the Apple Developer console.`,
    );
  }
  return trimmed;
}

function pemToPkcs8(providerId: string, pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  if (!body) {
    throw configError(
      providerId,
      `the Apple private key (.p8) is empty. Paste the PKCS#8 PEM contents ` +
        `of the AuthKey_*.p8 file Apple lets you download once.`,
    );
  }
  try {
    return decodeBase64(body);
  } catch (error) {
    throw configError(
      providerId,
      `the Apple private key (.p8) is not valid base64/PEM ` +
        `(${error instanceof Error ? error.message : String(error)}).`,
    );
  }
}

async function importPrivateKey(
  providerId: string,
  pem: string,
): Promise<CryptoKey> {
  const der = pemToPkcs8(providerId, pem);
  try {
    return await crypto.subtle.importKey(
      "pkcs8",
      toArrayBuffer(der),
      ES256_IMPORT,
      false,
      ["sign"],
    );
  } catch (error) {
    throw configError(
      providerId,
      `the Apple private key (.p8) could not be imported as a P-256 (ES256) ` +
        `key (${error instanceof Error ? error.message : String(error)}). ` +
        `Confirm you downloaded a "Sign in with Apple" key and pasted it ` +
        `unmodified.`,
    );
  }
}

/**
 * Generate a single Sign in with Apple client secret: an ES256 JWT with
 * `iss` = team id, `sub` = client id (Services ID), `aud` = Apple, and an `exp`
 * bounded by {@link APPLE_CLIENT_SECRET_MAX_TTL_SECONDS}. Prefer
 * {@link createAppleClientSecretFactory} in a long-lived process so the secret
 * is cached and renewed rather than re-signed on every sign-in.
 *
 * @throws {ExternalAuthError} `configuration` naming the offending input when
 *   the team id / key id / client id is empty, the `.p8` is not a valid P-256
 *   key, or the requested TTL exceeds Apple's cap.
 *
 * @example
 * ```ts
 * const secret = await generateAppleClientSecret({
 *   teamId: "ABCDE12345",
 *   keyId: "KEY1234567",
 *   clientId: "com.example.web",
 *   privateKey: Deno.env.get("APPLE_PRIVATE_KEY")!,
 * });
 * ```
 */
export async function generateAppleClientSecret(
  options: AppleClientSecretOptions,
): Promise<string> {
  const providerId = options.providerId ?? "apple";
  const teamId = requireNonEmpty(providerId, options.teamId, "team id");
  const keyId = requireNonEmpty(providerId, options.keyId, "key id");
  const clientId = requireNonEmpty(
    providerId,
    options.clientId,
    "client id (Services ID)",
  );
  const ttl = options.expiresInSeconds ??
    DEFAULT_APPLE_CLIENT_SECRET_TTL_SECONDS;
  if (ttl <= 0 || ttl > APPLE_CLIENT_SECRET_MAX_TTL_SECONDS) {
    throw configError(
      providerId,
      `Apple client secret TTL must be between 1 and ` +
        `${APPLE_CLIENT_SECRET_MAX_TTL_SECONDS} seconds (6 months); ` +
        `got ${ttl}.`,
    );
  }

  const privateKey = await importPrivateKey(providerId, options.privateKey);
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", kid: keyId };
  const payload = {
    iss: teamId,
    iat: now,
    exp: now + ttl,
    aud: APPLE_AUDIENCE,
    sub: clientId,
  };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(payload)}`;
  const signature = await crypto.subtle.sign(
    ES256_SIGN,
    privateKey,
    encoder.encode(signingInput),
  );
  return `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
}

function encodeSegment(value: unknown): string {
  return base64urlEncode(encoder.encode(JSON.stringify(value)));
}

/** A cached client-secret source: returns a valid secret, re-signing lazily. */
export type AppleClientSecretFactory = () => Promise<string>;

/**
 * Build a self-renewing Apple client-secret source. It signs a secret with
 * {@link generateAppleClientSecret} on first call, caches it, and re-signs
 * automatically once the cached secret is within `renewBeforeSeconds` of expiry
 * — so a long-lived {@link appleProvider} never presents an expired assertion.
 * The key material is validated on the first call, surfacing a misconfiguration
 * as a `configuration` {@link ExternalAuthError}.
 */
export function createAppleClientSecretFactory(
  options: AppleClientSecretOptions & { renewBeforeSeconds?: number },
): AppleClientSecretFactory {
  const ttl = options.expiresInSeconds ??
    DEFAULT_APPLE_CLIENT_SECRET_TTL_SECONDS;
  const renewBefore = options.renewBeforeSeconds ?? 60 * 60;
  let cached: { secret: string; expiresAt: number } | null = null;

  return async () => {
    const now = Math.floor(Date.now() / 1000);
    if (cached && now < cached.expiresAt - renewBefore) {
      return cached.secret;
    }
    const secret = await generateAppleClientSecret(options);
    cached = { secret, expiresAt: now + ttl };
    return secret;
  };
}
