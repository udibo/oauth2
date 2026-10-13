/**
 * RFC 7638 JWK thumbprints.
 *
 * @module
 */

import { encodeBase64Url } from "./_encoding.ts";

const REQUIRED_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  EC: ["crv", "kty", "x", "y"],
  OKP: ["crv", "kty", "x"],
  RSA: ["e", "kty", "n"],
};

/**
 * The RFC 7638 SHA-256 thumbprint of a JWK, base64url-encoded. Only the key
 * type's required public members are hashed, so a private JWK and its public
 * half share a thumbprint. Rejects with a `TypeError` for a key type other
 * than `EC`, `OKP` or `RSA`, or when a required member is missing.
 */
export async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  const members = jwk.kty === undefined ? undefined : REQUIRED_MEMBERS[jwk.kty];
  if (!members) {
    throw new TypeError(
      `Cannot compute a JWK thumbprint for key type ${JSON.stringify(jwk.kty)}`,
    );
  }
  const fields = jwk as Record<string, unknown>;
  const canonical: Record<string, string> = {};
  for (const member of members) {
    const value = fields[member];
    if (typeof value !== "string") {
      throw new TypeError(
        `Cannot compute a JWK thumbprint without the "${member}" member`,
      );
    }
    canonical[member] = value;
  }
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(canonical)),
  );
  return encodeBase64Url(new Uint8Array(digest));
}
