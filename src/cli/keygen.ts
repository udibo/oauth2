/**
 * The `oidc keygen` command: the ES256 signing key an OIDC provider persists
 * as `OIDC_SIGNING_KEY`.
 *
 * @module
 */

import {
  exportSigningKeyJwk,
  generateSigningKey,
} from "../server/signing-keys.ts";

const GUIDANCE = [
  "Store the JWK printed on stdout as the OIDC_SIGNING_KEY secret in your",
  "production secret store. It contains private key material: never commit it,",
  "never paste it into a log, and give every instance the same value so they",
  "all sign consistently.",
  "",
  "Leave OIDC_SIGNING_KEY unset in dev and test — the server falls back to an",
  "ephemeral per-process key there.",
].join("\n");

/**
 * Generates a fresh ES256 signing key, prints its private JWK as one line on
 * stdout, and prints operator guidance on stderr. Nothing is written to disk.
 *
 * Takes no arguments; throws when given any.
 */
export async function oidcKeygen(args: string[]): Promise<void> {
  if (args.length > 0) {
    throw new Error(`oidc keygen takes no arguments, got: ${args.join(" ")}`);
  }
  const key = await generateSigningKey();
  console.log(JSON.stringify(await exportSigningKeyJwk(key)));
  console.error(
    `Generated an ES256 OIDC signing key (kid ${key.kid}).\n\n${GUIDANCE}`,
  );
}
