/**
 * Internal helpers shared by the external-provider connectors.
 *
 * Not part of the public API — reach for a connector from
 * `@udibo/oauth2/identity/external` instead, which re-exports the one type an
 * adopter configures ({@link AzpPolicy}). These live here so the same failure
 * reads the same way whichever connector hit it: one error renderer, one
 * error-body reader, one provider-text sanitizer, and one id_token claim gate
 * rather than a copy per provider. The token exchange itself is
 * `_token-exchange.ts`.
 *
 * @module
 */

import { isOAuth2Error } from "../../errors.ts";
import { timingSafeEqualString } from "../../utils/crypto.ts";
import {
  PROVIDER_TEXT_MAX_LENGTH,
  sanitizeProviderText,
} from "../../utils/text.ts";
import { ExternalAuthError } from "./errors.ts";

export { PROVIDER_TEXT_MAX_LENGTH, sanitizeProviderText };

/**
 * Clock-skew allowance, in seconds, when checking an id_token's `exp` claim.
 * The default for {@link assertIdTokenClaims}.
 */
export const ID_TOKEN_EXPIRY_LEEWAY_SECONDS = 120;

/**
 * Renders a thrown value for an error message, unwrapping an OAuth2 error into
 * its `error` / `error_description` extensions so a provider-reported failure
 * is quoted rather than buried in a generic message. Every branch is
 * {@link sanitizeProviderText}-bounded: the thrown value routinely carries
 * provider bytes — a JSON parse error quotes the body it choked on, and an
 * OAuth2 error carries a description the provider wrote.
 */
export function describeError(error: unknown): string {
  if (isOAuth2Error(error)) {
    const code = sanitizeProviderText(error.extensions.error ?? "server_error");
    const description = sanitizeProviderText(
      error.extensions.error_description ?? error.message,
    );
    return description && description !== code
      ? `${code}: ${description}`
      : code;
  }
  return sanitizeProviderText(
    error instanceof Error ? error.message : String(error),
  );
}

/**
 * Reads a failed response's body into a bounded, single-line `": <text>"`
 * suffix to append to an error message, or `""` when the body is empty or
 * unreadable. Consumes the body, so the caller must not read it again.
 */
export async function readErrorBody(res: Response): Promise<string> {
  try {
    const snippet = sanitizeProviderText(await res.text());
    return snippet ? `: ${snippet}` : "";
  } catch {
    return "";
  }
}

/**
 * Drops one trailing `"/"` so issuer URLs compare and concatenate consistently
 * (`"https://x/"` and `"https://x"` identify the same issuer).
 */
export function stripTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

/**
 * How {@link assertIdTokenClaims} treats an id_token's `azp` (authorized
 * party) claim.
 *
 * - `"conditional"` — OpenID Connect Core §3.1.3.7: when the token carries
 *   multiple audiences or an `azp` claim, `azp` must be this client id.
 * - `"ignore"` — skip the check. For a provider that legitimately reports a
 *   *different* authorized party than the client doing the exchange: Google's
 *   cross-client identity, where another client of the same project requests the
 *   token (`azp` is that client id) for this client's audience (`aud`), is the
 *   canonical case. Weakens §3.1.3.7 rules 4 and 5, so `aud` remains the only
 *   check binding the token to this registration — reach for it only when a real
 *   provider forces it. Configure it on
 *   {@link OidcProviderOptions.azp}/{@link GoogleProviderOptions.azp}.
 */
export type AzpPolicy = "conditional" | "ignore";

/** Input for {@link assertIdTokenClaims}. */
export interface IdTokenClaimsInput {
  /** Provider id carried on the thrown {@link ExternalAuthError}. */
  provider: string;
  /** The decoded id_token claims. */
  claims: Record<string, unknown>;
  /** The issuer the `iss` claim must equal exactly. */
  issuer: string;
  /** The client id the `aud` claim must contain. */
  clientId: string;
  /** The nonce sent on the authorize request; omit when none was sent. */
  expectedNonce?: string;
  /** How to check `azp`. Defaults to `"conditional"`. */
  azp?: AzpPolicy;
  /**
   * Clock-skew allowance for `exp`, in seconds. Defaults to
   * {@link ID_TOKEN_EXPIRY_LEEWAY_SECONDS}.
   */
  leewaySeconds?: number;
}

/**
 * Enforces the id_token claim rules of OpenID Connect Core §3.1.3.7 that do not
 * depend on the signature: `iss`, `aud`, `azp`, `exp`, and `nonce`, in that
 * order. Callers verify the signature (or establish the token's provenance)
 * themselves before calling this.
 *
 * Throws {@link ExternalAuthError} with code `nonce_mismatch` when the `nonce`
 * claim does not match, and `provider_error` for every other rule.
 */
export function assertIdTokenClaims(input: IdTokenClaimsInput): void {
  const { provider, claims, issuer, clientId, expectedNonce } = input;
  if (claims.iss !== issuer) {
    throw new ExternalAuthError(
      provider,
      "provider_error",
      `id_token "iss" is "${String(claims.iss)}" but the expected issuer is ` +
        `"${issuer}" — the token was issued by a different provider, or the ` +
        `configured issuer points at a proxy or the wrong tenant.`,
    );
  }
  const aud = claims.aud;
  const audienceOk = aud === clientId ||
    (Array.isArray(aud) && aud.includes(clientId));
  if (!audienceOk) {
    throw new ExternalAuthError(
      provider,
      "provider_error",
      `id_token "aud" (${JSON.stringify(aud)}) does not include clientId ` +
        `"${clientId}" — the token was issued to a different client ` +
        `registration.`,
    );
  }
  const audienceCount = Array.isArray(aud) ? aud.length : 1;
  if (
    (input.azp ?? "conditional") === "conditional" &&
    (audienceCount > 1 || claims.azp !== undefined) &&
    claims.azp !== clientId
  ) {
    throw new ExternalAuthError(
      provider,
      "provider_error",
      `id_token "azp" (${JSON.stringify(claims.azp)}) is not this clientId ` +
        `"${clientId}" — the token's authorized party is a different client ` +
        `(OpenID Connect Core §3.1.3.7).`,
    );
  }
  const exp = claims.exp;
  const leewaySeconds = input.leewaySeconds ?? ID_TOKEN_EXPIRY_LEEWAY_SECONDS;
  if (typeof exp !== "number" || Date.now() / 1000 > exp + leewaySeconds) {
    throw new ExternalAuthError(
      provider,
      "provider_error",
      `id_token is expired or has no "exp" claim (exp=${
        JSON.stringify(exp)
      }) — reject per OpenID Connect Core §3.1.3.7. Ask the user to start ` +
        `again.`,
    );
  }
  if (
    expectedNonce !== undefined &&
    !(typeof claims.nonce === "string" &&
      timingSafeEqualString(claims.nonce, expectedNonce))
  ) {
    throw new ExternalAuthError(
      provider,
      "nonce_mismatch",
      `id_token "nonce" does not match this sign-in attempt — possible token ` +
        `replay or a mixed-up callback. Ask the user to start again.`,
    );
  }
}
