/**
 * Bounding and flattening for text a remote server chose.
 *
 * Lives in `utils/` rather than beside either caller because both ladders that
 * turn a server's bytes into an error message — the client's `_http.ts` and
 * the connectors' `_token-exchange.ts` — must sanitize identically, and the
 * client cannot reach up into `identity/external/`.
 *
 * @module
 */

/** Characters of remote-supplied text kept in an error message. */
export const PROVIDER_TEXT_MAX_LENGTH = 200;

/**
 * Bounds and flattens a remote-supplied string for inclusion in an error
 * message. Control characters become spaces so a hostile `error_description`
 * cannot forge a log line or inject an ANSI escape in a consumer's console,
 * the result is capped at {@link PROVIDER_TEXT_MAX_LENGTH}, and a surrogate
 * pair split by that cap is repaired rather than left lone. Use this on
 * every byte a remote server chose that reaches a message.
 *
 * @param value The remote-supplied text.
 * @returns The flattened, capped, well-formed text.
 */
export function sanitizeProviderText(value: string): string {
  // deno-lint-ignore no-control-regex
  const flattened = value.replace(/[\u0000-\u001F\u007F-\u009F]+/g, " ");
  return flattened.trim().slice(0, PROVIDER_TEXT_MAX_LENGTH).toWellFormed();
}
