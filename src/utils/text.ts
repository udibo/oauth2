/**
 * Bounding and flattening for text a remote server chose.
 *
 * @module
 */

/** Characters of remote-supplied text kept in an error message. */
export const PROVIDER_TEXT_MAX_LENGTH = 200;

/**
 * Bounds and flattens a remote-supplied string for inclusion in an error
 * message. Each run of C0/C1 control characters becomes one space (and the
 * result is trimmed) so a hostile `error_description`
 * cannot forge a log line or inject an ANSI escape in a consumer's console,
 * the result is capped at {@link PROVIDER_TEXT_MAX_LENGTH}, and a surrogate
 * pair split by that cap is repaired rather than left lone. Use this on
 * every byte a remote server chose that reaches a message.
 */
export function sanitizeProviderText(value: string): string {
  // deno-lint-ignore no-control-regex
  const flattened = value.replace(/[\u0000-\u001F\u007F-\u009F]+/g, " ");
  return flattened.trim().slice(0, PROVIDER_TEXT_MAX_LENGTH).toWellFormed();
}
