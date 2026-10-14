/**
 * Character-set rules for `WWW-Authenticate` challenge parameters (RFC 7235
 * §2.2, RFC 9110 §5.6.4, RFC 6750 §3).
 *
 * @module
 */

import { NQCHAR } from "../models/scope.ts";

const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;
// oxlint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\x00-\x1f\x7f]/g;
const OUTSIDE_DESCRIPTION_SET = /[^\x20\x21\x23-\x5b\x5d-\x7e]/gu;
const SCOPE_TOKEN_ONLY = new RegExp(`^${NQCHAR.source}+$`);

/** Throws `TypeError` unless `realm` is printable ASCII (U+0020–U+007E), the only text every HTTP stack carries in a header unaltered. */
export function assertRealm(realm: string): void {
  if (typeof realm !== "string" || !PRINTABLE_ASCII.test(realm)) {
    throw new TypeError(
      `realm must contain only printable ASCII characters (U+0020 to U+007E), got ${JSON.stringify(realm)}`,
    );
  }
}

/** The `realm` parameter as a quoted-string; `realm` must already satisfy {@linkcode assertRealm}. */
export function quoteRealm(realm: string): string {
  return `"${realm.replace(/["\\]/g, "\\$&")}"`;
}

/**
 * Maps text into the RFC 6750 §3 `error_description` set
 * (`%x20-21 / %x23-5B / %x5D-7E`): control characters are dropped, `"`
 * becomes `'`, and every other code point outside the set becomes `?`.
 */
export function toChallengeDescription(text: string): string {
  return text
    .replace(CONTROL_CHARACTERS, "")
    .replaceAll('"', "'")
    .replace(OUTSIDE_DESCRIPTION_SET, "?");
}

/** The space-separated tokens of `scope` that are RFC 6750 §3 scope-tokens, or `undefined` when none are. */
export function toChallengeScope(scope: string): string | undefined {
  const tokens = scope
    .split(" ")
    .filter((token) => SCOPE_TOKEN_ONLY.test(token));
  return tokens.length > 0 ? tokens.join(" ") : undefined;
}
