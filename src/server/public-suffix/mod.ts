/**
 * The bundled Public Suffix List, as an {@link isPublicSuffix} implementation.
 *
 * A *public suffix* is a domain you can only register names **under**, never
 * **at** — `com`, `co.uk`, `deno.net`, `s3.amazonaws.com`. The authorization
 * server needs the distinction to bound a wildcard redirect URI: everything a
 * wildcard covers must belong to one registrant, which is only true when the
 * domain beneath it is a registrable name rather than a shared suffix.
 *
 * This entrypoint is separate from `@udibo/oauth2/server` on purpose. The list
 * is roughly 150 kB of generated source, and a server that never accepts
 * wildcard registrations should not carry it — so
 * `checkRedirectUriPattern` takes the check as an injected seam and
 * refuses every pattern when none is supplied. Wire it once, where you build
 * the authorization server:
 *
 * ```ts
 * import { AuthorizationServer } from "@udibo/oauth2/server/authorization";
 * import { isPublicSuffix } from "@udibo/oauth2/server/public-suffix";
 *
 * const server = new AuthorizationServer({ isPublicSuffix, ...options });
 * ```
 *
 * The snapshot covers both the ICANN and the private sections. The private
 * section is the security-relevant half here: every shared hosting platform a
 * wildcard must not straddle (`github.io`, `vercel.app`, `blob.core.windows.net`)
 * is listed there and nowhere else.
 *
 * Regenerate it with `deno task psl:update`; `deno task psl:check` fails when
 * the snapshot has drifted from publicsuffix.org and runs on a schedule in CI.
 *
 * @module
 */

import { PUBLIC_SUFFIX_RULES, publicSuffixListInfo } from "./rules.ts";

export { publicSuffixListInfo };

let rules: Set<string> | undefined;

function ruleSet(): Set<string> {
  rules ??= new Set(PUBLIC_SUFFIX_RULES.split("\n"));
  return rules;
}

function asciiLabels(domain: string): string[] | null {
  const trimmed = domain.endsWith(".") ? domain.slice(0, -1) : domain;
  if (trimmed.length === 0) return null;
  const ascii = /[^!-~]/.test(trimmed)
    ? URL.parse(`https://${trimmed}`)?.hostname
    : trimmed.toLowerCase();
  if (!ascii) return null;
  const labels = ascii.split(".");
  if (labels.some((label) => label.length === 0)) return null;
  return labels;
}

function publicSuffixLabelCount(labels: string[]): number {
  const list = ruleSet();
  let matched = 0;
  for (let i = labels.length - 1; i >= 0; i--) {
    const candidate = labels.slice(i).join(".");
    if (list.has(`!${candidate}`)) return labels.length - i - 1;
    if (list.has(candidate)) {
      matched = labels.length - i;
    } else if (
      i < labels.length - 1 &&
      list.has(`*.${labels.slice(i + 1).join(".")}`)
    ) {
      matched = labels.length - i;
    }
  }
  return matched === 0 ? 1 : matched;
}

/**
 * Whether a domain is a public suffix — a name others register *under* rather
 * than a registrable domain someone owns.
 *
 * Implements the publicsuffix.org algorithm against the bundled snapshot,
 * including wildcard rules (`*.ck`), exception rules (`!www.ck`), and the
 * implicit `*` rule that makes any unlisted top-level domain a public suffix.
 * The argument may be Unicode or punycode, upper or lower case, with or
 * without a trailing dot; a host that cannot be normalized (empty, or with an
 * empty label) is reported as a public suffix so a caller bounding a wildcard
 * fails closed.
 *
 * @param domain The hostname to classify.
 * @returns `true` when the whole domain is a public suffix.
 *
 * @example
 * ```ts
 * import { isPublicSuffix } from "@udibo/oauth2/server/public-suffix";
 *
 * isPublicSuffix("co.uk"); // true
 * isPublicSuffix("deno.net"); // true — anyone can take a subdomain
 * isPublicSuffix("myorg.deno.net"); // false — one organization's namespace
 * isPublicSuffix("example.com"); // false
 * ```
 */
export function isPublicSuffix(domain: string): boolean {
  const labels = asciiLabels(domain);
  if (!labels) return true;
  return publicSuffixLabelCount(labels) === labels.length;
}
