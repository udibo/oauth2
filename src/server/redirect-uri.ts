/**
 * Redirect URI matching for the authorization server.
 *
 * RFC 6749 §3.1.2.3 and the OAuth 2.0 Security BCP require `redirect_uri` to be
 * compared against a pre-registered value by exact string match, and that is
 * what {@link matchRedirectUri} does for every ordinary registration. A
 * registration may instead be a **pattern** — a single `*` in the leftmost host
 * label — which lets one registration cover the per-deploy hostnames a preview
 * environment produces.
 *
 * Patterns are deliberately narrow, because a wildcard that reaches beyond the
 * registrant's own namespace hands authorization codes to whoever can obtain a
 * neighbouring host. The rules are enforced by {@link checkRedirectUriPattern},
 * and {@link matchRedirectUri} refuses to match a pattern that violates any of
 * them, so an invalid pattern in storage is inert rather than dangerous.
 *
 * The narrowest of those rules — the domain under the wildcard has to be one
 * registrant's — is decided by the Public Suffix List, injected as
 * {@link IsPublicSuffix} so this module carries no data. Pass `isPublicSuffix`
 * from `@udibo/oauth2/server/public-suffix`; a server that never accepts
 * patterns can leave it out and refuse them all.
 *
 * A registration whose host is a **loopback IP literal** (`127.0.0.1` or
 * `[::1]`) is the one other departure from exact matching: RFC 8252 §7.3
 * requires the authorization server to allow any port at request time, because
 * a native app binds an OS-assigned port it cannot know when it registers.
 * Only the port is relaxed, and only for the IP literals — `localhost` is a
 * name resolved by a host file this server does not control (RFC 8252 §8.3),
 * so it keeps exact matching.
 *
 * This module has no notion of environments. Deciding *which* clients may
 * register a pattern at all is the application's call — the usual policy is to
 * permit them for development registrations and refuse them for production
 * ones, which an application enforces by validating at registration time and by
 * not handing a pattern to the authorization server for a production client.
 * The loopback relaxation is likewise only reachable once the application has
 * chosen to register a loopback URI.
 *
 * @module
 */

/**
 * The registration rule a redirect URI pattern violated.
 *
 * - `syntax` — the pattern is not a parseable absolute URL.
 * - `scheme` — patterns are `https` only.
 * - `wildcard-count` — a pattern holds exactly one `*`.
 * - `wildcard-placement` — the `*` must sit in the leftmost host label, never
 *   in the scheme, userinfo, port, path, query, or fragment.
 * - `parent-domain` — the domain the wildcard sits under is too broad to be
 *   provably the registrant's own namespace.
 */
export type RedirectUriPatternRule =
  | "syntax"
  | "scheme"
  | "wildcard-count"
  | "wildcard-placement"
  | "parent-domain";

/** A redirect URI pattern rule that a registration failed, and why. */
export interface RedirectUriPatternViolation {
  /** The rule that was violated. */
  rule: RedirectUriPatternRule;
  /** A message naming the rule and the reason it exists. */
  message: string;
}

/**
 * Decides whether a domain is a public suffix — something names are registered
 * *under* rather than a registrable domain someone owns.
 *
 * The seam exists so this module carries no data: the Public Suffix List is
 * roughly 150 kB of generated source, and a server that never accepts wildcard
 * registrations should not pay for it. `@udibo/oauth2/server/public-suffix`
 * exports a bundled implementation; anything with the same shape (a PSL
 * library, a narrower hard-coded set) works too, and it must not perform I/O —
 * it is called synchronously on the authorize path.
 *
 * @param domain A hostname, already lowercased and punycode encoded when it
 * comes from a parsed URL.
 * @returns `true` when the whole domain is a public suffix.
 */
export type IsPublicSuffix = (domain: string) => boolean;

/**
 * A label used to ask whether the *children* of a parent domain are public
 * suffixes, which is a different question from whether the parent is one.
 *
 * `r.appspot.com` is a registrable domain by the list's reckoning, but the rule
 * `*.r.appspot.com` makes every one of its subdomains a public suffix belonging
 * to a different registrant — so a wildcard over it hands codes to strangers
 * even though the parent itself passes. Probing with a label no registry has
 * ever issued answers that in one lookup.
 */
const CHILD_PROBE_LABEL = "udibo-public-suffix-probe";

/**
 * Split a hostname into labels, or `null` when it is not usable for matching.
 *
 * A single trailing dot is the DNS root and is dropped, so `example.com.` and
 * `example.com` are the same host — without this, the extra empty label would
 * shift every label the public-suffix check looks at and let `*.deno.net.`
 * through. Any *other* empty label (`a..b`, a leading `.`) is refused outright
 * rather than normalized: it cannot resolve, and an empty leftmost label would
 * otherwise satisfy any prefix/suffix test.
 */
function hostLabels(hostname: string): string[] | null {
  const normalized = hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
  if (normalized.length === 0) return null;
  const labels = normalized.split(".");
  if (labels.some((label) => label.length === 0)) return null;
  return labels;
}

/**
 * Whether a registered redirect URI is a wildcard pattern rather than a literal
 * URI. Says nothing about whether the pattern is *valid* — use
 * {@link checkRedirectUriPattern} for that.
 *
 * @example
 * ```ts
 * import { isRedirectUriPattern } from "@udibo/oauth2/server";
 *
 * isRedirectUriPattern("https://myapp-*.myorg.deno.net/cb"); // true
 * isRedirectUriPattern("https://myapp.example.com/cb"); // false
 * ```
 */
export function isRedirectUriPattern(redirectUri: string): boolean {
  return redirectUri.includes("*");
}

function violation(
  rule: RedirectUriPatternRule,
  message: string,
): RedirectUriPatternViolation {
  return { rule, message };
}

/**
 * Check a registered redirect URI pattern against the pattern rules.
 *
 * Returns `null` when the value is safe to register — which includes any value
 * with no `*` in it at all, since a literal redirect URI is matched exactly and
 * has no pattern rules to break. Otherwise it returns the first
 * {@link RedirectUriPatternViolation}, whose `message` is written to be shown
 * to whoever is registering the URI.
 *
 * Use this at registration time to reject a bad pattern where the person
 * responsible can fix it. {@link matchRedirectUri} applies the same check at
 * request time, so a pattern that slipped into storage never matches.
 *
 * **Patterns need `isPublicSuffix`.** Without it there is no way to tell
 * `myorg.deno.net` (yours) from `deno.net` (everyone's), so every pattern is
 * refused. Pass `isPublicSuffix` from `@udibo/oauth2/server/public-suffix`, or
 * omit it deliberately on a server that only accepts literal redirect URIs.
 *
 * @param pattern The registered redirect URI to check.
 * @param isPublicSuffix Decides whether the domain under the wildcard is a
 * public suffix. Omitting it refuses every pattern.
 * @returns The violated rule and an explanation, or `null` when there is none.
 *
 * @example
 * ```ts
 * import { checkRedirectUriPattern } from "@udibo/oauth2/server";
 * import { isPublicSuffix } from "@udibo/oauth2/server/public-suffix";
 *
 * checkRedirectUriPattern("https://myapp-*.myorg.deno.net/cb", isPublicSuffix); // null
 * checkRedirectUriPattern("https://*.deno.net/cb", isPublicSuffix)?.rule; // "parent-domain"
 * checkRedirectUriPattern("http://*.a.example.com/cb", isPublicSuffix)?.rule; // "scheme"
 * ```
 */
export function checkRedirectUriPattern(
  pattern: string,
  isPublicSuffix?: IsPublicSuffix,
): RedirectUriPatternViolation | null {
  if (!isRedirectUriPattern(pattern)) return null;

  let url: URL;
  try {
    url = new URL(pattern);
  } catch {
    return violation(
      "syntax",
      `"${pattern}" is not a valid absolute URL, so it cannot be matched ` +
        `against a redirect_uri. Register the full callback URL, for example ` +
        `https://myapp-*.myorg.example.com/auth/callback.`,
    );
  }

  if (url.protocol !== "https:") {
    return violation(
      "scheme",
      `"${pattern}" must use https. A wildcard registration covers hosts that ` +
        `do not exist yet, so the authorization code it receives has to be ` +
        `protected in transit.`,
    );
  }

  if ((pattern.match(/\*/g) ?? []).length !== 1) {
    return violation(
      "wildcard-count",
      `"${pattern}" must contain exactly one "*". More than one wildcard ` +
        `widens the set of matching hosts past what can be reasoned about.`,
    );
  }

  const labels = hostLabels(url.hostname);
  if (!labels) {
    return violation(
      "syntax",
      `"${pattern}" has an empty host label. Remove the repeated or leading ` +
        `"." — a host like "a..example.com" cannot resolve, and an empty ` +
        `label beside the wildcard would match anything.`,
    );
  }

  if (!url.hostname.includes("*") || !labels[0].includes("*")) {
    return violation(
      "wildcard-placement",
      `"${pattern}" may only use "*" in the leftmost part of the host — never ` +
        `in the scheme, port, path, query, or fragment. A wildcard elsewhere ` +
        `would let an attacker choose where the authorization code is sent.`,
    );
  }

  const parentDomain = labels.slice(1).join(".");

  if (!isPublicSuffix) {
    return violation(
      "parent-domain",
      `"${pattern}" cannot be registered: this server has no Public Suffix ` +
        `List, so it cannot tell whether "${parentDomain}" is a namespace ` +
        `your organization controls or one anyone can obtain a host under. ` +
        `Register the callback URLs in full, or ask the operator to configure ` +
        `isPublicSuffix.`,
    );
  }

  if (isPublicSuffix(parentDomain)) {
    return violation(
      "parent-domain",
      `"${pattern}" wildcards "${parentDomain}", which is a public suffix — ` +
        `anyone can register a name directly under it, obtain a neighbouring ` +
        `host, and receive your authorization codes. Put the wildcard under a ` +
        `domain your organization registered, for example ` +
        `https://myapp-*.myorg.${parentDomain}/callback.`,
    );
  }

  if (isPublicSuffix(`${CHILD_PROBE_LABEL}.${parentDomain}`)) {
    return violation(
      "parent-domain",
      `"${pattern}" wildcards "${parentDomain}", whose subdomains are each a ` +
        `public suffix belonging to a different registrant, so a neighbouring ` +
        `host is available to anyone. Put the wildcard under a domain your ` +
        `organization registered.`,
    );
  }

  return null;
}

/**
 * The loopback IP literals RFC 8252 §7.3 covers, in the form
 * `URL.hostname` normalizes them to. `localhost` is deliberately absent: RFC
 * 8252 §8.3 advises against it because its resolution depends on a host file
 * the authorization server does not control.
 */
const LOOPBACK_HOSTNAMES = new Set(["127.0.0.1", "[::1]"]);

function matchesLoopback(registration: string, redirectUri: string): boolean {
  if (isRedirectUriPattern(registration)) return false;

  let registeredUrl: URL;
  let url: URL;
  try {
    registeredUrl = new URL(registration);
    url = new URL(redirectUri);
  } catch {
    return false;
  }

  if (!LOOPBACK_HOSTNAMES.has(registeredUrl.hostname)) return false;

  return registeredUrl.protocol === url.protocol &&
    registeredUrl.hostname === url.hostname &&
    registeredUrl.username === url.username &&
    registeredUrl.password === url.password &&
    registeredUrl.pathname === url.pathname &&
    registeredUrl.search === url.search &&
    registeredUrl.hash === url.hash;
}

function matchesPattern(
  pattern: string,
  redirectUri: string,
  isPublicSuffix?: IsPublicSuffix,
): boolean {
  if (checkRedirectUriPattern(pattern, isPublicSuffix) !== null) return false;

  let patternUrl: URL;
  let url: URL;
  try {
    patternUrl = new URL(pattern);
    url = new URL(redirectUri);
  } catch {
    return false;
  }

  if (url.protocol !== "https:") return false;
  if (url.port !== patternUrl.port) return false;
  if (url.username !== patternUrl.username) return false;
  if (url.password !== patternUrl.password) return false;
  if (url.pathname !== patternUrl.pathname) return false;
  if (url.search !== patternUrl.search) return false;
  if (url.hash !== patternUrl.hash) return false;

  if (url.hostname.includes("*")) return false;

  const patternLabels = hostLabels(patternUrl.hostname);
  const labels = hostLabels(url.hostname);
  if (!patternLabels || !labels) return false;
  if (patternLabels.length !== labels.length) return false;
  for (let i = 1; i < patternLabels.length; i++) {
    if (patternLabels[i] !== labels[i]) return false;
  }

  const [prefix, suffix] = patternLabels[0].split("*");
  const label = labels[0];
  return label.length >= prefix.length + suffix.length &&
    label.startsWith(prefix) && label.endsWith(suffix);
}

/**
 * Find the registered redirect URI that authorizes a requested `redirect_uri`.
 *
 * Literal registrations are compared by exact string match (RFC 6749
 * §3.1.2.3), and an exact match always wins.
 *
 * A registration whose host is a **loopback IP literal** — `127.0.0.1` or
 * `[::1]`, after `URL` normalizes forms like `127.1` and
 * `[0:0:0:0:0:0:0:1]` — is tried next, matching the request on every part
 * *except* the port (RFC 8252 §7.3: "the authorization server MUST allow any
 * port to be specified at the time of the request for loopback IP redirect
 * URIs"). Scheme, host, userinfo, path, query, and fragment must still be
 * equal, and `localhost` is not covered — it is a name resolved by a host file
 * this server does not control (RFC 8252 §8.3), so it matches exactly like any
 * other host.
 *
 * Only if neither matches are the pattern registrations tried, under the rules
 * in {@link checkRedirectUriPattern} plus:
 *
 * - The requested URI must be `https`, so a pattern can never be satisfied over
 *   plaintext.
 * - `*` matches within one host label and never across a `.`, so
 *   `https://a-*.example.com/cb` does not match
 *   `https://a-x.evil.example.com/cb`.
 * - Port, userinfo, path, query, and fragment must match the pattern exactly.
 * - A host label may never be empty, and a single trailing dot is treated as
 *   the same host, so `example.com.` cannot smuggle an extra label past the
 *   parent-domain rule.
 * - A requested URI containing `*` never matches anything, checked both on the
 *   raw string and on the percent-decoded host, so a pattern can never be
 *   replayed back as a literal redirect target.
 *
 * That last rule is a deliberate tightening: `*` is a legal host character, so
 * a registration containing one that was previously matched by exact string
 * comparison no longer matches at all. Such a registration cannot be created
 * any more — a `*` now makes the value a pattern, which must satisfy the rules
 * above — so this only affects rows written before patterns existed.
 *
 * @param registered The client's registered redirect URIs.
 * @param redirectUri The `redirect_uri` from the authorization request.
 * @param isPublicSuffix Decides whether the domain under a wildcard is a public
 * suffix. Omitting it makes every pattern registration inert; literal
 * registrations are unaffected.
 * @returns The registered entry that authorized the request, or `undefined`
 * when none did.
 *
 * @example
 * ```ts
 * import { matchRedirectUri } from "@udibo/oauth2/server";
 * import { isPublicSuffix } from "@udibo/oauth2/server/public-suffix";
 *
 * const registered = ["https://myapp-*.myorg.deno.net/auth/callback"];
 * matchRedirectUri(registered, "https://myapp-a1b2.myorg.deno.net/auth/callback", isPublicSuffix);
 * // "https://myapp-*.myorg.deno.net/auth/callback"
 * matchRedirectUri(registered, "https://myapp-a1b2.evil.myorg.deno.net/auth/callback", isPublicSuffix);
 * // undefined
 *
 * matchRedirectUri(["http://127.0.0.1/callback"], "http://127.0.0.1:53211/callback");
 * // "http://127.0.0.1/callback"
 * matchRedirectUri(["http://localhost/callback"], "http://localhost:53211/callback");
 * // undefined
 * ```
 */
export function matchRedirectUri(
  registered: readonly string[],
  redirectUri: string,
  isPublicSuffix?: IsPublicSuffix,
): string | undefined {
  if (isRedirectUriPattern(redirectUri)) return undefined;
  for (const entry of registered) {
    if (entry === redirectUri) return entry;
  }
  for (const entry of registered) {
    if (matchesLoopback(entry, redirectUri)) return entry;
  }
  for (const entry of registered) {
    if (
      isRedirectUriPattern(entry) &&
      matchesPattern(entry, redirectUri, isPublicSuffix)
    ) {
      return entry;
    }
  }
  return undefined;
}
