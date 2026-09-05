/**
 * `__Host-` / `__Secure-` cookie-name resolution shared by the BFF's cookies,
 * plus the attribute combinations a browser refuses outright.
 *
 * A browser honors those prefixes only when the cookie's own attributes satisfy
 * them, and silently drops the cookie otherwise — as it does for
 * `SameSite=None` without `Secure`. So the default name and the validation of
 * an explicit name both have to be derived from the same attributes — kept here
 * so the session cookie and the pending-authorization cookie cannot drift
 * apart, and so a dropped-cookie configuration fails loudly at construction
 * instead of as an inexplicably broken session.
 *
 * @module
 */

/** Cookie attributes a browser validates a cookie's name and delivery against. */
export interface PrefixConstrainedAttributes {
  /** Whether the cookie is marked `Secure`. */
  secure: boolean;
  /** The cookie's `Path`. */
  path: string;
  /** The cookie's `Domain`, or `undefined` when the cookie is host-bound. */
  domain: string | undefined;
  /** The cookie's `SameSite`, or `undefined` when the caller left it to the emitter. */
  sameSite: string | undefined;
}

/** The subset of a cookie-options object the prefixes constrain. */
export interface PrefixConstrainedOptions {
  /** Marks the cookie `Secure`. Defaults to `true`. */
  secure?: boolean;
  /** Cookie path. Defaults to `"/"`. */
  path?: string;
  /** Cookie domain. Omitted by default (host-bound). */
  domain?: string;
  /** Cookie `SameSite`. Left to the emitting cookie when unset. */
  sameSite?: string;
}

/**
 * Apply the attribute defaults every BFF cookie shares — `Secure`, `Path=/`,
 * and no `Domain` — so name resolution and the emitted cookie agree on what
 * the cookie will actually carry.
 */
export function resolvePrefixConstrainedAttributes(
  opts: PrefixConstrainedOptions | undefined,
): PrefixConstrainedAttributes {
  return {
    secure: opts?.secure ?? true,
    path: opts?.path ?? "/",
    domain: opts?.domain || undefined,
    sameSite: opts?.sameSite,
  };
}

function assertSameSiteSatisfiable(
  attrs: PrefixConstrainedAttributes,
  consequence: string,
): void {
  if (attrs.sameSite?.toLowerCase() !== "none" || attrs.secure) return;
  throw new Error(
    'cookie.sameSite is "None", which requires Secure, but cookie.secure is ' +
      `false. Every browser rejects such a cookie, so ${consequence}. Leave ` +
      'cookie.secure on, or use "Lax" for local http development.',
  );
}

function assertCookiePrefixSatisfiable(
  name: string,
  attrs: PrefixConstrainedAttributes,
  consequence: string,
): void {
  const lower = name.toLowerCase();
  const quoted = JSON.stringify(name);
  if (lower.startsWith("__host-")) {
    const conflicts: string[] = [];
    if (!attrs.secure) conflicts.push("cookie.secure is false");
    if (attrs.domain) {
      conflicts.push(`cookie.domain is ${JSON.stringify(attrs.domain)}`);
    }
    if (attrs.path !== "/") {
      conflicts.push(`cookie.path is ${JSON.stringify(attrs.path)}`);
    }
    if (conflicts.length > 0) {
      throw new Error(
        `cookie.name ${quoted} uses the "__Host-" prefix, which requires ` +
          `Secure, Path=/, and no Domain, but ${conflicts.join(" and ")}. ` +
          `Every browser rejects such a cookie, so ${consequence}. Remove the ` +
          "conflicting attribute or drop the prefix from cookie.name.",
      );
    }
    return;
  }
  if (lower.startsWith("__secure-") && !attrs.secure) {
    throw new Error(
      `cookie.name ${quoted} uses the "__Secure-" prefix, which requires ` +
        `Secure, but cookie.secure is false. Every browser rejects such a ` +
        `cookie, so ${consequence}. Leave cookie.secure on or drop the prefix ` +
        "from cookie.name.",
    );
  }
}

/** Inputs for {@link resolveCookieName}. */
export interface CookieNameResolution {
  /** The explicit `cookie.name`, when the caller set one. */
  name: string | undefined;
  /**
   * Unprefixed default name. `__Host-` is prepended to it when
   * {@link attributes} satisfy that prefix.
   */
  base: string;
  /** Attributes the emitted cookie carries. */
  attributes: PrefixConstrainedAttributes;
  /**
   * What is lost when a browser drops the cookie, as a clause completing
   * "Every browser rejects such a cookie, so …" in the thrown error.
   */
  consequence: string;
}

/**
 * Resolve a cookie's name: the caller's explicit name when set, else
 * `__Host-<base>` when the attributes satisfy that prefix, else the bare
 * `base`.
 *
 * @throws {Error} When the attributes describe a cookie no browser will keep —
 * an explicit name whose `__Host-` / `__Secure-` prefix they contradict, or
 * `SameSite=None` without `Secure`. Either way the cookie is silently dropped
 * and the failure surfaces as a broken flow rather than an error, so this
 * refuses the configuration up front. `None` and the prefixes are matched
 * case-insensitively, as browsers match them.
 */
export function resolveCookieName(resolution: CookieNameResolution): string {
  const { name, base, attributes, consequence } = resolution;
  assertSameSiteSatisfiable(attributes, consequence);
  if (name) {
    assertCookiePrefixSatisfiable(name, attributes, consequence);
    return name;
  }
  const hostPrefixOk = attributes.secure && attributes.path === "/" &&
    !attributes.domain;
  return hostPrefixOk ? `__Host-${base}` : base;
}
