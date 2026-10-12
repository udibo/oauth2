/**
 * URL safety helpers.
 *
 * @module
 */

const RESOLUTION_ORIGIN = "http://safe-return-to.invalid";

/** {@link SafeReturnToOptions.maxLength}'s default, in UTF-16 code units. */
export const DEFAULT_MAX_RETURN_TO_LENGTH = 2048;

/** Options for {@link safeReturnTo}. */
export interface SafeReturnToOptions {
  /**
   * Longest value accepted, in UTF-16 code units (`String.length`), not
   * bytes; a longer one collapses to the fallback. Defaults to {@link DEFAULT_MAX_RETURN_TO_LENGTH} (2048).
   * `Infinity` accepts any length.
   */
  maxLength?: number;
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/**
 * Open-redirect guard for a `return_to` / redirect target.
 *
 * Returns `value` only when it is a safe in-app destination: a path beginning
 * with a single `/` that still resolves to the current origin. This rejects
 * absolute URLs, protocol-relative `//evil.com`, backslash `/\evil.com` tricks
 * that some browsers resolve as a host, and any value containing a C0 control
 * character or `DEL` — browsers strip TAB/CR/LF before parsing a URL, so
 * `/<TAB>/evil.com` would otherwise navigate to `evil.com`. Anything else
 * collapses to `fallback` (default `/`), which is returned verbatim. The
 * fallback is trusted caller configuration; do not pass user-controlled input
 * there.
 *
 * Percent-encoded control characters (`/%09/x`) are safe and pass through: a
 * browser does not decode them before parsing, so they stay on the origin.
 *
 * A value longer than {@link SafeReturnToOptions.maxLength} (2048 characters
 * by default) also collapses to `fallback`, so a caller that stores the
 * result — a pending sign-in, a session — cannot be made to hold an
 * arbitrarily large string per anonymous request.
 *
 * Use this anywhere a user-influenced value — a `return_to` / `redirect` query
 * param or form field — is fed into a redirect `Location`, so a crafted
 * absolute target can't turn the (often post-authentication) redirect into an
 * open redirect.
 *
 * @example
 * ```ts
 * safeReturnTo("/dashboard");        // → "/dashboard"
 * safeReturnTo("https://evil.com");  // → "/"
 * safeReturnTo("//evil.com");        // → "/"
 * safeReturnTo("/\\evil.com");       // → "/"
 * safeReturnTo("/\t/evil.com");      // → "/"
 * safeReturnTo(undefined, "/home");  // → "/home"
 * safeReturnTo("/a-long-path", "/", { maxLength: 8 }); // → "/"
 * ```
 */
export function safeReturnTo(
  value: string | null | undefined,
  fallback = "/",
  options: SafeReturnToOptions = {},
): string {
  if (!value || !value.startsWith("/")) return fallback;
  if (value.length > (options.maxLength ?? DEFAULT_MAX_RETURN_TO_LENGTH)) {
    return fallback;
  }
  if (hasControlCharacter(value)) return fallback;

  let resolved: URL;
  try {
    resolved = new URL(value, RESOLUTION_ORIGIN);
  } catch {
    return fallback;
  }
  if (resolved.origin !== RESOLUTION_ORIGIN) return fallback;
  if (resolved.pathname.startsWith("//")) return fallback;

  return value;
}

/** Trusted application configuration for {@link loginContinuation}. */
export interface LoginContinuationOptions {
  /**
   * Trusted authorization endpoint (absolute URL or path). When `returnTo` points
   * at it, the flow is **resumed** (the in-flight authorize request already carries
   * its `state`). Omit it and every `returnTo` starts a fresh login.
   */
  authorizeEndpoint?: string;
  /** Trusted login path for a fresh login. Defaults to `"/auth/login"`. */
  loginPath?: string;
  /** Trusted fallback for missing/unsafe `returnTo`. Defaults to `"/"`. */
  defaultReturnTo?: string;
  /**
   * Longest `returnTo` accepted, in characters; a longer one falls back to
   * {@link defaultReturnTo}. Defaults to 2048 ({@link safeReturnTo}'s cap).
   */
  maxReturnToLength?: number;
}

/**
 * The URL that (re)starts sign-in toward `returnTo`, for an app that owns its
 * login surface and needs to hand back to the OAuth2/BFF flow after it
 * authenticates a user.
 *
 * - When `returnTo` is an **in-flight authorize URL** (its path equals
 *   `authorizeEndpoint`'s path — the user was bounced mid-authorize with `state`
 *   already minted), it is returned unchanged so the flow **resumes** without a
 *   redundant login hop.
 * - Otherwise it returns `${loginPath}?return_to=<returnTo>` to **start** a fresh
 *   login.
 *
 * Pure and client-safe — the same logic behind `HonoBff.loginContinuation`
 * (server) and `BffClient.loginContinuation` (browser). `returnTo` is
 * open-redirect-guarded via {@link safeReturnTo}. The fallback, authorization
 * endpoint and login path are trusted application configuration.
 */
export function loginContinuation(
  returnTo: string | null | undefined,
  options: LoginContinuationOptions = {},
): string {
  const safe = safeReturnTo(returnTo, options.defaultReturnTo ?? "/", {
    maxLength: options.maxReturnToLength,
  });
  if (options.authorizeEndpoint) {
    const base = "http://login.continuation.local";
    const authorizePath = new URL(options.authorizeEndpoint, base).pathname;
    if (new URL(safe, base).pathname === authorizePath) return safe;
  }
  return `${options.loginPath ?? "/auth/login"}?return_to=${encodeURIComponent(
    safe,
  )}`;
}
