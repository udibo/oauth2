/**
 * URL safety helpers.
 *
 * @module
 */

const RESOLUTION_ORIGIN = "http://safe-return-to.invalid";

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
 * collapses to `fallback` (default `/`).
 *
 * Percent-encoded control characters (`/%09/x`) are safe and pass through: a
 * browser does not decode them before parsing, so they stay on the origin.
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
 * ```
 */
export function safeReturnTo(
  value: string | null | undefined,
  fallback = "/",
): string {
  if (!value || !value.startsWith("/")) return fallback;
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

/** Options for {@link loginContinuation}. */
export interface LoginContinuationOptions {
  /**
   * The authorization endpoint (absolute URL or path). When `returnTo` points at
   * it, the flow is **resumed** (the in-flight authorize request already has a
   * PKCE `state`). Omit it and every `returnTo` starts a fresh login.
   */
  authorizeEndpoint?: string;
  /** The login path to start a fresh login. Defaults to `"/auth/login"`. */
  loginPath?: string;
  /** Fallback when `returnTo` is missing/unsafe. Defaults to `"/"`. */
  defaultReturnTo?: string;
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
 * open-redirect-guarded via {@link safeReturnTo}.
 */
export function loginContinuation(
  returnTo: string | null | undefined,
  options: LoginContinuationOptions = {},
): string {
  const safe = safeReturnTo(returnTo, options.defaultReturnTo ?? "/");
  if (options.authorizeEndpoint) {
    // Compare path only so the in-flight authorize query (client_id, state, …)
    // is preserved; the base lets absolute and relative inputs both resolve.
    const base = "http://login.continuation.local";
    const authorizePath = new URL(options.authorizeEndpoint, base).pathname;
    if (new URL(safe, base).pathname === authorizePath) return safe;
  }
  return `${options.loginPath ?? "/auth/login"}?return_to=${
    encodeURIComponent(safe)
  }`;
}
