/**
 * Environment-driven configuration. Every value has a local-dev default so the
 * app runs with no `.env` file; `.env.example` documents the full list.
 *
 * @module
 */

/** Public origin the app is served from. Issuer + redirect URIs derive from it. */
export const ORIGIN: string = Deno.env.get("ORIGIN") ?? "http://localhost:8000";

/** True when `APP_ENV=production` (minified builds, secure defaults). */
export const isProduction: boolean = Deno.env.get("APP_ENV") === "production";

/** Cookies are marked `Secure` whenever the app is served over HTTPS. */
export const secureCookies: boolean = ORIGIN.startsWith("https:");

/**
 * Secret for the SPA's confidential OAuth2 client. Falls back to a public
 * development value locally, but fails fast in production so the token endpoint
 * never ships accepting a secret that is committed to the template source.
 */
export const clientSecret: string = (() => {
  const secret = Deno.env.get("OAUTH2_CLIENT_SECRET");
  if (secret) return secret;
  if (isProduction) {
    throw new Error(
      "OAUTH2_CLIENT_SECRET must be set when APP_ENV=production — the " +
        "development fallback is public in the template source.",
    );
  }
  return "dev-only-secret";
})();
