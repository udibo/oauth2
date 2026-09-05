/**
 * Browser-visible runtime flags. `main.ts` injects them into the SPA shell as
 * globals before the bundle loads, so the client can read server-side facts
 * (like whether the demo account was seeded) without an extra request.
 *
 * @module
 */

/**
 * True when the server seeded the demo account (`APP_ENV != production`), so the
 * sign-in hints only appear where the account actually exists.
 */
export function hasDemoAccount(): boolean {
  return (globalThis as { __DEMO_ACCOUNT__?: boolean }).__DEMO_ACCOUNT__ ===
    true;
}
