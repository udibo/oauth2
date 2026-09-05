/**
 * Session revocation + step-up contracts for the identity layer.
 *
 * Three security primitives the own-auth flows need, kept as **contracts + a
 * pure helper** — storage stays app-owned (the `SessionStore` philosophy, and
 * the Lucia-deprecation lesson: don't ship a DB-adapter zoo):
 *
 * - {@link RevocableSessionService} — revoke a user's sessions on a credential
 *   change. After a password reset the app must end the *other* sessions, or a
 *   compromised account's other devices stay logged in. The reset flow calls
 *   this; your app implements it over its session store.
 * - {@link ListableSessionService} — the revocation seam's optional listing
 *   half: a user's live sessions as {@link SessionSummary} display rows, so a
 *   "where you're signed in" screen has one typed shape to render and wire the
 *   revoke buttons against. Only a stateful store can honestly implement it.
 * - {@link isRecentlyAuthenticated} — a recent-auth / step-up gate for sensitive
 *   changes (change password/email, delete account, add MFA).
 *
 * @module
 */

/**
 * Revocation operations a session store exposes so credential-change flows can
 * end sessions. Implement over your own session storage (DB / Redis / KV).
 */
export interface RevocableSessionService {
  /**
   * Revoke **every** session belonging to `userId`. Call after a password reset
   * or other full-account credential change. Returns the number revoked.
   */
  revokeAllByUser(userId: string): Promise<number>;
  /**
   * Revoke a user's sessions **except** `keepSessionId` — "sign out everywhere
   * else" after a password change in the current session. Returns the number
   * revoked.
   */
  revokeOthers(userId: string, keepSessionId: string): Promise<number>;
}

/**
 * One live session as a "where you're signed in" screen renders it — a display
 * projection, never the session's secret/hash or token material. The
 * current-session marker is the caller's concern: compare
 * {@link SessionSummary.id} against the id of the session backing the request
 * being rendered, and label / disable "revoke" on the match ("revoke" on the
 * current row is "sign out").
 *
 * Keep the optional client fields **coarse** — the contract omits raw address
 * fields on purpose. `userAgent` is the raw header for a component to parse into
 * a device label; `location` is a human-readable place (city / region /
 * country) resolved from the IP at creation, not the raw address. Anything more
 * precise turns a security screen into a tracking log; a store with nothing
 * coarse to report leaves the field unset rather than reaching for the raw value.
 */
export interface SessionSummary {
  /**
   * Stable session id — the revoke action's target and the value a caller
   * compares against the current session to mark "this device". Use a separate
   * non-secret record identifier, never the cookie value or its hash.
   */
  id: string;
  /** When the session was created. */
  createdAt: Date;
  /**
   * Last-activity timestamp. Bump it on a throttle (once a minute, say), not on
   * every request, or the session table becomes the hottest write path.
   */
  lastSeenAt: Date;
  /** Raw user-agent header, for the UI to summarize into a device label. */
  userAgent?: string;
  /**
   * Coarse, human-readable location resolved from the IP at creation (e.g.
   * `"San Francisco, US"`) — never the raw address.
   */
  location?: string;
}

/**
 * Optional {@link RevocableSessionService} capability: list a user's live
 * sessions as {@link SessionSummary} rows so the "where you're signed in"
 * screen you build renders one typed shape and wires its revoke buttons against
 * it, instead of every app inventing a different list shape. The screen is
 * app-owned — the package ships this seam and the row type, not a list
 * component. A store opts in by implementing this method — it is duck-typed at
 * runtime via
 * {@link supportsSessionListing}, mirroring how the BFF's `BackchannelLogoutStore`
 * is an optional capability a stateful `SessionStore` opts into.
 *
 * Only a store that keeps a server-side record can implement it: a listing seam
 * implies the rows are authoritative, and the paired revoke buttons promise
 * **immediate, not advisory** revocation. A stateless self-contained-token store
 * the server never looks up can neither enumerate its sessions nor honor a
 * revoke, so it omits this and the screen simply isn't offered.
 */
export interface ListableSessionService {
  /**
   * A user's live sessions as display summaries, most-recently-active first.
   * Return only what a session screen renders — never the session secret/hash
   * or token material. Excludes ended sessions (revoked, expired, idle-timed-out).
   */
  listByUser(userId: string): Promise<SessionSummary[]>;
}

/**
 * Whether a session service also implements the optional
 * {@link ListableSessionService} listing capability. Use it to decide whether to
 * offer the "where you're signed in" screen: a stateful store returns `true`, a
 * stateless one that only revokes returns `false`.
 */
export function supportsSessionListing(
  service: RevocableSessionService,
): service is RevocableSessionService & ListableSessionService {
  return typeof (service as Partial<ListableSessionService>).listByUser ===
    "function";
}

/**
 * Whether a session authenticated within `maxAgeMs` — a recent-auth ("step-up")
 * check to gate sensitive actions. Re-prompt for credentials when this is false.
 *
 * @param authenticatedAt When the session last actively authenticated (epoch ms).
 * @param maxAgeMs How recent counts as "fresh" (e.g. 5 minutes).
 * @param now Override the clock (for tests). Defaults to `Date.now()`.
 *
 * @example
 * ```ts
 * if (!isRecentlyAuthenticated(session.authenticatedAt, 5 * 60_000)) {
 *   throw redirect("/reauthenticate?return_to=/settings/password");
 * }
 * ```
 */
export function isRecentlyAuthenticated(
  authenticatedAt: number,
  maxAgeMs: number,
  now: number = Date.now(),
): boolean {
  return authenticatedAt > 0 && now - authenticatedAt <= maxAgeMs;
}
