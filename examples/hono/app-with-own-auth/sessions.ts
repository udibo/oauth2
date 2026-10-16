/**
 * Browser-session layer for the **authorization server** half of this
 * one-process example.
 *
 * Distinct from the BFF's `oauth2_session` cookie: this one tracks who
 * is logged in to the embedded IDP (where the login form lives); the
 * BFF's session cookie tracks the OAuth2 tokens issued to the SPA. The
 * IDP session survives BFF logout — same as a real SSO setup, where
 * logging out of an app doesn't sign you out of the identity provider.
 *
 * In a real app:
 *
 * - Replace the in-memory `Map` with a database / Redis-backed store.
 * - Add CSRF protection (this example omits it for readability — see
 *   the comment in `routes/login.ts`).
 * - Add session expiry, sliding renewal, and rotation on privilege
 *   change.
 * - Sign or encrypt the cookie if you ever store anything beyond a
 *   random session id in it.
 *
 * @module
 */

import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";

const SESSION_COOKIE_NAME = "idp_session";

/** An IDP session: who signed in, when, and for which authorize request. */
export interface SessionRecord {
  userId: string;
  /** When the user signed in, in epoch seconds — the ID token's `auth_time`. */
  authTime: number;
  /** The authorize URL (path and query) the sign-in returned to, if any. */
  signedInFor?: string;
}

const sessions = new Map<string, SessionRecord>();

/** Returns the request's session, or `undefined` when there is none. */
export function readSession(c: Context): SessionRecord | undefined {
  const id = getCookie(c, SESSION_COOKIE_NAME);
  if (!id) return undefined;
  return sessions.get(id);
}

/**
 * Returns the user id for the request, or `undefined` if no session
 * cookie is set or the session is unknown.
 */
export function readSessionUserId(c: Context): string | undefined {
  return readSession(c)?.userId;
}

/**
 * Sets the session cookie after a successful login. Pass the `return_to` the
 * sign-in redirects to as `signedInFor`, so the authorize handler can tell a
 * sign-in made for that request from an older one.
 */
export function startSession(
  c: Context,
  userId: string,
  signedInFor?: string,
): void {
  const id = crypto.randomUUID();
  sessions.set(id, {
    userId,
    authTime: Math.floor(Date.now() / 1000),
    signedInFor,
  });
  setCookie(c, SESSION_COOKIE_NAME, id, {
    path: "/",
    httpOnly: true,
    sameSite: "Lax",
    secure: false,
  });
}

/** Clears the session cookie and destroys the server-side record. */
export function endSession(c: Context): void {
  const id = getCookie(c, SESSION_COOKIE_NAME);
  if (id) sessions.delete(id);
  deleteCookie(c, SESSION_COOKIE_NAME, { path: "/" });
}

/**
 * Destroys the IDP sessions belonging to `userId` — called after a password
 * reset so other browsers are signed out. Pass `keepSessionId` to spare the
 * current session ("sign out everywhere else"). Returns the number revoked.
 */
export function revokeUserSessions(
  userId: string,
  keepSessionId?: string,
): number {
  let revoked = 0;
  for (const [id, record] of sessions) {
    if (record.userId === userId && id !== keepSessionId) {
      sessions.delete(id);
      revoked++;
    }
  }
  return revoked;
}
