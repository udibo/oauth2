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

interface SessionRecord {
  userId: string;
  createdAt: number;
}

const sessions = new Map<string, SessionRecord>();

/**
 * Returns the user id for the request, or `undefined` if no session
 * cookie is set or the session is unknown.
 */
export function readSessionUserId(c: Context): string | undefined {
  const id = getCookie(c, SESSION_COOKIE_NAME);
  if (!id) return undefined;
  return sessions.get(id)?.userId;
}

/** Sets the session cookie after a successful login. */
export function startSession(c: Context, userId: string): void {
  const id = crypto.randomUUID();
  sessions.set(id, { userId, createdAt: Date.now() });
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
