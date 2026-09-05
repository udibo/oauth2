/**
 * The login session for the embedded issuer — who is signed in to *your app's
 * identity layer*. Distinct from the BFF's `oauth2_session` cookie, which
 * holds the OAuth2 tokens issued to the SPA.
 *
 * In production, replace the in-memory `Map` with a database/Redis store and
 * add session expiry + rotation.
 *
 * @module
 */

import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";

import { secureCookies } from "@/config.ts";

const SESSION_COOKIE_NAME = "idp_session";

interface SessionRecord {
  userId: string;
  createdAt: number;
}

const sessions = new Map<string, SessionRecord>();

/** Returns the user id for the request's session cookie, or `undefined`. */
export function readSessionUserId(c: Context): string | undefined {
  const id = getCookie(c, SESSION_COOKIE_NAME);
  if (!id) return undefined;
  return sessions.get(id)?.userId;
}

/** Opens a session for `userId` and sets the HttpOnly session cookie. */
export function startSession(c: Context, userId: string): void {
  const id = crypto.randomUUID();
  sessions.set(id, { userId, createdAt: Date.now() });
  setCookie(c, SESSION_COOKIE_NAME, id, {
    path: "/",
    httpOnly: true,
    sameSite: "Lax",
    secure: secureCookies,
  });
}

/** Clears the session cookie and destroys the server-side record. */
export function endSession(c: Context): void {
  const id = getCookie(c, SESSION_COOKIE_NAME);
  if (id) sessions.delete(id);
  deleteCookie(c, SESSION_COOKIE_NAME, { path: "/" });
}

/**
 * Destroys the sessions belonging to `userId` — called after a password reset
 * so other browsers are signed out. Pass `keepSessionId` to spare the current
 * session. Returns the number revoked.
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
