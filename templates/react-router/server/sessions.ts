/**
 * The login session for the embedded issuer — who is signed in to *your app's
 * identity layer*. Distinct from the BFF's `oauth2_session` cookie, which
 * holds the OAuth2 tokens issued to the app.
 *
 * In production, replace the in-memory `Map` with a database/Redis store and
 * add session expiry + rotation.
 *
 * @module
 */

import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";

import { config } from "./config.ts";

const SESSION_COOKIE_NAME = "idp_session";

/** A login session: who signed in, when, and for which authorize request. */
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
 * Opens a session for `userId` and sets the HttpOnly session cookie. Pass the
 * `return_to` the sign-in continues to as `signedInFor`, so the authorize
 * handler can tell a sign-in made for that request from an older one.
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
    secure: config.secureCookies,
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
