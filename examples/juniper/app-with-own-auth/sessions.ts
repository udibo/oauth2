/**
 * Browser-session layer for the **identity provider** half of this
 * single-process example.
 *
 * This is distinct from the BFF's session cookie: this `idp_session`
 * tracks who is logged in to the embedded authorization server (where
 * the login form lives), while the BFF's `oauth2_session` cookie tracks
 * the OAuth2 tokens issued to the React SPA. The IDP session survives a
 * BFF logout — exactly like a real SSO setup, where signing out of an
 * app doesn't sign you out of the identity provider.
 *
 * Production shortcuts this file takes so the example runs over plain
 * `http://localhost`, none of which a deployed app should keep: the cookie
 * is written without `Secure`, so it would ride an unencrypted request; the
 * session records live in a process-local `Map`, so they vanish on restart
 * and never expire or rotate; and nothing here is CSRF-protected. In a real
 * app add `Secure`, move the records to a database/Redis store with expiry
 * and rotation on privilege change, add CSRF protection, and sign or encrypt
 * the cookie if it ever holds more than a random id.
 *
 * @module
 */

import type { Context } from "hono";
import { deleteCookie, getCookie } from "hono/cookie";

const SESSION_COOKIE_NAME = "idp_session";

interface SessionRecord {
  userId: string;
  createdAt: number;
}

const sessions = new Map<string, SessionRecord>();

/** Returns the user id for the request, or `undefined` if not signed in. */
export function readSessionUserId(c: Context): string | undefined {
  const id = getCookie(c, SESSION_COOKIE_NAME);
  if (!id) return undefined;
  return sessions.get(id)?.userId;
}

/**
 * Creates an IDP session and returns the `Set-Cookie` header value for it.
 *
 * Returns a string (rather than mutating a Hono `Context`) so the Juniper
 * `/login` action can attach it to its redirect `Response`.
 */
export function createSessionCookie(userId: string): string {
  const id = crypto.randomUUID();
  sessions.set(id, { userId, createdAt: Date.now() });
  return `${SESSION_COOKIE_NAME}=${id}; Path=/; HttpOnly; SameSite=Lax`;
}

/** Clears the session cookie and destroys the server-side record. */
export function endSession(c: Context): void {
  const id = getCookie(c, SESSION_COOKIE_NAME);
  if (id) sessions.delete(id);
  deleteCookie(c, SESSION_COOKIE_NAME, { path: "/" });
}
