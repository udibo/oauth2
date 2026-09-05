/**
 * Browser-session layer for the identity-provider half of the app — the
 * `idp_session` cookie tracks who is signed in to the embedded authorization
 * server (where the login and signup forms live). It is separate from the
 * BFF's session cookie, which tracks the OAuth2 tokens issued to the React
 * app.
 *
 * In production, replace the in-memory `Map` with a database/Redis store, add
 * CSRF protection, session expiry + rotation, and sign or encrypt the cookie
 * if it ever holds more than a random id.
 *
 * @module
 */

import type { Context } from "hono";
import { deleteCookie, getCookie } from "hono/cookie";

const SESSION_COOKIE_NAME = "idp_session";
const isProduction = Deno.env.get("APP_ENV") === "production";

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
 * Creates an IDP session and returns the `Set-Cookie` header value for it,
 * so route actions can attach it to their redirect `Response`.
 */
export function createSessionCookie(userId: string): string {
  const id = crypto.randomUUID();
  sessions.set(id, { userId, createdAt: Date.now() });
  const secure = isProduction ? "; Secure" : "";
  return `${SESSION_COOKIE_NAME}=${id}; Path=/; HttpOnly; SameSite=Lax${secure}`;
}

/** Clears the session cookie and destroys the server-side record. */
export function endSession(c: Context): void {
  const id = getCookie(c, SESSION_COOKIE_NAME);
  if (id) sessions.delete(id);
  deleteCookie(c, SESSION_COOKIE_NAME, { path: "/" });
}
