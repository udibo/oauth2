/**
 * The `BffClient` the React adapter uses.
 *
 * Deliberately kept in its own module with no server-side imports so it's safe
 * to pull into the browser bundle. The client never sees a token — it talks
 * to the same-origin `/auth/*` endpoints over `fetch` (with the HttpOnly
 * session cookie), so there's nothing secret to keep out of the browser.
 *
 * @module
 */

import { BffClient } from "@udibo/oauth2/client";

/**
 * Creates a same-origin BFF client. `BffClient` defaults its endpoints to
 * `/auth/login`, `/auth/callback`, `/auth/logout`, and `/auth/session`. Call it
 * once per rendered app (the root route does) rather than at module scope, so
 * a server render never shares a client between requests.
 */
export function createBrowserClient(): BffClient {
  return new BffClient();
}
