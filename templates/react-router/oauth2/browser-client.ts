/**
 * The `BffClient` the SPA uses.
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
 * Same-origin BFF client. `BffClient` defaults its endpoints to
 * `/auth/login`, `/auth/callback`, `/auth/logout`, and `/auth/session`.
 */
export const browserClient: BffClient = new BffClient();
