/**
 * The `BffClient` the React app uses. Kept in its own module with no
 * server-side imports so it's safe to bundle for the browser: the client
 * never sees a token — it talks to the same-origin `/auth/*` endpoints with
 * the session cookie.
 *
 * @module
 */

import { BffClient } from "@udibo/oauth2/client";

/**
 * Same-origin BFF client. `BffClient` defaults its endpoints to
 * `/auth/login`, `/auth/callback`, `/auth/logout`, and `/auth/session`.
 */
export const browserClient: BffClient = new BffClient();
