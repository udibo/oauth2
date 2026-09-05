/**
 * The BFF's browser-facing endpoints, mounted at `/auth/*`:
 * `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/session`.
 *
 * The React SPA never calls the authorization server directly — it goes
 * through these. `/auth/login` starts the auth-code flow; `/auth/callback`
 * exchanges the code for tokens with the external IDP over HTTP and stores
 * them in the server-side session; `/auth/session` reports who is signed
 * in; `/auth/logout` clears the session.
 *
 * @module
 */

import { bff } from "@/oauth2/server.ts";

export default bff.routes();
