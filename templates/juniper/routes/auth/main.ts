/**
 * The BFF's browser-facing endpoints, mounted at `/auth/*`: `/auth/login`,
 * `/auth/callback`, `/auth/logout`, `/auth/session`. The React app never
 * calls the authorization server directly — it goes through these.
 *
 * @module
 */

import { bff } from "@/oauth2/server.ts";

export default bff.routes();
