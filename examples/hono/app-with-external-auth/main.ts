/**
 * Example: a Hono SPA backend that delegates auth to an **external**
 * identity provider — the on-ramp for migrating to Udibo (or any
 * RFC 6749 / 6750 / 7662 IDP).
 *
 * Structurally identical to `app-with-own-auth/`. The differences are:
 *
 *   - The BFF's `DirectClient` is configured with real `fetch` against
 *     the IDP's endpoints, not `localAuthServerFetch`.
 *   - The resource server's token service is an
 *     `IntrospectionTokenReader` pointed at the IDP's introspection
 *     endpoint, not the auth server's shared in-process token service.
 *   - The login form, consent UI, and device-verification UI live on
 *     the IDP, not here. The app's `/oauth2/*` mount is gone.
 *
 * Mount layout (one sub-app per prefix — Hono best practice for larger
 * apps; see https://hono.dev/docs/guides/best-practices):
 *
 *   - `app.route("/", home)` — interactive SPA at `GET /` with a sign-in
 *     button and endpoint-call buttons that show how a token's scope
 *     governs access (`routes/home.ts`).
 *   - `app.route("/auth", bff.routes())` — the browser-facing BFF
 *     endpoints (`/auth/login`, `/auth/callback`, `/auth/logout`,
 *     `/auth/session`). `/auth/login` redirects the browser to the
 *     external IDP's `/oauth2/authorize`; `/auth/callback` exchanges
 *     the returned code over real HTTP.
 *   - `app.route("/api", api)` — protected API endpoints. Browser
 *     sends the session cookie, the BFF resolves it to a bearer token,
 *     the resource server introspects it against the external IDP.
 *   - `app.all("/remote-api/*", bff.proxy(...))` — the other topology:
 *     the API is a **separate service** (`api-service/` on port 8002),
 *     so instead of validating in-process the BFF forwards the call
 *     with the session's access token attached and streams the answer
 *     back. The browser still only talks to this origin, so there is no
 *     CORS to configure and no token in the page.
 *
 * **Pairing for local dev**: by default the IDP URLs in
 * `oauth2/server.ts` point at `app-with-own-auth/` on port 8001. Start
 * `app-with-own-auth/` in one terminal and this example in another to
 * exercise the end-to-end flow without a real Udibo deployment. Add
 * `api-service/` on port 8002 in a third terminal for the proxied
 * `/remote-api/*` route.
 *
 * Run:
 *   deno task serve    # or: deno task dev (auto-reload)
 *
 * Then visit http://localhost:8003/ and click "Sign in".
 *
 * @module
 */

import { Hono } from "hono";

import type { HonoResourceServerVariables } from "@udibo/oauth2/hono/resource-server";

import {
  API_SERVICE_URL,
  bff,
  type ExternalClient,
  type ExternalUser,
} from "./oauth2/server.ts";
import home from "./routes/home.ts";
import api from "./routes/api.ts";

const app = new Hono<{
  Variables: HonoResourceServerVariables<ExternalClient, ExternalUser>;
}>();

app.route("/", home);

app.route("/auth", bff.routes());

app.route("/api", api);

app.all(
  "/remote-api/*",
  bff.proxy(API_SERVICE_URL, { stripPrefix: "/remote-api" }),
);

export default app;
