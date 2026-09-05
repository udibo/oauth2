/**
 * Example: a Hono app that runs an OAuth2 authorization server, BFF
 * adapter, and resource server in **one process** — the same shape a
 * real SPA-backed app uses.
 *
 * Mount layout (one sub-app per prefix — Hono best practice for larger
 * apps; see https://hono.dev/docs/guides/best-practices). Each route file's
 * module doc covers its own details:
 *
 *   - `/` — interactive SPA showing how a token's scope governs access.
 *   - `/login`, `/create-account`, `/forgot-password`, `/reset-password`,
 *     `/verify-email`, `/logout` — the IDP's own auth surface;
 *     create-account is what forces the "resume an in-flight authorize URL
 *     vs. start fresh" handoff to appear, and the reset/verify routes run
 *     the library's own-auth flows (`oauth2/identity.ts`).
 *   - `/consent` — records the user's consent decision (server-side,
 *     one-time; see `routes/consent.ts` for why it never rides the
 *     authorize URL).
 *   - `/device` — device-code verification UI (RFC 8628).
 *   - `/oauth2` — every standard OAuth2 endpoint via `authServer.routes()`.
 *   - `/auth` — the browser-facing BFF endpoints.
 *   - `/api` — protected endpoints; the BFF resolves the session cookie to
 *     a bearer token and the resource server validates it, all in-process.
 *
 * Browser → API costs **one inbound request**, no outbound. Token
 * refreshes route through `localAuthServerFetch`, also in-process.
 *
 * Run:
 *   deno task serve    # or: deno task dev (auto-reload)
 *
 * Then visit http://localhost:8001/ and click "Sign in".
 *
 * @module
 */

import { Hono } from "hono";

import type { HonoResourceServerVariables } from "@udibo/oauth2/hono/resource-server";
import { BasicScope } from "@udibo/oauth2/server";

import {
  authServer,
  bff,
  type DemoClient,
  type DemoUser,
  userService,
} from "./oauth2/server.ts";
import { endSession, readSessionUserId } from "./sessions.ts";
import home from "./routes/home.ts";
import api from "./routes/api.ts";
import login from "./routes/login.ts";
import createAccount from "./routes/create-account.ts";
import forgotPassword from "./routes/forgot-password.ts";
import resetPassword from "./routes/reset-password.ts";
import verifyEmail from "./routes/verify-email.ts";
import logout from "./routes/logout.ts";
import consent, {
  renderConsentPage,
  takePendingConsent,
} from "./routes/consent.ts";
import device from "./routes/device.ts";

const app = new Hono<{
  Variables: HonoResourceServerVariables<DemoClient, DemoUser>;
}>();

app.route("/", home);
app.route("/login", login);
app.route("/create-account", createAccount);
app.route("/forgot-password", forgotPassword);
app.route("/reset-password", resetPassword);
app.route("/verify-email", verifyEmail);
app.route("/logout", logout);
app.route("/consent", consent);
app.route("/device", device);

app.route(
  "/oauth2",
  authServer.routes({
    authenticateUser: async (c) => {
      const userId = readSessionUserId(c);
      const url = new URL(c.req.url);
      const returnTo = `${url.pathname}${url.search}`;
      if (!userId) {
        return c.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`);
      }
      const user = await userService.get(userId);
      if (!user) {
        endSession(c);
        return c.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`);
      }
      return { user };
    },
    handleConsent: (c, client, requestedScope, user) => {
      const u = user as DemoUser;
      const url = new URL(c.req.url);
      const decision = takePendingConsent(
        c,
        u.id,
        client.id,
        url.searchParams.get("scope") ?? "",
      );
      if (decision === undefined) {
        const displayScope = requestedScope
          ? BasicScope.intersection(requestedScope.toString(), u.maxScope)
            .toString() || undefined
          : undefined;
        return Promise.resolve(
          renderConsentPage(c, client, displayScope, u, url.search),
        );
      }
      if (decision !== "approve") return Promise.resolve({ approved: false });
      if (!requestedScope) return Promise.resolve({ approved: true });
      const granted = BasicScope.intersection(
        requestedScope.toString(),
        u.maxScope,
      );
      return Promise.resolve({ approved: true, scope: granted });
    },
  }),
);

app.route("/auth", bff.routes());

app.route("/api", api);

export default app;
