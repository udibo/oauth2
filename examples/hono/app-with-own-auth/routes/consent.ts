/**
 * Consent screen for the authorization-code flow.
 *
 * Mounted at `/consent` by `main.ts`; the authorize endpoint's
 * `handleConsent` renders this page when the user has not decided yet. The
 * page POSTs back here, and the decision travels to the authorize endpoint
 * through a server-side one-time record — **never** through the authorize
 * URL. The authorize URL is client-controlled (the relying party builds it
 * and navigates the user's browser to it), so a decision carried in its
 * query string could be forged by any client (`&consent=approve`) and the
 * prompt silently skipped. Instead:
 *
 * - `POST /consent` requires the IDP session (a cross-site form POST sends
 *   no SameSite=Lax cookie, so it can't mint a decision), stores the
 *   decision keyed by a random one-time id bound to
 *   `(userId, clientId, scope)`, and puts only that id in a short-lived
 *   cookie scoped to `/oauth2`.
 * - {@link takePendingConsent} consumes the record (one-time, 60s TTL) and
 *   honors it only if the user, client, and scope of the authorize request
 *   match what the user actually approved.
 *
 * **First-party SPA tradeoff.** This example shows the consent screen even
 * for the demo SPA so the per-user scope-narrowing behaviour stays visible.
 * A server whose clients are all first-party can skip consent entirely —
 * omit `handleConsent` (the framework grants without a prompt) or
 * auto-approve inside it to still cap scope per user; see the README.
 *
 * In a real app you'd typically also persist decisions per
 * `(userId, clientId, scope)` so users aren't re-prompted every login,
 * render client name/logo/scope descriptions from a `ClientService` field,
 * and let users revoke granted consent from a settings page.
 *
 * @module
 */

import { type Context, Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";

import { escapeHtml } from "../html.ts";
import type { DemoClient, DemoUser } from "../oauth2/server.ts";
import { readSessionUserId } from "../sessions.ts";

const CONSENT_COOKIE_NAME = "consent_id";
const CONSENT_TTL_MS = 60_000;

interface PendingConsent {
  userId: string;
  clientId: string;
  /** The authorize request's raw `scope` parameter ("" when absent). */
  scope: string;
  decision: "approve" | "deny";
  expiresAt: number;
}

/** One-time decisions awaiting pickup by the authorize endpoint. */
const pendingConsents = new Map<string, PendingConsent>();

const app = new Hono();

app.post("/", async (c) => {
  const userId = readSessionUserId(c);
  if (!userId) return c.text("Sign in to continue", 403);

  const form = await c.req.formData();
  const decision = form.get("decision") === "approve" ? "approve" : "deny";
  const authorizeQuery = String(form.get("authorize_query") ?? "");
  const params = new URLSearchParams(authorizeQuery.replace(/^\?/, ""));

  const id = crypto.randomUUID();
  pendingConsents.set(id, {
    userId,
    clientId: params.get("client_id") ?? "",
    scope: params.get("scope") ?? "",
    decision,
    expiresAt: Date.now() + CONSENT_TTL_MS,
  });
  setCookie(c, CONSENT_COOKIE_NAME, id, {
    path: "/oauth2",
    httpOnly: true,
    sameSite: "Lax",
    maxAge: CONSENT_TTL_MS / 1000,
    secure: false,
  });
  return c.redirect(`/oauth2/authorize${authorizeQuery}`);
});

export default app;

/**
 * Consume the pending consent decision for this authorize request, or
 * `undefined` when there is none (first visit, expired, or a record that was
 * minted for a different user/client/scope — all of which re-prompt).
 */
export function takePendingConsent(
  c: Context,
  userId: string,
  clientId: string,
  scope: string,
): "approve" | "deny" | undefined {
  const id = getCookie(c, CONSENT_COOKIE_NAME);
  if (!id) return undefined;
  const record = pendingConsents.get(id);
  pendingConsents.delete(id);
  if (!record || record.expiresAt < Date.now()) return undefined;
  if (
    record.userId !== userId ||
    record.clientId !== clientId ||
    record.scope !== scope
  ) {
    return undefined;
  }
  return record.decision;
}

/**
 * Renders the consent screen. Imported by `main.ts` so the authorize
 * endpoint's `handleConsent` can return it as a `Response` when the user has
 * not yet made a decision.
 */
export function renderConsentPage(
  c: Context,
  client: DemoClient,
  scope: string | undefined,
  user: DemoUser,
  authorizeQuery: string,
): Response {
  return c.html(consentPage({ client, scope, user, authorizeQuery }));
}

function consentPage(
  options: {
    client: DemoClient;
    scope: string | undefined;
    user: DemoUser;
    authorizeQuery: string;
  },
): string {
  const clientName = escapeHtml(options.client.name);
  const username = escapeHtml(options.user.username);
  const scope = options.scope ?? "(default)";
  const scopeList = scope.split(/\s+/).filter(Boolean).map((s) =>
    `<li><code>${escapeHtml(s)}</code></li>`
  ).join("");
  const returnTo = `/oauth2/authorize${options.authorizeQuery}`;
  return `<!doctype html>
<title>Authorize ${clientName}</title>
<h1>Authorize <em>${clientName}</em></h1>
<p>
  Signed in as <strong>${username}</strong>.
  <form style="display:inline" method="post" action="/logout">
    <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
    <button type="submit">Sign out &amp; switch user</button>
  </form>
</p>
<p>${clientName} is requesting access to:</p>
<ul>${scopeList}</ul>
<form method="post" action="/consent">
  <input type="hidden" name="authorize_query" value="${
    escapeHtml(options.authorizeQuery)
  }">
  <button name="decision" value="approve" type="submit">Approve</button>
  <button name="decision" value="deny" type="submit">Deny</button>
</form>`;
}
