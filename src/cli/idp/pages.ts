/**
 * The development identity provider's HTML: a sign-in page, a consent screen,
 * and the status page served at `/`.
 *
 * Hand-written markup with no client-side JavaScript, so the pages render the
 * same in a browser and in a `fetch`-driven test. Every control a test needs
 * carries a stable `id` and `name`.
 *
 * @module
 */

import type { DevIdpClientConfig, DevIdpUserConfig } from "./config.ts";

const STYLE = `
  :root { color-scheme: light dark; }
  body {
    font: 16px/1.5 system-ui, sans-serif;
    margin: 0 auto; padding: 2rem 1.25rem; max-width: 40rem;
  }
  h1 { font-size: 1.5rem; margin: 0 0 0.25rem; }
  h2 { font-size: 1.05rem; margin: 1.75rem 0 0.5rem; }
  .banner {
    border: 1px solid currentColor; border-radius: 6px;
    padding: 0.5rem 0.75rem; margin-bottom: 1.5rem;
    font-size: 0.85rem; font-weight: 600; letter-spacing: 0.02em;
  }
  label { display: block; margin: 0.75rem 0 0.25rem; font-size: 0.9rem; }
  input {
    width: 100%; padding: 0.5rem; font: inherit;
    border: 1px solid currentColor; border-radius: 4px; background: transparent;
  }
  button {
    font: inherit; padding: 0.5rem 1rem; margin: 1rem 0.5rem 0 0;
    border: 1px solid currentColor; border-radius: 4px;
    background: transparent; cursor: pointer;
  }
  .error { font-weight: 600; margin-top: 1rem; }
  ul { padding-left: 1.25rem; }
  li { margin: 0.25rem 0; }
  code, .mono { font-family: ui-monospace, monospace; font-size: 0.9em; }
  .quick { display: flex; flex-wrap: wrap; gap: 0.5rem; }
  .quick button { margin: 0; }
  footer { margin-top: 2rem; font-size: 0.85rem; opacity: 0.75; }
`;

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function layout(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<p class="banner" id="dev-only-banner">Development identity provider — never
expose this to a network you do not control.</p>
${body}
<footer>@udibo/oauth2 <code>idp dev</code> · in-memory, no persistence</footer>
</body>
</html>
`;
}

/** Wraps HTML in a `Response` with the headers a browser and a test expect. */
export function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

/** Options for {@link loginPage}. */
export interface LoginPageOptions {
  /** URL to continue to after a successful sign-in, usually the authorize URL. */
  returnTo: string;
  /** Seeded users, offered as one-click sign-in buttons. */
  users: readonly DevIdpUserConfig[];
  /** Message to show above the form after a failed attempt. */
  error?: string;
}

/**
 * The sign-in page. Submits to `POST /login` with `username` + `password`, or
 * with `as=<username>` from a one-click button.
 */
export function loginPage(options: LoginPageOptions): string {
  const { returnTo, users, error } = options;
  const quickSignIn = users.length === 0 ? "" : `
<h2>Seeded users</h2>
<div class="quick">
${
    users.map((user) =>
      `  <button type="submit" name="as" value="${
        escapeHtml(user.username)
      }" form="sign-in-form">Sign in as ${escapeHtml(user.username)}</button>`
    ).join("\n")
  }
</div>
<p class="mono">Passwords are printed in the startup banner.</p>`;

  return layout(
    "Sign in",
    `
<h1>Sign in</h1>
${error ? `<p class="error" id="sign-in-error">${escapeHtml(error)}</p>` : ""}
<form method="post" action="/login" id="sign-in-form">
  <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
  <label for="username">Username</label>
  <input id="username" name="username" autocomplete="username" autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password"
    autocomplete="current-password">
  <button type="submit" id="sign-in">Sign in</button>
</form>
${quickSignIn}
`,
  );
}

/** Options for {@link consentPage}. */
export interface ConsentPageOptions {
  /** Client asking for access. */
  clientId: string;
  /** Scope being requested, or `undefined` when the request named none. */
  scope?: string;
  /** Signed-in user's login name. */
  username: string;
  /** Authorize URL to resume once the decision is recorded. */
  returnTo: string;
}

/**
 * The consent screen shown when the config sets `"consent": "prompt"`.
 * Submits to `POST /consent` with `decision=approve` or `decision=deny`.
 */
export function consentPage(options: ConsentPageOptions): string {
  const { clientId, scope, username, returnTo } = options;
  return layout(
    "Authorize application",
    `
<h1>Authorize application</h1>
<p><span class="mono">${escapeHtml(clientId)}</span> wants to access your
account as <span class="mono">${escapeHtml(username)}</span>.</p>
<h2>Requested scope</h2>
<p class="mono" id="requested-scope">${
      scope ? escapeHtml(scope) : "(no scope requested)"
    }</p>
<form method="post" action="/consent" id="consent-form">
  <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
  <button type="submit" name="decision" value="approve" id="approve">
    Approve
  </button>
  <button type="submit" name="decision" value="deny" id="deny">Deny</button>
</form>
`,
  );
}

/** Options for {@link statusPage}. */
export interface StatusPageOptions {
  /** Issuer as resolved for this request. */
  issuer: string;
  /** Seeded users. */
  users: readonly DevIdpUserConfig[];
  /** Registered clients. */
  clients: readonly DevIdpClientConfig[];
}

/** The page served at `/`: what is seeded and where the endpoints are. */
export function statusPage(options: StatusPageOptions): string {
  const { issuer, users, clients } = options;
  const userList = users.map((user) =>
    `  <li><span class="mono">${escapeHtml(user.username)}</span> · password
    <span class="mono">${escapeHtml(user.password)}</span> · sub
    <span class="mono">${escapeHtml(user.id)}</span></li>`
  ).join("\n");
  const clientList = clients.map((client) =>
    `  <li><span class="mono">${escapeHtml(client.id)}</span>${
      client.secret
        ? ` · secret <span class="mono">${escapeHtml(client.secret)}</span>`
        : " · public client"
    }<br>redirect URIs: <span class="mono">${
      client.redirectUris.map(escapeHtml).join(", ") || "(none)"
    }</span><br>grants: <span class="mono">${
      client.grants.map(escapeHtml).join(", ")
    }</span></li>`
  ).join("\n");

  return layout(
    "Development identity provider",
    `
<h1>Development identity provider</h1>
<p>Issuer <span class="mono">${escapeHtml(issuer)}</span></p>
<h2>Endpoints</h2>
<ul>
  <li><a href="/.well-known/openid-configuration">
    /.well-known/openid-configuration</a></li>
  <li><a href="/jwks">/jwks</a></li>
  <li><span class="mono">/authorize</span>,
    <span class="mono">/token</span>,
    <span class="mono">/userinfo</span>,
    <span class="mono">/revoke</span>,
    <span class="mono">/introspect</span></li>
  <li><span class="mono">/login</span>,
    <span class="mono">/logout</span></li>
</ul>
<h2>Users</h2>
<ul>
${userList || "  <li>(none seeded)</li>"}
</ul>
<h2>Clients</h2>
<ul>
${clientList || "  <li>(none registered)</li>"}
</ul>
<h2>Test control surface</h2>
<ul>
  <li><span class="mono">POST /__admin/reset</span> — drop every session,
    code, and token</li>
  <li><span class="mono">POST /__admin/session</span> — sign a user in
    without the form</li>
  <li><span class="mono">POST /__admin/tokens</span> — mint tokens without
    the browser</li>
  <li><span class="mono">GET /__admin/state</span> — what is seeded right
    now</li>
</ul>
`,
  );
}

/** A terminal page for a flow that ended without a redirect. */
export function messagePage(title: string, message: string): string {
  return layout(
    title,
    `
<h1>${escapeHtml(title)}</h1>
<p id="message">${escapeHtml(message)}</p>
<p><a href="/">Back to the status page</a></p>
`,
  );
}
