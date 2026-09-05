/**
 * Dev-only demo routes that let the homepage drive OAuth2 flows
 * against the companion authorization server end-to-end.
 *
 * Mounted at `/dev` by `main.ts`; the paths below are relative.
 *
 *   - `GET /callback` — the redirect URI registered with the
 *     authorization server's demo client. Receives `?code=...` after a
 *     successful authorize, exchanges the code server-side (so the
 *     client_secret never reaches the browser), and renders a tester
 *     page with the issued token pre-filled.
 *   - `POST /token` — server-side proxy to the auth server's
 *     `/oauth2/token`. Lets the homepage drive `client_credentials` /
 *     `refresh_token` / `device_code` flows from in-page buttons
 *     without leaking the `client_secret` to the browser and without
 *     needing CORS on the auth server. The browser POSTs JSON; the
 *     server forwards as form-encoded with Basic auth attached, then
 *     returns the auth server's response verbatim.
 *   - `POST /device-authorization` — server-side proxy to the auth
 *     server's `/oauth2/device_authorization` (RFC 8628 step 1). Same
 *     pattern as `/token`: JSON in, form-encoded forward with Basic
 *     auth, response verbatim out.
 *
 * In production these endpoints have no business living on a resource
 * server — token acquisition belongs to a client app (SPA, BFF, native).
 * They exist here only to give a single-page walkthrough of how an
 * api-service pairs with an authorization server.
 *
 * @module
 */

import { type Context, Hono } from "hono";
import { deleteCookie, getCookie } from "hono/cookie";

import { escapeHtml } from "../html.ts";
import {
  AUTH_SERVER_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  PKCE_COOKIE,
  REDIRECT_URI,
} from "../oauth2/server.ts";

const app = new Hono();

app.get("/callback", async (c) => {
  const url = new URL(c.req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");
  const errorDescription = url.searchParams.get("error_description");

  if (error) {
    return c.html(errorPage({ error, errorDescription }));
  }
  if (!code) {
    return c.html(infoPage());
  }

  const verifier = getCookie(c, PKCE_COOKIE);
  deleteCookie(c, PKCE_COOKIE, { path: "/" });

  const tokenParams = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
  });
  if (verifier) tokenParams.set("code_verifier", verifier);
  const tokenRes = await fetch(`${AUTH_SERVER_URL}/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: tokenParams,
  });
  const body = await tokenRes.text();
  return c.html(
    callbackPage({ status: tokenRes.status, body, state: state ?? undefined }),
  );
});

app.post("/token", (c) => proxy(c, `${AUTH_SERVER_URL}/oauth2/token`));
app.post(
  "/device-authorization",
  (c) => proxy(c, `${AUTH_SERVER_URL}/oauth2/device_authorization`),
);

/**
 * Forwards a JSON POST body to an auth-server form-encoded endpoint
 * with Basic auth attached. Pass-through status + body so the homepage
 * surfaces real OAuth2 errors (`invalid_grant`, `authorization_pending`,
 * …) instead of always seeing 200 OK from this proxy.
 */
async function proxy(c: Context, url: string): Promise<Response> {
  const params = (await c.req.json()) as Record<string, string>;
  const upstream = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params),
  });
  return new Response(await upstream.text(), {
    status: upstream.status,
    headers: { "Content-Type": "application/json" },
  });
}

export default app;

const STYLE = `<style>
  body { font: 14px/1.5 system-ui, sans-serif; max-width: 760px; margin: 2em auto; padding: 0 1em; }
  h1 { margin-top: 0; }
  h2 { border-bottom: 1px solid #ddd; padding-bottom: .2em; margin-top: 2em; }
  .ok-box { background: #eaf6ea; padding: 1em; border-radius: 4px; margin: 1em 0; }
  .no-box { background: #fbeaea; padding: 1em; border-radius: 4px; margin: 1em 0; }
  pre { background: #f5f5f5; padding: .8em 1em; overflow-x: auto; border-radius: 4px; white-space: pre-wrap; min-height: 1.5em; }
  code { background: #f5f5f5; padding: 0 .3em; border-radius: 2px; }
  pre code { background: none; padding: 0; }
  button { padding: .4em .9em; margin: 0 .3em .3em 0; cursor: pointer; }
  .ok { color: #2a7a2a; }
  .no { color: #b00020; }
</style>`;

function infoPage(): string {
  return `<!doctype html>
<title>Dev callback</title>
${STYLE}
<h1>Dev callback</h1>
<p>This page is the redirect URI for the api-service example's
   demo of the authorization-code flow. Start the flow from the
   <a href="/">homepage</a>.</p>`;
}

function errorPage(
  opts: { error: string; errorDescription: string | null },
): string {
  const desc = opts.errorDescription
    ? `<p>${escapeHtml(opts.errorDescription)}</p>`
    : "";
  return `<!doctype html>
<title>Authorization error</title>
${STYLE}
<h1>Authorization error</h1>
<div class="no-box">
  <p><strong>Error:</strong> <code>${escapeHtml(opts.error)}</code></p>
  ${desc}
</div>
<p><a href="/">← Back to homepage</a></p>`;
}

function callbackPage(
  opts: { status: number; body: string; state?: string },
): string {
  const ok = opts.status >= 200 && opts.status < 300;
  let token: string | undefined;
  let pretty = opts.body;
  try {
    const parsed = JSON.parse(opts.body);
    pretty = JSON.stringify(parsed, null, 2);
    if (ok && typeof parsed.access_token === "string") {
      token = parsed.access_token;
    }
  } catch {
    // Not JSON — show the raw body.
  }

  const statusBox = ok
    ? `<div class="ok-box">
        <p><strong>Status:</strong> <span class="ok">${opts.status}</span></p>
        ${
      opts.state
        ? `<p><strong>State:</strong> <code>${
          escapeHtml(opts.state)
        }</code></p>`
        : ""
    }
      </div>`
    : `<div class="no-box">
        <p><strong>Status:</strong> <span class="no">${opts.status}</span></p>
        <p>The token endpoint returned an error response.</p>
      </div>`;

  const testerSection = token
    ? `<h2>Test the token against this server</h2>
<p>
  The token is auto-filled below. Click the buttons to call each
  protected endpoint on this api-service — watch how the granted
  scope determines which ones succeed.
</p>
<p><textarea id="tester-token" rows="3">${escapeHtml(token)}</textarea></p>
<p>
  <button onclick="callApi('/api/public', 'api-public')">Call /api/public</button>
  <button onclick="callApi('/api/private', 'api-private')">Call /api/private</button>
  <button onclick="callApi('/api/write', 'api-write')">Call /api/write</button>
  <button onclick="callApi('/api/admin', 'api-admin')">Call /api/admin</button>
</p>
<div><strong>/api/public</strong><pre id="api-public">—</pre></div>
<div><strong>/api/private</strong><pre id="api-private">—</pre></div>
<div><strong>/api/write</strong><pre id="api-write">—</pre></div>
<div><strong>/api/admin</strong><pre id="api-admin">—</pre></div>
<script>
  async function callApi(path, outId) {
    const out = document.getElementById(outId);
    out.textContent = '…';
    const token = document.getElementById('tester-token').value.trim();
    const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
    const res = await fetch(path, { headers });
    const text = await res.text();
    let pretty = text;
    try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch {}
    out.textContent = '';
    const s = document.createElement('span');
    s.className = res.ok ? 'ok' : 'no';
    s.textContent = res.status + ' ' + res.statusText;
    out.appendChild(s);
    out.appendChild(document.createTextNode('\\n' + pretty));
  }
</script>`
    : "";

  return `<!doctype html>
<title>Authorization code exchanged</title>
${STYLE}
<h1>Authorization code exchanged</h1>
<p>
  The auth server redirected here with a one-time code. This page
  exchanged it server-side at
  <code>${escapeHtml(AUTH_SERVER_URL)}/oauth2/token</code> using the
  configured <code>client_secret</code>; the response is shown below.
</p>
${statusBox}
<h2>Token endpoint response</h2>
<pre>${escapeHtml(pretty)}</pre>
${testerSection}
<p><a href="/">← Back to homepage</a></p>`;
}
