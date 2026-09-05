/**
 * Interactive homepage for the api-service example.
 *
 * Documents each protected endpoint, demonstrates the OAuth2 flows
 * end-to-end against the companion auth server (the
 * `app-with-own-auth/` example on port 8001), and provides a token
 * tester that hits this server's `/api/*` endpoints. The flows route
 * through this server's own `/dev/*` proxy so the `client_secret`
 * stays server-side and the browser doesn't need CORS on the auth
 * server.
 *
 * @module
 */

import { Hono } from "hono";

import { setCookie } from "hono/cookie";
import {
  generateCodeChallenge,
  generateCodeVerifier,
} from "@udibo/oauth2/server/authorization";

import { escapeHtml } from "../html.ts";
import {
  AUTH_SERVER_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  PKCE_COOKIE,
  REDIRECT_URI,
} from "../oauth2/server.ts";

const app = new Hono();

app.get("/", async (c) => {
  const verifier = generateCodeVerifier();
  const challenge = await generateCodeChallenge(verifier);
  setCookie(c, PKCE_COOKIE, verifier, {
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
  });
  return c.html(homePage(challenge));
});

export default app;

function homePage(codeChallenge: string): string {
  const clientId = escapeHtml(CLIENT_ID);
  const clientSecret = escapeHtml(CLIENT_SECRET);
  const auth = `${clientId}:${clientSecret}`;
  const authServer = escapeHtml(AUTH_SERVER_URL);
  const redirectUri = escapeHtml(REDIRECT_URI);
  const authorizeUrl =
    `${AUTH_SERVER_URL}/oauth2/authorize?response_type=code` +
    `&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=read+write+admin&state=demo` +
    `&code_challenge=${encodeURIComponent(codeChallenge)}` +
    `&code_challenge_method=S256`;
  return `<!doctype html>
<title>API service — OAuth2 Example</title>
<style>
  body { font: 14px/1.5 system-ui, sans-serif; max-width: 920px; margin: 2em auto; padding: 0 1em; }
  h1 { margin-top: 0; }
  h2 { border-bottom: 1px solid #ddd; padding-bottom: .2em; margin-top: 2em; }
  table { border-collapse: collapse; }
  th, td { text-align: left; padding: .35em .8em; border-bottom: 1px solid #eee; vertical-align: top; }
  pre { background: #f5f5f5; padding: .8em 1em; overflow-x: auto; border-radius: 4px; white-space: pre-wrap; min-height: 1.5em; }
  code { background: #f5f5f5; padding: 0 .3em; border-radius: 2px; }
  pre code { background: none; padding: 0; }
  button { padding: .4em .9em; margin: 0 .3em .3em 0; cursor: pointer; }
  input[type=text], textarea { font: inherit; padding: .25em .4em; }
  textarea { width: 100%; box-sizing: border-box; }
  .runner { background: #f9f9fb; border: 1px solid #e3e3e8; border-radius: 4px; padding: .6em 1em; margin: .6em 0 1em 0; }
  .runner strong { display: block; margin-bottom: .3em; }
  .ok { color: #2a7a2a; }
  .no { color: #b00020; }
</style>
<h1>API service</h1>
<p>
  This server protects API routes with bearer tokens issued by the
  companion <a href="${authServer}/">authorization server</a> (port 8001).
  Each route declares a scope requirement; the resource server rejects
  tokens that lack the scope with RFC 6750
  <code>WWW-Authenticate: Bearer error="insufficient_scope"</code>.
</p>
<p>
  The walkthrough below drives every grant type against the auth server
  and tests the resulting token against this server's
  <code>/api/*</code> endpoints. <code>client_credentials</code> and
  <code>refresh_token</code> run in-page through a server-side proxy
  (<code>/dev/token</code>) so the <code>client_secret</code> never
  reaches the browser; <code>authorization_code</code> redirects through
  the auth server and lands on this server's
  <code><a href="/dev/callback">/dev/callback</a></code>.
</p>

<h2>Endpoints</h2>
<table>
  <tr><th>Path</th><th>Required scope</th><th>Notes</th></tr>
  <tr>
    <td><a href="/api/public"><code>GET /api/public</code></a></td>
    <td>—</td>
    <td>No token. Responds with a static JSON message.</td>
  </tr>
  <tr>
    <td><code>GET /api/private</code></td>
    <td>any valid token</td>
    <td><code>resourceServer.protect()</code> — token must verify, no scope check.</td>
  </tr>
  <tr>
    <td><code>GET /api/write</code></td>
    <td><code>write</code></td>
    <td><code>resourceServer.protect("write")</code></td>
  </tr>
  <tr>
    <td><code>GET /api/admin</code></td>
    <td><code>admin</code></td>
    <td><code>resourceServer.protect("admin")</code> — only <code>admin</code> users on the auth server can grant this scope.</td>
  </tr>
</table>

<h2>Flows</h2>

<h3>1. Client credentials</h3>
<p>No user involved — the confidential client authenticates itself.</p>
<pre><code>curl -X POST ${authServer}/oauth2/token \\
  -u ${auth} \\
  -d "grant_type=client_credentials"</code></pre>
<div class="runner">
  <strong>Run in browser</strong>
  <label>scope <input type="text" id="cc-scope" placeholder="(optional, e.g. read write)"></label>
  <button onclick="runClientCredentials()">POST ${authServer}/oauth2/token</button>
  <pre id="cc-result">—</pre>
</div>

<h3>2. Authorization code</h3>
<p>
  Redirects the browser to the auth server's
  <code>/oauth2/authorize</code> with this server's
  <code>${redirectUri}</code> as the redirect URI. After login + consent,
  the auth server redirects back here; the callback page exchanges the
  code server-side and shows the issued token plus a tester that calls
  the <code>/api/*</code> endpoints on this server.
</p>
<ol>
  <li><a href="${escapeHtml(authorizeUrl)}">Start the flow ↗</a></li>
  <li>Sign in on the auth server as <code>admin</code> or <code>user</code>.</li>
  <li>Approve the consent screen.</li>
  <li>Land on <a href="/dev/callback"><code>/dev/callback</code></a>;
      the issued token is auto-filled into a tester section.</li>
</ol>
<p>
  Compare <code>admin</code> vs <code>user</code> — admin grants all
  three scopes; user caps the granted scope at <code>read write</code>,
  so <code>/api/admin</code> comes back 403.
</p>

<h3>3. Refresh token</h3>
<p>Use a <code>refresh_token</code> from a previous flow to rotate the access token.</p>
<pre><code>curl -X POST ${authServer}/oauth2/token \\
  -u ${auth} \\
  -d "grant_type=refresh_token&amp;refresh_token=&lt;paste-refresh-token&gt;"</code></pre>
<div class="runner">
  <strong>Run in browser</strong>
  <p><textarea id="rt-refresh" rows="2" placeholder="paste a refresh_token"></textarea></p>
  <button onclick="runRefresh()">POST ${authServer}/oauth2/token</button>
  <pre id="rt-result">—</pre>
</div>

<h3>4. Device authorization</h3>
<p>
  Two-step flow (RFC 8628): the device requests a code pair, the user
  approves it from a separate browser on the auth server, then the
  device polls the token endpoint until the user finishes.
</p>
<ol>
  <li>Device requests a code pair:
    <pre><code>curl -X POST ${authServer}/oauth2/device_authorization \\
  -u ${auth} \\
  -d "client_id=${clientId}&amp;scope=read"</code></pre>
    <div class="runner">
      <strong>Run in browser</strong>
      <label>scope <input type="text" id="dev-scope" placeholder="(optional)"></label>
      <button onclick="requestDeviceCodes()">POST /dev/device-authorization</button>
      <pre id="dev-result">—</pre>
      <div id="dev-approve-wrap" style="display:none">
        <p><a id="dev-approve-link" target="_blank">Open the auth server's /device with the user_code pre-filled ↗</a></p>
      </div>
    </div>
  </li>
  <li>User opens the link above, signs in on the auth server as
      <code>admin</code> or <code>user</code>, and approves.</li>
  <li>Device polls the token endpoint with the <code>device_code</code>:
    <pre><code>curl -X POST ${authServer}/oauth2/token \\
  -u ${auth} \\
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&amp;device_code=&lt;paste-device-code&gt;"</code></pre>
    <div class="runner">
      <strong>Run in browser</strong>
      <p>Uses the <code>device_code</code> from step 1. Returns
         <code>authorization_pending</code> until the user approves; poll
         again after approval to get the token.</p>
      <button onclick="pollDevice()">POST /dev/token (poll once)</button>
      <pre id="dev-poll-result">—</pre>
    </div>
  </li>
</ol>

<h2 id="tester">Token tester</h2>
<p>
  Auto-filled when any flow above issues a token. Paste a token to
  test this service's <code>/api/*</code> endpoints.
</p>
<div class="runner">
  <p><textarea id="tester-token" rows="3" placeholder="paste an access_token"></textarea></p>
  <p>
    <button onclick="callApi('/api/public', 'api-public-result')">Call /api/public</button>
    <button onclick="callApi('/api/private', 'api-private-result')">Call /api/private</button>
    <button onclick="callApi('/api/write', 'api-write-result')">Call /api/write</button>
    <button onclick="callApi('/api/admin', 'api-admin-result')">Call /api/admin</button>
  </p>
  <div><strong>/api/public</strong><pre id="api-public-result">—</pre></div>
  <div><strong>/api/private</strong><pre id="api-private-result">—</pre></div>
  <div><strong>/api/write</strong><pre id="api-write-result">—</pre></div>
  <div><strong>/api/admin</strong><pre id="api-admin-result">—</pre></div>
</div>

<h2>Companion examples</h2>
<ul>
  <li>The <strong>app-with-own-auth</strong> example (port 8001) is the
      source of the tokens this server validates. It bundles an
      authorization server, BFF, and resource server in one process —
      the same shape a SaaS that hosts its own identity layer uses.</li>
  <li>The <strong>app-with-external-auth</strong> example (port 8003)
      shows the opposite topology: a SPA + BFF + own API delegating
      authentication to an external IDP via introspection — the same
      shape this service would be paired with when both sit behind a
      shared IDP.</li>
</ul>

<script>
  const AUTH_SERVER_URL = ${JSON.stringify(AUTH_SERVER_URL)};
  const CLIENT_ID = ${JSON.stringify(CLIENT_ID)};
  let LAST_DEVICE_CODE = null;

  function showResult(elemId, status, ok, body) {
    const out = document.getElementById(elemId);
    out.textContent = '';
    const s = document.createElement('span');
    s.className = ok ? 'ok' : 'no';
    s.textContent = status;
    out.appendChild(s);
    out.appendChild(document.createTextNode('\\n' + body));
  }

  function showErr(elemId, msg) {
    showResult(elemId, 'error', false, msg);
  }

  function prettify(text) {
    try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
  }

  function maybeSaveToken(text) {
    try {
      const data = JSON.parse(text);
      if (data && data.access_token) {
        document.getElementById('tester-token').value = data.access_token;
      }
    } catch {}
  }

  // Server-side proxy: POSTs JSON to /dev/token, which forwards as
  // form-encoded to the auth server's /oauth2/token with Basic auth
  // attached, and returns the upstream response verbatim.
  async function postTokenProxy(params) {
    const res = await fetch('/dev/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    return { res, text: await res.text() };
  }

  async function runClientCredentials() {
    const scope = document.getElementById('cc-scope').value.trim();
    const params = { grant_type: 'client_credentials' };
    if (scope) params.scope = scope;
    const { res, text } = await postTokenProxy(params);
    showResult('cc-result', res.status + ' ' + res.statusText, res.ok, prettify(text));
    maybeSaveToken(text);
  }

  async function runRefresh() {
    const refresh = document.getElementById('rt-refresh').value.trim();
    if (!refresh) { showErr('rt-result', 'paste a refresh_token first'); return; }
    const { res, text } = await postTokenProxy({
      grant_type: 'refresh_token',
      refresh_token: refresh,
    });
    showResult('rt-result', res.status + ' ' + res.statusText, res.ok, prettify(text));
    maybeSaveToken(text);
  }

  // Server-side proxy: POSTs JSON to /dev/device-authorization, which
  // forwards to the auth server's /oauth2/device_authorization with
  // Basic auth attached. The response includes device_code, user_code,
  // and verification_uri.
  async function requestDeviceCodes() {
    const scope = document.getElementById('dev-scope').value.trim();
    const params = { client_id: CLIENT_ID };
    if (scope) params.scope = scope;
    const res = await fetch('/dev/device-authorization', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    const text = await res.text();
    showResult('dev-result', res.status + ' ' + res.statusText, res.ok, prettify(text));
    LAST_DEVICE_CODE = null;
    try {
      const data = JSON.parse(text);
      if (data && data.device_code) {
        LAST_DEVICE_CODE = data.device_code;
        // Link the user to the auth server's /device page with their
        // user_code pre-filled, the same way the auth server's own
        // homepage runner does.
        const link = document.getElementById('dev-approve-link');
        link.href = AUTH_SERVER_URL + '/device?user_code=' + encodeURIComponent(data.user_code);
        document.getElementById('dev-approve-wrap').style.display = 'block';
      }
    } catch {}
  }

  async function pollDevice() {
    if (!LAST_DEVICE_CODE) {
      showErr('dev-poll-result', 'request a device code first');
      return;
    }
    const { res, text } = await postTokenProxy({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: LAST_DEVICE_CODE,
    });
    showResult('dev-poll-result', res.status + ' ' + res.statusText, res.ok, prettify(text));
    maybeSaveToken(text);
  }

  async function callApi(path, outId) {
    const token = document.getElementById('tester-token').value.trim();
    const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
    const res = await fetch(path, { headers });
    const text = await res.text();
    showResult(outId, res.status + ' ' + res.statusText, res.ok, prettify(text));
  }
</script>`;
}
