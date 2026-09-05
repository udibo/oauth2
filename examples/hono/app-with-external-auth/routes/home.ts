/**
 * Interactive SPA homepage for the app-with-external-auth example.
 *
 * One self-contained HTML page that drives the entire flow:
 *
 *   - "Sign in" redirects to `POST /auth/login`, which begins the
 *     authorization-code flow against the **external** IDP. The IDP
 *     shows its own login form and consent screen (this app doesn't
 *     host either) and redirects back to `/auth/callback` once
 *     complete. The BFF exchanges the code over real HTTP.
 *   - "Sign out" calls `POST /auth/logout` to clear the BFF session
 *     locally. Note this does **not** sign the user out of the IDP;
 *     hit the IDP's own logout endpoint for that (a real app's button
 *     would call both).
 *   - Buttons for each protected endpoint (`/api/me`, `/api/write`,
 *     `/api/admin`) show the response body, status, and granted scope.
 *   - A button for `/remote-api/private`, which the BFF proxies to the
 *     separate `api-service/` example on port 8002.
 *
 * Sign in as `admin` at the IDP and every endpoint works. Sign in as
 * `user` and `/api/admin` comes back 403 with the RFC 6750
 * `insufficient_scope` error — that's the demo.
 *
 * @module
 */

import { Hono } from "hono";

const app = new Hono();

app.get("/", (c) => c.html(homePage()));

export default app;

function homePage(): string {
  return `<!doctype html>
<title>App with external auth — OAuth2 Example</title>
<style>
  body { font: 14px/1.5 system-ui, sans-serif; max-width: 760px; margin: 2em auto; padding: 0 1em; }
  h1 { margin-top: 0; }
  h2 { border-bottom: 1px solid #ddd; padding-bottom: .2em; margin-top: 2em; }
  button { padding: .4em .9em; margin: 0 .3em .3em 0; cursor: pointer; }
  pre { background: #f5f5f5; padding: .8em 1em; overflow-x: auto; border-radius: 4px; min-height: 1.5em; white-space: pre-wrap; }
  code { background: #f5f5f5; padding: 0 .3em; border-radius: 2px; }
  pre code { background: none; padding: 0; }
  .row { margin: .5em 0; }
  .ok { color: #2a7a2a; }
  .no { color: #b00020; }
  table { border-collapse: collapse; }
  th, td { text-align: left; padding: .35em .8em; border-bottom: 1px solid #eee; vertical-align: top; }
</style>
<h1>App with external auth</h1>
<p>
  This app is a SPA backed by a BFF that delegates authentication to an
  <strong>external</strong> identity provider over real HTTP. The BFF
  holds the session cookie; protected API endpoints validate tokens via
  RFC 7662 introspection against the IDP. Diff this example against
  <code>app-with-own-auth/</code> to see the literal migration path.
</p>

<h2>Pairing for local dev</h2>
<p>
  By default the IDP URLs point at <code>app-with-own-auth/</code> on
  port 8001. Start that example in another terminal and you can
  exercise the full flow without a real Udibo deployment. To point at
  Udibo (or another IDP), change <code>IDP_BASE_URL</code> and the
  client credentials in <code>oauth2/server.ts</code>.
</p>

<h2>1. Sign in</h2>
<p>
  Sign in starts the authorization-code flow at <code>POST /auth/login</code>.
  The BFF redirects the browser to the external IDP's
  <code>/oauth2/authorize</code>; the IDP renders its own login form
  and consent screen, then redirects back to <code>/auth/callback</code>.
</p>
<div class="row">
  <form action="/auth/login" method="post" style="display:inline">
    <button type="submit">Sign in</button>
  </form>
  <button onclick="signOut()">Sign out</button>
</div>
<pre id="session">(checking session…)</pre>

<h2>2. Call the protected endpoints</h2>
<table>
  <tr><th>Endpoint</th><th>Required scope</th><th>Try it</th></tr>
  <tr>
    <td><code>GET /api/me</code></td>
    <td>any valid token</td>
    <td><button onclick="call('/api/me', 'me')">Call</button></td>
  </tr>
  <tr>
    <td><code>GET /api/write</code></td>
    <td><code>write</code></td>
    <td><button onclick="call('/api/write', 'write')">Call</button></td>
  </tr>
  <tr>
    <td><code>GET /api/admin</code></td>
    <td><code>admin</code></td>
    <td><button onclick="call('/api/admin', 'admin')">Call</button></td>
  </tr>
</table>
<div class="row">
  <strong>/api/me</strong>
  <pre id="api-me">—</pre>
</div>
<div class="row">
  <strong>/api/write</strong>
  <pre id="api-write">—</pre>
</div>
<div class="row">
  <strong>/api/admin</strong>
  <pre id="api-admin">—</pre>
</div>
<p>
  Sign in as <code>admin</code> at the IDP and all three return
  <span class="ok">200</span>. Sign in as <code>user</code> and
  <code>/api/admin</code> comes back <span class="no">403</span> with
  the RFC 6750 <code>insufficient_scope</code> error — the IDP's
  consent handler narrowed the granted scope to <code>read write</code>
  for that user.
</p>

<h2>3. Call a separate API through the BFF proxy</h2>
<p>
  The endpoints above are validated <em>in this process</em>. When the
  API is a different service, <code>bff.proxy()</code> forwards the call
  instead: it reads the session, attaches the access token server-side,
  and streams the response back. The browser only ever talks to this
  origin — no CORS, no token in the page.
</p>
<p>
  Start <code>api-service/</code> on port 8002 in a third terminal
  first; it introspects against the same IDP, so the session's token is
  valid there. Without it running the call returns
  <span class="no">502</span>.
</p>
<table>
  <tr><th>Endpoint</th><th>Proxied to</th><th>Try it</th></tr>
  <tr>
    <td><code>GET /remote-api/private</code></td>
    <td><code>localhost:8002/api/private</code></td>
    <td><button onclick="call('/remote-api/private', 'remote')">Call</button></td>
  </tr>
</table>
<div class="row">
  <strong>/remote-api/private</strong>
  <pre id="api-remote">—</pre>
</div>

<script>
  // The BFF's CSRF defense requires a custom header on every credentialed
  // request. A real SPA gets this from BffClient / the React adapter.
  const CSRF = { 'x-csrf': '1' };
  async function signOut() {
    // Clear the local BFF session. This does NOT sign the user out of
    // the external IDP — a real app's button would also hit the IDP's
    // logout endpoint (typically an OIDC end-session URL).
    await fetch('/auth/logout', { method: 'POST', headers: CSRF });
    refreshSession();
    for (const id of ['api-me', 'api-write', 'api-admin', 'api-remote']) {
      document.getElementById(id).textContent = '—';
    }
  }
  async function call(path, id) {
    const target = document.getElementById('api-' + id);
    target.textContent = '…';
    const res = await fetch(path, { credentials: 'include', headers: CSRF });
    const body = await res.text();
    const status = document.createElement('span');
    status.className = res.ok ? 'ok' : 'no';
    status.textContent = res.status + ' ' + res.statusText;
    target.textContent = '';
    target.appendChild(status);
    target.appendChild(document.createTextNode('\\n' + body));
  }
  async function refreshSession() {
    const res = await fetch('/auth/session', { headers: CSRF });
    const data = await res.json();
    document.getElementById('session').textContent =
      JSON.stringify(data, null, 2);
  }
  refreshSession();
</script>`;
}
