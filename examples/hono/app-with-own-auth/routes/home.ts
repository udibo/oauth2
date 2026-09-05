/**
 * Interactive SPA homepage for the app-with-own-auth example.
 *
 * One self-contained HTML page that drives the entire flow:
 *
 *   - "Sign in" redirects to `POST /auth/login`, which begins the
 *     authorization-code flow. The first time through, the auth server
 *     finds no IDP session cookie and renders the login form at
 *     `/login`; once you sign in, the flow continues to `/auth/callback`
 *     and you land back here authenticated.
 *   - "Sign out" calls both `POST /auth/logout` (clears the BFF
 *     session) and `POST /logout` (clears the IDP session). Doing both
 *     means signing in again shows the login form, so you can test as
 *     a different user.
 *   - Buttons for each protected endpoint (`/api/me`, `/api/write`,
 *     `/api/admin`) show the response body, status, and granted scope.
 *
 * Sign in as `admin` and every endpoint works. Sign in as `user` and
 * `/api/admin` comes back 403 with the RFC 6750 `insufficient_scope`
 * error — that's the demo.
 *
 * @module
 */

import { Hono } from "hono";

const app = new Hono();

app.get("/", (c) => c.html(homePage()));

export default app;

function homePage(): string {
  return `<!doctype html>
<title>App with own auth — OAuth2 Example</title>
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
<h1>App with own auth</h1>
<p>
  One Hono process runs an authorization server, an OAuth2 client + BFF,
  and a resource server. The browser holds a session cookie; the BFF
  resolves it to a bearer token in-process when calling protected APIs.
</p>

<h2>Seeded users</h2>
<table>
  <tr><th>Username</th><th>Password</th><th>Can grant scopes</th></tr>
  <tr><td><code>admin</code></td><td><code>password</code></td><td><code>read write admin</code></td></tr>
  <tr><td><code>user</code></td><td><code>password</code></td><td><code>read write</code></td></tr>
</table>

<h2>1. Sign in</h2>
<p>
  Sign in starts the authorization-code flow at <code>POST /auth/login</code>.
  The embedded auth server has no IDP session yet, so it redirects to
  the login form at <code>/login</code>; submit either set of demo
  credentials and the flow resumes back to <code>/auth/callback</code>.
</p>
<div class="row">
  <form action="/auth/login" method="post" style="display:inline">
    <button type="submit">Sign in</button>
  </form>
  <a href="/create-account">Create account</a>
  <button onclick="signOut()">Sign out</button>
</div>
<p style="font-size:smaller;color:#666">
  "Create account" is reached with no in-flight authorize URL, so after sign-up
  it <em>starts</em> a fresh login — the case <code>routes/login.ts</code> never
  has to handle.
</p>
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
  Sign in as <code>admin</code> and all three return <span class="ok">200</span>.
  Sign in as <code>user</code> and <code>/api/admin</code> comes back
  <span class="no">403</span> with the RFC 6750
  <code>insufficient_scope</code> error — the consent handler narrowed
  the granted scope to <code>read write</code> when <code>user</code> signed in.
</p>

<script>
  async function signOut() {
    // Clear both layers: the BFF session (revokes tokens + clears
    // the SPA's cookie) and the IDP session (lets the next sign-in
    // show the login form again instead of silently re-authenticating
    // the same user).
    await fetch('/auth/logout', { method: 'POST' });
    await fetch('/logout', { method: 'POST' });
    refreshSession();
    for (const id of ['api-me', 'api-write', 'api-admin']) {
      document.getElementById(id).textContent = '—';
    }
  }
  async function call(path, id) {
    const target = document.getElementById('api-' + id);
    target.textContent = '…';
    const res = await fetch(path, { credentials: 'include' });
    const body = await res.text();
    const status = document.createElement('span');
    status.className = res.ok ? 'ok' : 'no';
    status.textContent = res.status + ' ' + res.statusText;
    target.textContent = '';
    target.appendChild(status);
    target.appendChild(document.createTextNode('\\n' + body));
  }
  async function refreshSession() {
    const res = await fetch('/auth/session');
    const data = await res.json();
    document.getElementById('session').textContent =
      JSON.stringify(data, null, 2);
  }
  refreshSession();
</script>`;
}
