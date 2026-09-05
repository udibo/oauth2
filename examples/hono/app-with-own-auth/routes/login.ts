/**
 * Login form for the embedded authorization server.
 *
 * Mounted at `/login` by `main.ts`; the paths below are relative.
 *
 * `GET /` renders an inline HTML form. `POST /` validates the
 * credentials against the auth server's `userService`, opens an IDP
 * session, and redirects back to the supplied `return_to` URL (typically
 * the original `/oauth2/authorize` URL preserved by the authorize handler
 * when it found no session cookie) — guarded to same-origin paths only, the
 * same open-redirect guard as `logout.ts`.
 *
 * Real SPA-backed apps redirect to a real login page on the IDP; that's
 * what this file demonstrates.
 *
 * Things this example deliberately omits (call them out when you copy
 * this file): **CSRF protection**, account creation / password reset /
 * MFA / rate-limiting / account lockout / brute-force protection,
 * password complexity rules, captcha, session expiry. Each one is
 * independent of the OAuth2 wiring shown here.
 *
 * One of those omissions is sharper than it looks: `getAuthenticated` looks the
 * account up first and only hashes a password when it finds one, so an unknown
 * username answers measurably faster than a wrong password — a **username
 * enumeration oracle**. `IdentityService.signIn` is the answer (it throttles
 * before the lookup and does the password work on every failure branch);
 * `templates/juniper` wires it that way. This example keeps the direct call so
 * the OAuth2 wiring stays the only thing on screen.
 *
 * @module
 */

import { Hono } from "hono";

import { safeReturnTo } from "@udibo/oauth2/url";

import { escapeHtml } from "../html.ts";
import { userService } from "../oauth2/server.ts";
import { startSession } from "../sessions.ts";

const app = new Hono();

app.get("/", (c) => {
  const returnTo = safeReturnTo(c.req.query("return_to"));
  return c.html(loginPage({ returnTo }));
});

app.post("/", async (c) => {
  const form = await c.req.formData();
  const username = String(form.get("username") ?? "");
  const password = String(form.get("password") ?? "");
  const returnTo = safeReturnTo(form.get("return_to")?.toString());

  const user = await userService.getAuthenticated(username, password);
  if (!user) {
    return c.html(
      loginPage({ returnTo, error: "Invalid username or password." }),
      401,
    );
  }

  startSession(c, user.id);
  return c.redirect(returnTo);
});

export default app;

function loginPage(
  options: { returnTo: string; error?: string },
): string {
  const returnTo = escapeHtml(options.returnTo);
  const error = options.error
    ? `<p style="color:red">${escapeHtml(options.error)}</p>`
    : "";
  const createHref = escapeHtml(
    `/create-account?return_to=${encodeURIComponent(options.returnTo)}`,
  );
  return `<!doctype html>
<title>Sign in</title>
<h1>Sign in</h1>
${error}
<form method="post" action="/login">
  <input type="hidden" name="return_to" value="${returnTo}">
  <p>
    <label>Username <input name="username" autocomplete="username" required></label>
  </p>
  <p>
    <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  </p>
  <button type="submit">Sign in</button>
</form>
<p style="font-size:smaller">
  <a href="${createHref}">Create account</a> &middot;
  <a href="/forgot-password">Forgot password?</a>
</p>
<p style="font-size:smaller;color:#666">
  Demo credentials: <code>admin</code> / <code>password</code> or <code>user</code> / <code>password</code>
</p>`;
}
