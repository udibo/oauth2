/**
 * Password-reset consumption — where the emailed link from
 * `routes/forgot-password.ts` lands.
 *
 * Mounted at `/reset-password` by `main.ts`; the paths below are relative.
 *
 * `GET /?token=…` **validates without consuming** (`tokens.validate`), so
 * rendering the form never burns the single-use token; an invalid or expired
 * link gets a distinct page offering to request a new one. `POST /` consumes
 * the token via `identity.resetPassword`, which sets the new credential and
 * revokes the user's other IDP sessions. Failure states are user-safe: a
 * reused, expired, or unknown token produces the same "invalid or expired"
 * message.
 *
 * @module
 */

import { Hono } from "hono";

import { IdentityError, TokenPurpose } from "@udibo/oauth2/identity";

import { escapeHtml } from "../html.ts";
import { identity, tokens } from "../oauth2/identity.ts";

const app = new Hono();

app.get("/", async (c) => {
  const token = c.req.query("token") ?? "";
  const valid = token &&
    await tokens.validate(TokenPurpose.PasswordReset, token);
  if (!valid) return c.html(invalidPage(), 400);
  return c.html(resetPage({ token }));
});

app.post("/", async (c) => {
  const form = await c.req.formData();
  const token = String(form.get("token") ?? "");
  const password = String(form.get("password") ?? "");

  try {
    const result = await identity.resetPassword({ token, password });
    if (!result) return c.html(invalidPage(), 400);
  } catch (error) {
    if (error instanceof IdentityError && error.code === "weak_password") {
      return c.html(
        resetPage({ token, error: "Password must be at least 8 characters." }),
        422,
      );
    }
    throw error;
  }
  return c.html(successPage());
});

export default app;

function resetPage(options: { token: string; error?: string }): string {
  const error = options.error
    ? `<p style="color:red">${escapeHtml(options.error)}</p>`
    : "";
  return `<!doctype html>
<title>Choose a new password</title>
<h1>Choose a new password</h1>
${error}
<form method="post" action="/reset-password">
  <input type="hidden" name="token" value="${escapeHtml(options.token)}">
  <p>
    <label>New password <input name="password" type="password" autocomplete="new-password" required></label>
  </p>
  <button type="submit">Reset password</button>
</form>`;
}

function invalidPage(): string {
  return `<!doctype html>
<title>Link invalid</title>
<h1>This reset link is invalid or has expired</h1>
<p>Reset links are single-use and expire after an hour.</p>
<p><a href="/forgot-password">Request a new one</a></p>`;
}

function successPage(): string {
  return `<!doctype html>
<title>Password reset</title>
<h1>Password reset</h1>
<p>Your password has been changed and any other sessions were signed out.</p>
<p><a href="/auth/login">Sign in</a></p>`;
}
