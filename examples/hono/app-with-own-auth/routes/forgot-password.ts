/**
 * Forgot-password form for the embedded authorization server's login surface.
 *
 * Mounted at `/forgot-password` by `main.ts`; the paths below are relative.
 *
 * `POST /` runs the library's `requestPasswordReset` flow: a single-use,
 * expiring reset token is minted (hashed at rest) and its link is handed to
 * the delivery hooks in `oauth2/identity.ts` — this example logs it to the
 * server console; a real app emails it. The response is **enumeration-safe**:
 * identical whether or not the address matches an account. The link lands on
 * `/reset-password` (see `routes/reset-password.ts`).
 *
 * @module
 */

import { Hono } from "hono";

import { identity } from "../oauth2/identity.ts";

const app = new Hono();

const SUCCESS_MESSAGE =
  "If an account exists for that address, a password reset link has been sent.";

app.get("/", (c) => c.html(forgotPasswordPage({})));

app.post("/", async (c) => {
  const form = await c.req.formData();
  const email = String(form.get("email") ?? "").trim();

  if (email) {
    await identity.requestPasswordReset(email);
  }
  return c.html(forgotPasswordPage({ message: SUCCESS_MESSAGE }));
});

export default app;

function forgotPasswordPage(options: { message?: string }): string {
  const notice = options.message
    ? `<p style="color:green">${options.message}</p>`
    : "";
  const formOrNotice = options.message
    ? notice
    : `<form method="post" action="/forgot-password">
  <p>
    <label>Email <input name="email" type="email" autocomplete="email" required></label>
  </p>
  <button type="submit">Send reset link</button>
</form>`;
  return `<!doctype html>
<title>Reset your password</title>
<h1>Reset your password</h1>
<p>Enter your email and we'll send a link to reset your password.</p>
${formOrNotice}
<p style="font-size:smaller;color:#666">
  <a href="/auth/login">Back to sign in</a>
</p>`;
}
