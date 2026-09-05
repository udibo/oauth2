/**
 * Email-verification consumption — where the verification link minted at
 * sign-up (`routes/create-account.ts`) lands.
 *
 * Mounted at `/verify-email` by `main.ts`; the paths below are relative.
 *
 * `GET /?token=…` consumes the single-use token via `identity.verifyEmail`,
 * which marks the user's email verified. The discriminated result gives
 * **expired** links a distinct page from generically **invalid** ones, so the
 * UI can suggest requesting a fresh link instead of a dead-end error — the
 * library's `inspect()` distinction surfaced end-to-end.
 *
 * @module
 */

import { Hono } from "hono";

import { identity } from "../oauth2/identity.ts";

const app = new Hono();

app.get("/", async (c) => {
  const token = c.req.query("token") ?? "";
  const result = token
    ? await identity.verifyEmail(token)
    : { status: "invalid" as const };

  switch (result.status) {
    case "success":
      return c.html(outcomePage(
        "Email verified",
        "Your email address is confirmed.",
      ));
    case "expired":
      return c.html(
        outcomePage(
          "Verification link expired",
          "Verification links are single-use and expire after 24 hours. Sign in and request a fresh one.",
        ),
        400,
      );
    case "invalid":
      return c.html(
        outcomePage(
          "Verification link invalid",
          "This link is invalid or was already used.",
        ),
        400,
      );
  }
});

export default app;

function outcomePage(title: string, detail: string): string {
  return `<!doctype html>
<title>${title}</title>
<h1>${title}</h1>
<p>${detail}</p>
<p><a href="/auth/login">Sign in</a></p>`;
}
