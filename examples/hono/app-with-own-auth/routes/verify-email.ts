/**
 * Email-verification consumption — where the verification link minted at
 * sign-up (`routes/create-account.ts`) lands.
 *
 * Mounted at `/verify-email` by `main.ts`; the paths below are relative.
 *
 * `GET /?token=…` consumes the single-use token via `identity.verifyEmail`,
 * which marks the user's email verified. It passes the signed-in user from the
 * IDP session, because the token verifies only for the account it was sent
 * for: a signed-out visitor, or one signed in as someone else, is asked to sign
 * in and the link stays usable. The discriminated result gives
 * **expired** links a distinct page from generically **invalid** ones, so the
 * UI can suggest requesting a fresh link instead of a dead-end error — the
 * library's `inspect()` distinction surfaced end-to-end.
 *
 * @module
 */

import { Hono } from "hono";

import { identity } from "../oauth2/identity.ts";
import { readSessionUserId } from "../sessions.ts";

const app = new Hono();

app.get("/", async (c) => {
  const token = c.req.query("token") ?? "";
  const result = token
    ? await identity.verifyEmail({
        token,
        sessionUserId: readSessionUserId(c) ?? null,
      })
    : { status: "invalid" as const };
  const here = new URL(c.req.url);
  const signIn = `/login?return_to=${encodeURIComponent(here.pathname + here.search)}`;

  switch (result.status) {
    case "success":
      return c.html(
        outcomePage("Email verified", "Your email address is confirmed."),
      );
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
    case "sign-in-required":
      return c.html(
        outcomePage(
          "Sign in to verify your email",
          "Sign in to the account this link was sent for, then open the link again.",
          signIn,
        ),
        401,
      );
    case "wrong-account":
      return c.html(
        outcomePage(
          "This link is for another account",
          "Sign in as the account this link was sent for, then open the link again.",
          signIn,
        ),
        403,
      );
  }
});

export default app;

function outcomePage(
  title: string,
  detail: string,
  signIn = "/auth/login",
): string {
  return `<!doctype html>
<title>${title}</title>
<h1>${title}</h1>
<p>${detail}</p>
<p><a href="${escapeAttribute(signIn)}">Sign in</a></p>`;
}

function escapeAttribute(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll('"', "&quot;");
}
