/**
 * Account creation for the embedded authorization server's own login surface.
 *
 * Mounted at `/create-account` by `main.ts`; the paths below are relative.
 *
 * This is the route that makes the example **realistic**. The moment an app
 * owns its login it almost always owns sign-up and password reset too — and
 * unlike `routes/login.ts` (only ever reached mid-authorize, so it can resume
 * with a trivial `redirect(returnTo)`), create-account is reached two ways:
 *
 *   - **From the home page** (a normal entry point): there is no in-flight
 *     authorize URL, so after creating the account we must *start* a fresh BFF
 *     login (`/auth/login`) so OAuth2 tokens get attached to the session.
 *   - **From the login form's "Create account" link** (mid-authorize): the
 *     `return_to` is the original `/oauth2/authorize?...` URL whose PKCE `state`
 *     is already minted, so we *resume* it directly.
 *
 * The "resume vs. start" decision is general to the own-auth + BFF topology, not
 * to this app — so it lives on the BFF as `bff.loginContinuation(returnTo)`
 * (CP-02 of `docs/plans/shipped/oauth2-best-in-class.md`). The BFF already knows its
 * authorize endpoint (from the client config) and its login path, so the app
 * never restates those strings.
 *
 * Sign-up runs through `identity.signUp` (`oauth2/identity.ts`), which hashes
 * the password, enforces the password policy, and — when an email is provided —
 * is followed by `requestEmailVerification`, whose link lands on
 * `/verify-email`. Deliberately omitted (same caveats as `routes/login.ts`):
 * CSRF, rate limiting, captcha.
 *
 * @module
 */

import { Hono } from "hono";

import { IdentityError } from "@udibo/oauth2/identity";
import { safeReturnTo } from "@udibo/oauth2/url";

import { escapeHtml } from "../html.ts";
import { identity } from "../oauth2/identity.ts";
import { bff, userService } from "../oauth2/server.ts";
import { startSession } from "../sessions.ts";

const app = new Hono();

app.get("/", (c) => {
  const returnTo = safeReturnTo(c.req.query("return_to"));
  return c.html(createAccountPage({ returnTo }));
});

app.post("/", async (c) => {
  const form = await c.req.formData();
  const username = String(form.get("username") ?? "").trim();
  const name = String(form.get("name") ?? "").trim();
  const email = String(form.get("email") ?? "").trim();
  const password = String(form.get("password") ?? "");
  const returnTo = safeReturnTo(form.get("return_to")?.toString());

  if (!username || !password) {
    return c.html(
      createAccountPage({
        returnTo,
        error: "Username and password are required.",
      }),
      400,
    );
  }

  if (await userService.findByUsername(username)) {
    return c.html(
      createAccountPage({ returnTo, error: "That username is taken." }),
      409,
    );
  }

  let user;
  try {
    user = await identity.signUp({
      password,
      profile: { username, name, email: email || undefined },
    });
  } catch (error) {
    if (error instanceof IdentityError && error.code === "weak_password") {
      return c.html(
        createAccountPage({
          returnTo,
          error: "Password must be at least 8 characters.",
        }),
        422,
      );
    }
    throw error;
  }

  if (user.email) {
    await identity.requestEmailVerification({
      userId: user.id,
      email: user.email,
    });
  }

  startSession(c, user.id);
  return c.redirect(bff.loginContinuation(returnTo));
});

export default app;

function createAccountPage(
  options: { returnTo: string; error?: string },
): string {
  const returnTo = escapeHtml(options.returnTo);
  const error = options.error
    ? `<p style="color:red">${escapeHtml(options.error)}</p>`
    : "";
  const signInHref = escapeHtml(bff.loginContinuation(options.returnTo));
  return `<!doctype html>
<title>Create account</title>
<h1>Create your account</h1>
${error}
<form method="post" action="/create-account">
  <input type="hidden" name="return_to" value="${returnTo}">
  <p>
    <label>Username <input name="username" autocomplete="username" required></label>
  </p>
  <p>
    <label>Name <input name="name" autocomplete="name"></label>
  </p>
  <p>
    <label>Email <input name="email" type="email" autocomplete="email"></label>
  </p>
  <p>
    <label>Password <input name="password" type="password" autocomplete="new-password" required></label>
  </p>
  <button type="submit">Create account</button>
</form>
<p style="font-size:smaller;color:#666">
  Already have an account? <a href="${signInHref}">Sign in</a>
</p>`;
}
