/**
 * Login form for the embedded authorization server (the IDP), mounted at
 * `/login`. A Juniper (SSR React) route — the IDP UI is part of the same app,
 * server-rendered as JSX rather than a hand-written HTML string.
 *
 * The page renders the form (data via props); `login.ts` holds the server
 * loader (reads `return_to`) and action (validates credentials, opens the IDP
 * session, redirects back to `return_to`).
 *
 * Deliberately omitted (call these out when copying): CSRF protection,
 * account creation / password reset / MFA / rate-limiting / lockout,
 * password rules, captcha. Each is independent of the OAuth2 wiring.
 *
 * @module
 */

import { Form, useNavigation } from "react-router";

import type { AnyParams, RouteProps } from "@udibo/juniper";

export interface LoginLoaderData {
  /** Sanitized same-origin path to resume after a successful sign-in. */
  returnTo: string;
}

export interface LoginActionData {
  error: string;
  returnTo: string;
}

export default function Login({
  loaderData,
  actionData,
}: RouteProps<AnyParams, LoginLoaderData, LoginActionData>) {
  const navigation = useNavigation();
  const isSubmitting = navigation.state === "submitting";
  const returnTo = actionData?.returnTo ?? loaderData.returnTo;

  return (
    <section>
      <title>Sign in</title>
      <h2>Sign in</h2>
      {actionData?.error && (
        <p role="alert" style={{ color: "crimson" }}>{actionData.error}</p>
      )}
      <Form method="post">
        <input type="hidden" name="return_to" value={returnTo} />
        <p>
          <label>
            Username <input name="username" autoComplete="username" required />
          </label>
        </p>
        <p>
          <label>
            Password{" "}
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </label>
        </p>
        <button type="submit" disabled={isSubmitting}>
          {isSubmitting ? "Signing in…" : "Sign in"}
        </button>
      </Form>
      <p style={{ fontSize: "smaller", color: "#666" }}>
        Demo credentials: <code>admin</code> / <code>password</code> or{" "}
        <code>user</code> / <code>password</code>
      </p>
    </section>
  );
}
