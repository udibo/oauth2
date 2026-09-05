/**
 * Password-reset landing page — the target of the link the server logs on a
 * reset request. Built on the package's `ResetPasswordForm`, which carries the
 * token through and blocks a mismatched confirmation client-side. Consumes the
 * single-use token via `/identity/password/reset` and reports the outcome.
 *
 * @module
 */

import { useState } from "react";
import { Link, useSearchParams } from "react-router";

import { ResetPasswordForm } from "@udibo/oauth2/react/components";

const ERRORS: Record<string, string> = {
  invalid_token: "That link is invalid or has already been used.",
  token_expired: "That link has expired. Request a new one.",
  weak_password: "Password must be at least 8 characters.",
};

export function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");
  const [done, setDone] = useState(false);

  if (!token) {
    return (
      <main>
        <h1>Reset password</h1>
        <p>This link is missing its token. Request a new one.</p>
        <p>
          <Link to="/forgot-password">Request a reset link</Link>
        </p>
      </main>
    );
  }

  if (done) {
    return (
      <main>
        <h1>Password updated</h1>
        <p>
          Your password has been changed. <Link to="/login">Sign in</Link>{" "}
          with your new password.
        </p>
      </main>
    );
  }

  return (
    <main>
      <h1>Choose a new password</h1>
      <ResetPasswordForm
        token={token}
        onSubmit={async (values) => {
          const response = await fetch("/identity/password/reset", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              token: values.token,
              password: values.password,
            }),
          }).catch(() => null);
          if (response?.ok) return;
          const data = await response?.json().catch(() => ({})) as {
            error?: string;
          };
          return {
            error: ERRORS[data?.error ?? ""] ??
              "Something went wrong. Try again.",
          };
        }}
        onSuccess={() => setDone(true)}
      />
    </main>
  );
}
