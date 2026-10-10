/**
 * Password-reset request page, built on the package's
 * `RequestPasswordResetForm` — including its neutral, enumeration-safe success
 * state. Posts an email to `/identity/password/reset-request`; the server logs
 * a reset link (`/reset-password?token=…`) to its console and never reveals
 * whether the address has an account.
 *
 * @module
 */

import type { ReactNode } from "react";
import { Link } from "react-router";

import { RequestPasswordResetForm } from "@udibo/oauth2/react/components";
import type { Route } from "./+types/forgot-password";

export function meta(): Route.MetaDescriptors {
  return [{ title: "Reset your password" }];
}

export default function ForgotPassword(): ReactNode {
  return (
    <main>
      <h1>Reset your password</h1>
      <RequestPasswordResetForm
        labels={{
          success:
            "If that address has an account, a reset link is on its way. In " +
            "this starter it's printed to the server console.",
        }}
        onSubmit={async ({ email }) => {
          await fetch("/identity/password/reset-request", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ email }),
          }).catch(() => {});
        }}
      />
      <p>
        <Link to="/login">Back to sign in</Link>
      </p>
    </main>
  );
}
