/**
 * Sign-in page, built on the package's `SignInForm` so the accessible markup,
 * error summary, and focus handling come from `@udibo/oauth2/react/components`
 * instead of being hand-rolled here. It posts credentials to
 * `/identity/signin`; on success the server opens the sessions and the browser
 * lands back on `return_to` (an in-flight authorize URL when the user was
 * bounced here from a protected page, `/dashboard` otherwise).
 *
 * @module
 */

import { Link, useSearchParams } from "react-router";

import { SignInForm } from "@udibo/oauth2/react/components";

import { hasDemoAccount } from "@/client/env.ts";
import { submitIdentityForm } from "@/client/identity.ts";

export function Login() {
  const [searchParams] = useSearchParams();
  const returnTo = searchParams.get("return_to");

  const signupTo = returnTo
    ? `/signup?return_to=${encodeURIComponent(returnTo)}`
    : "/signup";

  return (
    <main>
      <h1>Sign in</h1>
      <SignInForm
        labels={{ identifier: "Email" }}
        forgotPasswordHref="/forgot-password"
        onSubmit={async ({ identifier, password }) => {
          const error = await submitIdentityForm("/identity/signin", {
            identifier,
            password,
          }, returnTo);
          if (error) return { error };
        }}
      />
      <p>
        No account? <Link to={signupTo}>Create one</Link>.
      </p>
      {hasDemoAccount() && (
        <p>
          Demo account: <code>demo@example.com</code> / <code>password</code>
        </p>
      )}
    </main>
  );
}
