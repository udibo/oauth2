/**
 * Sign-up page, built on the package's `SignUpForm` — including its
 * client-side confirm-password check — so this template does not hand-roll
 * markup the package already ships. It posts to `/identity/signup`; the server
 * creates the account, logs an email-verification link to its console, signs
 * the new user in, and the browser lands on `return_to` (default
 * `/dashboard`).
 *
 * @module
 */

import { Link, useSearchParams } from "react-router";

import { SignUpForm } from "@udibo/oauth2/react/components";

import { submitIdentityForm } from "@/client/identity.ts";

export function SignUp() {
  const [searchParams] = useSearchParams();
  const returnTo = searchParams.get("return_to");

  const loginTo = returnTo
    ? `/login?return_to=${encodeURIComponent(returnTo)}`
    : "/login";

  return (
    <main>
      <h1>Create account</h1>
      <SignUpForm
        showName
        onSubmit={async ({ email, password, firstName, lastName }) => {
          const error = await submitIdentityForm("/identity/signup", {
            name: `${firstName} ${lastName}`.trim(),
            email,
            password,
          }, returnTo);
          if (error) return { error };
        }}
      />
      <p>
        Already have an account? <Link to={loginTo}>Sign in</Link>.
      </p>
    </main>
  );
}
