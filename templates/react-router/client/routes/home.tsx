/**
 * Public landing page. Viewable signed in or out; replace with your real
 * landing content.
 *
 * @module
 */

import { Link } from "react-router";

import { useOAuth2 } from "@udibo/oauth2/react";

import { hasDemoAccount } from "@/client/env.ts";

export function Home() {
  const { isAuthenticated, isLoading } = useOAuth2();
  return (
    <main>
      <h1>Welcome</h1>
      <p>
        This is a public page. The <Link to="/dashboard">dashboard</Link>{" "}
        is protected — visiting it signed out sends you to the sign-in page and
        back again afterwards.
      </p>
      {!isLoading && !isAuthenticated && (
        hasDemoAccount()
          ? (
            <p>
              Try the seeded demo account: <code>demo@example.com</code> /{" "}
              <code>password</code>, or{" "}
              <Link to="/signup">create an account</Link>.
            </p>
          )
          : (
            <p>
              <Link to="/signup">Create an account</Link> to get started.
            </p>
          )
      )}
    </main>
  );
}
