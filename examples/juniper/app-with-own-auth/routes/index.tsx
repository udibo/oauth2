/**
 * Home page — the React SPA. Demonstrates the `@udibo/oauth2/react`
 * adapter against the BFF:
 *
 *   - `useOAuth2()` for `{ isAuthenticated, isLoading, user, login, logout }` —
 *     the `isAuthenticated` check gates the protected section so this landing
 *     page stays viewable when signed out.
 *   - `<RequireAuth>` wrapping that section as a belt-and-suspenders demo. It's
 *     the tool for a *standalone* protected route — there it auto-calls
 *     `login()` and redirects to the IDP when signed out, which is why it isn't
 *     the sole gate on this public page.
 *   - Calling the scope-protected API with the session cookie
 *     (`credentials: "include"`) to show how a token's scope governs
 *     access — the regular `user` gets 403 from `/api/admin`.
 *
 * @module
 */

import { useState } from "react";
import { RequireAuth, useOAuth2 } from "@udibo/oauth2/react";

interface CallResult {
  status: number;
  body: string;
}

function ApiButton({ path }: { path: string }) {
  const [result, setResult] = useState<CallResult | null>(null);
  const call = async () => {
    const res = await fetch(path, { credentials: "include" });
    setResult({ status: res.status, body: await res.text() });
  };
  return (
    <div style={{ margin: "0.5rem 0" }}>
      <button type="button" onClick={call}>
        GET {path}
      </button>
      {result && (
        <pre
          style={{ background: "#f4f4f4", padding: "0.5rem", overflow: "auto" }}
        >
          {result.status} {result.body}
        </pre>
      )}
    </div>
  );
}

function Protected() {
  return (
    <section>
      <h3>Protected API</h3>
      <p>
        Sign in as <code>admin</code> to call all three; as <code>user</code>
        {" "}
        the <code>/api/admin</code> call returns 403 (the token lacks the{" "}
        <code>admin</code> scope).
      </p>
      <ApiButton path="/api/me" />
      <ApiButton path="/api/write" />
      <ApiButton path="/api/admin" />
    </section>
  );
}

export default function Home() {
  const { isAuthenticated, isLoading, user, login, logout } = useOAuth2();

  if (isLoading) return <p>Loading…</p>;

  return (
    <>
      <meta name="description" content="OAuth2 + Juniper BFF example" />
      {isAuthenticated
        ? (
          <>
            <p>
              Signed in as{" "}
              <strong>
                {String(user?.name ?? user?.username ?? user?.sub ?? "")}
              </strong>.{" "}
              <button type="button" onClick={() => logout()}>Sign out</button>
            </p>
            <RequireAuth fallback={<p>Redirecting to sign in…</p>}>
              <Protected />
            </RequireAuth>
          </>
        )
        : (
          <>
            <p>You are not signed in.</p>
            <button type="button" onClick={() => login()}>Sign in</button>
          </>
        )}
    </>
  );
}
