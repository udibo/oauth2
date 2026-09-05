/**
 * Protected page. `<RequireAuth>` redirects signed-out visitors into the BFF
 * login flow (which lands on `/login`) and back here afterwards. The content
 * calls the protected API through `useOAuth2().fetch`, which sends the session
 * cookie and CSRF header — the browser never handles a token.
 *
 * @module
 */

import { useEffect, useState } from "react";

import { RequireAuth, useOAuth2 } from "@udibo/oauth2/react";

interface Me {
  sub: string;
  name: string;
  email: string;
  emailVerified: boolean;
}

function DashboardContent() {
  const { user, fetch } = useOAuth2();
  const [me, setMe] = useState<Me | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/me")
      .then((response) => (response.ok ? response.json() : null))
      .then((data: Me | null) => {
        if (!cancelled && data) setMe(data);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [fetch]);

  return (
    <main>
      <h1>Dashboard</h1>
      <p>
        Signed in as{" "}
        <strong>{String(user?.name ?? user?.email ?? user?.sub ?? "")}</strong>.
      </p>
      <h2>GET /api/me</h2>
      {me
        ? <pre>{JSON.stringify(me, null, 2)}</pre>
        : <p>Loading your profile…</p>}
      {me && !me.emailVerified && (
        <p>
          Your email isn't verified yet — the verification link is in the server
          console.
        </p>
      )}
    </main>
  );
}

export function Dashboard() {
  return (
    <RequireAuth fallback={<p>Checking your session…</p>}>
      <DashboardContent />
    </RequireAuth>
  );
}
