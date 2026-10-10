/**
 * Protected page. The loader sends a signed-out request straight into the BFF
 * login flow (which lands on `/login`) and back here afterwards, so the check
 * happens on the server, before any HTML. The content calls the protected API
 * through `useOAuth2().fetch`, which sends the session cookie and CSRF header —
 * the browser never handles a token.
 *
 * @module
 */

import { type ReactNode, useEffect, useState } from "react";
import { redirectDocument } from "react-router";

import { useOAuth2 } from "@udibo/oauth2/react";

import { requestContext } from "../context.ts";
import type { Route } from "./+types/dashboard";

interface Me {
  sub: string;
  name: string;
  email: string;
  emailVerified: boolean;
}

export function meta(): Route.MetaDescriptors {
  return [{ title: "Dashboard" }];
}

export function loader({ context, request }: Route.LoaderArgs): null {
  if (context.get(requestContext).session.isAuthenticated) return null;
  const { pathname, search } = new URL(request.url);
  throw redirectDocument(
    `/auth/login?return_to=${encodeURIComponent(pathname + search)}`,
  );
}

export default function Dashboard(): ReactNode {
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
      {me ? (
        <pre>{JSON.stringify(me, null, 2)}</pre>
      ) : (
        <p>Loading your profile…</p>
      )}
      {me && !me.emailVerified && (
        <p>
          Your email isn't verified yet — the verification link is in the server
          console.
        </p>
      )}
    </main>
  );
}
