/**
 * Root layout. Wraps the whole app in `<OAuth2Provider>` so any route can
 * call `useOAuth2()` / `<RequireAuth>`.
 *
 * The provider is given the same-origin BFF client (`browserClient`). With
 * no `initialState` it probes `GET /auth/session` on mount to learn who is
 * signed in — simple, with a brief unauthenticated flash on first paint.
 * To eliminate the flash, resolve the session in a server loader and pass
 * it as `initialState` (the Udibo dashboard does this); the README has the
 * recipe.
 *
 * @module
 */

import type { ReactNode } from "react";
import { Outlet } from "react-router";
import type { ErrorBoundaryProps } from "@udibo/juniper";
import { OAuth2Provider } from "@udibo/oauth2/react";

import { browserClient } from "@/oauth2/browser-client.ts";

function Layout({ children }: { children: ReactNode }) {
  return (
    <main style={{ fontFamily: "system-ui, sans-serif", maxWidth: "640px" }}>
      <meta charSet="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1.0" />
      <title>OAuth2 + Juniper (own auth)</title>
      <h1>OAuth2 + Juniper — own auth</h1>
      {children}
    </main>
  );
}

export default function Main() {
  return (
    <OAuth2Provider client={browserClient}>
      <Layout>
        <Outlet />
      </Layout>
    </OAuth2Provider>
  );
}

export function ErrorBoundary({ error }: ErrorBoundaryProps) {
  const name = error instanceof Error ? error.name : "Error";
  const message = error instanceof Error
    ? error.message
    : "An unexpected error occurred.";
  return (
    <Layout>
      <h2>{name}</h2>
      <p>{message}</p>
    </Layout>
  );
}
