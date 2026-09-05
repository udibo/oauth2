import type { ReactNode } from "react";
import { Link, Outlet } from "react-router";
import type { ErrorBoundaryProps } from "@udibo/juniper";
import { OAuth2Provider } from "@udibo/oauth2/react";

import { browserClient } from "@/oauth2/browser-client.ts";

function Layout({ children }: { children: ReactNode }) {
  return (
    <main style={{ fontFamily: "system-ui, sans-serif", maxWidth: "640px" }}>
      <meta charSet="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1.0" />
      <title>My App</title>
      <h1>My App</h1>
      <nav style={{ display: "flex", gap: "1rem" }}>
        <Link to="/">Home</Link>
        <Link to="/profile">Profile</Link>
      </nav>
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
