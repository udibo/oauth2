/**
 * Root layout: header with navigation and the signed-in state, rendered
 * around every route via `<Outlet>`.
 *
 * @module
 */

import { Link, Outlet } from "react-router";

import { useOAuth2 } from "@udibo/oauth2/react";

function AuthStatus() {
  const { isAuthenticated, isLoading, user, logout } = useOAuth2();
  if (isLoading) return null;
  if (!isAuthenticated) {
    return (
      <span style={{ display: "flex", gap: "0.75rem" }}>
        <Link to="/login">Sign in</Link>
        <Link to="/signup">Create account</Link>
      </span>
    );
  }
  return (
    <span style={{ display: "flex", gap: "0.75rem", alignItems: "baseline" }}>
      <span>{String(user?.name ?? user?.email ?? "")}</span>
      <button
        type="button"
        onClick={() =>
          logout({ returnTo: "/" })}
      >
        Sign out
      </button>
    </span>
  );
}

export function Layout() {
  return (
    <div
      style={{
        fontFamily: "system-ui, sans-serif",
        maxWidth: "40rem",
        margin: "2rem auto",
        padding: "0 1rem",
      }}
    >
      <header
        style={{
          display: "flex",
          gap: "1rem",
          alignItems: "baseline",
          justifyContent: "space-between",
        }}
      >
        <nav style={{ display: "flex", gap: "0.75rem" }}>
          <Link to="/">
            <strong>My App</strong>
          </Link>
          <Link to="/dashboard">Dashboard</Link>
        </nav>
        <AuthStatus />
      </header>
      <hr />
      <Outlet />
    </div>
  );
}
