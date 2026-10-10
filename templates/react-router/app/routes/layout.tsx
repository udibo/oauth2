/**
 * Layout route: header with navigation and the signed-in state, rendered
 * around every page via `<Outlet>`.
 *
 * @module
 */

import type { ReactNode } from "react";
import { Link, Outlet } from "react-router";

import { useOAuth2 } from "@udibo/oauth2/react";

function AuthStatus(): ReactNode {
  const { isAuthenticated, isLoading, user, logout } = useOAuth2();
  if (isLoading) return null;
  if (!isAuthenticated) {
    return (
      <span className="flex gap-3">
        <Link to="/login">Sign in</Link>
        <Link to="/signup">Create account</Link>
      </span>
    );
  }
  return (
    <span className="flex items-baseline gap-3">
      <span>{String(user?.name ?? user?.email ?? "")}</span>
      <button type="button" onClick={() => logout({ returnTo: "/" })}>
        Sign out
      </button>
    </span>
  );
}

export default function Layout(): ReactNode {
  return (
    <div className="mx-auto my-8 max-w-xl px-4">
      <header className="flex items-baseline justify-between gap-4">
        <nav className="flex gap-3">
          <Link to="/">
            <strong>My App</strong>
          </Link>
          <Link to="/dashboard">Dashboard</Link>
        </nav>
        <AuthStatus />
      </header>
      <hr className="my-4" />
      <Outlet />
    </div>
  );
}
