/**
 * `<RequireAuth>` — gate a subtree behind authentication. If the user is
 * not authenticated, calls `login({ returnTo })` (the {@link useOAuth2}
 * action, which navigates the browser to the login / authorize URL) with
 * `returnTo` set to the current path, and renders a configurable
 * `fallback` while the redirect is in flight.
 *
 * It starts no login while a `logout()` from {@link useOAuth2} is running or
 * navigating away, so signing out from a protected page ends at the logout
 * destination rather than the login page. A logout that returns no URL (a
 * `DirectClient` whose server has no end-session endpoint) leaves the page
 * signed out, and the gate then starts a login as usual.
 *
 * @module
 */

import { type ReactNode, useContext, useEffect } from "react";

import { LogoutTrackerContext } from "./_logout.ts";
import { useOAuth2 } from "./use-oauth2.ts";

/** Props for {@link RequireAuth}. */
export interface RequireAuthProps {
  /** Children rendered when authenticated. */
  children: ReactNode;
  /**
   * What to render while the redirect is being kicked off / the
   * initial probe is in flight. Defaults to `null` (nothing).
   */
  fallback?: ReactNode;
  /** Optional explicit `returnTo`. Defaults to `window.location.pathname + window.location.search`. */
  returnTo?: string;
}

const isBrowser = (): boolean => typeof window !== "undefined";

/**
 * Render `children` only when authenticated. Otherwise call
 * `login({ returnTo })` once and render `fallback` while the redirect
 * is in flight. While a `useOAuth2().logout()` is running or navigating away,
 * no new login starts; what renders still follows `isLoading` and
 * `isAuthenticated`, so the page shows `fallback` once the logout has signed
 * it out.
 */
export function RequireAuth(props: RequireAuthProps): ReactNode {
  const { children, fallback = null, returnTo } = props;
  const { isAuthenticated, isLoading, login } = useOAuth2();
  const logoutInFlight = useContext(LogoutTrackerContext)?.inFlight ?? false;

  useEffect(() => {
    if (isLoading || isAuthenticated || logoutInFlight) return;
    if (!isBrowser()) return;
    const target =
      returnTo ?? `${window.location.pathname}${window.location.search}`;
    login({ returnTo: target }).catch(() => {});
  }, [isLoading, isAuthenticated, logoutInFlight, login, returnTo]);

  if (isLoading || !isAuthenticated) return fallback;
  return children;
}
