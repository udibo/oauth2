// deno-lint-ignore-file no-window -- browser-only; `window` used only after isBrowser() guards

/**
 * `<RequireAuth>` — gate a subtree behind authentication. If the user is
 * not authenticated, calls `login({ returnTo })` (the {@link useOAuth2}
 * action, which navigates the browser to the login / authorize URL) with
 * `returnTo` set to the current path, and renders a configurable
 * `fallback` while the redirect is in flight.
 *
 * Avoids the `withAuthenticationRequired` re-mount footgun (the HOC
 * isn't created in render; this component just gates its children).
 *
 * @module
 */

import { type ReactNode, useEffect } from "react";

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
 * is in flight.
 */
export function RequireAuth(props: RequireAuthProps): ReactNode {
  const { children, fallback = null, returnTo } = props;
  const { isAuthenticated, isLoading, login } = useOAuth2();

  useEffect(() => {
    if (isLoading || isAuthenticated) return;
    if (!isBrowser()) return;
    const target = returnTo ??
      `${window.location.pathname}${window.location.search}`;
    login({ returnTo: target }).catch(() => {});
  }, [isLoading, isAuthenticated, login, returnTo]);

  if (isLoading || !isAuthenticated) return fallback;
  return children;
}
