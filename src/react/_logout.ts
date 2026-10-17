/**
 * Not part of the public API. Lets `useOAuth2().logout()` tell
 * `<RequireAuth>` that a sign-out is under way, so the `logged_out` event the
 * client emits before the browser leaves does not start a login over the
 * logout navigation.
 *
 * @module
 */

import { type Context, createContext } from "react";

/** The provider's view of `useOAuth2().logout()` calls. */
export interface LogoutTracker {
  /**
   * True from the start of a logout until it settles without navigating. A
   * logout that navigates away stays in flight until the page is restored
   * from the back-forward cache.
   */
  inFlight: boolean;
  /** Marks a logout as started. Call before `client.logout()`. */
  start(): void;
  /** Marks a started logout as finished without leaving the page. */
  settle(): void;
}

/** Supplied by `<OAuth2Provider>`; `null` under any other provider. */
export const LogoutTrackerContext: Context<LogoutTracker | null> =
  createContext<LogoutTracker | null>(null);
