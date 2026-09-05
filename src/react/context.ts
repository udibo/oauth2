/**
 * React context wiring for the OAuth2 client.
 *
 * Internal — consumers should reach for {@link useOAuth2} (the hook),
 * {@link OAuth2Provider}, {@link RequireAuth}, and {@link OAuth2Callback}
 * rather than the context object directly.
 *
 * @module
 */

import { type Context, createContext } from "react";

import type {
  OAuth2ClientBase,
  OAuth2Error,
  UserInfoClaims,
} from "../client/mod.ts";

/** Shape exposed by `useOAuth2()`. */
export interface OAuth2State {
  /** Whether a user is currently authenticated. */
  isAuthenticated: boolean;
  /**
   * `true` during the initial session probe and during a token refresh
   * with no currently valid access token. Settles to `false` once
   * authentication state is known.
   */
  isLoading: boolean;
  /**
   * Current user claims, or `null` when unauthenticated. From
   * `GET /auth/session` behind a `BffClient`; the decoded `id_token` claims
   * (or the `userinfo_endpoint` body) behind a `DirectClient`.
   */
  user: UserInfoClaims | null;
  /** Last error surfaced by the client, or `null`. */
  error: OAuth2Error | null;
  /**
   * Seconds until the session's access token expires, or `null` when unknown.
   * The provider calls `client.renewSession()` shortly before this elapses.
   */
  sessionExpiresIn: number | null;
  /**
   * A URL that ends the session, or `null` when the client has none to offer.
   * Lets a UI render a sign-out link without hardcoding the path.
   */
  logoutUrl: string | null;
}

/** Internal context value shared by the provider and consumers. */
export interface OAuth2ContextValue extends OAuth2State {
  /** The underlying client — a `BffClient` or a `DirectClient`. */
  client: OAuth2ClientBase;
}

/**
 * Internal context — providers wire up the value, consumers read it
 * through `useOAuth2()`. Default `null` so `useOAuth2()` can throw a
 * clear error when called outside any provider.
 */
export const OAuth2Context: Context<OAuth2ContextValue | null> = createContext<
  OAuth2ContextValue | null
>(null);
