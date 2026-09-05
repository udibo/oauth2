// deno-lint-ignore-file no-window -- `login`/`logout` touch `window` only after an isBrowser() guard

/**
 * `useOAuth2()` — the primary React hook for consuming OAuth2 state and
 * driving auth actions, plus the two hooks that narrow the context's client
 * to a concrete transport.
 *
 * @module
 */

import { useCallback, useContext } from "react";

import {
  type BaseLoginOptions,
  BffClient,
  DirectClient,
  type LogoutOptions,
  type OAuth2ClientBase,
  type OAuth2Error,
  type UserInfoClaims,
} from "../client/mod.ts";

import { OAuth2Context, type OAuth2ContextValue } from "./context.ts";

/** Return value of {@link useOAuth2}. */
export interface UseOAuth2Result {
  /** True iff a user is authenticated. */
  isAuthenticated: boolean;
  /** True during the initial probe / a refresh in progress. */
  isLoading: boolean;
  /** Current user claims, or `null`. */
  user: UserInfoClaims | null;
  /** Last error surfaced by the client, or `null`. */
  error: OAuth2Error | null;
  /**
   * Seconds until the session's access token expires, or `null` when unknown.
   * The provider renews shortly before this elapses.
   */
  sessionExpiresIn: number | null;
  /** A URL that ends the session, or `null` when the client offers none. */
  logoutUrl: string | null;
  /**
   * Start a login. Calls `client.login(opts)` and, in the browser, navigates
   * to the returned URL (the BFF login endpoint, or the authorization
   * endpoint). Returns the `{ url }` so non-browser callers (SSR) can
   * navigate themselves.
   *
   * Takes only what both clients understand. For a `DirectClient`'s per-call
   * `scope` / `prompt` / `extraParams`, go through
   * {@link useDirectClient}`().login(...)` — those options have no meaning to
   * a BFF, which builds its own authorize request server-side.
   */
  login(opts?: BaseLoginOptions): Promise<{ url?: string }>;
  /**
   * Start a logout. Calls `client.logout(opts)` and, in the browser,
   * navigates to the returned URL if the flow needs a redirect (the BFF
   * logout endpoint, or the IDP end-session URL). Returns `{ url }` for
   * SSR callers.
   */
  logout(opts?: LogoutOptions): Promise<{ url?: string }>;
  /** Bound `client.fetch` — the request-with-auth helper. */
  fetch: typeof fetch;
  /**
   * The underlying client. Narrow it with {@link useBffClient} or
   * {@link useDirectClient} to reach transport-specific methods.
   */
  client: OAuth2ClientBase;
}

function useOAuth2Context(): OAuth2ContextValue {
  const context = useContext(OAuth2Context);
  if (!context) {
    throw new Error(
      "useOAuth2 must be used inside an <OAuth2Provider>. Did you " +
        "forget to wrap your app?",
    );
  }
  return context;
}

/**
 * Reads the OAuth2 context, returning the current state and bound convenience
 * methods. Works with either client, so components written against it don't
 * care whether a BFF or this process holds the tokens.
 *
 * @returns Auth state plus `login` / `logout` / `fetch` and the raw client.
 * @throws {Error} when called outside an `<OAuth2Provider>`.
 *
 * @example
 * ```tsx
 * import { useOAuth2 } from "@udibo/oauth2/react";
 *
 * function Header() {
 *   const { isAuthenticated, user, login, logout } = useOAuth2();
 *   return isAuthenticated
 *     ? <button onClick={() => logout()}>Sign out {String(user?.sub)}</button>
 *     : <button onClick={() => login()}>Sign in</button>;
 * }
 * ```
 */
export function useOAuth2(): UseOAuth2Result {
  const context = useOAuth2Context();
  const { client } = context;

  const login = useCallback(
    async (opts?: BaseLoginOptions): Promise<{ url?: string }> => {
      const result = await client.login(opts);
      if (result.url && typeof window !== "undefined") {
        window.location.assign(result.url);
      }
      return result;
    },
    [client],
  );
  const logout = useCallback(
    async (opts?: LogoutOptions): Promise<{ url?: string }> => {
      const result = await client.logout(opts);
      if (result.url && typeof window !== "undefined") {
        window.location.assign(result.url);
      }
      return result;
    },
    [client],
  );
  const boundFetch = useCallback<typeof fetch>(
    (input, init) => client.fetch(input, init),
    [client],
  );

  return {
    isAuthenticated: context.isAuthenticated,
    isLoading: context.isLoading,
    user: context.user,
    error: context.error,
    sessionExpiresIn: context.sessionExpiresIn,
    logoutUrl: context.logoutUrl,
    login,
    logout,
    fetch: boundFetch,
    client,
  };
}

/**
 * The context's client, narrowed to a `BffClient`. Use it for the BFF-only
 * surface — chiefly `loginContinuation`, for a "Sign in" link from your own
 * create-account or forgot-password page.
 *
 * @returns The provider's `BffClient`.
 * @throws {Error} when called outside an `<OAuth2Provider>`, or when the
 * provider was given a `DirectClient` — the BFF routes it targets don't exist
 * in that deployment.
 *
 * @example
 * ```tsx
 * import { useBffClient } from "@udibo/oauth2/react";
 *
 * function SignInLink({ returnTo }: { returnTo: string }) {
 *   const client = useBffClient();
 *   return <a href={client.loginContinuation(returnTo)}>Sign in</a>;
 * }
 * ```
 */
export function useBffClient(): BffClient {
  const { client } = useOAuth2Context();
  if (!(client instanceof BffClient)) {
    throw new Error(
      "useBffClient() requires the provider's client to be a BffClient; " +
        "this app is wired with a DirectClient.",
    );
  }
  return client;
}

/**
 * The context's client, narrowed to a `DirectClient`. Use it for the surface
 * that only exists when this process holds the tokens — `getAccessToken`,
 * `handleAuthorizationCallback`, `refresh`, `introspect`, `revoke`.
 *
 * @returns The provider's `DirectClient`.
 * @throws {Error} when called outside an `<OAuth2Provider>`, or when the
 * provider was given a `BffClient` — the browser never sees a token in that
 * deployment, so there is none to hand back.
 *
 * @example
 * ```tsx
 * import { useDirectClient } from "@udibo/oauth2/react";
 *
 * function useBearer() {
 *   const client = useDirectClient();
 *   return () => client.getAccessToken();
 * }
 * ```
 */
export function useDirectClient(): DirectClient {
  const { client } = useOAuth2Context();
  if (!(client instanceof DirectClient)) {
    throw new Error(
      "useDirectClient() requires the provider's client to be a " +
        "DirectClient; this app is wired with a BffClient, where the " +
        "browser never sees an access token. Use `fetch` instead.",
    );
  }
  return client;
}
