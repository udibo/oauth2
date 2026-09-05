/**
 * `<OAuth2Provider>` — wraps the app, wires an {@link OAuth2ClientBase} into
 * a React context, and re-renders subscribers when the client emits
 * authentication state changes.
 *
 * @module
 */

import { type ReactNode, useEffect, useMemo, useState } from "react";

import type {
  OAuth2ClientBase,
  OAuth2ClientEvent,
  TokenBundle,
  UserInfoClaims,
} from "../client/mod.ts";
import { toOAuth2Error } from "../errors.ts";

import {
  OAuth2Context,
  type OAuth2ContextValue,
  type OAuth2State,
} from "./context.ts";

/** Props for {@link OAuth2Provider}. */
export interface OAuth2ProviderProps {
  /**
   * The OAuth2 client driving the flows — a `BffClient` or a `DirectClient`.
   * Construct once per app.
   */
  client: OAuth2ClientBase;
  /**
   * Optional pre-resolved auth state (typically from a server-side
   * session probe). Populating this skips the on-mount session probe
   * and renders the authenticated tree on the first paint — no
   * hydration flash. Pass a stable reference (don't construct it inline
   * in render) so the on-mount effect doesn't re-run.
   */
  initialState?: Partial<OAuth2State>;
  /** The app subtree that reads auth state via `useOAuth2()`. */
  children: ReactNode;
}

const DEFAULT_STATE: OAuth2State = {
  isAuthenticated: false,
  isLoading: true,
  user: null,
  error: null,
  sessionExpiresIn: null,
  logoutUrl: null,
};

const RENEW_SKEW_SECONDS = 30;
const MIN_RENEW_MS = 5_000;

/**
 * Fraction of the renew delay given up to jitter, applied one-sided so a renew
 * never lands later than the un-jittered schedule.
 */
const RENEW_JITTER = 0.1;

const isBrowser = (): boolean => typeof window !== "undefined";

/**
 * Delay before renewing a session that expires in `expiresIn` seconds.
 *
 * Floors at {@link MIN_RENEW_MS}, so `0` — which a `DirectClient` reports for
 * an already-expired token a refresh token can still revive — schedules a
 * near-immediate renew rather than nothing at all.
 */
function renewDelayMs(expiresIn: number): number {
  const base = Math.max(MIN_RENEW_MS, (expiresIn - RENEW_SKEW_SECONDS) * 1000);
  return base * (1 - RENEW_JITTER * Math.random());
}

/** Seconds until `tokens` expires, or `null` when the server said nothing. */
function expiresInFrom(tokens: TokenBundle): number | null {
  if (!tokens.accessTokenExpiresAt) return null;
  return Math.max(
    0,
    Math.round((tokens.accessTokenExpiresAt - Date.now()) / 1000),
  );
}

/**
 * Provider — install once near the root of your app. Children read the
 * state via `useOAuth2()`.
 *
 * While authenticated it renews the session on a timer shortly before the
 * access token expires, re-arming after each renew. Renewal is per tab and
 * uncoordinated: a `DirectClient` given a refresh-token storage shared across
 * tabs (e.g. `IndexedDBRefreshTokenStorage`) against a server that
 * rotates refresh tokens can still have two tabs redeem the same token, which
 * reuse detection may answer by ending the session everywhere.
 */
export function OAuth2Provider(props: OAuth2ProviderProps): ReactNode {
  const { client, children, initialState } = props;

  const [state, setState] = useState<OAuth2State>(() => ({
    ...DEFAULT_STATE,
    isLoading: initialState ? false : true,
    ...initialState,
  }));
  const [renewCount, setRenewCount] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const handle = (event: OAuth2ClientEvent) => {
      setState((prev) => reduce(prev, event));
      // The `authenticated` event carries tokens only, so refetch user claims.
      if (event.type === "authenticated") {
        client.getUser().then(
          (user: UserInfoClaims | null) => {
            if (!cancelled) setState((prev) => ({ ...prev, user }));
          },
          () => {},
        );
      }
    };
    const unsubscribe = client.subscribe(handle);
    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [client]);

  // Re-sync when the server-resolved state changes (the only signal in BFF
  // mode, whose callback completes server-side). Keyed on an identity
  // signature, not the often-inline `initialState` reference, to avoid thrash.
  const seededAuthenticated = initialState?.isAuthenticated ?? null;
  const seededUserSub =
    (initialState?.user as { sub?: unknown } | null | undefined)?.sub ?? null;
  useEffect(() => {
    if (!initialState) return;
    setState((prev) => {
      const next: OAuth2State = {
        ...DEFAULT_STATE,
        isLoading: false,
        ...initialState,
      };
      if (
        prev.isAuthenticated === next.isAuthenticated &&
        (prev.user?.sub ?? null) === (next.user?.sub ?? null) &&
        prev.isLoading === next.isLoading
      ) {
        return prev;
      }
      return next;
    });
  }, [client, seededAuthenticated, seededUserSub]);

  useEffect(() => {
    if (initialState) return;
    if (!isBrowser()) return;
    let cancelled = false;
    setState((prev) => ({ ...prev, isLoading: true }));
    client.getSession().then(
      (session) => {
        if (!cancelled) setState({ ...session, isLoading: false, error: null });
      },
      (error: unknown) => {
        if (cancelled) return;
        setState({
          ...DEFAULT_STATE,
          isLoading: false,
          error: toOAuth2Error(error),
        });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [client, initialState]);

  useEffect(() => {
    if (!isBrowser()) return;
    if (!state.isAuthenticated) return;
    const expiresIn = state.sessionExpiresIn;
    if (expiresIn == null || !Number.isFinite(expiresIn) || expiresIn < 0) {
      return;
    }
    let cancelled = false;
    const delayMs = renewDelayMs(expiresIn);
    const timer = setTimeout(() => {
      client.renewSession().then(
        (session) => {
          if (cancelled) return;
          setState((prev) => ({ ...prev, ...session }));
          setRenewCount((count) => count + 1);
        },
        () => {
          if (!cancelled) setRenewCount((count) => count + 1);
        },
      );
    }, delayMs);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [client, state.isAuthenticated, state.sessionExpiresIn, renewCount]);

  const value = useMemo<OAuth2ContextValue>(() => ({
    client,
    ...state,
  }), [client, state]);

  return (
    <OAuth2Context.Provider value={value}>
      {children}
    </OAuth2Context.Provider>
  );
}

function reduce(prev: OAuth2State, event: OAuth2ClientEvent): OAuth2State {
  switch (event.type) {
    case "authenticated":
      return {
        ...prev,
        isAuthenticated: true,
        isLoading: false,
        error: null,
        sessionExpiresIn: expiresInFrom(event.tokens),
      };
    case "logged_out":
      return {
        isAuthenticated: false,
        isLoading: false,
        user: null,
        error: null,
        sessionExpiresIn: null,
        logoutUrl: null,
      };
    case "token_refreshed":
      return {
        ...prev,
        isLoading: false,
        error: null,
        sessionExpiresIn: expiresInFrom(event.tokens),
      };
    case "error":
      return { ...prev, error: toOAuth2Error(event.error) };
  }
}
