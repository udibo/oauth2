/**
 * `<OAuth2Provider>` — wraps the app, wires an {@link OAuth2ClientBase} into
 * a React context, and re-renders subscribers when the client emits
 * authentication state changes.
 *
 * @module
 */

import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import type {
  OAuth2ClientBase,
  OAuth2ClientEvent,
  TokenBundle,
  UserInfoClaims,
} from "../client/mod.ts";
import { toOAuth2Error } from "../errors.ts";

import { type LogoutTracker, LogoutTrackerContext } from "./_logout.ts";
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
   * hydration flash. When a later render passes a different value, the
   * provider re-seeds its state only if `isAuthenticated` or `user.sub`
   * changed, so an object built inline in render is fine.
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
const MAX_RENEW_BACKOFF_MS = 300_000;

const RENEW_JITTER = 0.1;

const isBrowser = (): boolean => typeof window !== "undefined";

const EXPIRY_ROUNDING_MS = 1_000;

interface ReportedExpiry {
  expiresIn: number;
  at: number;
}

function reportExpiry(expiresIn: number | null): ReportedExpiry | null {
  return expiresIn == null ? null : { expiresIn, at: Date.now() };
}

function isLaterExpiry(
  next: ReportedExpiry | null,
  prev: ReportedExpiry | null,
): boolean {
  if (next == null || next.expiresIn <= 0) return false;
  if (prev == null) return true;
  return (
    next.at + next.expiresIn * 1000 >
    prev.at + prev.expiresIn * 1000 + EXPIRY_ROUNDING_MS
  );
}

function renewDelayMs(expiresIn: number, staleRenewals: number): number {
  const base =
    staleRenewals === 0
      ? Math.max(MIN_RENEW_MS, (expiresIn - RENEW_SKEW_SECONDS) * 1000)
      : Math.min(MAX_RENEW_BACKOFF_MS, MIN_RENEW_MS * 2 ** staleRenewals);
  return base * (1 - RENEW_JITTER * Math.random());
}

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
 * access token expires (at least 5 seconds apart), re-arming after each
 * renew. A renew that fails, or reports no later expiry than the one before,
 * as a `BffClient` session does (`sessionExpiresIn: 0`) until a proxied call
 * refreshes the token, backs off instead: the wait doubles after each one, up
 * to one renew every 5 minutes. A renew or client event that reports a later
 * expiry returns it to the pre-expiry schedule. Renewal is per tab and
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
  const staleRenewals = useRef(0);
  const reportedExpiry = useRef<ReportedExpiry | null>(null);
  const [logoutsInFlight, setLogoutsInFlight] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const handle = (event: OAuth2ClientEvent) => {
      setState((prev) => reduce(prev, event));
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
    if (!state.isAuthenticated) {
      staleRenewals.current = 0;
      reportedExpiry.current = null;
      return;
    }
    const expiresIn = state.sessionExpiresIn;
    if (expiresIn == null || !Number.isFinite(expiresIn) || expiresIn < 0) {
      return;
    }
    if (reportedExpiry.current?.expiresIn !== expiresIn) {
      const reported = reportExpiry(expiresIn);
      if (isLaterExpiry(reported, reportedExpiry.current)) {
        staleRenewals.current = 0;
      }
      reportedExpiry.current = reported;
    }
    let cancelled = false;
    const delayMs = renewDelayMs(expiresIn, staleRenewals.current);
    const timer = setTimeout(() => {
      client.renewSession().then(
        (session) => {
          if (cancelled) return;
          const reported = reportExpiry(session.sessionExpiresIn);
          staleRenewals.current = isLaterExpiry(
            reported,
            reportedExpiry.current,
          )
            ? 0
            : staleRenewals.current + 1;
          reportedExpiry.current = reported;
          setState((prev) => ({ ...prev, ...session }));
          setRenewCount((count) => count + 1);
        },
        () => {
          if (cancelled) return;
          staleRenewals.current += 1;
          setRenewCount((count) => count + 1);
        },
      );
    }, delayMs);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [client, state.isAuthenticated, state.sessionExpiresIn, renewCount]);

  useEffect(() => {
    if (!isBrowser()) return;
    const onPageShow = (event: PageTransitionEvent) => {
      if (event.persisted) setLogoutsInFlight(0);
    };
    window.addEventListener("pageshow", onPageShow);
    return () => window.removeEventListener("pageshow", onPageShow);
  }, []);

  const value = useMemo<OAuth2ContextValue>(
    () => ({
      client,
      ...state,
    }),
    [client, state],
  );
  const startLogout = useCallback(
    () => setLogoutsInFlight((count) => count + 1),
    [],
  );
  const settleLogout = useCallback(
    () => setLogoutsInFlight((count) => Math.max(0, count - 1)),
    [],
  );
  const logoutTracker = useMemo<LogoutTracker>(
    () => ({
      inFlight: logoutsInFlight > 0,
      start: startLogout,
      settle: settleLogout,
    }),
    [logoutsInFlight, startLogout, settleLogout],
  );

  return (
    <OAuth2Context.Provider value={value}>
      <LogoutTrackerContext.Provider value={logoutTracker}>
        {children}
      </LogoutTrackerContext.Provider>
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
