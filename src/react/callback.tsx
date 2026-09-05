// deno-lint-ignore-file no-window -- browser-only; `window` used only after isBrowser() guards

/**
 * `<OAuth2Callback>` — mount on the SPA's callback route when the app runs a
 * `DirectClient`. Calls `client.handleAuthorizationCallback` with the current
 * URL, then navigates to the captured `returnTo`.
 *
 * Not for a `BffClient` app — the BFF owns `/auth/callback` there, and this
 * component renders its `fallback` with a clear error rather than pretend
 * otherwise.
 *
 * Idempotent against React 18 strict-mode double-mounts because the
 * client itself dedupes by `code` — the second invocation returns the
 * first call's promise.
 *
 * @module
 */

import { type ReactNode, useEffect, useRef, useState } from "react";

import { DirectClient, type OAuth2Error } from "../client/mod.ts";
import { ServerError, toOAuth2Error } from "../errors.ts";
import { useOAuth2 } from "./use-oauth2.ts";

/** Props for {@link OAuth2Callback}. */
export interface OAuth2CallbackProps {
  /**
   * Optional navigation hook. Receives the captured `returnTo` (or
   * `"/"` if the original request didn't carry one). Use this to
   * delegate to your router (`react-router`, `tanstack-router`,
   * `wouter`, …). Defaults to
   * `history.replaceState(null, "", returnTo)` so the auth params drop
   * out of the URL bar without a full page navigation.
   */
  onNavigate?: (returnTo: string) => void;
  /**
   * Renders during the in-flight code exchange. Defaults to `null`.
   */
  pending?: ReactNode;
  /**
   * Renders if the callback fails. Defaults to a plain `<pre>` with the
   * message.
   *
   * The error is always a real {@link OAuth2Error}, so `extensions` is safe to
   * read: a failure the authorization server did not describe — a bookmarked
   * callback route with no `code`, an undecodable `id_token` — arrives wrapped
   * as `server_error` with the original error as its `cause`.
   */
  fallback?: (error: OAuth2Error) => ReactNode;
}

const isBrowser = (): boolean => typeof window !== "undefined";

const defaultNavigate = (returnTo: string): void => {
  if (!isBrowser()) return;
  window.history.replaceState(null, "", returnTo);
};

const defaultFallback = (error: OAuth2Error): ReactNode => (
  <pre style={{ color: "red" }}>{error.message}</pre>
);

/**
 * Mount on the callback route. Exchanges the code, then navigates to
 * `returnTo`.
 *
 * @param props Optional navigation hook plus pending / error renderers.
 * @returns The pending node while the exchange is in flight, the fallback on
 * failure, and nothing once it has navigated.
 */
export function OAuth2Callback(props: OAuth2CallbackProps): ReactNode {
  const {
    onNavigate = defaultNavigate,
    pending = null,
    fallback = defaultFallback,
  } = props;
  const { client } = useOAuth2();
  const [error, setError] = useState<OAuth2Error | null>(null);

  // Ref so the exchange effect depends only on `client`; a non-memoized
  // `onNavigate` must not re-run it after `code` is stripped from the URL.
  const onNavigateRef = useRef(onNavigate);
  onNavigateRef.current = onNavigate;

  useEffect(() => {
    if (!isBrowser()) return;
    if (!(client instanceof DirectClient)) {
      setError(
        new ServerError(
          "<OAuth2Callback> needs the provider's client to be a " +
            `DirectClient, but it is a ${client.constructor.name}. Behind a ` +
            "BffClient the BFF owns the callback route.",
        ),
      );
      return;
    }
    let cancelled = false;
    client.handleAuthorizationCallback(window.location.href).then(
      (result) => {
        if (cancelled) return;
        onNavigateRef.current(result.returnTo ?? "/");
      },
      (err: unknown) => {
        if (cancelled) return;
        setError(toOAuth2Error(err));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [client]);

  if (error) return fallback(error);
  return pending;
}
