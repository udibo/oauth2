/**
 * The surface {@link BffClient} and {@link DirectClient} share: subscribing to
 * authentication events, starting and ending a login, reading the current
 * session, and issuing authenticated requests.
 *
 * Program against {@link OAuth2ClientBase} when the code shouldn't care which
 * transport holds the tokens — the React adapter's `<OAuth2Provider>` does
 * exactly this. Reach for the concrete class when you need transport-specific
 * capability: {@link BffClient.loginContinuation} or
 * {@link DirectClient.getAccessToken}.
 *
 * @module
 */

import {
  EventBus,
  type OAuth2ClientEvent,
  type OAuth2ClientEventListener,
} from "./events.ts";

/** Generic user-info claims returned by the userinfo or `id_token` helpers. */
export type UserInfoClaims = Record<string, unknown>;

/**
 * The headers a wrapped `fetch` should send for `(input, init)`: the ones
 * already on a `Request` input, overlaid with `init.headers`.
 *
 * Both client `fetch` wrappers need this because passing `headers` in an init
 * *replaces* a `Request` input's header list rather than adding to it, which
 * silently drops every header a caller set on the `Request`.
 */
export function mergedHeaders(
  input: RequestInfo | URL,
  init: RequestInit,
): Headers {
  const headers = new Headers(
    input instanceof Request ? input.headers : undefined,
  );
  for (const [name, value] of new Headers(init.headers)) {
    headers.set(name, value);
  }
  return headers;
}

/** Options accepted by every client. */
export interface BaseOptions {
  /**
   * Optional fetch implementation. Defaults to `globalThis.fetch`.
   *
   * Inject a custom `fetch` for:
   *
   * - **Co-located auth servers** — pass `localAuthServerFetch(authServer)`
   *   to dispatch token-endpoint calls directly into an in-process
   *   `AuthorizationServer` without a socket round-trip.
   * - **Tests** — pass the `fetch` from `createMemoryAuthorizationServer()`
   *   (or any other `fetch`-compatible responder) so the client talks to
   *   an in-memory server. Preferred over stubbing `globalThis.fetch`,
   *   which would also intercept unrelated outbound requests the app may
   *   make.
   */
  fetch?: typeof fetch;
}

/**
 * The `login` options every client understands.
 *
 * Named apart from {@link LoginOptions} — which keeps the richer
 * `DirectClient` shape it has always had — so that a consumer importing
 * `LoginOptions` and passing `scope` still compiles. Reach for this one only
 * when writing against {@link OAuth2ClientBase}.
 */
export interface BaseLoginOptions {
  /** Path or URL to return to after a successful login. */
  returnTo?: string;
}

/** Options every client's `logout` accepts. */
export interface LogoutOptions {
  /** Path or URL to return to after logout. */
  returnTo?: string;
}

/** A URL the caller must navigate the browser to. */
export interface LoginRedirect {
  /** Where to send the browser to start (or resume) sign-in. */
  url: string;
}

/**
 * Where to send the browser to finish signing out, if anywhere. `url` is
 * absent when the sign-out completed locally with nothing left to visit.
 */
export interface LogoutRedirect {
  /** The logout / end-session URL, when the flow needs a redirect. */
  url?: string;
}

/**
 * The signed-out {@link SessionState}, frozen because it is returned by
 * reference from every client's `getSession`.
 */
export const SIGNED_OUT: Readonly<SessionState> = Object.freeze({
  isAuthenticated: false,
  user: null,
  sessionExpiresIn: null,
  logoutUrl: null,
});

/** A snapshot of who is signed in, as the client currently understands it. */
export interface SessionState {
  /** True iff a session is active. */
  isAuthenticated: boolean;
  /** Cached user claims, or `null`. */
  user: UserInfoClaims | null;
  /**
   * Seconds until the session's access token expires, or `null` when unknown.
   * A UI can use it to schedule {@link OAuth2ClientBase.renewSession} before
   * expiry.
   */
  sessionExpiresIn: number | null;
  /**
   * A URL that ends the session, or `null` when the client has no such URL to
   * offer (a direct client revokes locally instead — see
   * {@link OAuth2ClientBase.logout}).
   */
  logoutUrl: string | null;
}

/**
 * Base class for the OAuth2 clients. Owns the event bus and the resolved
 * `fetch`; subclasses supply the transport.
 *
 * Not constructible on its own — build a {@link BffClient} (tokens live
 * server-side behind a session cookie) or a {@link DirectClient} (this
 * process holds the tokens) and pass it wherever an `OAuth2ClientBase` is
 * accepted.
 *
 * @example Accept either client
 * ```ts
 * import type { OAuth2ClientBase } from "@udibo/oauth2/client";
 *
 * async function greet(client: OAuth2ClientBase): Promise<string> {
 *   const { isAuthenticated, user } = await client.getSession();
 *   return isAuthenticated ? `hello ${user?.sub}` : "hello stranger";
 * }
 * ```
 */
export abstract class OAuth2ClientBase {
  readonly #events = new EventBus();
  readonly #customFetch?: typeof fetch;

  /**
   * Called by the concrete clients; there is nothing to construct here on its
   * own.
   *
   * @param options Only `fetch` is read at this level — subclasses consume
   * the rest of their own options.
   */
  protected constructor(options: BaseOptions = {}) {
    this.#customFetch = options.fetch;
  }

  /**
   * Subscribes to `authenticated` / `logged_out` / `token_refreshed` /
   * `error` events. Returns a function that removes the listener.
   *
   * @param listener Called for every event, in subscription order. One
   * listener throwing does not stop delivery to the rest.
   */
  subscribe(listener: OAuth2ClientEventListener): () => void {
    return this.#events.subscribe(listener);
  }

  /** Publishes an event to every subscriber. */
  protected emit(event: OAuth2ClientEvent): void {
    this.#events.emit(event);
  }

  /**
   * The configured fetch, resolved at call time so the client picks up a
   * polyfilled global if the runtime installs one after construction.
   */
  protected fetchImpl(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    return (this.#customFetch ?? globalThis.fetch)(input, init);
  }

  /**
   * Builds the URL that starts sign-in. The caller navigates the browser
   * there; nothing is signed in until that round trip completes.
   */
  abstract login(options?: BaseLoginOptions): Promise<LoginRedirect>;

  /**
   * Ends the session and returns the URL to finish signing out, if the flow
   * needs one. Emits `logged_out`.
   */
  abstract logout(options?: LogoutOptions): Promise<LogoutRedirect>;

  /**
   * The claims of the signed-in user, or `null` when nobody is signed in.
   * Use {@link getSession} when you also need expiry or the logout URL.
   */
  abstract getUser(): Promise<UserInfoClaims | null>;

  /**
   * The current {@link SessionState}, as this client can determine it.
   *
   * **Never rejects.** A transport failure, an unreadable response, or claims
   * that cannot be decoded all report a signed-out session and emit an `error`
   * event instead of throwing, so a caller holding an `OAuth2ClientBase` needs
   * no per-subclass `try`/`catch` to ask who is signed in. Rejection is
   * reserved for a programming error, never a remote one.
   */
  abstract getSession(): Promise<SessionState>;

  /**
   * Brings the session up to date — renewing credentials where this client
   * owns them — and returns the resulting {@link SessionState}. Call it
   * shortly before {@link SessionState.sessionExpiresIn} elapses.
   *
   * **Never rejects**, on the same terms as {@link getSession}. Because this
   * runs on a background timer, a transport failure emits no `error` event
   * either: a blip that will simply be retried must not surface as a
   * user-visible error over a session that is still valid. A session that has
   * genuinely ended still emits `logged_out`.
   */
  abstract renewSession(): Promise<SessionState>;

  /**
   * Drop-in `fetch` that authenticates the request the way this client's
   * transport requires, and recovers from a `401` where it can.
   */
  abstract fetch(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response>;
}
