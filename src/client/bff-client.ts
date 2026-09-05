/**
 * Browser client for an app fronted by a Backend-for-Frontend.
 *
 * The BFF holds the tokens; this client only ever talks to the BFF's
 * `/auth/*` routes with the session cookie attached, so no token reaches the
 * browser. Pair it with the `@udibo/oauth2/hono/bff` adapter, or any BFF
 * serving the same four routes.
 *
 * @module
 */

import { loginContinuation as computeLoginContinuation } from "../utils/url.ts";

import { receiveJson, sendGuarded } from "./_http.ts";

import {
  type BaseLoginOptions,
  type BaseOptions,
  type LoginRedirect,
  type LogoutOptions,
  type LogoutRedirect,
  mergedHeaders,
  OAuth2ClientBase,
  type SessionState,
  SIGNED_OUT,
  type UserInfoClaims,
} from "./base.ts";

/** Paths (or absolute URLs) for the BFF session endpoints. */
export interface BffEndpoints {
  /** Base URL the BFF is mounted under (e.g. `""` for same-origin). */
  baseUrl?: string;
  /** Path to the BFF's login route. Defaults to `/auth/login`. */
  login?: string;
  /**
   * Path to the BFF's logout route. Defaults to `/auth/logout`.
   *
   * {@link BffClient.logout} only builds this URL; the caller navigates to it,
   * so sign-out travels the BFF's `GET` route and is guarded by its
   * same-origin check rather than the `x-csrf` header. Post to this path
   * yourself, with that header, for the stronger check.
   */
  logout?: string;
  /** Path to `GET /auth/session`. Defaults to `/auth/session`. */
  session?: string;
}

/** Options accepted by {@link BffClient}. */
export interface BffClientOptions extends BaseOptions {
  /** Override the default `/auth/*` BFF session endpoint paths. */
  endpoints?: BffEndpoints;
  /**
   * Path (or URL) of the authorization endpoint the BFF redirects to (e.g.
   * `"/api/oauth2/authorize"`). Lets {@link BffClient.loginContinuation}
   * recognize an in-flight authorize URL to resume. Optional — without it,
   * `loginContinuation` always starts a fresh login.
   */
  authorizePath?: string;
  /**
   * Custom header sent on credentialed BFF requests — the `GET /auth/session`
   * probe and the wrapped {@link BffClient.fetch} — so the BFF's CSRF guard
   * accepts them. The header makes the request "non-simple", forcing a CORS
   * preflight a cross-site page cannot pass.
   *
   * Defaults to `{ name: "x-csrf", value: "1" }`, matching `HonoBff`'s
   * default. Set `false` to send no header (only if the BFF disables its
   * CSRF check).
   */
  csrfHeader?: { name?: string; value?: string } | false;
}

interface ResolvedBffEndpoints {
  baseUrl: string;
  login: string;
  logout: string;
  session: string;
}

/**
 * OAuth2 client for a browser app whose sessions live in a
 * Backend-for-Frontend.
 *
 * Every method here is a same-origin call to the BFF with `credentials:
 * "include"`, never a call to the authorization server. There is no token
 * storage, no PKCE, and no access token to read — if you need one, the app
 * wants a {@link DirectClient} instead.
 *
 * @example Same-origin BFF
 * ```ts
 * import { BffClient } from "@udibo/oauth2/client";
 *
 * const client = new BffClient();
 *
 * const session = await client.getSession();
 * if (!session.isAuthenticated) {
 *   const { url } = await client.login({ returnTo: location.pathname });
 *   location.assign(url);
 * }
 *
 * const res = await client.fetch("/api/items");
 * ```
 *
 * @example BFF mounted elsewhere, with a custom CSRF header
 * ```ts
 * import { BffClient } from "@udibo/oauth2/client";
 *
 * const client = new BffClient({
 *   endpoints: { baseUrl: "https://api.example.com", login: "/session/start" },
 *   csrfHeader: { name: "x-requested-with", value: "spa" },
 * });
 * ```
 */
export class BffClient extends OAuth2ClientBase {
  readonly #endpoints: ResolvedBffEndpoints;
  readonly #authorizePath?: string;
  readonly #csrfHeader: Record<string, string>;

  /**
   * Builds a client against the BFF's `/auth/*` routes.
   *
   * @param options Endpoint overrides, the CSRF header to send, and the
   * `fetch` to use. Every field is optional; the defaults match `HonoBff`
   * mounted at `/auth` on the same origin.
   */
  constructor(options: BffClientOptions = {}) {
    super(options);
    const endpoints = options.endpoints ?? {};
    this.#endpoints = {
      baseUrl: endpoints.baseUrl ?? "",
      login: endpoints.login ?? "/auth/login",
      logout: endpoints.logout ?? "/auth/logout",
      session: endpoints.session ?? "/auth/session",
    };
    this.#authorizePath = options.authorizePath;
    this.#csrfHeader = options.csrfHeader === false ? {} : {
      [options.csrfHeader?.name ?? "x-csrf"]: options.csrfHeader?.value ?? "1",
    };
  }

  #url(path: string): string {
    const origin = typeof location !== "undefined"
      ? location.origin
      : "http://localhost";
    return new URL(`${this.#endpoints.baseUrl}${path}`, origin).toString();
  }

  /**
   * Builds the BFF login URL. Navigate the browser there; the BFF runs the
   * authorization-code flow and drops the session cookie before redirecting
   * back to `returnTo`.
   *
   * @param options `returnTo` is passed through as the `return_to` query
   * parameter. The BFF is responsible for validating it against open
   * redirects.
   * @returns The URL to navigate to.
   *
   * @example
   * ```ts
   * import { BffClient } from "@udibo/oauth2/client";
   *
   * const client = new BffClient();
   * const { url } = await client.login({ returnTo: "/dashboard" });
   * location.assign(url);
   * ```
   */
  login(options: BaseLoginOptions = {}): Promise<LoginRedirect> {
    const url = new URL(this.#url(this.#endpoints.login));
    if (options.returnTo) url.searchParams.set("return_to", options.returnTo);
    return Promise.resolve({ url: url.toString() });
  }

  /**
   * Builds the BFF logout URL and emits `logged_out` so the UI can render
   * signed-out immediately. Navigate the browser to the returned URL; the BFF
   * destroys the session and clears the cookie.
   *
   * @param options `returnTo` is passed through as the `return_to` query
   * parameter.
   * @returns The URL to navigate to.
   *
   * @example
   * ```ts
   * import { BffClient } from "@udibo/oauth2/client";
   *
   * const client = new BffClient();
   * const { url } = await client.logout({ returnTo: "/" });
   * location.assign(url!);
   * ```
   */
  logout(options: LogoutOptions = {}): Promise<LogoutRedirect> {
    const url = new URL(this.#url(this.#endpoints.logout));
    if (options.returnTo) url.searchParams.set("return_to", options.returnTo);
    this.emit({ type: "logged_out", reason: "user" });
    return Promise.resolve({ url: url.toString() });
  }

  /**
   * Probes `GET /auth/session` and returns the full {@link SessionState} —
   * `isAuthenticated`, `user`, plus the `sessionExpiresIn` and `logoutUrl` a
   * SPA uses to schedule a re-probe and render a sign-out link.
   *
   * **Never rejects**, per {@link OAuth2ClientBase.getSession}: an
   * unreachable BFF, a non-OK status, and a body that is not a JSON object
   * (an HTML error page from a misrouted path is the common one) all read as
   * signed out. A failure that was not simply "nobody is signed in" — anything
   * other than a `401` — also emits an `error` event so a UI can tell the two
   * apart. The read is bounded and deadlined like every other call this
   * package makes.
   *
   * Only `isAuthenticated: true` carries `user` / `sessionExpiresIn` /
   * `logoutUrl` through; an anonymous payload always reports them as `null`,
   * whatever the BFF put in the body.
   *
   * @returns The session as the BFF reports it. Tokens are never included.
   *
   * @example
   * ```ts
   * import { BffClient } from "@udibo/oauth2/client";
   *
   * const { isAuthenticated, logoutUrl } = await new BffClient().getSession();
   * ```
   */
  async getSession(): Promise<SessionState> {
    return await this.#probe(false);
  }

  async #probe(quiet: boolean): Promise<SessionState> {
    let body: Record<string, unknown>;
    try {
      const res = await sendGuarded(
        (input, init) => this.fetchImpl(input, init),
        this.#url(this.#endpoints.session),
        {
          credentials: "include",
          headers: { Accept: "application/json", ...this.#csrfHeader },
        },
        "session endpoint",
      );
      if (res.status === 401) {
        await res.body?.cancel();
        return SIGNED_OUT;
      }
      body = await receiveJson(res, "session endpoint");
    } catch (error) {
      if (!quiet) this.emit({ type: "error", error });
      return SIGNED_OUT;
    }
    const session = body as Partial<SessionState>;
    if (!session.isAuthenticated) return SIGNED_OUT;
    return {
      isAuthenticated: true,
      user: session.user ?? null,
      sessionExpiresIn: session.sessionExpiresIn ?? null,
      logoutUrl: session.logoutUrl ?? null,
    };
  }

  /**
   * The signed-in user's claims from the session probe, or `null`.
   *
   * @returns The `user` field of {@link getSession}.
   */
  async getUser(): Promise<UserInfoClaims | null> {
    return (await this.getSession()).user;
  }

  /**
   * Re-probes `GET /auth/session`.
   *
   * The BFF owns credential renewal — its `attachToken` middleware refreshes
   * the access token server-side when a proxied call needs one — so this
   * reports the current state rather than driving a refresh itself. Call it
   * shortly before {@link SessionState.sessionExpiresIn} elapses to keep the
   * UI honest about whether the session is still alive.
   *
   * Emits no `error` event, per {@link OAuth2ClientBase.renewSession}: this
   * runs on a background timer, where a failed probe means "ask again shortly",
   * not "show the user a problem".
   *
   * @returns The refreshed {@link SessionState}.
   */
  renewSession(): Promise<SessionState> {
    return this.#probe(true);
  }

  /**
   * Fetches with the session cookie and the CSRF header attached, so the BFF
   * authenticates the call and its CSRF guard accepts it.
   *
   * A `401` emits `logged_out` with reason `session_expired` and is returned
   * as-is — the BFF, not the browser, decides whether a refresh is possible.
   *
   * @param input Request target, as for `fetch`. A `Request` keeps the headers
   * and body it was built with.
   * @param init Request options. A caller-set CSRF header is left alone, and
   * `init.headers` override same-named headers on a `Request` input.
   * @returns The BFF's response, unmodified.
   *
   * @example
   * ```ts
   * import { BffClient } from "@udibo/oauth2/client";
   *
   * const res = await new BffClient().fetch("/api/items");
   * ```
   */
  async fetch(
    input: RequestInfo | URL,
    init: RequestInit = {},
  ): Promise<Response> {
    const headers = mergedHeaders(input, init);
    for (const [name, value] of Object.entries(this.#csrfHeader)) {
      if (!headers.has(name)) headers.set(name, value);
    }
    const res = await this.fetchImpl(input, {
      ...init,
      credentials: "include",
      headers,
    });
    if (res.status === 401) {
      this.emit({ type: "logged_out", reason: "session_expired" });
    }
    return res;
  }

  /**
   * Builds the URL that (re)starts sign-in toward `returnTo`, for an app whose
   * own login surface (a sign-in form, create-account, forgot-password) hands
   * back to the BFF flow after authenticating a user: resume an in-flight
   * authorize URL, or start a fresh BFF login.
   *
   * Pure and synchronous — safe in render. The mirror of
   * `HonoBff.loginContinuation`, so both sides of the app agree on where
   * "sign in" goes.
   *
   * Recognizing an in-flight authorize URL requires `authorizePath` in the
   * constructor options; without it every `returnTo` starts a fresh login.
   *
   * @param returnTo Where the user was headed. `null` / `undefined` fall back
   * to `/`.
   * @returns The URL to redirect to.
   *
   * @example
   * ```ts
   * import { BffClient } from "@udibo/oauth2/client";
   *
   * const client = new BffClient({ authorizePath: "/api/oauth2/authorize" });
   * const href = client.loginContinuation("/api/oauth2/authorize?client_id=a");
   * ```
   */
  loginContinuation(returnTo: string | null | undefined): string {
    return computeLoginContinuation(returnTo, {
      authorizeEndpoint: this.#authorizePath,
      loginPath: `${this.#endpoints.baseUrl}${this.#endpoints.login}`,
      defaultReturnTo: "/",
    });
  }
}
