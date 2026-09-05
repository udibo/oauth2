/**
 * Testing helpers for the `@udibo/oauth2/react` adapter.
 *
 * Three mock clients and a provider:
 *
 * - {@link createMockOAuth2Client} — an `OAuth2ClientBase` with no HTTP,
 *   PKCE, or storage behind it. Use it for a component written against the
 *   shared surface.
 * - {@link createMockBffClient} / {@link createMockDirectClient} — the same
 *   mock behavior on a real `BffClient` / `DirectClient` subclass, so
 *   `useBffClient()`, `useDirectClient()`, and `<OAuth2Callback>` accept them.
 *   Reach for these when the component under test narrows.
 * - {@link MockOAuth2Provider} — drop-in replacement for `<OAuth2Provider>`
 *   that skips the initial session probe and accepts any of the three. Use it
 *   to unit-test components that consume `useOAuth2()` / `<RequireAuth>`
 *   without any network.
 *
 * Every mock emits on the same event bus the real clients use, so a subtree
 * under a real `<OAuth2Provider>` re-renders just as it would in production.
 * {@link MockOAuth2Provider} is not live: it seeds its context once from the
 * client and keeps that snapshot, so a test that needs the state to *change*
 * mid-render should mount a real `<OAuth2Provider>` around the mock client and
 * call `signIn` / `signOut` on it. Configure `sessionExpiresIn` to exercise
 * `<OAuth2Provider>`'s pre-expiry renew timer, and read
 * {@link MockOAuth2Controls.renewCount} to assert it fired.
 *
 * **JSDOM recipes** for component tests in this adapter:
 *
 * - `window.location.assign` — the adapter's `login()` / `logout()` (via
 *   `useOAuth2()` and `<RequireAuth>`) navigate by calling
 *   `window.location.assign(url)`. JSDOM throws on unhandled navigation;
 *   stub it: `stub(window.location, "assign", () => {})` (or the
 *   equivalent for your runner).
 * - `crypto.subtle` — required for PKCE in a real `DirectClient`. The mocks
 *   don't use it, so JSDOM tests of components-with-mock-client are
 *   safe out of the box.
 * - `sessionStorage` — needed by
 *   `SessionStorageAuthRequestStorage`. JSDOM ships one; the mocks
 *   never touch it.
 * - `history.replaceState` — `<OAuth2Callback>`'s default `onNavigate`
 *   uses it. JSDOM ships it.
 *
 * @module
 */

import { type ReactNode, useMemo } from "react";

import {
  type AuthorizationRedirect,
  type BaseLoginOptions,
  BffClient,
  DirectClient,
  type LoginRedirect,
  type LogoutRedirect,
  OAuth2ClientBase,
  type OAuth2ClientEvent,
  type OAuth2Error,
  type SessionState,
  type TokenBundle,
  type UserInfoClaims,
} from "../client/mod.ts";

import { OAuth2Context, type OAuth2State } from "./context.ts";

/** Where a mock client starts. */
export interface MockOAuth2ClientState {
  /** Whether the mock starts signed in. Defaults to `user !== null`. */
  isAuthenticated?: boolean;
  /** The cached user claims the mock starts with. Defaults to `null`. */
  user?: UserInfoClaims | null;
  /** The `logoutUrl` the mock reports while signed in. Defaults to `/auth/logout`. */
  logoutUrl?: string | null;
  /**
   * Seconds the mock reports until expiry. Defaults to `null` (no expiry, so
   * `<OAuth2Provider>` schedules no renew). Set it to arm the renew timer.
   */
  sessionExpiresIn?: number | null;
}

/** The state knobs every mock client exposes, whatever it subclasses. */
export interface MockOAuth2Controls {
  /**
   * The starting state the mock was built with, defaults applied — what
   * {@link MockOAuth2Provider} seeds its context from, so configuring the
   * client is enough. A snapshot taken at construction: later
   * `signIn`/`signOut` calls drive the event bus and do not change it.
   */
  readonly initialState: Pick<OAuth2State, "isAuthenticated" | "user">;
  /** How many times `renewSession()` has been called. */
  readonly renewCount: number;
  /** Pushes the mock into an authenticated state and emits `authenticated`. */
  signIn(user?: UserInfoClaims): void;
  /** Pushes the mock into an unauthenticated state and emits `logged_out`. */
  signOut(): void;
  /** Emits `token_refreshed` with a bundle expiring in `expiresIn` seconds. */
  refreshTokens(expiresIn?: number | null): void;
  /** Surfaces an error through the event bus. */
  setError(error: OAuth2Error | unknown): void;
  /** Replaces the cached user without changing authentication status. */
  setUser(user: UserInfoClaims | null): void;
  /** Replaces the reported seconds-to-expiry. */
  setSessionExpiresIn(seconds: number | null): void;
}

/** The mock behavior each client class delegates to. */
class MockCore {
  readonly initialState: Pick<OAuth2State, "isAuthenticated" | "user">;
  renewCount = 0;

  #user: UserInfoClaims | null;
  #isAuthenticated: boolean;
  #logoutUrl: string | null;
  #sessionExpiresIn: number | null;
  readonly #emit: (event: OAuth2ClientEvent) => void;

  constructor(
    state: MockOAuth2ClientState,
    emit: (event: OAuth2ClientEvent) => void,
  ) {
    this.#user = state.user ?? null;
    this.#isAuthenticated = state.isAuthenticated ?? this.#user !== null;
    this.#logoutUrl = state.logoutUrl ?? "/auth/logout";
    this.#sessionExpiresIn = state.sessionExpiresIn ?? null;
    this.#emit = emit;
    this.initialState = {
      isAuthenticated: this.#isAuthenticated,
      user: this.#user,
    };
  }

  session(): SessionState {
    return {
      isAuthenticated: this.#isAuthenticated,
      user: this.#isAuthenticated ? this.#user : null,
      sessionExpiresIn: this.#isAuthenticated ? this.#sessionExpiresIn : null,
      logoutUrl: this.#isAuthenticated ? this.#logoutUrl : null,
    };
  }

  user(): UserInfoClaims | null {
    return this.#isAuthenticated ? this.#user : null;
  }

  renew(): SessionState {
    this.renewCount++;
    return this.session();
  }

  signIn(user?: UserInfoClaims): void {
    this.#isAuthenticated = true;
    this.#user = user ?? this.#user ?? { sub: "mock-user" };
    this.#emit({ type: "authenticated", tokens: this.#tokens() });
  }

  signOut(): void {
    this.#isAuthenticated = false;
    this.#user = null;
    this.#emit({ type: "logged_out", reason: "user" });
  }

  refreshTokens(expiresIn?: number | null): void {
    if (expiresIn !== undefined) this.#sessionExpiresIn = expiresIn;
    this.#emit({ type: "token_refreshed", tokens: this.#tokens() });
  }

  setError(error: OAuth2Error | unknown): void {
    this.#emit({ type: "error", error });
  }

  setUser(user: UserInfoClaims | null): void {
    this.#user = user;
  }

  setSessionExpiresIn(seconds: number | null): void {
    this.#sessionExpiresIn = seconds;
  }

  #tokens(): TokenBundle {
    return {
      accessToken: "mock-access-token",
      tokenType: "Bearer",
      accessTokenExpiresAt: this.#sessionExpiresIn === null
        ? undefined
        : Date.now() + this.#sessionExpiresIn * 1000,
    };
  }
}

const MOCK_LOGIN_URL = "mock://login";

/**
 * A client that satisfies the shared `OAuth2ClientBase` surface without making
 * a single request.
 *
 * Neither a `BffClient` nor a `DirectClient`, so `useBffClient()` and
 * `useDirectClient()` reject it — that is deliberate, and
 * {@link createMockBffClient} / {@link createMockDirectClient} are what a
 * narrowing component wants.
 */
export class MockOAuth2Client extends OAuth2ClientBase
  implements MockOAuth2Controls {
  readonly #core: MockCore;

  /**
   * Builds a mock client and snapshots its starting state.
   *
   * @param state Where the mock starts. Everything is optional; the default
   * is a signed-out client.
   */
  constructor(state: MockOAuth2ClientState = {}) {
    super();
    this.#core = new MockCore(state, (event) => this.emit(event));
  }

  /** The starting state, defaults applied. */
  get initialState(): Pick<OAuth2State, "isAuthenticated" | "user"> {
    return this.#core.initialState;
  }

  /** How many times `renewSession()` has been called. */
  get renewCount(): number {
    return this.#core.renewCount;
  }

  /** Resolves a fixed `mock://login` URL without touching any network. */
  login(_options?: BaseLoginOptions): Promise<LoginRedirect> {
    return Promise.resolve({ url: MOCK_LOGIN_URL });
  }

  /** Drops to signed out, emits `logged_out`, and returns no redirect URL. */
  logout(): Promise<LogoutRedirect> {
    this.signOut();
    return Promise.resolve({});
  }

  /** The mock's current user, or `null` while signed out. */
  getUser(): Promise<UserInfoClaims | null> {
    return Promise.resolve(this.#core.user());
  }

  /** The mock's current state. */
  getSession(): Promise<SessionState> {
    return Promise.resolve(this.#core.session());
  }

  /** Counts the call and re-reads {@link getSession}. */
  renewSession(): Promise<SessionState> {
    return Promise.resolve(this.#core.renew());
  }

  /** Passes straight through to `globalThis.fetch` with no auth attached. */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    return globalThis.fetch(input, init);
  }

  /** Pushes the mock into an authenticated state and emits `authenticated`. */
  signIn(user?: UserInfoClaims): void {
    this.#core.signIn(user);
  }

  /** Pushes the mock into an unauthenticated state and emits `logged_out`. */
  signOut(): void {
    this.#core.signOut();
  }

  /** Emits `token_refreshed` with a bundle expiring in `expiresIn` seconds. */
  refreshTokens(expiresIn?: number | null): void {
    this.#core.refreshTokens(expiresIn);
  }

  /** Surfaces an error through the event bus. */
  setError(error: OAuth2Error | unknown): void {
    this.#core.setError(error);
  }

  /** Replaces the cached user without changing authentication status. */
  setUser(user: UserInfoClaims | null): void {
    this.#core.setUser(user);
  }

  /** Replaces the reported seconds-to-expiry. */
  setSessionExpiresIn(seconds: number | null): void {
    this.#core.setSessionExpiresIn(seconds);
  }
}

/**
 * A real `BffClient` whose four session operations answer from mock state
 * instead of the BFF. `useBffClient()` accepts it.
 */
export class MockBffClient extends BffClient implements MockOAuth2Controls {
  readonly #core: MockCore;

  /**
   * Builds a mock client and snapshots its starting state.
   *
   * @param state Where the mock starts. Everything is optional; the default
   * is a signed-out client.
   */
  constructor(state: MockOAuth2ClientState = {}) {
    super();
    this.#core = new MockCore(state, (event) => this.emit(event));
  }

  /** The starting state, defaults applied. */
  get initialState(): Pick<OAuth2State, "isAuthenticated" | "user"> {
    return this.#core.initialState;
  }

  /** How many times `renewSession()` has been called. */
  get renewCount(): number {
    return this.#core.renewCount;
  }

  /** Resolves a fixed `mock://login` URL, bypassing the BFF's URL builder. */
  override login(_options?: BaseLoginOptions): Promise<LoginRedirect> {
    return Promise.resolve({ url: MOCK_LOGIN_URL });
  }

  /** Drops to signed out and returns no redirect URL. */
  override logout(): Promise<LogoutRedirect> {
    this.signOut();
    return Promise.resolve({});
  }

  /** The mock's current user, with no session probe. */
  override getUser(): Promise<UserInfoClaims | null> {
    return Promise.resolve(this.#core.user());
  }

  /** The mock's current state, with no session probe. */
  override getSession(): Promise<SessionState> {
    return Promise.resolve(this.#core.session());
  }

  /** Counts the call and re-reads {@link getSession}. */
  override renewSession(): Promise<SessionState> {
    return Promise.resolve(this.#core.renew());
  }

  /** Passes straight through to `globalThis.fetch`. */
  override fetch(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    return globalThis.fetch(input, init);
  }

  /** Pushes the mock into an authenticated state and emits `authenticated`. */
  signIn(user?: UserInfoClaims): void {
    this.#core.signIn(user);
  }

  /** Pushes the mock into an unauthenticated state and emits `logged_out`. */
  signOut(): void {
    this.#core.signOut();
  }

  /** Emits `token_refreshed` with a bundle expiring in `expiresIn` seconds. */
  refreshTokens(expiresIn?: number | null): void {
    this.#core.refreshTokens(expiresIn);
  }

  /** Surfaces an error through the event bus. */
  setError(error: OAuth2Error | unknown): void {
    this.#core.setError(error);
  }

  /** Replaces the cached user without changing authentication status. */
  setUser(user: UserInfoClaims | null): void {
    this.#core.setUser(user);
  }

  /** Replaces the reported seconds-to-expiry. */
  setSessionExpiresIn(seconds: number | null): void {
    this.#core.setSessionExpiresIn(seconds);
  }
}

/**
 * A real `DirectClient` whose session operations answer from mock state
 * instead of a token endpoint. `useDirectClient()` and `<OAuth2Callback>`
 * accept it.
 *
 * The token-holding methods it does **not** override (`refresh`,
 * `handleAuthorizationCallback`, `introspect`, …) still reach for the network.
 * Stub the one your test drives, or point a real `DirectClient` at
 * `createMemoryAuthorizationServer().fetch` instead.
 */
export class MockDirectClient extends DirectClient
  implements MockOAuth2Controls {
  readonly #core: MockCore;

  /**
   * Builds a mock client and snapshots its starting state.
   *
   * @param state Where the mock starts. Everything is optional; the default
   * is a signed-out client.
   */
  constructor(state: MockOAuth2ClientState = {}) {
    super({ clientId: "mock-client", endpoints: { token: "mock://token" } });
    this.#core = new MockCore(state, (event) => this.emit(event));
  }

  /** The starting state, defaults applied. */
  get initialState(): Pick<OAuth2State, "isAuthenticated" | "user"> {
    return this.#core.initialState;
  }

  /** How many times `renewSession()` has been called. */
  get renewCount(): number {
    return this.#core.renewCount;
  }

  /** Resolves a fixed `mock://login` URL, skipping PKCE and storage. */
  override login(
    _options?: BaseLoginOptions,
  ): Promise<AuthorizationRedirect> {
    return Promise.resolve({ url: MOCK_LOGIN_URL, state: "mock-state" });
  }

  /** Drops to signed out without revoking anything. */
  override logout(): Promise<LogoutRedirect> {
    this.signOut();
    return Promise.resolve({});
  }

  /** The mock's current user, with no token read. */
  override getUser(): Promise<UserInfoClaims | null> {
    return Promise.resolve(this.#core.user());
  }

  /** The mock's current state, with no token read. */
  override getSession(): Promise<SessionState> {
    return Promise.resolve(this.#core.session());
  }

  /** Counts the call and re-reads {@link getSession}. */
  override renewSession(): Promise<SessionState> {
    return Promise.resolve(this.#core.renew());
  }

  /** Passes straight through to `globalThis.fetch`, attaching no bearer. */
  override fetch(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    return globalThis.fetch(input, init);
  }

  /** Resolves the mock access token without touching storage. */
  override getAccessToken(): Promise<string> {
    return Promise.resolve("mock-access-token");
  }

  /** Pushes the mock into an authenticated state and emits `authenticated`. */
  signIn(user?: UserInfoClaims): void {
    this.#core.signIn(user);
  }

  /** Pushes the mock into an unauthenticated state and emits `logged_out`. */
  signOut(): void {
    this.#core.signOut();
  }

  /** Emits `token_refreshed` with a bundle expiring in `expiresIn` seconds. */
  refreshTokens(expiresIn?: number | null): void {
    this.#core.refreshTokens(expiresIn);
  }

  /** Surfaces an error through the event bus. */
  setError(error: OAuth2Error | unknown): void {
    this.#core.setError(error);
  }

  /** Replaces the cached user without changing authentication status. */
  setUser(user: UserInfoClaims | null): void {
    this.#core.setUser(user);
  }

  /** Replaces the reported seconds-to-expiry. */
  setSessionExpiresIn(seconds: number | null): void {
    this.#core.setSessionExpiresIn(seconds);
  }
}

/**
 * Builds a {@link MockOAuth2Client}. No HTTP, no storage, no PKCE — just
 * state and an event bus that the React adapter reads through the provider.
 *
 * @param initialState Where the mock starts.
 * @returns The mock client, ready to hand to a provider.
 *
 * @example
 * ```tsx
 * import { createMockOAuth2Client, MockOAuth2Provider } from
 *   "@udibo/oauth2/react/testing";
 *
 * const client = createMockOAuth2Client({ user: { sub: "u1" } });
 * render(
 *   <MockOAuth2Provider client={client}>
 *     <Header />
 *   </MockOAuth2Provider>,
 * );
 * ```
 */
export function createMockOAuth2Client(
  initialState: MockOAuth2ClientState = {},
): MockOAuth2Client {
  return new MockOAuth2Client(initialState);
}

/**
 * Builds a {@link MockBffClient} — mock state on a real `BffClient`, so a
 * component that calls `useBffClient()` can be unit-tested.
 *
 * @param initialState Where the mock starts.
 * @returns The mock client, ready to hand to a provider.
 *
 * @example
 * ```tsx
 * import { createMockBffClient, MockOAuth2Provider } from
 *   "@udibo/oauth2/react/testing";
 *
 * const client = createMockBffClient({ user: { sub: "u1" } });
 * render(
 *   <MockOAuth2Provider client={client}>
 *     <SignInLink returnTo="/dashboard" />
 *   </MockOAuth2Provider>,
 * );
 * ```
 */
export function createMockBffClient(
  initialState: MockOAuth2ClientState = {},
): MockBffClient {
  return new MockBffClient(initialState);
}

/**
 * Builds a {@link MockDirectClient} — mock state on a real `DirectClient`, so
 * a component that calls `useDirectClient()` (or mounts `<OAuth2Callback>`)
 * can be unit-tested.
 *
 * @param initialState Where the mock starts.
 * @returns The mock client, ready to hand to a provider.
 *
 * @example
 * ```tsx
 * import { createMockDirectClient, MockOAuth2Provider } from
 *   "@udibo/oauth2/react/testing";
 *
 * const client = createMockDirectClient({ user: { sub: "u1" } });
 * render(
 *   <MockOAuth2Provider client={client}>
 *     <TokenReadout />
 *   </MockOAuth2Provider>,
 * );
 * ```
 */
export function createMockDirectClient(
  initialState: MockOAuth2ClientState = {},
): MockDirectClient {
  return new MockDirectClient(initialState);
}

/** Props for {@link MockOAuth2Provider}. */
export interface MockOAuth2ProviderProps {
  /**
   * Built via {@link createMockOAuth2Client}, {@link createMockBffClient}, or
   * {@link createMockDirectClient}.
   */
  client: OAuth2ClientBase & MockOAuth2Controls;
  /**
   * Optional initial state override, applied key by key: a key you pass wins
   * (including `user: null`), a key you omit falls back to the mock client's
   * {@link MockOAuth2Controls.initialState} for `isAuthenticated` / `user` and
   * to the signed-out default for the rest. So a test configures the client
   * once instead of restating the same user here.
   */
  state?: Partial<OAuth2State>;
  /** The subtree rendered under the mock provider. */
  children: ReactNode;
}

/**
 * Drop-in replacement for `<OAuth2Provider>` that skips the on-mount
 * session probe (the mock clients don't issue one) and surfaces the
 * mock state synchronously.
 *
 * The context it publishes is a snapshot of the client as it was built (plus
 * any `state` overrides): it subscribes to nothing, so calling `signIn` /
 * `signOut` on the client afterwards does not re-render the subtree. Render
 * the state you want, or use a real `<OAuth2Provider>` when the test is about
 * a transition.
 *
 * @param props A mock client, optional state overrides, and children.
 * @returns The subtree wrapped in a pre-resolved OAuth2 context.
 */
export function MockOAuth2Provider(
  props: MockOAuth2ProviderProps,
): ReactNode {
  const { client, state, children } = props;
  const value = useMemo(() => {
    const override = state ?? {};
    const overrides = (key: keyof OAuth2State) => key in override;
    return {
      client,
      isAuthenticated: overrides("isAuthenticated")
        ? override.isAuthenticated === true
        : client.initialState.isAuthenticated,
      isLoading: override.isLoading ?? false,
      user: overrides("user")
        ? override.user ?? null
        : client.initialState.user,
      error: override.error ?? null,
      sessionExpiresIn: override.sessionExpiresIn ?? null,
      logoutUrl: override.logoutUrl ?? null,
    };
  }, [client, state]);
  return (
    <OAuth2Context.Provider value={value}>
      {children}
    </OAuth2Context.Provider>
  );
}
