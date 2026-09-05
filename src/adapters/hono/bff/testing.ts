/**
 * Testing helpers for the Hono BFF adapter.
 *
 * Lets a consumer's tests drive protected endpoints without walking
 * through the full login → authorize → callback flow, and ages the
 * access token in the underlying {@link SessionStore} so a follow-up
 * request through `attachToken()` exercises the refresh path
 * deterministically (no `setTimeout` required).
 *
 * The runner-style helper {@link runSessionStoreContractTests} is
 * available for verifying custom {@link SessionStore} implementations
 * (Postgres, Redis, DynamoDB, …) satisfy the create / read / update /
 * destroy contract.
 *
 * @module
 */

import { assert, assertEquals, assertStrictEquals } from "@std/assert";
import { delay } from "@std/async/delay";
import { beforeEach, describe, it } from "@std/testing/bdd";

import type { ClientInterface } from "../../../models/client.ts";
import type { AbstractScope } from "../../../models/scope.ts";
import type { TokenServiceInterface } from "../../../server/services/token.ts";
import type { TokenBundle, UserInfoClaims } from "../../../client/mod.ts";
import type { HonoBff } from "./bff.ts";
import {
  type SessionData,
  type SessionStore,
  sessionStoreMaxAgeMs,
} from "./session-store.ts";

/** Options for {@link createTestSession}. */
export interface CreateTestSessionOptions {
  /**
   * Token bundle to install. Anything you don't supply gets a sensible
   * default (random access token, expires in 1 hour, no refresh token).
   */
  tokens?: Partial<TokenBundle>;
  /** Refresh token to store alongside the bundle. */
  refreshToken?: string;
  /** Cached user claims surfaced by `GET /auth/session`. */
  user?: UserInfoClaims | null;
  /** Override `createdAt` (epoch ms). Defaults to now. */
  createdAt?: number;
  /** Override `updatedAt` (epoch ms). Defaults to now. */
  updatedAt?: number;
}

/**
 * Seeds a session in `bff.sessionStore` and returns a `Cookie` header
 * value (`<name>=<value>`) ready to attach to subsequent
 * `app.request(...)` calls. Skips the authorize / callback round-trip
 * entirely — useful for tests that only care about authenticated
 * endpoint behavior.
 *
 * **Important — token recognition.** The seeded access token is random by
 * default and is NOT registered with any resource server. That is enough for
 * `GET /auth/session` (which reads the cached `user` claim), but a route
 * guarded by {@link HonoBff.protect} validates the session's access token
 * against the resource server's token service — so an unrecognized token
 * yields 401. For protected API routes, either pre-register the token
 * (`tokenService.save({ accessToken, ... })` then pass the same
 * `tokens.accessToken` here), or use {@link createAuthenticatedTestSession},
 * which does both in one call.
 *
 * @example
 * ```ts
 * // Probe-only (GET /auth/session) — no resource server involved:
 * const cookie = await createTestSession(bff, {
 *   user: { sub: "u1", name: "Alice" },
 * });
 * const res = await app.request("/auth/session", { headers: { cookie } });
 * ```
 */
export async function createTestSession(
  bff: HonoBff,
  options: CreateTestSessionOptions = {},
): Promise<string> {
  const now = Date.now();
  const data: SessionData = {
    tokens: {
      accessToken: options.tokens?.accessToken ?? crypto.randomUUID(),
      accessTokenExpiresAt: options.tokens?.accessTokenExpiresAt ??
        now + 60 * 60 * 1000,
      tokenType: options.tokens?.tokenType ?? "Bearer",
      scope: options.tokens?.scope,
      idToken: options.tokens?.idToken,
    },
    refreshToken: options.refreshToken,
    user: options.user ?? null,
    createdAt: options.createdAt ?? now,
    updatedAt: options.updatedAt ?? now,
  };
  const cookieValue = await bff.sessionStore.create(data);
  return `${bff.cookieName}=${cookieValue}`;
}

/** Options for {@link createAuthenticatedTestSession}. */
export interface CreateAuthenticatedTestSessionOptions<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope,
> {
  /**
   * The resource server's token service. The minted access token is saved
   * here so {@link HonoBff.protect} recognizes it — pass the SAME token
   * service the BFF's resource server validates against.
   */
  tokenService: TokenServiceInterface<Client, User, Scope>;
  /** Client the token is issued to. */
  client: Client;
  /** User the token is issued for. */
  user?: User;
  /** Scope granted to the token (drives `protect("scope")` checks). */
  scope?: Scope;
  /** Access-token lifetime in seconds. Defaults to one hour. */
  accessTokenLifetime?: number;
  /** Cached user claims surfaced by `GET /auth/session`. Defaults to null. */
  claims?: UserInfoClaims | null;
}

/**
 * Mints a real access token, registers it with the resource server's token
 * service, AND seeds a matching BFF session — the one-call setup for testing a
 * route guarded by {@link HonoBff.protect}. Returns a `Cookie` header ready to
 * attach to `app.request(...)`.
 *
 * This is the combined form of the two-step pattern (save a token, then
 * {@link createTestSession} with the same access token) that protected-route
 * tests otherwise hand-roll. Works with any {@link SessionStore} the BFF can
 * `create()` into (e.g. `MemorySessionStore`,
 * `EncryptedCookieSessionStore`); apps with a DB-backed store that mints
 * its own cookie/secret should seed via that store directly.
 *
 * @example
 * ```ts
 * const cookie = await createAuthenticatedTestSession(bff, {
 *   tokenService,
 *   client: { id: "spa" },
 *   user: { id: "u1", username: "alice" },
 *   scope: new BasicScope("read write"),
 *   claims: { sub: "u1", name: "Alice" },
 * });
 * const res = await app.request("/api/me", { headers: { cookie } });
 * ```
 */
export async function createAuthenticatedTestSession<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope,
>(
  bff: HonoBff,
  options: CreateAuthenticatedTestSessionOptions<Client, User, Scope>,
): Promise<string> {
  const accessToken = crypto.randomUUID();
  const accessTokenExpiresAt = new Date(
    Date.now() + (options.accessTokenLifetime ?? 60 * 60) * 1000,
  );
  await options.tokenService.save({
    accessToken,
    accessTokenExpiresAt,
    client: options.client,
    user: options.user,
    scope: options.scope,
  });
  return createTestSession(bff, {
    tokens: {
      accessToken,
      accessTokenExpiresAt: accessTokenExpiresAt.getTime(),
    },
    user: options.claims ?? null,
  });
}

/**
 * Ages the access token in the underlying session so the next request
 * through {@link HonoBff.attachToken} sees it as expired and triggers
 * the refresh path.
 *
 * Returns a fresh `Cookie` header. For stateful stores
 * (`MemorySessionStore` and DB-backed variants) the cookie value
 * is unchanged. For stateless stores
 * (`EncryptedCookieSessionStore`) the value is re-encrypted and
 * differs from the input — use the returned header for subsequent
 * requests.
 *
 * @param expiredAt Optional time to set the access token's expiry to
 * (epoch ms). Defaults to one second in the past.
 */
export async function forceTokenExpiry(
  bff: HonoBff,
  cookieHeader: string,
  expiredAt?: number,
): Promise<string> {
  const value = parseCookieHeader(cookieHeader, bff.cookieName);
  const data = await bff.sessionStore.read(value);
  if (!data) {
    throw new Error(
      `forceTokenExpiry: no session found for cookie value "${value}"`,
    );
  }
  const aged: SessionData = {
    ...data,
    tokens: {
      ...data.tokens,
      accessTokenExpiresAt: expiredAt ?? Date.now() - 1000,
    },
    updatedAt: Date.now(),
  };
  const newValue = await bff.sessionStore.update(value, aged);
  return `${bff.cookieName}=${newValue}`;
}

/**
 * Returns the session data currently stored under the given cookie
 * header, or `null` if there is none. Convenience wrapper around
 * `bff.sessionStore.read` that handles cookie parsing.
 */
export function readTestSession(
  bff: HonoBff,
  cookieHeader: string,
): Promise<SessionData | null> {
  const value = parseCookieHeader(cookieHeader, bff.cookieName);
  return Promise.resolve(bff.sessionStore.read(value));
}

function parseCookieHeader(header: string, name: string): string {
  if (!header.includes("=")) return header;
  const cookies = header.split(/;\s*/);
  for (const cookie of cookies) {
    const idx = cookie.indexOf("=");
    if (idx < 0) continue;
    const k = cookie.slice(0, idx).trim();
    if (k === name) return cookie.slice(idx + 1).trim();
  }
  throw new Error(
    `parseCookieHeader: cookie "${name}" not found in header "${header}"`,
  );
}

/** Options for {@link runSessionStoreContractTests}. */
export interface SessionStoreContractOptions {
  /** Returns a fresh, empty store for each test. */
  makeStore(): Promise<SessionStore> | SessionStore;
  /**
   * Some stateless stores (`EncryptedCookieSessionStore`) cannot
   * distinguish "session destroyed" from "session never existed" —
   * destroy is a no-op on the server, with the cookie clear happening on
   * the client side. Set this to `false` to skip the post-destroy
   * `read` returns null assertion.
   */
  destroyClearsRead?: boolean;
  /** Label for the generated `describe` block. Defaults to `"SessionStore contract"`. */
  describeName?: string;
  /**
   * Returns a store bound to the given maximum session age, in milliseconds.
   * Supply it whenever your store enforces an age bound — the suite builds a
   * store with a one-second bound, waits it out, and requires `read` to stop
   * returning the session. One second is whole-second-expressible, so a store
   * whose TTL column or `EXPIRE` call has second resolution can honor it
   * exactly.
   *
   * `HonoBff` trusts the `maxAgeMs` a store advertises when it refuses a
   * configuration whose session cookie would expire before the store stops
   * honoring the session. A store that advertises a bound it does not enforce
   * defeats that check, so the suite fails a store that advertises one without
   * supplying this factory.
   */
  makeBoundedStore?(maxAgeMs: number): Promise<SessionStore> | SessionStore;
}

const BOUND_MS = 1000;

/** Contract test suite for {@link SessionStore} implementations. */
export function runSessionStoreContractTests(
  options: SessionStoreContractOptions,
): void {
  const destroyClearsRead = options.destroyClearsRead ?? true;
  const makeBoundedStore = options.makeBoundedStore;

  describe(options.describeName ?? "SessionStore contract", () => {
    let store: SessionStore;

    beforeEach(async () => {
      store = await options.makeStore();
    });

    function sampleSession(): SessionData {
      const now = Date.now();
      return {
        tokens: {
          accessToken: "access-1",
          accessTokenExpiresAt: now + 60_000,
          tokenType: "Bearer",
        },
        refreshToken: "refresh-1",
        user: { sub: "u1" },
        createdAt: now,
        updatedAt: now,
      };
    }

    it("create returns a non-empty cookie value", async () => {
      const value = await store.create(sampleSession());
      assertEquals(typeof value, "string");
      assert(value.length > 0);
    });

    it("read returns null for an unknown cookie value", async () => {
      assertStrictEquals(await store.read("no-such-session"), null);
    });

    it("create + read round-trips the session data", async () => {
      const original = sampleSession();
      const value = await store.create(original);
      const fetched = await store.read(value);
      assert(fetched !== null, "read should return data for a created session");
      assertEquals(fetched.tokens.accessToken, original.tokens.accessToken);
      assertEquals(fetched.refreshToken, original.refreshToken);
      assertEquals(fetched.user, original.user);
    });

    it("preserves createdAt, which carries the session's absolute age", async () => {
      const original = sampleSession();
      const value = await store.create(original);
      const fetched = await store.read(value);
      assert(fetched !== null, "read should return data for a created session");
      assertEquals(
        fetched.createdAt,
        original.createdAt,
        "a store that drops createdAt silently opts its sessions out of " +
          "HonoBffOptions.sessionMaxAgeMs, so they never age out",
      );
    });

    it("update reflects changes on subsequent read", async () => {
      const value = await store.create(sampleSession());
      const updated: SessionData = {
        ...sampleSession(),
        user: { sub: "u1", role: "admin" },
        updatedAt: Date.now(),
      };
      const newValue = await store.update(value, updated);
      const fetched = await store.read(newValue);
      assertEquals(fetched?.user, { sub: "u1", role: "admin" });
    });

    if (destroyClearsRead) {
      it("destroy removes the session", async () => {
        const value = await store.create(sampleSession());
        await store.destroy(value);
        assertStrictEquals(await store.read(value), null);
      });
    }

    it("never advertises a max age without proving it enforces one", () => {
      const advertised = sessionStoreMaxAgeMs(store);
      assertEquals(
        advertised !== undefined && makeBoundedStore === undefined,
        false,
        `this store advertises maxAgeMs=${advertised}, which HonoBff trusts ` +
          "when it refuses a session cookie that would expire before the " +
          "session does. Supply makeBoundedStore so the contract can prove " +
          "the bound is real.",
      );
    });

    if (makeBoundedStore) {
      it("reports the max age it was built with, so a BFF can outlive it", async () => {
        const bounded = await makeBoundedStore(BOUND_MS);
        assertStrictEquals(
          sessionStoreMaxAgeMs(bounded),
          BOUND_MS,
          "a store that hides its bound gets no divergence check from HonoBff",
        );
      });

      it("stops reading a session older than the max age it enforces", async () => {
        const bounded = await makeBoundedStore(BOUND_MS);
        const value = await bounded.create(sampleSession());
        assert(
          await bounded.read(value) !== null,
          "a session created moments ago must still read",
        );
        await delay(BOUND_MS + 500);
        assertStrictEquals(
          await bounded.read(value),
          null,
          "a session past the store's own bound must stop reading, or a " +
            "captured cookie outlives the window the bound promises",
        );
      });
    }
  });
}
