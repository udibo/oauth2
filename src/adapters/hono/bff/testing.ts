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
 * destroy contract, and the refresh lock when the store implements
 * `RefreshLockStore`.
 *
 * @module
 */

import { assert, beforeEach, describe, expect, it } from "vitest";
import { delay } from "../../../utils/_delay.ts";
import type { ClientInterface } from "../../../models/client.ts";
import type { AbstractScope } from "../../../models/scope.ts";
import type { TokenServiceInterface } from "../../../server/services/token.ts";
import type { TokenBundle, UserInfoClaims } from "../../../client/mod.ts";
import type { HonoBff } from "./bff.ts";
import { InvalidGrantError } from "../../../errors.ts";
import {
  type RefreshLease,
  type RefreshLockStore,
  type SessionData,
  type SessionStore,
  sessionStoreMaxAgeMs,
  supportsRefreshLock,
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
 * // With CSRF on (the default), a request carrying the cookie needs the header.
 * const res = await app.request("/auth/session", {
 *   headers: { cookie, "x-csrf": "1" },
 * });
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
      accessTokenExpiresAt:
        options.tokens?.accessTokenExpiresAt ?? now + 60 * 60 * 1000,
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
 * const res = await app.request("/api/me", {
 *   headers: { cookie, "x-csrf": "1" },
 * });
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
  /**
   * Set to `true` when the store's refresh lock never expires, so a holder
   * keeps it until its `refresh` settles, as `MemorySessionStore` does by
   * default. The suite then skips the lease checks for a store whose
   * `withRefreshLock` passes no {@link RefreshLease}, instead of failing it.
   *
   * Without a lease, nothing stops a holder that lost an expiring lock from
   * writing or destroying the session, and the suite cannot tell a lock that
   * never expires from one that does. Declare it only when no holder can lose
   * the lock while its refresh runs, as when the lock lives in the one process
   * that runs every refresh. Then a holder that hangs holds the session's
   * refresh until it settles. Defaults to `false`.
   */
  refreshLockNeverExpires?: boolean;
}

const BOUND_MS = 1000;
const LOCK_WAIT_MS = 2000;
const LOCK_CONTENTION_MS = 100;

async function settlesWithin<T>(
  promise: Promise<T>,
  message: string,
): Promise<T> {
  const timer = new AbortController();
  const { signal } = timer;
  const timedOut = Symbol("timed out");
  try {
    const result = await Promise.race([
      promise,
      delay(LOCK_WAIT_MS, { signal }).then(() => timedOut),
    ]);
    assert(result !== timedOut, message);
    return result as T;
  } finally {
    timer.abort();
  }
}

function required(lease: RefreshLease | undefined): RefreshLease {
  assert(
    lease !== undefined,
    "withRefreshLock passed a lease to one refresh and none to another",
  );
  return lease;
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  const fulfilled = Symbol("fulfilled");
  const outcome = await promise.then(
    () => fulfilled,
    (error: unknown) => error,
  );
  assert(outcome !== fulfilled, "expected the lease to refuse");
  return outcome;
}

/**
 * Contract test suite for {@link SessionStore} implementations. Registers
 * `describe`/`it` blocks from Vitest, so call it at a test
 * module's top level. It does not check that a stateful store's `update`
 * rejects a missing or destroyed session, which {@link SessionStore.update}
 * requires — test that yourself.
 *
 * A store that implements `withRefreshLock` ({@link RefreshLockStore}) also
 * runs the lock checks; they are skipped for a store without it. The lease
 * checks ({@link RefreshLease}) fail a store whose `withRefreshLock` passes no
 * lease, unless the options declare that its lock never expires
 * ({@linkcode SessionStoreContractOptions.refreshLockNeverExpires}). They
 * prove that a lease stops acting once its call releases the lock or another
 * call holds it, not that it stops
 * when the lock expires: expire a lease in a test of your own for that. They
 * use one store object, so they prove the lock's behavior, not that separate
 * instances share it: point two store objects at one backend in a test of
 * your own for that.
 */
export function runSessionStoreContractTests(
  options: SessionStoreContractOptions,
): void {
  const destroyClearsRead = options.destroyClearsRead ?? true;
  const makeBoundedStore = options.makeBoundedStore;
  const refreshLockNeverExpires = options.refreshLockNeverExpires ?? false;

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
      expect(typeof value).toStrictEqual("string");
      assert(value.length > 0);
    });

    it("read returns null for an unknown cookie value", async () => {
      expect(await store.read("no-such-session")).toBe(null);
    });

    it("create + read round-trips the session data", async () => {
      const original = sampleSession();
      const value = await store.create(original);
      const fetched = await store.read(value);
      assert(fetched !== null, "read should return data for a created session");
      expect(fetched.tokens.accessToken).toStrictEqual(
        original.tokens.accessToken,
      );
      expect(fetched.refreshToken).toStrictEqual(original.refreshToken);
      expect(fetched.user).toStrictEqual(original.user);
    });

    it("preserves createdAt, which carries the session's absolute age", async () => {
      const original = sampleSession();
      const value = await store.create(original);
      const fetched = await store.read(value);
      assert(fetched !== null, "read should return data for a created session");
      expect(
        fetched.createdAt,
        "a store that drops createdAt silently opts its sessions out of " +
          "HonoBffOptions.sessionMaxAgeMs, so they never age out",
      ).toStrictEqual(original.createdAt);
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
      expect(fetched?.user).toStrictEqual({ sub: "u1", role: "admin" });
    });

    if (destroyClearsRead) {
      it("destroy removes the session", async () => {
        const value = await store.create(sampleSession());
        await store.destroy(value);
        expect(await store.read(value)).toBe(null);
      });
    }

    it("never advertises a max age without proving it enforces one", () => {
      const advertised = sessionStoreMaxAgeMs(store);
      expect(
        advertised !== undefined && makeBoundedStore === undefined,
        `this store advertises maxAgeMs=${advertised}, which HonoBff trusts ` +
          "when it refuses a session cookie that would expire before the " +
          "session does. Supply makeBoundedStore so the contract can prove " +
          "the bound is real.",
      ).toStrictEqual(false);
    });

    function lockStore(skip: (condition: boolean, note: string) => void) {
      skip(
        !supportsRefreshLock(store),
        "the store does not implement withRefreshLock",
      );
      return store as SessionStore & RefreshLockStore;
    }

    it("withRefreshLock runs one refresh of a session at a time", async ({
      skip,
    }) => {
      const locking = lockStore(skip);
      const value = await locking.create(sampleSession());
      const firstStarted = Promise.withResolvers<void>();
      const releaseFirst = Promise.withResolvers<void>();
      const order: string[] = [];

      const first = locking.withRefreshLock(value, async () => {
        order.push("first started");
        firstStarted.resolve();
        await releaseFirst.promise;
        order.push("first settled");
        return "first";
      });
      await settlesWithin(
        firstStarted.promise,
        "withRefreshLock never ran a refresh on a session nobody else holds",
      );
      const second = locking.withRefreshLock(value, () => {
        order.push("second started");
        return Promise.resolve("second");
      });
      await delay(LOCK_CONTENTION_MS);
      expect(
        order,
        "a second refresh of one session started while the first still held " +
          "the lock, so both would spend the same refresh token",
      ).toStrictEqual(["first started"]);

      releaseFirst.resolve();
      expect(
        await settlesWithin(
          Promise.all([first, second]),
          "the second refresh never ran after the first released the lock",
        ),
      ).toStrictEqual(["first", "second"]);
      expect(order).toStrictEqual([
        "first started",
        "first settled",
        "second started",
      ]);
    });

    it("withRefreshLock does not hold up another session's refresh", async ({
      skip,
    }) => {
      const locking = lockStore(skip);
      const held = await locking.create(sampleSession());
      const other = await locking.create(sampleSession());
      const releaseHeld = Promise.withResolvers<void>();
      const holding = locking.withRefreshLock(held, () => releaseHeld.promise);

      expect(
        await settlesWithin(
          locking.withRefreshLock(other, () => Promise.resolve("other")),
          "a refresh of one session waited on another session's lock",
        ),
      ).toBe("other");

      releaseHeld.resolve();
      await holding;
    });

    it("withRefreshLock lets the refresh read and update the session it locks", async ({
      skip,
    }) => {
      const locking = lockStore(skip);
      const value = await locking.create(sampleSession());
      const updated: SessionData = {
        ...sampleSession(),
        tokens: { ...sampleSession().tokens, accessToken: "access-2" },
        refreshToken: "refresh-2",
      };

      const fetched = await settlesWithin(
        locking.withRefreshLock(value, async () => {
          const next = await locking.update(value, updated);
          return await locking.read(next);
        }),
        "read or update blocked inside withRefreshLock: HonoBff reads and " +
          "writes the session while it holds the lock, so it would deadlock",
      );
      expect(fetched?.tokens.accessToken).toBe("access-2");
      expect(fetched?.refreshToken).toBe("refresh-2");
    });

    it("withRefreshLock lets the refresh destroy the session it locks", async ({
      skip,
    }) => {
      const locking = lockStore(skip);
      const value = await locking.create(sampleSession());

      await settlesWithin(
        locking.withRefreshLock(value, () => locking.destroy(value)),
        "destroy blocked inside withRefreshLock: HonoBff destroys the " +
          "session it locks when the authorization server refuses the " +
          "refresh, so it would deadlock",
      );
    });

    it("withRefreshLock runs a refresh that was waiting when the holder threw", async ({
      skip,
    }) => {
      const locking = lockStore(skip);
      const value = await locking.create(sampleSession());
      const failure = new Error("token endpoint unreachable");
      const releaseFirst = Promise.withResolvers<void>();

      const first = locking.withRefreshLock(value, async () => {
        await releaseFirst.promise;
        throw failure;
      });
      const waiting = locking.withRefreshLock(value, () =>
        Promise.resolve("waiting"),
      );
      releaseFirst.resolve();

      await expect(first).rejects.toBe(failure);
      expect(
        await settlesWithin(
          waiting.catch((error: unknown) => error),
          "a refresh queued behind one that threw never ran, so every " +
            "request waiting on that session hangs",
        ),
        "a refresh queued behind one that threw must run, not inherit its error",
      ).toBe("waiting");
    });

    it("withRefreshLock releases the lock when the refresh throws", async ({
      skip,
    }) => {
      const locking = lockStore(skip);
      const value = await locking.create(sampleSession());
      const failure = new Error("token endpoint unreachable");

      await expect(
        locking.withRefreshLock(value, () => Promise.reject(failure)),
      ).rejects.toBe(failure);
      expect(
        await settlesWithin(
          locking.withRefreshLock(value, () => Promise.resolve("next")),
          "a refresh that threw kept the lock, so the session can never " +
            "refresh again",
        ),
      ).toBe("next");
    });

    async function leaseOf(
      locking: SessionStore & RefreshLockStore,
      value: string,
      skip: (condition: boolean, note: string) => void,
    ): Promise<RefreshLease> {
      const lease = await locking.withRefreshLock(value, (given) =>
        Promise.resolve(given),
      );
      skip(
        lease === undefined && refreshLockNeverExpires,
        "withRefreshLock passes the refresh no lease, and the store declares " +
          "that its lock never expires",
      );
      assert(
        lease !== undefined,
        "withRefreshLock passed the refresh no lease, so a holder that " +
          "stalls past an expiring lock can still write and destroy the " +
          "session another holder refreshed. Pass a RefreshLease, or set " +
          "refreshLockNeverExpires: true if the lock never expires.",
      );
      return lease;
    }

    function refreshedSession(): SessionData {
      return {
        ...sampleSession(),
        tokens: { ...sampleSession().tokens, accessToken: "access-2" },
        refreshToken: "refresh-2",
      };
    }

    it("withRefreshLock passes a lease that writes the session while the lock is held", async ({
      skip,
    }) => {
      const locking = lockStore(skip);
      const value = await locking.create(sampleSession());
      await leaseOf(locking, value, skip);

      const next = await settlesWithin(
        locking.withRefreshLock(value, (lease) =>
          required(lease).update(refreshedSession()),
        ),
        "a lease's update blocked on the lock its own call holds",
      );
      const fetched = await locking.read(next);
      expect(fetched?.refreshToken).toBe("refresh-2");
    });

    it("withRefreshLock's lease refuses to write or destroy once its call has settled", async ({
      skip,
    }) => {
      const locking = lockStore(skip);
      const value = await locking.create(sampleSession());
      const former = await leaseOf(locking, value, skip);

      const error = await rejection(former.update(refreshedSession()));
      expect(
        error,
        "a holder whose lock was released wrote the session, so a holder " +
          "that stalled past its lock would overwrite the next holder's refresh",
      ).toBeInstanceOf(InvalidGrantError);
      expect(
        await former.destroy("refresh-1"),
        "a holder whose lock was released destroyed the session",
      ).toBe(false);
      expect((await locking.read(value))?.refreshToken).toBe("refresh-1");
    });

    it("withRefreshLock's lease cannot act while a later call holds the lock", async ({
      skip,
    }) => {
      const locking = lockStore(skip);
      const value = await locking.create(sampleSession());
      const former = await leaseOf(locking, value, skip);
      const holding = Promise.withResolvers<RefreshLease>();
      const releaseHolder = Promise.withResolvers<void>();
      const holder = locking.withRefreshLock(value, async (given) => {
        const lease = required(given);
        holding.resolve(lease);
        await releaseHolder.promise;
        return await lease.update(refreshedSession());
      });
      await settlesWithin(
        holding.promise,
        "the second call never took the lock",
      );

      const refusedWrite = await rejection(former.update(sampleSession()));
      const refusedDestroy = await former.destroy("refresh-1");
      releaseHolder.resolve();
      await holder;

      expect(refusedWrite).toBeInstanceOf(InvalidGrantError);
      expect(refusedDestroy).toBe(false);
      expect(
        (await locking.read(value))?.refreshToken,
        "the current holder's write must stand",
      ).toBe("refresh-2");
    });

    it("withRefreshLock's lease destroys the session only while it stores the given refresh token", async ({
      skip,
    }) => {
      const locking = lockStore(skip);
      const value = await locking.create(sampleSession());
      await leaseOf(locking, value, skip);

      const results = await locking.withRefreshLock(value, async (given) => {
        const lease = required(given);
        return [
          await lease.destroy("refresh-0"),
          (await locking.read(value)) !== null,
          await lease.destroy("refresh-1"),
        ];
      });

      expect(
        results,
        "a destroy for a refresh token the session no longer stores would end " +
          "a session a peer has just refreshed",
      ).toStrictEqual([false, true, true]);
      expect(await locking.read(value)).toBe(null);
    });

    it("withRefreshLock's lease never restores a destroyed session", async ({
      skip,
    }) => {
      const locking = lockStore(skip);
      const value = await locking.create(sampleSession());
      await leaseOf(locking, value, skip);

      const error = await locking.withRefreshLock(value, async (lease) => {
        await locking.destroy(value);
        return await rejection(required(lease).update(refreshedSession()));
      });

      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(await locking.read(value)).toBe(null);
    });

    if (makeBoundedStore) {
      it("reports the max age it was built with, so a BFF can outlive it", async () => {
        const bounded = await makeBoundedStore(BOUND_MS);
        expect(
          sessionStoreMaxAgeMs(bounded),
          "a store that hides its bound gets no divergence check from HonoBff",
        ).toBe(BOUND_MS);
      });

      it("stops reading a session older than the max age it enforces", async () => {
        const bounded = await makeBoundedStore(BOUND_MS);
        const value = await bounded.create(sampleSession());
        assert(
          (await bounded.read(value)) !== null,
          "a session created moments ago must still read",
        );
        await delay(BOUND_MS + 500);
        expect(
          await bounded.read(value),
          "a session past the store's own bound must stop reading, or a " +
            "captured cookie outlives the window the bound promises",
        ).toBe(null);
      });
    }
  });
}
