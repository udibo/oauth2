/**
 * {@link AuthRequestStorageFactory} implementations for {@link HonoBff}.
 *
 * The pending authorization request — the `state`, its PKCE code verifier, and
 * where to return afterwards — has to survive the round trip to the identity
 * provider. {@link MemoryAuthRequestStorageFactory} keeps it in the process
 * that started the flow, which breaks on any platform that spreads requests
 * across isolates or instances: `/auth/login` stores the record on one and
 * `/auth/callback` looks for it on another, so sign-in fails intermittently
 * with `unknown state parameter`. `HonoBff` therefore has no default; the
 * caller chooses.
 *
 * {@link EncryptedCookieAuthRequestStorage} carries the record in an encrypted
 * cookie instead (AES-GCM under a key derived from a server-held secret), so no
 * server-side storage is involved and any instance can complete the flow. Apps
 * that already have a database can implement {@link AuthRequestStorage} against
 * it instead.
 *
 * **Which storage you pick is a reliability decision, not a security one.**
 * Server-side storage on its own says a `state` is pending somewhere — never
 * that *this* browser is the one that started it, so a process-wide store like
 * {@link MemoryAuthRequestStorageFactory} would otherwise let anyone's browser complete anyone
 * else's pending sign-in (login CSRF). {@link HonoBff} closes that separately
 * and unconditionally: `/auth/login` also binds the `state` to the browser in
 * a short-lived cookie that `/auth/callback` requires, whichever storage is
 * configured. Choose here on whether every instance can read the record back.
 *
 * @module
 */

import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";

import {
  type AuthRequestRecord,
  type AuthRequestStorage,
  MemoryAuthRequestStorage,
  type MemoryAuthRequestStorageOptions,
} from "../../../client/mod.ts";
import { sealJson, unsealJson } from "../../../utils/crypto.ts";
import {
  AUTH_REQUEST_COOKIE_KEY_INFO,
  deriveCookieKey,
} from "./_cookie-keys.ts";
import {
  resolveCookieName,
  resolvePrefixConstrainedAttributes,
} from "./cookie-prefix.ts";

/**
 * Cookie attributes for the pending-authorization cookie.
 *
 * The **default** name is prefix-aware: it carries `__Host-` only when every
 * attribute that prefix requires holds, and falls back to the bare name
 * otherwise. An **explicit** {@link name} whose prefix contradicts the other
 * attributes throws from the {@link EncryptedCookieAuthRequestStorage}
 * constructor instead of emitting a cookie every browser silently drops.
 */
export interface AuthRequestCookieOptions {
  /**
   * Cookie name. Defaults to `"__Host-oauth2_auth_request"` when the other
   * options satisfy that prefix — {@link secure} on, {@link path} `"/"`, and no
   * {@link domain} — and to `"oauth2_auth_request"` otherwise, because a
   * browser rejects a `__Host-` cookie that breaks any of them.
   *
   * Setting this explicitly to a `__Host-` or `__Secure-` prefixed name throws
   * when the other options contradict the prefix. Prefixes are matched
   * case-insensitively, as browsers match them.
   */
  name?: string;
  /**
   * Cookie path. Defaults to `"/"`. Any other value drops the default
   * `__Host-` prefix, which requires `Path=/`.
   */
  path?: string;
  /**
   * Marks the cookie Secure. Defaults to `true`. Turning it off — as local
   * plain-HTTP development needs — drops the default `__Host-` prefix, which
   * requires `Secure`.
   */
  secure?: boolean;
  /**
   * `SameSite` policy. Defaults to `"Lax"`, which is the strictest value that
   * still survives the identity provider's redirect back to the callback —
   * `"Strict"` withholds the cookie on that navigation and every sign-in
   * fails.
   *
   * `"None"` requires {@link AuthRequestCookieOptions.secure}; the constructor
   * throws on the combination rather than emitting a cookie every modern
   * browser silently drops.
   */
  sameSite?: "Strict" | "Lax" | "None";
  /**
   * Optional cookie domain. Omitting it (the default) keeps the cookie
   * host-bound; setting it drops the default `__Host-` prefix, which forbids
   * `Domain`.
   */
  domain?: string;
}

/** Options for {@link EncryptedCookieAuthRequestStorage}. */
export interface EncryptedCookieAuthRequestStorageOptions {
  /**
   * Secret the AES-256 key is derived from; at least 32 bytes. Reuse the
   * secret across instances so any of them can unseal a cookie another sealed.
   *
   * Prefer a secret of its own, separate from the session store's. Sharing
   * one with {@link EncryptedCookieSessionStore} is still safe: each store
   * derives its key with HKDF-SHA-256 under its own label, so neither store
   * opens the other's cookie.
   */
  secret: string;
  /** Cookie attribute overrides. */
  cookie?: AuthRequestCookieOptions;
  /**
   * How long a pending request stays valid, in ms. Also the cookie's
   * `Max-Age`. Defaults to 10 minutes, matching the client's
   * `authRequestTtlMs` default.
   */
  ttlMs?: number;
  /**
   * How many pending requests the cookie carries at once. A second sign-in
   * started in another tab would otherwise evict the first, so its callback
   * would fail. Defaults to 3; the oldest is dropped beyond that, and also
   * whenever keeping it would push the sealed cookie past what every browser
   * stores (about 4 KB), since a browser silently drops an oversized cookie
   * and every pending sign-in in it with it. The sign-in being started is
   * never the one dropped. Must be a positive integer.
   */
  maxPending?: number;
}

const BASE_NAME = "oauth2_auth_request";
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const DEFAULT_MAX_PENDING = 3;
// RFC 6265 §6.1 only guarantees 4096 bytes per cookie, attributes included.
const MAX_COOKIE_NAME_VALUE_BYTES = 3900;

interface PendingRequests {
  [state: string]: AuthRequestRecord;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function cookieAttributes(
  options: AuthRequestCookieOptions | undefined,
  maxAgeSeconds?: number,
) {
  const { secure, path, domain } = resolvePrefixConstrainedAttributes(options);
  return {
    path,
    secure,
    httpOnly: true,
    sameSite: options?.sameSite ?? ("Lax" as const),
    ...(domain ? { domain } : {}),
    ...(maxAgeSeconds === undefined ? {} : { maxAge: maxAgeSeconds }),
  };
}

/**
 * Resolves the {@link AuthRequestStorage} for a single request.
 *
 * {@link HonoBffOptions.authRequestStorage} takes one of these rather than a
 * bare storage because a cookie-backed store can only read and write through
 * the request's {@link Context}. Pass an
 * {@link EncryptedCookieAuthRequestStorage}, a
 * {@link MemoryAuthRequestStorageFactory} for a single process, or implement
 * `forRequest` over storage every instance shares. A storage that needs no
 * request context is wrapped as `{ forRequest: () => storage }`.
 */
export interface AuthRequestStorageFactory {
  /** Returns the storage bound to `c`, for the duration of that request. */
  forRequest(c: Context): AuthRequestStorage;
}

/**
 * Stateless {@link AuthRequestStorage}: the pending authorization requests live
 * in an AES-GCM cookie under a server-held secret, so `/auth/login` and
 * `/auth/callback` need not be served by the same instance.
 *
 * Reach for it whenever the BFF runs on more than one isolate or instance —
 * {@link MemoryAuthRequestStorageFactory} fails those deployments with
 * `unknown state parameter`. The AES key is derived on first use and shared by
 * every later request.
 *
 * It has no `take`: the record travels with the browser and cannot be claimed
 * atomically, so a replayed callback is bounded by the authorization server's
 * single-use code and PKCE.
 *
 * @example
 * ```ts
 * const bff = new HonoBff({
 *   client,
 *   sessionStore: new EncryptedCookieSessionStore({
 *     secret: process.env.SESSION_SECRET!,
 *   }),
 *   authRequestStorage: new EncryptedCookieAuthRequestStorage({
 *     secret: process.env.AUTH_REQUEST_SECRET!,
 *   }),
 * });
 * ```
 */
export class EncryptedCookieAuthRequestStorage implements AuthRequestStorageFactory {
  readonly #cookie: AuthRequestCookieOptions | undefined;
  readonly #secret: string;
  readonly #name: string;
  readonly #ttlMs: number;
  readonly #maxPending: number;
  #keyPromise: Promise<CryptoKey> | undefined;

  /**
   * Resolves and validates the cookie name up front; the AES key is derived
   * lazily on the first request that touches the cookie.
   *
   * @throws {Error} When an explicit {@link AuthRequestCookieOptions.name}
   * carries a `__Host-`/`__Secure-` prefix the other cookie options contradict,
   * or when {@link AuthRequestCookieOptions.sameSite} is `"None"` without
   * {@link AuthRequestCookieOptions.secure}.
   * @throws {RangeError} When
   * {@link EncryptedCookieAuthRequestStorageOptions.maxPending} is not a
   * positive integer.
   */
  constructor(options: EncryptedCookieAuthRequestStorageOptions) {
    this.#cookie = options.cookie;
    this.#secret = options.secret;
    this.#name = resolveCookieName({
      name: options.cookie?.name,
      base: BASE_NAME,
      attributes: resolvePrefixConstrainedAttributes(options.cookie),
      consequence:
        "the pending request would be lost and every callback would fail " +
        "with an unknown state parameter",
    });
    this.#ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.#maxPending = options.maxPending ?? DEFAULT_MAX_PENDING;
    if (!(Number.isInteger(this.#maxPending) && this.#maxPending > 0)) {
      throw new RangeError(
        "EncryptedCookieAuthRequestStorage maxPending must be a positive " +
          `integer, got ${this.#maxPending}.`,
      );
    }
  }

  #key(): Promise<CryptoKey> {
    return (this.#keyPromise ??= deriveCookieKey(
      this.#secret,
      AUTH_REQUEST_COOKIE_KEY_INFO,
    ));
  }

  async #read(c: Context): Promise<PendingRequests> {
    const cookieValue = getCookie(c, this.#name);
    if (!cookieValue) return {};
    const pending = await unsealJson<unknown>(await this.#key(), cookieValue);
    if (!isObject(pending)) return {};

    const cutoff = Date.now() - this.#ttlMs;
    return Object.fromEntries(
      Object.entries(pending).filter(
        (entry): entry is [string, AuthRequestRecord] =>
          isObject(entry[1]) &&
          typeof entry[1].createdAt === "number" &&
          entry[1].createdAt > cutoff,
      ),
    );
  }

  async #write(
    c: Context,
    pending: PendingRequests,
    keep?: string,
  ): Promise<void> {
    const entries = Object.entries(pending)
      .sort(
        ([stateA, a], [stateB, b]) =>
          Number(stateB === keep) - Number(stateA === keep) ||
          b.createdAt - a.createdAt,
      )
      .slice(0, this.#maxPending);

    if (entries.length === 0) {
      this.#clear(c);
      return;
    }

    const key = await this.#key();
    let sealed = await sealJson(key, Object.fromEntries(entries));
    while (
      entries.length > 1 &&
      this.#name.length + 1 + sealed.length > MAX_COOKIE_NAME_VALUE_BYTES
    ) {
      entries.pop();
      sealed = await sealJson(key, Object.fromEntries(entries));
    }

    setCookie(
      c,
      this.#name,
      sealed,
      cookieAttributes(this.#cookie, Math.ceil(this.#ttlMs / 1000)),
    );
  }

  #clear(c: Context): void {
    deleteCookie(c, this.#name, cookieAttributes(this.#cookie));
  }

  /** Returns the storage bound to `c`, for the duration of that request. */
  forRequest(c: Context): AuthRequestStorage {
    return {
      get: async (state: string): Promise<AuthRequestRecord | null> =>
        (await this.#read(c))[state] ?? null,
      set: async (state: string, value: AuthRequestRecord): Promise<void> => {
        const pending = await this.#read(c);
        pending[state] = value;
        await this.#write(c, pending, state);
      },
      delete: async (state: string): Promise<void> => {
        const pending = await this.#read(c);
        delete pending[state];
        await this.#write(c, pending);
      },
      clear: (): void => this.#clear(c),
    };
  }
}

/**
 * Convenience factory for {@link EncryptedCookieAuthRequestStorage} — the same
 * as `new EncryptedCookieAuthRequestStorage(options)`, for call sites that
 * prefer a function to a constructor.
 *
 * @example
 * ```ts
 * import { encryptedCookieAuthRequestStorage } from "@udibo/oauth2/hono/bff";
 *
 * const authRequestStorage = encryptedCookieAuthRequestStorage({
 *   secret: process.env.AUTH_REQUEST_SECRET!,
 * });
 * ```
 */
export function encryptedCookieAuthRequestStorage(
  options: EncryptedCookieAuthRequestStorageOptions,
): EncryptedCookieAuthRequestStorage {
  return new EncryptedCookieAuthRequestStorage(options);
}

/**
 * In-process {@link AuthRequestStorageFactory}: every request shares one
 * {@link MemoryAuthRequestStorage}, so a sign-in completes only on the process
 * that started it.
 *
 * Pass it explicitly for a single long-lived process, tests and local
 * development. A deployment that can serve `/auth/login` and `/auth/callback`
 * from different instances or isolates fails sign-in with it, intermittently,
 * with an unknown `state`; use {@link EncryptedCookieAuthRequestStorage} or a
 * factory over shared storage there. The options are
 * {@link MemoryAuthRequestStorage}'s: records older than `ttlMs` (10 minutes
 * by default) are pruned and at most `maxEntries` (1000 by default) are held.
 *
 * @example
 * ```ts
 * import {
 *   HonoBff,
 *   MemoryAuthRequestStorageFactory,
 *   MemorySessionStore,
 * } from "@udibo/oauth2/hono/bff";
 * import { DirectClient } from "@udibo/oauth2/client";
 *
 * const bff = new HonoBff({
 *   client: new DirectClient({
 *     clientId: "local-app",
 *     clientSecret: "dev-secret",
 *     issuer: "http://localhost:8000",
 *   }),
 *   sessionStore: new MemorySessionStore(),
 *   authRequestStorage: new MemoryAuthRequestStorageFactory(),
 * });
 * ```
 */
export class MemoryAuthRequestStorageFactory implements AuthRequestStorageFactory {
  readonly #storage: MemoryAuthRequestStorage;

  /**
   * @throws {RangeError} When `maxEntries` is neither a positive integer nor
   * `Infinity`.
   */
  constructor(options: MemoryAuthRequestStorageOptions = {}) {
    this.#storage = new MemoryAuthRequestStorage(options);
  }

  /** Returns the process-wide storage; `c` is not consulted. */
  forRequest(_c: Context): AuthRequestStorage {
    return this.#storage;
  }
}
