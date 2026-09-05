/**
 * Stateless {@link AuthRequestStorage} for {@link HonoBff}.
 *
 * The pending authorization request — the `state`, its PKCE code verifier, and
 * where to return afterwards — has to survive the round trip to the identity
 * provider. The client's default {@link MemoryAuthRequestStorage} keeps it in
 * the process that started the flow, which breaks on any platform that spreads
 * requests across isolates or instances: `/auth/login` stores the record on one
 * and `/auth/callback` looks for it on another, so sign-in fails intermittently
 * with `unknown state parameter`.
 *
 * {@link EncryptedCookieAuthRequestStorage} carries the record in an encrypted
 * cookie instead (AES-GCM under a server-held secret, the same construction
 * {@link EncryptedCookieSessionStore} uses), so no server-side storage is
 * involved and any instance can complete the flow. Apps that already have a
 * database can implement {@link AuthRequestStorage} against it instead.
 *
 * **Which storage you pick is a reliability decision, not a security one.**
 * Server-side storage on its own says a `state` is pending somewhere — never
 * that *this* browser is the one that started it, so a process-wide store like
 * the memory default would otherwise let anyone's browser complete anyone
 * else's pending sign-in (login CSRF). {@link HonoBff} closes that separately
 * and unconditionally: `/auth/login` also binds the `state` to the browser in
 * a short-lived cookie that `/auth/callback` requires, whichever storage is
 * configured. Choose here on whether every instance can read the record back.
 *
 * @module
 */

import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";

import type {
  AuthRequestRecord,
  AuthRequestStorage,
} from "../../../client/mod.ts";
import { deriveAesKey, sealJson, unsealJson } from "../../../utils/crypto.ts";
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
   * would fail. Defaults to 3; the oldest is dropped beyond that.
   */
  maxPending?: number;
}

const BASE_NAME = "oauth2_auth_request";
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const DEFAULT_MAX_PENDING = 3;

interface PendingRequests {
  [state: string]: AuthRequestRecord;
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
    sameSite: options?.sameSite ?? "Lax" as const,
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
 * {@link EncryptedCookieAuthRequestStorage}, or implement `forRequest` over
 * storage of your own.
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
 * the client's default in-memory storage fails those deployments with
 * `unknown state parameter`. The AES key is derived on first use and shared by
 * every later request.
 *
 * @example
 * ```ts
 * const bff = new HonoBff({
 *   client,
 *   sessionStore: new EncryptedCookieSessionStore({ secret }),
 *   authRequestStorage: new EncryptedCookieAuthRequestStorage({ secret }),
 * });
 * ```
 */
export class EncryptedCookieAuthRequestStorage
  implements AuthRequestStorageFactory {
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
  }

  #key(): Promise<CryptoKey> {
    return this.#keyPromise ??= deriveAesKey(this.#secret);
  }

  async #read(c: Context): Promise<PendingRequests> {
    const cookieValue = getCookie(c, this.#name);
    if (!cookieValue) return {};
    const pending = await unsealJson<PendingRequests>(
      await this.#key(),
      cookieValue,
    );
    if (!pending) return {};

    const cutoff = Date.now() - this.#ttlMs;
    return Object.fromEntries(
      Object.entries(pending).filter(([, record]) => record.createdAt > cutoff),
    );
  }

  async #write(c: Context, pending: PendingRequests): Promise<void> {
    const entries = Object.entries(pending)
      .sort(([, a], [, b]) => b.createdAt - a.createdAt)
      .slice(0, this.#maxPending);

    if (entries.length === 0) {
      this.#clear(c);
      return;
    }

    setCookie(
      c,
      this.#name,
      await sealJson(await this.#key(), Object.fromEntries(entries)),
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
        await this.#write(c, pending);
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
 *   secret: Deno.env.get("SESSION_SECRET")!,
 * });
 * ```
 */
export function encryptedCookieAuthRequestStorage(
  options: EncryptedCookieAuthRequestStorageOptions,
): EncryptedCookieAuthRequestStorage {
  return new EncryptedCookieAuthRequestStorage(options);
}
