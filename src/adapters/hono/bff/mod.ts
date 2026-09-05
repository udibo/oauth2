/**
 * Backend-for-Frontend adapter for Hono.
 *
 * Exposes a {@link HonoBff} class that wraps an
 * `DirectClient` constructed with a client secret, plus the
 * {@link SessionStore} contract and two ready-to-use implementations
 * ({@link MemorySessionStore}, {@link EncryptedCookieSessionStore}).
 *
 * Need a server-side store (Postgres, Redis, Deno KV, …)? Implement the
 * {@link SessionStore} interface and verify it with
 * `runSessionStoreContractTests` from `@udibo/oauth2/hono/bff/testing`.
 *
 * @module
 */

export {
  type BackchannelLogoutSubject,
  type BffCallbackError,
  HonoBff,
  type HonoBffBackchannelOptions,
  type HonoBffCookieOptions,
  type HonoBffCsrfOptions,
  type HonoBffOptions,
  type HonoBffPaths,
  type HonoBffResourceServer,
} from "./bff.ts";
export {
  type AuthRequestCookieOptions,
  type AuthRequestStorageFactory,
  EncryptedCookieAuthRequestStorage,
  encryptedCookieAuthRequestStorage,
  type EncryptedCookieAuthRequestStorageOptions,
} from "./auth-request-store.ts";
export {
  DEFAULT_PROXY_FORWARD_HEADERS,
  type HonoBffProxyOptions,
} from "./proxy.ts";
export {
  type BackchannelLogoutStore,
  type BoundedSessionStore,
  DEFAULT_SESSION_MAX_AGE_MS,
  EncryptedCookieSessionStore,
  type EncryptedCookieSessionStoreOptions,
  MemorySessionStore,
  type SessionData,
  type SessionStore,
  sessionStoreMaxAgeMs,
  supportsBackchannelLogout,
} from "./session-store.ts";
