/**
 * Discovery-metadata cache shared across `DirectClient` instances, for
 * servers that build a short-lived client per request.
 *
 * @module
 */

import type { AuthorizationServerMetadata } from "../models/responses.ts";

/** Default entry lifetime for {@link MemoryDiscoveryCache}: one hour. */
export const DEFAULT_DISCOVERY_TTL_MS = 60 * 60 * 1000;

/** Default entry ceiling for {@link MemoryDiscoveryCache}. */
export const DEFAULT_DISCOVERY_CACHE_MAX_ENTRIES = 100;

/**
 * What {@link DiscoveryCache.resolve} answers with: the metadata document plus
 * the moment it stops being fresh.
 *
 * A reader holds `metadata` without calling `resolve` again until `expiresAt`,
 * so a cache that costs a round trip is read once per entry lifetime rather
 * than once per endpoint lookup — which is why a remote implementation needs no
 * memo of its own.
 */
export interface DiscoveryCacheEntry {
  /** The metadata document for the issuer. */
  metadata: AuthorizationServerMetadata;
  /**
   * Epoch ms at which {@link DiscoveryCacheEntry.metadata} stops being fresh.
   *
   * Report the entry's own expiry, never later: a value further out pins a
   * stale document in every reader. `Infinity` never expires; a value in the
   * past forces a `resolve` call on every lookup.
   */
  expiresAt: number;
}

type CacheEntry = DiscoveryCacheEntry;

/**
 * A cache of authorization-server metadata keyed by issuer, shared by any
 * number of `DirectClient` instances.
 *
 * Implement this to back discovery with something other than process memory
 * (Redis, a file, a CDN edge cache). The single {@link DiscoveryCache.resolve}
 * method is get-or-load rather than get/set so an implementation can also
 * collapse concurrent misses into one `load` call — a get/set pair cannot.
 *
 * Metadata is issuer-scoped and public: it carries no client id, secret, or
 * tenant data, so one cache may serve many tenants pointed at the same issuer.
 * Do share a cache across clients that reach an issuer the same way; do not
 * share one between a stubbed transport and live traffic.
 *
 * @example Backing discovery with a store of your own
 * ```ts
 * declare const store: Map<string, { json: string; expiresAt: number }>;
 * const ttlMs = 60 * 60 * 1000;
 *
 * const discoveryCache: DiscoveryCache = {
 *   async resolve(issuer, load) {
 *     const hit = store.get(issuer);
 *     if (hit && hit.expiresAt > Date.now()) {
 *       return { metadata: JSON.parse(hit.json), expiresAt: hit.expiresAt };
 *     }
 *     const metadata = await load();
 *     const expiresAt = Date.now() + ttlMs;
 *     store.set(issuer, { json: JSON.stringify(metadata), expiresAt });
 *     return { metadata, expiresAt };
 *   },
 * };
 * ```
 */
export interface DiscoveryCache {
  /**
   * Returns the cached entry for `issuer`, or awaits `load` and caches it.
   *
   * `load` must not be called when a fresh entry exists, and concurrent calls
   * for one issuer should share a single `load`. A rejected `load` must not be
   * cached — the rejection propagates and the next call retries. The returned
   * `expiresAt` is what lets a reader skip this call entirely while the
   * document it already holds is still fresh, so it must not outlast the
   * entry.
   */
  resolve(
    issuer: string,
    load: () => Promise<AuthorizationServerMetadata>,
  ): Promise<DiscoveryCacheEntry>;
}

/** Options for {@link MemoryDiscoveryCache}. */
export interface MemoryDiscoveryCacheOptions {
  /**
   * How long an entry stays fresh, in ms. Defaults to
   * {@link DEFAULT_DISCOVERY_TTL_MS}; `Infinity` never expires.
   */
  ttlMs?: number;
  /**
   * Maximum number of issuers held. Defaults to
   * {@link DEFAULT_DISCOVERY_CACHE_MAX_ENTRIES}. Expired entries are dropped
   * first, then the least recently stored, so a multi-tenant server with an
   * unbounded issuer list cannot grow without limit.
   */
  maxEntries?: number;
}

/**
 * In-memory {@link DiscoveryCache}: TTL entries plus in-flight de-duplication,
 * so a burst of requests against a cold issuer triggers exactly one discovery
 * fetch. Failures are never cached.
 *
 * Construct one per process (or per trust boundary) and hand it to every
 * client that should share it.
 *
 * Because one document is handed to every client on that issuer, stored
 * metadata is deep-frozen: a consumer that tries to patch a field it read
 * throws rather than silently rewriting the entry every other client sees.
 * Entries are evicted least-recently-used, so one issuer churning through the
 * cache cannot evict a busier one.
 *
 * @example
 * ```ts
 * const discoveryCache = new MemoryDiscoveryCache();
 *
 * // Per request: a fresh client, but at most one discovery fetch per hour.
 * const client = new DirectClient({
 *   clientId,
 *   clientSecret,
 *   issuer: "https://sso.example",
 *   discoveryCache,
 * });
 * ```
 */
export class MemoryDiscoveryCache implements DiscoveryCache {
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #entries = new Map<string, CacheEntry>();
  readonly #inFlight = new Map<string, Promise<CacheEntry>>();

  /** Creates a cache with the given TTL and entry ceiling. */
  constructor(options: MemoryDiscoveryCacheOptions = {}) {
    this.#ttlMs = options.ttlMs ?? DEFAULT_DISCOVERY_TTL_MS;
    this.#maxEntries = options.maxEntries ??
      DEFAULT_DISCOVERY_CACHE_MAX_ENTRIES;
  }

  /**
   * Returns the fresh cached entry for `issuer`, joins the in-flight `load`
   * for it, or starts one. Trailing slashes on `issuer` are insignificant. A
   * hit counts as a use, so a busy issuer outlives an idle one under
   * {@link MemoryDiscoveryCacheOptions.maxEntries} pressure. The entry's
   * `expiresAt` is when this cache would reload, so a reader holding it may
   * skip the call until then.
   */
  resolve(
    issuer: string,
    load: () => Promise<AuthorizationServerMetadata>,
  ): Promise<DiscoveryCacheEntry> {
    const key = normalizeIssuer(issuer);
    const entry = this.#entries.get(key);
    if (entry) {
      if (entry.expiresAt > Date.now()) {
        this.#entries.delete(key);
        this.#entries.set(key, entry);
        return Promise.resolve({ ...entry });
      }
      this.#entries.delete(key);
    }
    const pending = this.#inFlight.get(key);
    if (pending) return pending;

    const promise = load().then((metadata) => this.#store(key, metadata));
    this.#inFlight.set(key, promise);
    const settle = () => {
      if (this.#inFlight.get(key) === promise) this.#inFlight.delete(key);
    };
    promise.then(settle, settle);
    return promise;
  }

  /** Drops the entry for `issuer`, forcing the next resolve to re-fetch. */
  delete(issuer: string): void {
    this.#entries.delete(normalizeIssuer(issuer));
  }

  /** Drops every entry. In-flight loads still settle for their callers. */
  clear(): void {
    this.#entries.clear();
  }

  #store(key: string, metadata: AuthorizationServerMetadata): CacheEntry {
    const entry: CacheEntry = {
      metadata: deepFreeze(metadata),
      expiresAt: Date.now() + this.#ttlMs,
    };
    this.#entries.delete(key);
    this.#entries.set(key, entry);
    this.#prune();
    return { ...entry };
  }

  #prune(): void {
    const now = Date.now();
    for (const [key, entry] of this.#entries) {
      if (entry.expiresAt <= now) this.#entries.delete(key);
    }
    while (this.#entries.size > this.#maxEntries) {
      const leastRecentlyUsed = this.#entries.keys().next();
      if (leastRecentlyUsed.done) return;
      this.#entries.delete(leastRecentlyUsed.value);
    }
  }
}

function normalizeIssuer(issuer: string): string {
  return issuer.replace(/\/+$/, "");
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) {
    return value;
  }
  Object.freeze(value);
  for (const key of Object.getOwnPropertyNames(value)) {
    deepFreeze((value as Record<string, unknown>)[key]);
  }
  return value;
}
