/**
 * Browser-storage implementations of {@link RefreshTokenStorage} and
 * {@link AuthRequestStorage}.
 *
 * Both ship from the `@udibo/oauth2/client` subpath alongside the
 * `Memory*` defaults so non-React browser consumers (vanilla JS,
 * Vue, Svelte, …) can use them too.
 *
 * Both implementations are **SSR-safe**: if `window` / `indexedDB` /
 * `sessionStorage` is undefined at construction, the storage degrades
 * to a no-op (`get` returns `null`, `set`/`clear` do nothing). The
 * client constructs the real backing on first use in the browser.
 *
 * @module
 */

import type {
  AuthRequestRecord,
  AuthRequestStorage,
  RefreshTokenStorage,
} from "./storage.ts";

/** Options for {@link IndexedDBRefreshTokenStorage}. */
export interface IndexedDBRefreshTokenStorageOptions {
  /**
   * Discriminates this client's refresh token from every other OAuth2
   * client's on the same origin, which all share one IndexedDB namespace.
   * Pass the `client_id` handed to the client; when one client id is
   * registered at more than one issuer, include the issuer too so the two
   * registrations do not share a slot.
   */
  clientId: string;
  /** IndexedDB database name. Defaults to `"@udibo/oauth2"`. */
  databaseName?: string;
  /** Object store name. Defaults to `"refresh-token"`. */
  storeName?: string;
}

/**
 * Refresh token storage backed by IndexedDB.
 *
 * IndexedDB is preferred over `localStorage` because the latter is
 * synchronously readable from any script that runs in the document
 * (including injected XSS payloads). IndexedDB's same-origin guarantees
 * are similar but its async API and per-database isolation make
 * exfiltration somewhat harder. Combined with refresh-token rotation +
 * reuse detection on the authorization server, it's the recommended
 * default for a browser `DirectClient`.
 *
 * No `localStorage`-backed variant is shipped: it is synchronously
 * readable by any in-document script (including injected XSS), which
 * defeats the protection above.
 *
 * Every instance needs a
 * {@link IndexedDBRefreshTokenStorageOptions.clientId} — the token is stored
 * under it, so two clients on one origin (two APIs, two issuers) keep
 * separate refresh tokens instead of overwriting each other's.
 *
 * @example
 * ```ts
 * import {
 *   DirectClient,
 *   IndexedDBRefreshTokenStorage,
 * } from "@udibo/oauth2/client";
 *
 * const client = new DirectClient({
 *   clientId: "web-app",
 *   issuer: "https://sso.example",
 *   refreshTokenStorage: new IndexedDBRefreshTokenStorage({
 *     clientId: "web-app",
 *   }),
 * });
 * ```
 */
export class IndexedDBRefreshTokenStorage implements RefreshTokenStorage {
  readonly #databaseName: string;
  readonly #storeName: string;
  readonly #key: string;

  /**
   * Names the slot this instance owns.
   *
   * @param options Must carry `clientId`; `databaseName` and `storeName`
   * isolate further when one client id needs more than one slot.
   * @throws {TypeError} when `clientId` is empty, which would put every
   * client on the origin back in one slot.
   */
  constructor(options: IndexedDBRefreshTokenStorageOptions) {
    if (!options.clientId) {
      throw new TypeError(
        "`clientId` is required so clients on one origin do not share a " +
          "refresh token slot",
      );
    }
    this.#databaseName = options.databaseName ?? "@udibo/oauth2";
    this.#storeName = options.storeName ?? "refresh-token";
    this.#key = options.clientId;
  }

  /**
   * Returns the stored refresh token, or `null` when none is stored, when
   * `indexedDB` is unavailable (SSR / non-browser), or when another tab is
   * blocking the store's creation.
   *
   * @throws {DOMException} when IndexedDB rejects the read.
   */
  async get(): Promise<string | null> {
    const db = await this.#openDb();
    if (!db) return null;
    return await new Promise<string | null>((resolve, reject) => {
      const tx = db.transaction(this.#storeName, "readonly");
      const req = tx.objectStore(this.#storeName).get(this.#key);
      req.onsuccess = () => resolve((req.result as string | undefined) ?? null);
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => db.close();
    });
  }

  /**
   * Persists {@linkcode value} as the refresh token. A no-op when `indexedDB`
   * is unavailable (SSR / non-browser).
   *
   * @throws {DOMException} when IndexedDB rejects the write.
   */
  async set(value: string): Promise<void> {
    const db = await this.#openDb();
    if (!db) return;
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(this.#storeName, "readwrite");
      const req = tx.objectStore(this.#storeName).put(value, this.#key);
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
    });
  }

  /**
   * Discards the stored refresh token. A no-op when `indexedDB` is unavailable
   * (SSR / non-browser).
   *
   * @throws {DOMException} when IndexedDB rejects the delete.
   */
  async clear(): Promise<void> {
    const db = await this.#openDb();
    if (!db) return;
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(this.#storeName, "readwrite");
      const req = tx.objectStore(this.#storeName).delete(this.#key);
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
    });
  }

  async #openDb(): Promise<IDBDatabase | null> {
    if (typeof indexedDB === "undefined") return null;
    const db = await this.#open();
    if (!db || db.objectStoreNames.contains(this.#storeName)) return db;
    const nextVersion = db.version + 1;
    db.close();
    return await this.#open(nextVersion);
  }

  #open(version?: number): Promise<IDBDatabase | null> {
    return new Promise<IDBDatabase | null>((resolve, reject) => {
      const req = version === undefined
        ? indexedDB.open(this.#databaseName)
        : indexedDB.open(this.#databaseName, version);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(this.#storeName)) {
          db.createObjectStore(this.#storeName);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
      req.onblocked = () => resolve(null);
    });
  }
}

/** Options for {@link SessionStorageAuthRequestStorage}. */
export interface SessionStorageAuthRequestStorageOptions {
  /** sessionStorage key prefix. Defaults to `"oauth2:auth-req:"`. */
  keyPrefix?: string;
  /**
   * Maximum age of an auth request before it's treated as expired
   * (epoch-ms). Reads of older entries return `null` and the entry is
   * removed. Defaults to 10 minutes — long enough for a slow
   * authorize-redirect round-trip, short enough that stale state from a
   * previous abandoned login doesn't accumulate.
   */
  ttlMs?: number;
}

/**
 * Auth-request storage backed by `sessionStorage`.
 *
 * Survives the authorize-redirect round-trip (sessionStorage persists
 * across navigations within the same tab) but doesn't outlive the tab,
 * so a forgotten in-flight authorization doesn't leak across browser
 * sessions.
 *
 * Stale entries past {@link SessionStorageAuthRequestStorageOptions.ttlMs}
 * are pruned on read.
 */
export class SessionStorageAuthRequestStorage implements AuthRequestStorage {
  readonly #keyPrefix: string;
  readonly #ttlMs: number;

  /** Configures the key prefix and TTL; both default per option. */
  constructor(options: SessionStorageAuthRequestStorageOptions = {}) {
    this.#keyPrefix = options.keyPrefix ?? "oauth2:auth-req:";
    this.#ttlMs = options.ttlMs ?? 10 * 60 * 1000;
  }

  /**
   * Returns the record for {@linkcode state}, or `null` when it is absent,
   * unparseable, expired past the configured TTL, or `sessionStorage` is
   * unavailable (SSR / non-browser). Expired or unparseable entries are pruned.
   */
  get(state: string): AuthRequestRecord | null {
    const storage = this.#storage();
    if (!storage) return null;
    const raw = storage.getItem(this.#keyPrefix + state);
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as AuthRequestRecord;
      if (Date.now() - parsed.createdAt > this.#ttlMs) {
        storage.removeItem(this.#keyPrefix + state);
        return null;
      }
      return parsed;
    } catch {
      storage.removeItem(this.#keyPrefix + state);
      return null;
    }
  }

  /**
   * Stores {@linkcode value} under {@linkcode state}. A no-op when
   * `sessionStorage` is unavailable (SSR / non-browser).
   */
  set(state: string, value: AuthRequestRecord): void {
    const storage = this.#storage();
    if (!storage) return;
    storage.setItem(this.#keyPrefix + state, JSON.stringify(value));
  }

  /**
   * Removes the record for {@linkcode state}. A no-op when `sessionStorage` is
   * unavailable (SSR / non-browser).
   */
  delete(state: string): void {
    const storage = this.#storage();
    if (!storage) return;
    storage.removeItem(this.#keyPrefix + state);
  }

  /**
   * Removes every record under the configured key prefix, leaving unrelated
   * `sessionStorage` entries intact. A no-op when `sessionStorage` is
   * unavailable (SSR / non-browser).
   */
  clear(): void {
    const storage = this.#storage();
    if (!storage) return;
    const keysToRemove: string[] = [];
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (key && key.startsWith(this.#keyPrefix)) keysToRemove.push(key);
    }
    for (const key of keysToRemove) storage.removeItem(key);
  }

  #storage(): Storage | null {
    if (typeof sessionStorage === "undefined") return null;
    return sessionStorage;
  }
}
