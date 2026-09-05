import { assertEquals, assertStrictEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  IndexedDBRefreshTokenStorage,
  SessionStorageAuthRequestStorage,
} from "./browser-storage.ts";

type Handler = (() => void) | null;

interface FakeRequest {
  result: unknown;
  error: DOMException | null;
  onsuccess: Handler;
  onerror: Handler;
  onupgradeneeded: Handler;
  onblocked: Handler;
}

interface FakeTransaction {
  oncomplete: Handler;
  onerror: Handler;
  objectStore(name: string): {
    get(key: string): FakeRequest;
    put(value: unknown, key: string): FakeRequest;
    delete(key: string): FakeRequest;
  };
}

interface DatabaseRecord {
  version: number;
  stores: Map<string, Map<string, unknown>>;
}

function newRequest(): FakeRequest {
  return {
    result: undefined,
    error: null,
    onsuccess: null,
    onerror: null,
    onupgradeneeded: null,
    onblocked: null,
  };
}

function storeRequest(
  run: () => unknown,
  transaction: FakeTransaction,
): FakeRequest {
  const request = newRequest();
  queueMicrotask(() => {
    request.result = run();
    request.onsuccess?.();
    queueMicrotask(() => transaction.oncomplete?.());
  });
  return request;
}

function fakeDatabase(record: DatabaseRecord): IDBDatabase {
  const database = {
    get version(): number {
      return record.version;
    },
    objectStoreNames: {
      contains: (name: string) => record.stores.has(name),
    },
    createObjectStore(name: string): void {
      record.stores.set(name, new Map());
    },
    close(): void {},
    transaction(storeName: string): FakeTransaction {
      if (!record.stores.has(storeName)) {
        throw new DOMException(
          `no object store named ${storeName}`,
          "NotFoundError",
        );
      }
      const transaction: FakeTransaction = {
        oncomplete: null,
        onerror: null,
        objectStore: (name: string) => {
          const entries = record.stores.get(name)!;
          return {
            get: (key: string) =>
              storeRequest(() => entries.get(key), transaction),
            put: (value: unknown, key: string) =>
              storeRequest(() => entries.set(key, value), transaction),
            delete: (key: string) =>
              storeRequest(() => entries.delete(key), transaction),
          };
        },
      };
      return transaction;
    },
  };
  return database as unknown as IDBDatabase;
}

function installFakeIndexedDB(): Disposable {
  const databases = new Map<string, DatabaseRecord>();
  const factory = {
    open(name: string, version?: number): FakeRequest {
      const request = newRequest();
      queueMicrotask(() => {
        let record = databases.get(name);
        if (!record) {
          record = { version: 0, stores: new Map() };
          databases.set(name, record);
        }
        const target = version ?? Math.max(record.version, 1);
        if (target < record.version) {
          request.error = new DOMException("version too low", "VersionError");
          request.onerror?.();
          return;
        }
        request.result = fakeDatabase(record);
        if (target > record.version) {
          record.version = target;
          request.onupgradeneeded?.();
        }
        request.onsuccess?.();
      });
      return request;
    },
  };
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    factory as unknown as IDBFactory;
  return {
    [Symbol.dispose]: () => {
      delete (globalThis as { indexedDB?: IDBFactory }).indexedDB;
    },
  };
}

describe("IndexedDBRefreshTokenStorage (SSR / no-IndexedDB runtime)", () => {
  it("get returns null when indexedDB is unavailable", async () => {
    const storage = new IndexedDBRefreshTokenStorage({ clientId: "web-app" });
    assertStrictEquals(await storage.get(), null);
  });

  it("set is a no-op when indexedDB is unavailable", async () => {
    const storage = new IndexedDBRefreshTokenStorage({ clientId: "web-app" });
    await storage.set("ignored");
    assertStrictEquals(await storage.get(), null);
  });

  it("clear is a no-op when indexedDB is unavailable", async () => {
    const storage = new IndexedDBRefreshTokenStorage({ clientId: "web-app" });
    await storage.clear();
    assertStrictEquals(await storage.get(), null);
  });
});

describe("IndexedDBRefreshTokenStorage", () => {
  it("refuses an empty clientId, which would put every client in one slot", () => {
    assertThrows(
      () => new IndexedDBRefreshTokenStorage({ clientId: "" }),
      TypeError,
      "`clientId` is required",
    );
  });

  it("keeps a separate refresh token per client on one origin", async () => {
    using _indexedDB = installFakeIndexedDB();
    const first = new IndexedDBRefreshTokenStorage({ clientId: "app-a" });
    const second = new IndexedDBRefreshTokenStorage({ clientId: "app-b" });

    await first.set("token-a");
    await second.set("token-b");

    assertStrictEquals(await first.get(), "token-a");
    assertStrictEquals(await second.get(), "token-b");

    await second.clear();
    assertStrictEquals(await first.get(), "token-a");
    assertStrictEquals(await second.get(), null);
  });

  it("creates a store the existing database does not have yet", async () => {
    using _indexedDB = installFakeIndexedDB();
    const original = new IndexedDBRefreshTokenStorage({ clientId: "app-a" });
    await original.set("token-a");

    const renamed = new IndexedDBRefreshTokenStorage({
      clientId: "app-a",
      storeName: "refresh-token-v2",
    });

    await renamed.set("token-v2");
    assertStrictEquals(await renamed.get(), "token-v2");
    assertStrictEquals(
      await original.get(),
      "token-a",
      "adding a store must not disturb the one already there",
    );
  });

  it("round-trips through a database that did not exist yet", async () => {
    using _indexedDB = installFakeIndexedDB();
    const storage = new IndexedDBRefreshTokenStorage({
      clientId: "app-a",
      databaseName: "other-db",
    });

    assertStrictEquals(await storage.get(), null);
    await storage.set("token-a");
    assertStrictEquals(await storage.get(), "token-a");
    await storage.clear();
    assertStrictEquals(await storage.get(), null);
  });
});

describe("SessionStorageAuthRequestStorage", () => {
  it("get returns null when sessionStorage is unavailable (SSR)", () => {
    const storage = new SessionStorageAuthRequestStorage();
    assertStrictEquals(storage.get("any-state"), null);
  });

  it("set / delete / clear are no-ops without sessionStorage", () => {
    const storage = new SessionStorageAuthRequestStorage();
    storage.set("s", { codeVerifier: "v", createdAt: Date.now() });
    storage.delete("s");
    storage.clear();
  });

  it("uses sessionStorage when available", () => {
    const backing = new Map<string, string>();
    const storage = {
      length: 0,
      getItem: (k: string) => backing.get(k) ?? null,
      setItem: (k: string, v: string) => {
        backing.set(k, v);
      },
      removeItem: (k: string) => {
        backing.delete(k);
      },
      clear: () => backing.clear(),
      key: (i: number) => Array.from(backing.keys())[i] ?? null,
    };
    Object.defineProperty(storage, "length", {
      get: () => backing.size,
    });
    (globalThis as unknown as { sessionStorage: Storage }).sessionStorage =
      storage as unknown as Storage;

    try {
      const sStore = new SessionStorageAuthRequestStorage();
      const record = {
        codeVerifier: "v",
        returnTo: "/dashboard",
        createdAt: Date.now(),
      };
      sStore.set("state-1", record);
      const fetched = sStore.get("state-1");
      assertEquals(fetched?.codeVerifier, "v");
      assertEquals(fetched?.returnTo, "/dashboard");

      sStore.delete("state-1");
      assertStrictEquals(sStore.get("state-1"), null);
    } finally {
      delete (globalThis as { sessionStorage?: Storage }).sessionStorage;
    }
  });

  it("prunes entries past ttlMs and treats them as missing", () => {
    const backing = new Map<string, string>();
    const storage = {
      get length() {
        return backing.size;
      },
      getItem: (k: string) => backing.get(k) ?? null,
      setItem: (k: string, v: string) => {
        backing.set(k, v);
      },
      removeItem: (k: string) => {
        backing.delete(k);
      },
      clear: () => backing.clear(),
      key: (i: number) => Array.from(backing.keys())[i] ?? null,
    };
    (globalThis as unknown as { sessionStorage: Storage }).sessionStorage =
      storage as unknown as Storage;

    try {
      const sStore = new SessionStorageAuthRequestStorage({ ttlMs: 50 });
      sStore.set("stale", {
        codeVerifier: "v",
        createdAt: Date.now() - 10_000,
      });
      assertStrictEquals(sStore.get("stale"), null);
      assertStrictEquals(backing.has("oauth2:auth-req:stale"), false);
    } finally {
      delete (globalThis as { sessionStorage?: Storage }).sessionStorage;
    }
  });
});
