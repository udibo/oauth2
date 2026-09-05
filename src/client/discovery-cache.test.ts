import {
  assertEquals,
  assertRejects,
  assertStrictEquals,
  assertThrows,
} from "@std/assert";
import { delay } from "@std/async/delay";
import { describe, it } from "@std/testing/bdd";
import { FakeTime } from "@std/testing/time";

import type { AuthorizationServerMetadata } from "../models/responses.ts";
import { DirectClient } from "./direct-client.ts";
import {
  DEFAULT_DISCOVERY_TTL_MS,
  type DiscoveryCache,
  MemoryDiscoveryCache,
} from "./discovery-cache.ts";

type DiscoveryCacheEntry = Awaited<ReturnType<DiscoveryCache["resolve"]>>;

const ISSUER = "https://sso.example";

function metadata(issuer: string): AuthorizationServerMetadata {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
  };
}

function countingLoader(issuer = ISSUER): {
  load: () => Promise<AuthorizationServerMetadata>;
  calls: () => number;
} {
  let calls = 0;
  return {
    load: () => {
      calls++;
      return Promise.resolve(metadata(issuer));
    },
    calls: () => calls,
  };
}

function discoveryFetch(issuer: string): {
  fetch: typeof fetch;
  calls: () => number;
} {
  let calls = 0;
  return {
    fetch: (input) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.endsWith("/.well-known/openid-configuration")) {
        calls++;
        return Promise.resolve(Response.json(metadata(issuer)));
      }
      return Promise.resolve(new Response("Not Found", { status: 404 }));
    },
    calls: () => calls,
  };
}

function countingCache(inner: DiscoveryCache): {
  cache: DiscoveryCache;
  reads: () => number;
} {
  let reads = 0;
  return {
    cache: {
      resolve: (
        issuer: string,
        load: () => Promise<AuthorizationServerMetadata>,
      ): Promise<DiscoveryCacheEntry> => {
        reads++;
        return inner.resolve(issuer, load);
      },
    },
    reads: () => reads,
  };
}

function issuerClient(
  fetchImpl: typeof fetch,
  discoveryCache?: MemoryDiscoveryCache,
): DirectClient {
  return new DirectClient({
    clientId: "web-app",
    issuer: ISSUER,
    fetch: fetchImpl,
    discoveryCache,
  });
}

describe("MemoryDiscoveryCache", () => {
  it("serves a cached entry without loading again", async () => {
    const cache = new MemoryDiscoveryCache();
    const { load, calls } = countingLoader();

    const first = await cache.resolve(ISSUER, load);
    const second = await cache.resolve(ISSUER, load);

    assertEquals(first.metadata.issuer, ISSUER);
    assertStrictEquals(second.metadata, first.metadata);
    assertStrictEquals(calls(), 1);
  });

  it("keys entries by issuer, ignoring a trailing slash", async () => {
    const cache = new MemoryDiscoveryCache();
    const first = countingLoader(ISSUER);
    const other = countingLoader("https://other.example");

    await cache.resolve(ISSUER, first.load);
    await cache.resolve(`${ISSUER}/`, first.load);
    const otherMeta = await cache.resolve("https://other.example", other.load);

    assertStrictEquals(first.calls(), 1);
    assertStrictEquals(other.calls(), 1);
    assertEquals(otherMeta.metadata.issuer, "https://other.example");
  });

  it("reloads once the entry expires", async () => {
    using time = new FakeTime();
    const cache = new MemoryDiscoveryCache({ ttlMs: 60_000 });
    const { load, calls } = countingLoader();

    await cache.resolve(ISSUER, load);
    time.tick(59_999);
    await cache.resolve(ISSUER, load);
    assertStrictEquals(calls(), 1);

    time.tick(2);
    await cache.resolve(ISSUER, load);
    assertStrictEquals(calls(), 2);
  });

  it("collapses concurrent misses into one load", async () => {
    const cache = new MemoryDiscoveryCache();
    let calls = 0;
    const load = async (): Promise<AuthorizationServerMetadata> => {
      calls++;
      await delay(5);
      return metadata(ISSUER);
    };

    const results = await Promise.all([
      cache.resolve(ISSUER, load),
      cache.resolve(ISSUER, load),
      cache.resolve(ISSUER, load),
    ]);

    assertStrictEquals(calls, 1);
    assertStrictEquals(results[1].metadata, results[0].metadata);
    assertStrictEquals(results[2].metadata, results[0].metadata);
  });

  it("does not cache a failed load, and retries on the next call", async () => {
    const cache = new MemoryDiscoveryCache();
    let calls = 0;
    const load = (): Promise<AuthorizationServerMetadata> => {
      calls++;
      return calls === 1
        ? Promise.reject(new Error("issuer unreachable"))
        : Promise.resolve(metadata(ISSUER));
    };

    await assertRejects(
      () => cache.resolve(ISSUER, load),
      Error,
      "issuer unreachable",
    );

    const recovered = await cache.resolve(ISSUER, load);
    assertEquals(recovered.metadata.issuer, ISSUER);
    assertStrictEquals(calls, 2);
  });

  it("rejects every concurrent caller of a failed load without caching it", async () => {
    const cache = new MemoryDiscoveryCache();
    let calls = 0;
    const load = async (): Promise<AuthorizationServerMetadata> => {
      calls++;
      await delay(5);
      throw new Error("issuer unreachable");
    };

    const results = await Promise.allSettled([
      cache.resolve(ISSUER, load),
      cache.resolve(ISSUER, load),
    ]);

    assertEquals(results.map((result) => result.status), [
      "rejected",
      "rejected",
    ]);
    assertStrictEquals(calls, 1);

    const { load: succeed, calls: successCalls } = countingLoader();
    await cache.resolve(ISSUER, succeed);
    assertStrictEquals(successCalls(), 1);
  });

  it("drops the entry on delete and clear", async () => {
    const cache = new MemoryDiscoveryCache();
    const { load, calls } = countingLoader();

    await cache.resolve(ISSUER, load);
    cache.delete(`${ISSUER}/`);
    await cache.resolve(ISSUER, load);
    assertStrictEquals(calls(), 2);

    cache.clear();
    await cache.resolve(ISSUER, load);
    assertStrictEquals(calls(), 3);
  });

  it("hands out metadata a consumer cannot mutate into the cache", async () => {
    const cache = new MemoryDiscoveryCache();
    const { load, calls } = countingLoader();

    const first = await cache.resolve(ISSUER, load);
    assertThrows(() => {
      first.metadata.token_endpoint = "https://evil.example/token";
    }, TypeError);
    assertThrows(() => {
      first.metadata.scopes_supported = ["openid"];
    }, TypeError);

    const second = await cache.resolve(ISSUER, load);
    assertEquals(second.metadata.token_endpoint, `${ISSUER}/token`);
    assertStrictEquals(calls(), 1);
  });

  it("freezes nested metadata values", async () => {
    const cache = new MemoryDiscoveryCache();
    const cached = await cache.resolve(ISSUER, () =>
      Promise.resolve({
        ...metadata(ISSUER),
        scopes_supported: ["openid", "email"],
      }));

    assertThrows(() => {
      cached.metadata.scopes_supported!.push("profile");
    }, TypeError);
    assertEquals(cached.metadata.scopes_supported, ["openid", "email"]);
  });

  it("keeps a recently read entry over a stale one when evicting", async () => {
    const cache = new MemoryDiscoveryCache({ maxEntries: 2 });
    const read = countingLoader("https://read.example");
    const idle = countingLoader("https://idle.example");
    const fresh = countingLoader("https://fresh.example");

    await cache.resolve("https://read.example", read.load);
    await cache.resolve("https://idle.example", idle.load);
    await cache.resolve("https://read.example", read.load);
    await cache.resolve("https://fresh.example", fresh.load);

    await cache.resolve("https://read.example", read.load);
    assertStrictEquals(read.calls(), 1);

    await cache.resolve("https://idle.example", idle.load);
    assertStrictEquals(idle.calls(), 2);
  });

  it("evicts the least recently used entry past maxEntries", async () => {
    const cache = new MemoryDiscoveryCache({ maxEntries: 2 });
    const oldest = countingLoader("https://a.example");
    const middle = countingLoader("https://b.example");
    const newest = countingLoader("https://c.example");

    await cache.resolve("https://a.example", oldest.load);
    await cache.resolve("https://b.example", middle.load);
    await cache.resolve("https://c.example", newest.load);

    await cache.resolve("https://b.example", middle.load);
    await cache.resolve("https://c.example", newest.load);
    assertStrictEquals(middle.calls(), 1);
    assertStrictEquals(newest.calls(), 1);

    await cache.resolve("https://a.example", oldest.load);
    assertStrictEquals(oldest.calls(), 2);
  });

  it("reports when its entry expires so a reader can hold the document", async () => {
    using time = new FakeTime();
    const cache = new MemoryDiscoveryCache({ ttlMs: 60_000 });
    const { load } = countingLoader();

    const loaded = await cache.resolve(ISSUER, load);
    assertStrictEquals(loaded.expiresAt, Date.now() + 60_000);

    time.tick(30_000);
    const hit = await cache.resolve(ISSUER, load);
    assertStrictEquals(
      hit.expiresAt,
      loaded.expiresAt,
      "a hit reports the stored entry's expiry, not a renewed one",
    );
  });

  it("defaults to a one hour lifetime", async () => {
    using time = new FakeTime();
    const cache = new MemoryDiscoveryCache();
    const { load, calls } = countingLoader();

    await cache.resolve(ISSUER, load);
    time.tick(DEFAULT_DISCOVERY_TTL_MS - 1);
    await cache.resolve(ISSUER, load);
    assertStrictEquals(calls(), 1);

    time.tick(2);
    await cache.resolve(ISSUER, load);
    assertStrictEquals(calls(), 2);
  });
});

describe("DirectClient discovery cache", () => {
  it("shares one discovery fetch across clients built per request", async () => {
    const cache = new MemoryDiscoveryCache();
    const { fetch: fetchImpl, calls } = discoveryFetch(ISSUER);

    const first = await issuerClient(fetchImpl, cache).discover();
    const second = await issuerClient(fetchImpl, cache).discover();

    assertEquals(first.token_endpoint, `${ISSUER}/token`);
    assertEquals(second.token_endpoint, `${ISSUER}/token`);
    assertStrictEquals(calls(), 1);
  });

  it("applies cached metadata to the endpoints of the client that read it", async () => {
    const cache = new MemoryDiscoveryCache();
    const { fetch: fetchImpl } = discoveryFetch(ISSUER);

    await issuerClient(fetchImpl, cache).discover();
    const client = issuerClient(fetchImpl, cache);
    await client.discover();

    assertEquals(client.authorizationEndpoint, `${ISSUER}/authorize`);
  });

  it("re-fetches per client without a shared cache", async () => {
    const { fetch: fetchImpl, calls } = discoveryFetch(ISSUER);

    await issuerClient(fetchImpl).discover();
    await issuerClient(fetchImpl).discover();

    assertStrictEquals(calls(), 2);
  });

  it("re-resolves discovery once the per-client memo expires", async () => {
    using time = new FakeTime();
    const { fetch: fetchImpl, calls } = discoveryFetch(ISSUER);
    const client = issuerClient(fetchImpl);

    await client.discover();
    time.tick(DEFAULT_DISCOVERY_TTL_MS - 1);
    await client.discover();
    assertStrictEquals(calls(), 1);

    time.tick(2);
    await client.discover();
    assertStrictEquals(calls(), 2);
  });

  it("lets a shared cache's TTL, not the client, decide when to reload", async () => {
    using time = new FakeTime();
    const cache = new MemoryDiscoveryCache({ ttlMs: 60_000 });
    const { fetch: fetchImpl, calls } = discoveryFetch(ISSUER);
    const client = issuerClient(fetchImpl, cache);

    await client.discover();
    time.tick(59_999);
    await client.discover();
    assertStrictEquals(calls(), 1);

    time.tick(2);
    await client.discover();
    assertStrictEquals(calls(), 2);
  });

  it("picks up a moved endpoint on the next endpoint use after expiry", async () => {
    using time = new FakeTime();
    let authorizeEndpoint = `${ISSUER}/authorize`;
    const fetchImpl: typeof fetch = (input) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.endsWith("/.well-known/openid-configuration")) {
        return Promise.resolve(Response.json({
          issuer: ISSUER,
          authorization_endpoint: authorizeEndpoint,
          token_endpoint: `${ISSUER}/token`,
        }));
      }
      return Promise.resolve(new Response("Not Found", { status: 404 }));
    };
    const client = new DirectClient({
      clientId: "web-app",
      issuer: ISSUER,
      redirectUri: "https://app.example/callback",
      fetch: fetchImpl,
    });

    await client.login();
    assertEquals(client.authorizationEndpoint, `${ISSUER}/authorize`);

    authorizeEndpoint = `${ISSUER}/oauth2/authorize`;
    time.tick(DEFAULT_DISCOVERY_TTL_MS + 1);
    await client.login();

    assertEquals(client.authorizationEndpoint, `${ISSUER}/oauth2/authorize`);
  });

  it("reads the shared cache once per TTL window however many endpoints are needed", async () => {
    using time = new FakeTime();
    const { cache, reads } = countingCache(
      new MemoryDiscoveryCache({ ttlMs: 60_000 }),
    );
    const { fetch: fetchImpl, calls } = discoveryFetch(ISSUER);
    const client = new DirectClient({
      clientId: "web-app",
      issuer: ISSUER,
      redirectUri: "https://app.example/callback",
      fetch: fetchImpl,
      discoveryCache: cache,
    });

    await client.login();
    await client.login();
    await client.discover();
    assertStrictEquals(reads(), 1);
    assertStrictEquals(calls(), 1);

    time.tick(60_001);
    await client.login();
    assertStrictEquals(reads(), 2);
    assertStrictEquals(calls(), 2);
  });

  it("leaves the shared cache usable after a failed discovery", async () => {
    const cache = new MemoryDiscoveryCache();
    let fail = true;
    const { fetch: fetchImpl, calls } = discoveryFetch(ISSUER);
    const flakyFetch: typeof fetch = (input, init) => {
      if (fail) return Promise.reject(new TypeError("network error"));
      return fetchImpl(input, init);
    };

    await assertRejects(() => issuerClient(flakyFetch, cache).discover());

    fail = false;
    const meta = await issuerClient(flakyFetch, cache).discover();
    assertEquals(meta.issuer, ISSUER);
    assertStrictEquals(calls(), 1);
  });
});
