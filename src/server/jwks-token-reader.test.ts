import {
  assert,
  assertEquals,
  assertRejects,
  assertStrictEquals,
  assertThrows,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { ServerError, TemporarilyUnavailableError } from "../errors.ts";
import { base64urlEncode } from "../utils/crypto.ts";
import {
  JwksTokenReader,
  type JwksTokenReaderOptions,
} from "./jwks-token-reader.ts";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";
const JWKS_URI = `${ISSUER}/jwks`;
const OAUTH_METADATA_URL = `${ISSUER}/.well-known/oauth-authorization-server`;
const OIDC_METADATA_URL = `${ISSUER}/.well-known/openid-configuration`;
const ALWAYS_STALE = Number.NEGATIVE_INFINITY;
const NEVER_THROTTLED = Number.NEGATIVE_INFINITY;

interface TestClient {
  id: string;
}

interface TestUser {
  id: string;
}

type PublishedJwk = JsonWebKey & { kid?: string };

interface TestKey {
  kid: string;
  alg: string;
  privateKey: CryptoKey;
  jwk: PublishedJwk;
}

const encoder = new TextEncoder();

const generateParams: Record<string, EcKeyGenParams | RsaHashedKeyGenParams> = {
  ES256: { name: "ECDSA", namedCurve: "P-256" },
  ES384: { name: "ECDSA", namedCurve: "P-384" },
  RS256: {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  PS256: {
    name: "RSA-PSS",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
};

const signParams: Record<
  string,
  AlgorithmIdentifier | EcdsaParams | RsaPssParams
> = {
  ES256: { name: "ECDSA", hash: "SHA-256" },
  ES384: { name: "ECDSA", hash: "SHA-384" },
  RS256: { name: "RSASSA-PKCS1-v1_5" },
  PS256: { name: "RSA-PSS", saltLength: 32 },
};

async function createKey(kid: string, alg = "ES256"): Promise<TestKey> {
  const pair = await crypto.subtle.generateKey(
    generateParams[alg],
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { kid, alg, privateKey: pair.privateKey, jwk: { ...jwk, kid, alg } };
}

function claimsFor(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    sub: "user-1",
    client_id: "my-client",
    aud: AUDIENCE,
    iat: now,
    exp: now + 3600,
    jti: crypto.randomUUID(),
    scope: "read write",
    ...overrides,
  };
}

function encodeSegment(value: unknown): string {
  return base64urlEncode(encoder.encode(JSON.stringify(value)));
}

async function signToken(
  key: TestKey,
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
): Promise<string> {
  const signingInput = `${
    encodeSegment({ alg: key.alg, typ: "at+jwt", kid: key.kid, ...header })
  }.${encodeSegment(claims)}`;
  const signature = await crypto.subtle.sign(
    signParams[key.alg],
    key.privateKey,
    encoder.encode(signingInput),
  );
  return `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
}

function mockFetch(
  handler: (url: string) => Response | Promise<Response>,
): { fetch: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl: typeof fetch = (input) => {
    const url = typeof input === "string"
      ? input
      : input instanceof URL
      ? input.toString()
      : input.url;
    calls.push(url);
    return Promise.resolve(handler(url));
  };
  return { fetch: fetchImpl, calls };
}

function jwksFetch(
  state: { keys: PublishedJwk[]; fail?: () => Response },
): { fetch: typeof fetch; calls: string[] } {
  return mockFetch((url) => {
    if (url !== JWKS_URI) return new Response("not found", { status: 404 });
    if (state.fail) return state.fail();
    return Response.json({ keys: state.keys });
  });
}

function neverRespondingFetch(): typeof fetch {
  return (_input, init) =>
    new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener(
        "abort",
        () => reject(new DOMException("request aborted", "AbortError")),
      );
    });
}

function createReader(
  fetchImpl: typeof fetch,
  options: Partial<JwksTokenReaderOptions<TestClient, TestUser>> = {},
): JwksTokenReader<TestClient, TestUser> {
  return new JwksTokenReader<TestClient, TestUser>({
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUri: JWKS_URI,
    getClient: (claims) => ({ id: String(claims.client_id) }),
    getUser: (claims) => claims.sub ? { id: claims.sub } : undefined,
    fetch: fetchImpl,
    ...options,
  });
}

describe("JwksTokenReader", () => {
  describe("valid tokens", () => {
    it("accepts an ES256 token signed by a published key", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor());

      const token = await reader.getToken(accessToken);

      assertStrictEquals(token?.accessToken, accessToken);
      assertStrictEquals(token?.client.id, "my-client");
      assertStrictEquals(token?.user?.id, "user-1");
      assertStrictEquals(token?.scope?.toString(), "read write");
      assert(token?.accessTokenExpiresAt instanceof Date);
    });

    it("surfaces the verified claims on the token", async () => {
      const key = await createKey("key-claims");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(
        key,
        claimsFor({ permissions: ["posts:write"], org_id: "org-1" }),
      );

      const token = await reader.getToken(accessToken);

      assertEquals(token?.claims?.permissions, ["posts:write"]);
      assertEquals(token?.claims?.org_id, "org-1");
      assertEquals(token?.claims?.iss, ISSUER);
    });

    it("accepts an RS256 token signed by a published RSA key", async () => {
      const key = await createKey("key-rsa", "RS256");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);

      const token = await reader.getToken(await signToken(key, claimsFor()));

      assertStrictEquals(token?.client.id, "my-client");
    });

    it("accepts a PS256 token signed by a published RSA key", async () => {
      const key = await createKey("key-pss", "PS256");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);

      const token = await reader.getToken(await signToken(key, claimsFor()));

      assertStrictEquals(token?.client.id, "my-client");
    });

    it("accepts an RSA key published without an alg", async () => {
      const key = await createKey("key-rsa", "RS256");
      const { alg: _alg, ...jwkWithoutAlg } = key.jwk;
      const { fetch } = jwksFetch({ keys: [jwkWithoutAlg] });
      const reader = createReader(fetch);

      const token = await reader.getToken(await signToken(key, claimsFor()));

      assertStrictEquals(token?.client.id, "my-client");
    });

    it("accepts a token whose aud array includes the configured audience", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(
        key,
        claimsFor({ aud: ["https://other.example.com", AUDIENCE] }),
      );

      assertStrictEquals(
        (await reader.getToken(accessToken))?.client.id,
        "my-client",
      );
    });

    it("accepts a token matching any of several configured audiences", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, {
        audience: ["https://other.example.com", AUDIENCE],
      });

      assertStrictEquals(
        (await reader.getToken(await signToken(key, claimsFor())))?.client.id,
        "my-client",
      );
    });

    it("accepts a token without a kid by trying every compatible key", async () => {
      const keyA = await createKey("key-a");
      const keyB = await createKey("key-b");
      const { fetch } = jwksFetch({ keys: [keyA.jwk, keyB.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(keyB, claimsFor(), {
        kid: undefined,
      });

      assertStrictEquals(
        (await reader.getToken(accessToken))?.client.id,
        "my-client",
      );
    });

    it("accepts the application/at+jwt long form of the typ header", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor(), {
        typ: "application/at+jwt",
      });

      assertStrictEquals(
        (await reader.getToken(accessToken))?.client.id,
        "my-client",
      );
    });

    it("accepts a plain JWT typ when configured to", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, { types: ["at+jwt", "jwt"] });
      const accessToken = await signToken(key, claimsFor(), { typ: "JWT" });

      assertStrictEquals(
        (await reader.getToken(accessToken))?.client.id,
        "my-client",
      );
    });

    it("skips the typ check when types is empty", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, { types: [] });
      const accessToken = await signToken(key, claimsFor(), { typ: undefined });

      assertStrictEquals(
        (await reader.getToken(accessToken))?.client.id,
        "my-client",
      );
    });

    it("reads scope from the scp array claim", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(
        key,
        claimsFor({ scope: undefined, scp: ["read", "write"] }),
      );

      assertStrictEquals(
        (await reader.getToken(accessToken))?.scope?.toString(),
        "read write",
      );
    });

    it("omits scope and user when the token carries neither", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, { getUser: undefined });
      const accessToken = await signToken(
        key,
        claimsFor({ scope: undefined, sub: undefined }),
      );
      const token = await reader.getToken(accessToken);

      assertStrictEquals(token?.scope, undefined);
      assertStrictEquals(token?.user, undefined);
    });

    it("awaits async mappers", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, {
        getClient: (claims) =>
          Promise.resolve({ id: String(claims.client_id) }),
        getUser: (claims) => Promise.resolve({ id: `db:${claims.sub}` }),
      });

      const token = await reader.getToken(await signToken(key, claimsFor()));

      assertStrictEquals(token?.user?.id, "db:user-1");
    });
  });

  describe("discovery", () => {
    it("discovers the jwks_uri from the issuer's metadata", async () => {
      const key = await createKey("key-a");
      const { fetch, calls } = mockFetch((url) => {
        if (url === OAUTH_METADATA_URL) {
          return Response.json({ issuer: ISSUER, jwks_uri: JWKS_URI });
        }
        if (url === JWKS_URI) return Response.json({ keys: [key.jwk] });
        return new Response("not found", { status: 404 });
      });
      const reader = createReader(fetch, { jwksUri: undefined });

      const token = await reader.getToken(await signToken(key, claimsFor()));

      assertStrictEquals(token?.client.id, "my-client");
      assertStrictEquals(calls[0], OAUTH_METADATA_URL);
      assertStrictEquals(calls[1], JWKS_URI);
    });

    it("falls back to openid-configuration", async () => {
      const key = await createKey("key-a");
      const { fetch, calls } = mockFetch((url) => {
        if (url === OIDC_METADATA_URL) {
          return Response.json({ issuer: ISSUER, jwks_uri: JWKS_URI });
        }
        if (url === JWKS_URI) return Response.json({ keys: [key.jwk] });
        return new Response("not found", { status: 404 });
      });
      const reader = createReader(fetch, { jwksUri: undefined });

      const token = await reader.getToken(await signToken(key, claimsFor()));

      assertStrictEquals(token?.client.id, "my-client");
      assertStrictEquals(calls[0], OAUTH_METADATA_URL);
      assertStrictEquals(calls[1], OIDC_METADATA_URL);
    });

    it("throws server_error when the metadata has no jwks_uri", async () => {
      const key = await createKey("key-a");
      const { fetch } = mockFetch(() => Response.json({ issuer: ISSUER }));
      const reader = createReader(fetch, { jwksUri: undefined });
      const accessToken = await signToken(key, claimsFor());

      await assertRejects(() => reader.getToken(accessToken), ServerError);
    });

    it("reuses a discovered jwks_uri across refreshes", async () => {
      const keyA = await createKey("key-a");
      const keyB = await createKey("key-b");
      const state = { keys: [keyA.jwk] };
      const { fetch, calls } = mockFetch((url) => {
        if (url === OAUTH_METADATA_URL) {
          return Response.json({ issuer: ISSUER, jwks_uri: JWKS_URI });
        }
        if (url === JWKS_URI) return Response.json({ keys: state.keys });
        return new Response("not found", { status: 404 });
      });
      const reader = createReader(fetch, {
        jwksUri: undefined,
        minFetchIntervalMs: 0,
      });
      await reader.getToken(await signToken(keyA, claimsFor()));

      state.keys = [keyB.jwk];
      await reader.getToken(await signToken(keyB, claimsFor()));

      assertStrictEquals(
        calls.filter((url) => url === OAUTH_METADATA_URL).length,
        1,
      );
    });
  });

  describe("caching and rotation", () => {
    it("fetches the JWKS once and serves later tokens from cache", async () => {
      const key = await createKey("key-a");
      const { fetch, calls } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);

      await reader.getToken(await signToken(key, claimsFor()));
      await reader.getToken(await signToken(key, claimsFor()));

      assertStrictEquals(calls.length, 1);
    });

    it("refetches on every read when cacheMaxAgeMs keeps the cache stale", async () => {
      const key = await createKey("key-a");
      const { fetch, calls } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, {
        cacheMaxAgeMs: ALWAYS_STALE,
        minFetchIntervalMs: NEVER_THROTTLED,
      });

      await reader.getToken(await signToken(key, claimsFor()));
      await reader.getToken(await signToken(key, claimsFor()));

      assertStrictEquals(calls.length, 2);
    });

    it("refetches once when a token names an unknown kid", async () => {
      const keyA = await createKey("key-a");
      const keyB = await createKey("key-b");
      const state = { keys: [keyA.jwk] };
      const { fetch, calls } = jwksFetch(state);
      const reader = createReader(fetch, { minFetchIntervalMs: 0 });
      await reader.getToken(await signToken(keyA, claimsFor()));

      state.keys = [keyA.jwk, keyB.jwk];
      const token = await reader.getToken(await signToken(keyB, claimsFor()));

      assertStrictEquals(token?.client.id, "my-client");
      assertStrictEquals(calls.length, 2);
    });

    it("dedupes concurrent refetches for the same unknown kid", async () => {
      const keyA = await createKey("key-a");
      const keyB = await createKey("key-b");
      const state = { keys: [keyA.jwk] };
      const { fetch, calls } = jwksFetch(state);
      const reader = createReader(fetch, { minFetchIntervalMs: 0 });
      await reader.getToken(await signToken(keyA, claimsFor()));

      state.keys = [keyB.jwk];
      const accessToken = await signToken(keyB, claimsFor());
      const results = await Promise.all(
        Array.from({ length: 8 }, () => reader.getToken(accessToken)),
      );

      assertStrictEquals(calls.length, 2);
      for (const result of results) {
        assertStrictEquals(result?.client.id, "my-client");
      }
    });

    it("dedupes the concurrent initial fetch", async () => {
      const key = await createKey("key-a");
      const { fetch, calls } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor());

      await Promise.all(
        Array.from({ length: 8 }, () => reader.getToken(accessToken)),
      );

      assertStrictEquals(calls.length, 1);
    });

    it("does not refetch for unknown kids within the minimum fetch interval", async () => {
      const keyA = await createKey("key-a");
      const keyB = await createKey("key-b");
      const state = { keys: [keyA.jwk] };
      const { fetch, calls } = jwksFetch(state);
      const reader = createReader(fetch, { minFetchIntervalMs: 60_000 });
      await reader.getToken(await signToken(keyA, claimsFor()));

      state.keys = [keyA.jwk, keyB.jwk];
      for (let attempt = 0; attempt < 20; attempt++) {
        const unknown = await createKey(`attacker-${attempt}`);
        assertStrictEquals(
          await reader.getToken(await signToken(unknown, claimsFor())),
          undefined,
        );
      }

      assertStrictEquals(calls.length, 1);
    });

    it("keeps serving cached keys when a refresh fails", async () => {
      const key = await createKey("key-a");
      const state: { keys: PublishedJwk[]; fail?: () => Response } = {
        keys: [key.jwk],
      };
      const { fetch, calls } = jwksFetch(state);
      const reader = createReader(fetch, {
        cacheMaxAgeMs: ALWAYS_STALE,
        minFetchIntervalMs: NEVER_THROTTLED,
      });
      await reader.getToken(await signToken(key, claimsFor()));

      state.fail = () => new Response("boom", { status: 503 });
      const token = await reader.getToken(await signToken(key, claimsFor()));

      assertStrictEquals(token?.client.id, "my-client");
      assertStrictEquals(calls.length, 2);
    });
  });

  describe("rejected tokens", () => {
    it("rejects malformed tokens without touching the network", async () => {
      const { fetch, calls } = jwksFetch({ keys: [] });
      const reader = createReader(fetch);

      for (
        const malformed of [
          "",
          "not-a-jwt",
          "a.b",
          "a.b.c.d",
          "!!!.???.###",
          `${btoa("[]")}.${btoa("{}")}.sig`,
        ]
      ) {
        assertStrictEquals(await reader.getToken(malformed), undefined);
      }

      assertStrictEquals(calls.length, 0);
    });

    it("rejects a token signed by an unpublished key without refetching", async () => {
      const published = await createKey("key-a");
      const attacker = await createKey("key-a");
      const { fetch, calls } = jwksFetch({ keys: [published.jwk] });
      const reader = createReader(fetch, { minFetchIntervalMs: 0 });

      assertStrictEquals(
        await reader.getToken(await signToken(attacker, claimsFor())),
        undefined,
      );
      assertStrictEquals(calls.length, 1);
    });

    it("rejects a token whose kid is still unknown after a refetch", async () => {
      const published = await createKey("key-a");
      const rotated = await createKey("key-c");
      const { fetch, calls } = jwksFetch({ keys: [published.jwk] });
      const reader = createReader(fetch, { minFetchIntervalMs: 0 });

      assertStrictEquals(
        await reader.getToken(await signToken(rotated, claimsFor())),
        undefined,
      );
      assertStrictEquals(calls.length, 2);
    });

    it("rejects a token from another issuer", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(
        key,
        claimsFor({ iss: "https://evil.example.com" }),
      );

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects a token minted for another audience", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(
        key,
        claimsFor({ aud: "https://other.example.com" }),
      );

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects a token with no audience", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor({ aud: undefined }));

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects an expired token", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const now = Math.floor(Date.now() / 1000);
      const accessToken = await signToken(key, claimsFor({ exp: now - 3600 }));

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects a token with no exp claim", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor({ exp: undefined }));

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects a token whose exp is not a number", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor({ exp: "later" }));

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects a token whose nbf is in the future", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const now = Math.floor(Date.now() / 1000);
      const accessToken = await signToken(key, claimsFor({ nbf: now + 3600 }));

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects a token with the wrong typ header", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor(), { typ: "JWT" });

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects an unsigned token claiming alg none", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = `${
        encodeSegment({ alg: "none", typ: "at+jwt", kid: key.kid })
      }.${encodeSegment(claimsFor())}.`;

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects an HS256 token even when the JWKS publishes a symmetric key", async () => {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const hmacKey = await crypto.subtle.importKey(
        "raw",
        secret,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
      );
      const signingInput = `${
        encodeSegment({ alg: "HS256", typ: "at+jwt", kid: "key-hmac" })
      }.${encodeSegment(claimsFor())}`;
      const signature = await crypto.subtle.sign(
        "HMAC",
        hmacKey,
        encoder.encode(signingInput),
      );
      const accessToken = `${signingInput}.${
        base64urlEncode(new Uint8Array(signature))
      }`;
      const { fetch } = jwksFetch({
        keys: [{
          kty: "oct",
          k: base64urlEncode(secret),
          alg: "HS256",
          kid: "key-hmac",
        }],
      });
      const reader = createReader(fetch);

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects a header alg the published key does not carry", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor(), { alg: "RS256" });

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects an algorithm outside the configured allowlist", async () => {
      const key = await createKey("key-384", "ES384");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, { algorithms: ["ES256"] });

      assertStrictEquals(
        await reader.getToken(await signToken(key, claimsFor())),
        undefined,
      );
    });

    it("ignores published keys marked for encryption", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [{ ...key.jwk, use: "enc" }] });
      const reader = createReader(fetch);

      assertStrictEquals(
        await reader.getToken(await signToken(key, claimsFor())),
        undefined,
      );
    });
  });

  describe("clock skew", () => {
    it("accepts a token that expired within the skew", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, { clockSkewSeconds: 120 });
      const now = Math.floor(Date.now() / 1000);
      const accessToken = await signToken(key, claimsFor({ exp: now - 30 }));

      assertStrictEquals(
        (await reader.getToken(accessToken))?.client.id,
        "my-client",
      );
    });

    it("rejects a token that expired beyond the skew", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, { clockSkewSeconds: 10 });
      const now = Math.floor(Date.now() / 1000);
      const accessToken = await signToken(key, claimsFor({ exp: now - 30 }));

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("accepts an nbf that is in the future within the skew", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, { clockSkewSeconds: 120 });
      const now = Math.floor(Date.now() / 1000);
      const accessToken = await signToken(key, claimsFor({ nbf: now + 30 }));

      assertStrictEquals(
        (await reader.getToken(accessToken))?.client.id,
        "my-client",
      );
    });

    it("rejects an nbf beyond the skew", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, { clockSkewSeconds: 10 });
      const now = Math.floor(Date.now() / 1000);
      const accessToken = await signToken(key, claimsFor({ nbf: now + 30 }));

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });
  });

  describe("unavailable key material", () => {
    it("throws temporarily_unavailable when the endpoint is unreachable", async () => {
      const key = await createKey("key-a");
      const { fetch } = mockFetch(() => {
        throw new TypeError("network down");
      });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor());

      await assertRejects(
        () => reader.getToken(accessToken),
        TemporarilyUnavailableError,
      );
    });

    it("throws temporarily_unavailable on a 5xx", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({
        keys: [],
        fail: () => new Response("boom", { status: 503 }),
      });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor());

      await assertRejects(
        () => reader.getToken(accessToken),
        TemporarilyUnavailableError,
      );
    });

    it("throws server_error on a 4xx", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({
        keys: [],
        fail: () => new Response("nope", { status: 404 }),
      });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor());

      await assertRejects(() => reader.getToken(accessToken), ServerError);
    });

    it("throws server_error when the body is not a JWKS", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({
        keys: [],
        fail: () => Response.json({ nope: true }),
      });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor());

      await assertRejects(() => reader.getToken(accessToken), ServerError);
    });

    it("does not retry a failed fetch within the minimum fetch interval", async () => {
      const key = await createKey("key-a");
      const { fetch, calls } = jwksFetch({
        keys: [],
        fail: () => new Response("boom", { status: 503 }),
      });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor());

      await assertRejects(
        () => reader.getToken(accessToken),
        TemporarilyUnavailableError,
      );
      await assertRejects(
        () => reader.getToken(accessToken),
        TemporarilyUnavailableError,
      );

      assertStrictEquals(calls.length, 1);
    });
  });

  describe("token substitution", () => {
    it("rejects an id_token even when typ and audience would both pass", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, {
        types: ["at+jwt", "jwt"],
        audience: "my-client",
      });
      const now = Math.floor(Date.now() / 1000);
      const idToken = await signToken(key, {
        iss: ISSUER,
        sub: "user-1",
        aud: "my-client",
        iat: now,
        exp: now + 3600,
        nonce: "n-abc",
        at_hash: "kR8mQ2p",
        auth_time: now,
      }, { typ: "JWT" });

      assertStrictEquals(await reader.getToken(idToken), undefined);
    });

    it("rejects a token with no client_id claim", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(
        key,
        claimsFor({ client_id: undefined }),
      );

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });

    it("rejects a token carrying id_token-only claims", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);

      for (const claim of ["nonce", "at_hash", "c_hash", "s_hash"]) {
        const accessToken = await signToken(
          key,
          claimsFor({ [claim]: "value" }),
        );
        assertStrictEquals(
          await reader.getToken(accessToken),
          undefined,
          `expected a token carrying ${claim} to be rejected`,
        );
      }
    });

    it("accepts auth_time, acr and amr, which RFC 9068 permits", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const now = Math.floor(Date.now() / 1000);
      const accessToken = await signToken(
        key,
        claimsFor({
          auth_time: now,
          acr: "urn:mace:incommon:iap:silver",
          amr: ["pwd"],
        }),
      );

      assertStrictEquals(
        (await reader.getToken(accessToken))?.client.id,
        "my-client",
      );
    });

    it("reads the client id from a vendor claim when configured", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch, {
        clientIdClaim: "cid",
        getClient: (claims) => ({ id: String(claims.cid) }),
      });
      const accessToken = await signToken(
        key,
        claimsFor({ client_id: undefined, cid: "okta-client" }),
      );

      assertStrictEquals(
        (await reader.getToken(accessToken))?.client.id,
        "okta-client",
      );
    });

    it("rejects a token with a crit header it does not understand", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({ keys: [key.jwk] });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor(), {
        crit: ["http://example.invalid/UNDEFINED"],
        "http://example.invalid/UNDEFINED": true,
      });

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });
  });

  describe("rotation without a kid", () => {
    it("refetches when no cached key verifies a kid-less token", async () => {
      const keyA = await createKey("key-a");
      const keyB = await createKey("key-b");
      const { kid: _kidA, ...jwkA } = keyA.jwk;
      const { kid: _kidB, ...jwkB } = keyB.jwk;
      const state = { keys: [jwkA] };
      const { fetch, calls } = jwksFetch(state);
      const reader = createReader(fetch, { minFetchIntervalMs: 0 });
      await reader.getToken(
        await signToken(keyA, claimsFor(), { kid: undefined }),
      );
      assertStrictEquals(calls.length, 1);

      state.keys = [jwkB];
      const token = await reader.getToken(
        await signToken(keyB, claimsFor(), { kid: undefined }),
      );

      assertStrictEquals(token?.client.id, "my-client");
      assertStrictEquals(calls.length, 2);
    });

    it("throttles kid-less refetches to the minimum interval", async () => {
      const keyA = await createKey("key-a");
      const { kid: _kidA, ...jwkA } = keyA.jwk;
      const state = { keys: [jwkA] };
      const { fetch, calls } = jwksFetch(state);
      const reader = createReader(fetch, { minFetchIntervalMs: 60_000 });
      await reader.getToken(
        await signToken(keyA, claimsFor(), { kid: undefined }),
      );

      for (let attempt = 0; attempt < 10; attempt++) {
        const attacker = await createKey(`attacker-${attempt}`);
        assertStrictEquals(
          await reader.getToken(
            await signToken(attacker, claimsFor(), { kid: undefined }),
          ),
          undefined,
        );
      }

      assertStrictEquals(calls.length, 1);
    });
  });

  describe("unresponsive JWKS endpoint", () => {
    it("aborts a request that never responds", async () => {
      const key = await createKey("key-a");
      const reader = createReader(neverRespondingFetch(), {
        fetchTimeoutMs: 10,
      });
      const accessToken = await signToken(key, claimsFor());

      await assertRejects(
        () => reader.getToken(accessToken),
        TemporarilyUnavailableError,
      );
    });

    it("serves cached keys without blocking on a hanging refresh", async () => {
      const key = await createKey("key-a");
      const state = { hang: false };
      let release: (() => void) | undefined;
      const { fetch, calls } = mockFetch((url) => {
        if (url !== JWKS_URI) return new Response("not found", { status: 404 });
        if (!state.hang) return Response.json({ keys: [key.jwk] });
        return new Promise<Response>((resolve) => {
          release = () => resolve(Response.json({ keys: [key.jwk] }));
        });
      });
      const reader = createReader(fetch, {
        cacheMaxAgeMs: ALWAYS_STALE,
        minFetchIntervalMs: NEVER_THROTTLED,
      });
      await reader.getToken(await signToken(key, claimsFor()));

      state.hang = true;
      const token = await reader.getToken(await signToken(key, claimsFor()));

      assertStrictEquals(token?.client.id, "my-client");
      assertStrictEquals(calls.length, 2);
      release!();
    });
  });

  describe("malformed JWKS documents", () => {
    it("throws server_error for a null body", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({
        keys: [],
        fail: () => Response.json(null),
      });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor());

      await assertRejects(() => reader.getToken(accessToken), ServerError);
    });

    it("throws server_error when keys is not an array", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({
        keys: [],
        fail: () => Response.json({ keys: "nope" }),
      });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor());

      await assertRejects(() => reader.getToken(accessToken), ServerError);
    });

    it("drops keys whose members have the wrong types", async () => {
      const key = await createKey("key-a");
      const { fetch } = jwksFetch({
        keys: [
          { ...key.jwk, key_ops: 5 } as unknown as PublishedJwk,
          { ...key.jwk, alg: 5 } as unknown as PublishedJwk,
          null as unknown as PublishedJwk,
          "not-a-key" as unknown as PublishedJwk,
        ],
      });
      const reader = createReader(fetch);
      const accessToken = await signToken(key, claimsFor());

      assertStrictEquals(await reader.getToken(accessToken), undefined);
    });
  });

  describe("discovery URL construction", () => {
    const TENANT_ISSUER = "https://auth.example.com/tenants/acme";
    const TENANT_OAUTH_URL =
      "https://auth.example.com/.well-known/oauth-authorization-server/tenants/acme";
    const TENANT_OIDC_INSERTED =
      "https://auth.example.com/.well-known/openid-configuration/tenants/acme";
    const TENANT_OIDC_APPENDED =
      "https://auth.example.com/tenants/acme/.well-known/openid-configuration";

    it("inserts the well-known segment before the issuer path (RFC 8414)", async () => {
      const key = await createKey("key-a");
      const { fetch, calls } = mockFetch((url) => {
        if (url === TENANT_OAUTH_URL) {
          return Response.json({ issuer: TENANT_ISSUER, jwks_uri: JWKS_URI });
        }
        if (url === JWKS_URI) return Response.json({ keys: [key.jwk] });
        return new Response("not found", { status: 404 });
      });
      const reader = createReader(fetch, {
        issuer: TENANT_ISSUER,
        jwksUri: undefined,
      });
      const accessToken = await signToken(
        key,
        claimsFor({ iss: TENANT_ISSUER }),
      );

      assertStrictEquals(
        (await reader.getToken(accessToken))?.client.id,
        "my-client",
      );
      assertStrictEquals(calls[0], TENANT_OAUTH_URL);
    });

    it("falls back to the appended OIDC form last", async () => {
      const key = await createKey("key-a");
      const { fetch, calls } = mockFetch((url) => {
        if (url === TENANT_OIDC_APPENDED) {
          return Response.json({ issuer: TENANT_ISSUER, jwks_uri: JWKS_URI });
        }
        if (url === JWKS_URI) return Response.json({ keys: [key.jwk] });
        return new Response("not found", { status: 404 });
      });
      const reader = createReader(fetch, {
        issuer: TENANT_ISSUER,
        jwksUri: undefined,
      });
      const accessToken = await signToken(
        key,
        claimsFor({ iss: TENANT_ISSUER }),
      );

      assertStrictEquals(
        (await reader.getToken(accessToken))?.client.id,
        "my-client",
      );
      assertEquals(calls.slice(0, 3), [
        TENANT_OAUTH_URL,
        TENANT_OIDC_INSERTED,
        TENANT_OIDC_APPENDED,
      ]);
    });

    it("tries only one openid-configuration URL for a path-less issuer", async () => {
      const key = await createKey("key-a");
      const { fetch, calls } = mockFetch((url) => {
        if (url === JWKS_URI) return Response.json({ keys: [key.jwk] });
        return new Response("not found", { status: 404 });
      });
      const reader = createReader(fetch, { jwksUri: undefined });
      const accessToken = await signToken(key, claimsFor());

      await assertRejects(() => reader.getToken(accessToken), ServerError);
      assertEquals(calls, [OAUTH_METADATA_URL, OIDC_METADATA_URL]);
    });

    it("reports a transient discovery failure over a later permanent one", async () => {
      const key = await createKey("key-a");
      const { fetch } = mockFetch((url) => {
        if (url === OAUTH_METADATA_URL) {
          return new Response("boom", { status: 503 });
        }
        return new Response("not found", { status: 404 });
      });
      const reader = createReader(fetch, { jwksUri: undefined });
      const accessToken = await signToken(key, claimsFor());

      await assertRejects(
        () => reader.getToken(accessToken),
        TemporarilyUnavailableError,
      );
    });
  });

  describe("configuration", () => {
    it("rejects an issuer that is not an absolute URL", () => {
      assertThrows(
        () =>
          createReader(jwksFetch({ keys: [] }).fetch, { issuer: "auth.local" }),
        TypeError,
      );
    });

    it("rejects an algorithm it cannot verify", () => {
      assertThrows(
        () =>
          createReader(jwksFetch({ keys: [] }).fetch, {
            algorithms: ["HS256"],
          }),
        TypeError,
      );
    });

    it("rejects an empty audience list", () => {
      assertThrows(
        () => createReader(jwksFetch({ keys: [] }).fetch, { audience: [] }),
        TypeError,
      );
    });
  });
});
