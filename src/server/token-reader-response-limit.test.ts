import { describe, expect, it } from "vitest";
import { rejection, thrown } from "../_test_assert.ts";
import {
  jsonOfSize,
  type Reply,
  serveReplies,
} from "../_test_response-server.ts";
import { ServerError, TemporarilyUnavailableError } from "../errors.ts";
import { base64urlEncode } from "../utils/crypto.ts";
import { IntrospectionTokenReader } from "./introspection-token-reader.ts";
import {
  JwksTokenReader,
  type JwksTokenReaderOptions,
} from "./jwks-token-reader.ts";

const AUDIENCE = "https://api.example.com";
const JWKS_DEFAULT_LIMIT = 256 * 1024;
const INTROSPECTION_DEFAULT_LIMIT = 64 * 1024;
const encoder = new TextEncoder();

interface TestClient {
  id: string;
}

interface SigningPair {
  privateKey: CryptoKey;
  jwk: JsonWebKey & { kid: string; alg: string };
}

async function createKey(): Promise<SigningPair> {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    privateKey: pair.privateKey,
    jwk: { ...jwk, kid: "key-a", alg: "ES256" },
  };
}

function segment(value: unknown): string {
  return base64urlEncode(encoder.encode(JSON.stringify(value)));
}

async function signToken(key: SigningPair, issuer: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const input = `${segment({ alg: "ES256", typ: "at+jwt", kid: "key-a" })}.${segment(
    {
      iss: issuer,
      sub: "user-1",
      client_id: "my-client",
      aud: AUDIENCE,
      iat: now,
      exp: now + 3600,
      jti: crypto.randomUUID(),
    },
  )}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key.privateKey,
    encoder.encode(input),
  );
  return `${input}.${base64urlEncode(new Uint8Array(signature))}`;
}

function jwksReader(
  issuer: string,
  options: Partial<JwksTokenReaderOptions<TestClient, undefined>> = {},
): JwksTokenReader<TestClient, undefined> {
  return new JwksTokenReader<TestClient, undefined>({
    issuer,
    audience: AUDIENCE,
    minFetchIntervalMs: 0,
    getClient: (claims) => ({ id: String(claims.client_id) }),
    ...options,
  });
}

function jwksOfSize(key: SigningPair, bytes: number): string {
  return jsonOfSize(bytes, { keys: [key.jwk] });
}

describe("JwksTokenReader response size limit", () => {
  it("verifies against a chunked JWKS of exactly the default 256 KiB cap", async () => {
    const key = await createKey();
    await using server = await serveReplies(() => ({
      body: jwksOfSize(key, JWKS_DEFAULT_LIMIT),
      transfer: "chunked",
    }));
    const reader = jwksReader(server.origin, {
      jwksUri: `${server.origin}/jwks`,
    });

    const token = await reader.getToken(await signToken(key, server.origin));

    expect(token?.client.id).toBe("my-client");
  });

  for (const transfer of ["length", "chunked"] as const) {
    it(`refuses a JWKS one byte over the default cap (${transfer})`, async () => {
      const key = await createKey();
      await using server = await serveReplies(() => ({
        body: jwksOfSize(key, JWKS_DEFAULT_LIMIT + 1),
        transfer,
      }));
      const reader = jwksReader(server.origin, {
        jwksUri: `${server.origin}/jwks`,
      });

      await rejection(
        () => signToken(key, server.origin).then((t) => reader.getToken(t)),
        ServerError,
        `jwks response exceeded ${JWKS_DEFAULT_LIMIT} bytes`,
      );
    });
  }

  it("stops reading an endless chunked JWKS at the cap and cancels it", async () => {
    const key = await createKey();
    await using server = await serveReplies(() => ({
      body: `{"keys":[${JSON.stringify(key.jwk)}]`,
      transfer: "endless",
    }));
    const reader = jwksReader(server.origin, {
      jwksUri: `${server.origin}/jwks`,
      fetchTimeoutMs: 2_000,
    });

    await rejection(
      () => signToken(key, server.origin).then((t) => reader.getToken(t)),
      ServerError,
      `jwks response exceeded ${JWKS_DEFAULT_LIMIT} bytes`,
    );
    await server.abandoned;
  });

  it("refuses a JWKS whose Content-Length declares more than the cap without waiting for it", async () => {
    const key = await createKey();
    await using server = await serveReplies(() => ({
      body: "{",
      transfer: "declared",
      declaredLength: JWKS_DEFAULT_LIMIT + 1,
    }));
    const reader = jwksReader(server.origin, {
      jwksUri: `${server.origin}/jwks`,
      fetchTimeoutMs: 20_000,
    });

    await rejection(
      () => signToken(key, server.origin).then((t) => reader.getToken(t)),
      ServerError,
      `jwks response exceeded ${JWKS_DEFAULT_LIMIT} bytes`,
    );
    await server.abandoned;
  });

  it("reports a JWKS body cut off by the deadline as temporarily unavailable", async () => {
    const key = await createKey();
    await using server = await serveReplies(() => ({
      body: '{"keys":[',
      transfer: "declared",
      declaredLength: 1024,
    }));
    const reader = jwksReader(server.origin, {
      jwksUri: `${server.origin}/jwks`,
      fetchTimeoutMs: 100,
    });

    await rejection(
      () => signToken(key, server.origin).then((t) => reader.getToken(t)),
      TemporarilyUnavailableError,
      "jwks request failed",
    );
  });

  it("refuses discovery metadata over the cap at every well-known URL", async () => {
    const key = await createKey();
    const replies: Record<string, Reply> = {};
    await using server = await serveReplies(
      (pathname) =>
        replies[pathname] ?? { status: 404, body: "{}", transfer: "length" },
    );
    const oversized = jsonOfSize(JWKS_DEFAULT_LIMIT + 1, {
      issuer: server.origin,
      jwks_uri: `${server.origin}/jwks`,
    });
    replies["/.well-known/oauth-authorization-server"] = {
      body: oversized,
      transfer: "chunked",
    };
    replies["/.well-known/openid-configuration"] = {
      body: oversized,
      transfer: "length",
    };
    replies["/jwks"] = {
      body: JSON.stringify({ keys: [key.jwk] }),
      transfer: "length",
    };
    const reader = jwksReader(server.origin);

    await rejection(
      () => signToken(key, server.origin).then((t) => reader.getToken(t)),
      ServerError,
      `discovery response exceeded ${JWKS_DEFAULT_LIMIT} bytes`,
    );
    expect(server.requests).toBe(2);
  });

  it("applies maxResponseBytes to discovery and to the JWKS", async () => {
    const key = await createKey();
    const documents: Record<string, string> = {};
    await using server = await serveReplies((pathname) => ({
      body: documents[pathname] ?? "{}",
      transfer: "chunked",
    }));
    const metadata = JSON.stringify({
      issuer: server.origin,
      jwks_uri: `${server.origin}/jwks`,
    });
    const jwks = JSON.stringify({ keys: [key.jwk] });
    documents["/.well-known/oauth-authorization-server"] = metadata;
    documents["/.well-known/openid-configuration"] = metadata;
    documents["/jwks"] = jwks;
    const metadataBytes = Buffer.byteLength(metadata);
    expect(Buffer.byteLength(jwks)).toBeGreaterThan(metadataBytes);

    await rejection(
      () =>
        signToken(key, server.origin).then((t) =>
          jwksReader(server.origin, {
            maxResponseBytes: metadataBytes - 1,
          }).getToken(t),
        ),
      ServerError,
      `discovery response exceeded ${metadataBytes - 1} bytes`,
    );
    await rejection(
      () =>
        signToken(key, server.origin).then((t) =>
          jwksReader(server.origin, {
            maxResponseBytes: metadataBytes,
          }).getToken(t),
        ),
      ServerError,
      `jwks response exceeded ${metadataBytes} bytes`,
    );
  });

  it("accepts a JWKS over the default cap when maxResponseBytes allows it", async () => {
    const key = await createKey();
    await using server = await serveReplies(() => ({
      body: jwksOfSize(key, 2 * JWKS_DEFAULT_LIMIT),
      transfer: "chunked",
    }));
    const reader = jwksReader(server.origin, {
      jwksUri: `${server.origin}/jwks`,
      maxResponseBytes: 2 * JWKS_DEFAULT_LIMIT,
    });

    const token = await reader.getToken(await signToken(key, server.origin));

    expect(token?.client.id).toBe("my-client");
  });

  it("rejects a maxResponseBytes that is not a positive integer", () => {
    for (const maxResponseBytes of [0, -1, 1.5, Number.NaN, Infinity]) {
      thrown(
        () => jwksReader("https://auth.example.com", { maxResponseBytes }),
        RangeError,
        "maxResponseBytes must be a positive integer",
      );
    }
  });
});

function introspectionReader(
  endpoint: string,
  options: { maxResponseBytes?: number; fetchTimeoutMs?: number } = {},
): IntrospectionTokenReader<TestClient, undefined> {
  return new IntrospectionTokenReader<TestClient, undefined>({
    introspectionEndpoint: endpoint,
    clientId: "api",
    clientSecret: "secret",
    getClient: (data) => ({ id: String(data.client_id) }),
    ...options,
  });
}

function introspectionOfSize(bytes: number): string {
  return jsonOfSize(bytes, {
    active: true,
    token_type: "Bearer",
    client_id: "my-client",
  });
}

describe("IntrospectionTokenReader response size limit", () => {
  it("accepts a chunked response of exactly the default 64 KiB cap", async () => {
    await using server = await serveReplies(() => ({
      body: introspectionOfSize(INTROSPECTION_DEFAULT_LIMIT),
      transfer: "chunked",
    }));
    const reader = introspectionReader(`${server.origin}/introspect`);

    const token = await reader.getToken("opaque-token");

    expect(token?.client.id).toBe("my-client");
  });

  for (const transfer of ["length", "chunked"] as const) {
    it(`refuses a response one byte over the default cap (${transfer})`, async () => {
      await using server = await serveReplies(() => ({
        body: introspectionOfSize(INTROSPECTION_DEFAULT_LIMIT + 1),
        transfer,
      }));
      const reader = introspectionReader(`${server.origin}/introspect`);

      await rejection(
        () => reader.getToken("opaque-token"),
        ServerError,
        `token introspection response exceeded ${INTROSPECTION_DEFAULT_LIMIT} bytes`,
      );
    });
  }

  it("stops reading an endless chunked response at the cap and cancels it", async () => {
    await using server = await serveReplies(() => ({
      body: '{"active":true,"token_type":"Bearer","client_id":"my-client"',
      transfer: "endless",
    }));
    const reader = introspectionReader(`${server.origin}/introspect`, {
      fetchTimeoutMs: 2_000,
    });

    await rejection(
      () => reader.getToken("opaque-token"),
      ServerError,
      `token introspection response exceeded ${INTROSPECTION_DEFAULT_LIMIT} bytes`,
    );
    await server.abandoned;
  });

  it("refuses a response whose Content-Length declares more than the cap without waiting for it", async () => {
    await using server = await serveReplies(() => ({
      body: "{",
      transfer: "declared",
      declaredLength: INTROSPECTION_DEFAULT_LIMIT + 1,
    }));
    const reader = introspectionReader(`${server.origin}/introspect`, {
      fetchTimeoutMs: 20_000,
    });

    await rejection(
      () => reader.getToken("opaque-token"),
      ServerError,
      `token introspection response exceeded ${INTROSPECTION_DEFAULT_LIMIT} bytes`,
    );
    await server.abandoned;
  });

  it("uses maxResponseBytes in place of the default", async () => {
    const body = introspectionOfSize(2048);
    await using server = await serveReplies(() => ({
      body,
      transfer: "chunked",
    }));

    await rejection(
      () =>
        introspectionReader(`${server.origin}/introspect`, {
          maxResponseBytes: 2047,
        }).getToken("opaque-token"),
      ServerError,
      "token introspection response exceeded 2047 bytes",
    );
    const token = await introspectionReader(`${server.origin}/introspect`, {
      maxResponseBytes: 2048,
    }).getToken("opaque-token");
    expect(token?.client.id).toBe("my-client");
  });

  it("rejects a maxResponseBytes that is not a positive integer", () => {
    for (const maxResponseBytes of [0, -1, 1.5, Number.NaN, Infinity]) {
      thrown(
        () =>
          introspectionReader("https://auth.example.com/introspect", {
            maxResponseBytes,
          }),
        RangeError,
        "maxResponseBytes must be a positive integer",
      );
    }
  });
});
