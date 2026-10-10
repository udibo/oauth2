import { describe, expect, it } from "vitest";
import { rejection } from "../_test_assert.ts";
import { serve } from "../_test_server.ts";
import { BasicScope } from "../models/scope.ts";
import { ServerError, TemporarilyUnavailableError } from "../errors.ts";
import { IntrospectionTokenReader } from "./introspection-token-reader.ts";
import { encodeBasicAuth, parseBasicAuth } from "../utils/basic-auth.ts";
import { hangUntilAborted, stubDenoRuntime } from "../_test_deno-runtime.ts";
import { FakeTime } from "../_test_fake-time.ts";

interface TestClient {
  id: string;
}

interface TestUser {
  id: string;
  username?: string;
}

const getClient = (data: { client_id?: string }): TestClient => ({
  id: data.client_id ?? "",
});

const getUser = (data: {
  sub?: string;
  username?: string;
}): TestUser | undefined =>
  data.sub ? { id: data.sub, username: data.username } : undefined;

async function withMockServer(
  responses: Map<string, Record<string, unknown>>,
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const server = await serve(async (request) => {
    const authorization = request.headers.get("authorization");
    if (!authorization?.startsWith("Basic ")) {
      return Response.json({ error: "invalid_client" }, { status: 401 });
    }

    const body = await request.formData();
    const token = body.get("token") as string;
    const responseData = responses.get(token) ?? { active: false };
    return Response.json(responseData);
  });

  try {
    await fn(server.origin);
  } finally {
    await server.shutdown();
  }
}

describe("IntrospectionTokenReader", () => {
  it("should return token for active introspection response", async () => {
    const responses = new Map([
      [
        "valid-token",
        {
          active: true,
          token_type: "Bearer",
          client_id: "my-client",
          sub: "user-1",
          username: "testuser",
          scope: "read write",
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
      ],
    ]);

    await withMockServer(responses, async (baseUrl) => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        introspectionEndpoint: `${baseUrl}/introspect`,
        clientId: "test-client",
        clientSecret: "test-secret",
        getClient,
        getUser,
      });
      const token = await reader.getToken("valid-token");

      expect(token?.accessToken).toBe("valid-token");
      expect(token?.client.id).toBe("my-client");
      expect(token?.user?.id).toBe("user-1");
      expect(token?.user?.username).toBe("testuser");
      expect(token?.scope?.toString()).toBe("read write");
      expect(token?.accessTokenExpiresAt instanceof Date).toStrictEqual(true);
    });
  });

  it("surfaces the introspection response as the token's claims", async () => {
    const responses = new Map([
      [
        "valid-token",
        {
          active: true,
          token_type: "Bearer",
          client_id: "my-client",
          sub: "user-1",
          scope: "read",
          exp: Math.floor(Date.now() / 1000) + 3600,
          permissions: ["posts:write"],
          org_id: "org-1",
          org_roles: ["admin"],
        },
      ],
    ]);

    await withMockServer(responses, async (baseUrl) => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        introspectionEndpoint: `${baseUrl}/introspect`,
        clientId: "test-client",
        clientSecret: "test-secret",
        getClient,
        getUser,
      });
      const token = await reader.getToken("valid-token");

      expect(token?.claims?.permissions).toStrictEqual(["posts:write"]);
      expect(token?.claims?.org_id).toStrictEqual("org-1");
      expect(token?.claims?.org_roles).toStrictEqual(["admin"]);
      expect(token?.claims?.sub).toStrictEqual("user-1");
    });
  });

  it("should return undefined for inactive token", async () => {
    const responses = new Map([
      ["expired-token", { active: false } as Record<string, unknown>],
    ]);

    await withMockServer(responses, async (baseUrl) => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        introspectionEndpoint: `${baseUrl}/introspect`,
        clientId: "test-client",
        clientSecret: "test-secret",
        getClient,
        getUser,
      });
      const token = await reader.getToken("expired-token");

      expect(token).toBe(undefined);
    });
  });

  it("should return undefined for unknown token", async () => {
    await withMockServer(new Map(), async (baseUrl) => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        introspectionEndpoint: `${baseUrl}/introspect`,
        clientId: "test-client",
        clientSecret: "test-secret",
        getClient,
        getUser,
      });
      const token = await reader.getToken("unknown-token");

      expect(token).toBe(undefined);
    });
  });

  it("should handle response without optional fields", async () => {
    const responses = new Map([
      [
        "minimal-token",
        {
          active: true,
          token_type: "Bearer",
          client_id: "my-client",
        },
      ],
    ]);

    await withMockServer(responses, async (baseUrl) => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        introspectionEndpoint: `${baseUrl}/introspect`,
        clientId: "test-client",
        clientSecret: "test-secret",
        getClient,
        getUser,
      });
      const token = await reader.getToken("minimal-token");

      expect(token?.accessToken).toBe("minimal-token");
      expect(token?.client.id).toBe("my-client");
      expect(token?.user).toBe(undefined);
      expect(token?.scope).toBe(undefined);
      expect(token?.accessTokenExpiresAt).toBe(undefined);
    });
  });

  it("should omit user when getUser is not provided", async () => {
    const responses = new Map([
      [
        "user-token",
        {
          active: true,
          token_type: "Bearer",
          client_id: "my-client",
          sub: "user-1",
        },
      ],
    ]);

    await withMockServer(responses, async (baseUrl) => {
      const reader = new IntrospectionTokenReader<TestClient, never>({
        introspectionEndpoint: `${baseUrl}/introspect`,
        clientId: "test-client",
        clientSecret: "test-secret",
        getClient,
      });
      const token = await reader.getToken("user-token");

      expect(token?.client.id).toBe("my-client");
      expect(token?.user).toBe(undefined);
    });
  });

  it("should project extension fields via getUser", async () => {
    interface RichUser {
      id: string;
      email: string;
      roles: string[];
    }

    const responses = new Map([
      [
        "rich-token",
        {
          active: true,
          token_type: "Bearer",
          client_id: "my-client",
          sub: "user-1",
          email: "alice@example.com",
          roles: ["admin", "editor"],
        },
      ],
    ]);

    await withMockServer(responses, async (baseUrl) => {
      const reader = new IntrospectionTokenReader<TestClient, RichUser>({
        introspectionEndpoint: `${baseUrl}/introspect`,
        clientId: "test-client",
        clientSecret: "test-secret",
        getClient,
        getUser: (data) => ({
          id: data.sub as string,
          email: data.email as string,
          roles: data.roles as string[],
        }),
      });
      const token = await reader.getToken("rich-token");

      expect(token?.user?.id).toBe("user-1");
      expect(token?.user?.email).toBe("alice@example.com");
      expect(token?.user?.roles).toStrictEqual(["admin", "editor"]);
    });
  });

  it("should await async mappers", async () => {
    interface EnrichedUser {
      id: string;
      email: string;
    }

    const userDb = new Map([["user-1", { email: "alice@example.com" }]]);

    const responses = new Map([
      [
        "enrich-token",
        {
          active: true,
          token_type: "Bearer",
          client_id: "my-client",
          sub: "user-1",
        },
      ],
    ]);

    await withMockServer(responses, async (baseUrl) => {
      const reader = new IntrospectionTokenReader<TestClient, EnrichedUser>({
        introspectionEndpoint: `${baseUrl}/introspect`,
        clientId: "test-client",
        clientSecret: "test-secret",
        getClient: (data) => Promise.resolve({ id: data.client_id ?? "" }),
        getUser: async (data) => {
          if (!data.sub) return undefined;
          const record = await Promise.resolve(userDb.get(data.sub));
          return record ? { id: data.sub, email: record.email } : undefined;
        },
      });
      const token = await reader.getToken("enrich-token");

      expect(token?.client.id).toBe("my-client");
      expect(token?.user?.id).toBe("user-1");
      expect(token?.user?.email).toBe("alice@example.com");
    });
  });

  it("should use custom Scope constructor", async () => {
    const responses = new Map([
      [
        "scoped-token",
        {
          active: true,
          token_type: "Bearer",
          client_id: "c",
          scope: "admin",
        },
      ],
    ]);

    await withMockServer(responses, async (baseUrl) => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        introspectionEndpoint: `${baseUrl}/introspect`,
        clientId: "test-client",
        clientSecret: "test-secret",
        getClient,
        getUser,
        Scope: BasicScope,
      });
      const token = await reader.getToken("scoped-token");

      expect(token?.scope?.toString()).toBe("admin");
    });
  });

  describe("injected fetch + transport vs inactive", () => {
    const baseOptions = {
      introspectionEndpoint: "https://auth.example.com/introspect",
      clientId: "rs",
      clientSecret: "rs-secret",
      getClient,
      getUser,
    };

    it("refuses an active response that names no token_type, as an introspected refresh token does", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () =>
          Promise.resolve(
            Response.json({
              active: true,
              client_id: "c",
              sub: "u1",
              scope: "read write",
              exp: Math.floor(Date.now() / 1000) + 86_400,
            }),
          ),
      });

      expect(await reader.getToken("a-refresh-token")).toBe(undefined);
    });

    it("refuses an active response whose token_type is not a bearer token", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () =>
          Promise.resolve(
            Response.json({ active: true, token_type: "mac", client_id: "c" }),
          ),
      });

      expect(await reader.getToken("t")).toBe(undefined);
    });

    it("accepts a lowercase token_type, since RFC 6750 makes the scheme case-insensitive", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () =>
          Promise.resolve(
            Response.json({
              active: true,
              token_type: "bearer",
              client_id: "c",
              sub: "u1",
            }),
          ),
      });

      expect((await reader.getToken("t"))?.user?.id).toBe("u1");
    });

    it("uses the injected fetch instead of the global", async () => {
      let called = 0;
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () => {
          called++;
          return Promise.resolve(
            Response.json({
              active: true,
              token_type: "Bearer",
              client_id: "c",
              sub: "u1",
            }),
          );
        },
      });
      const token = await reader.getToken("t");
      expect(called).toBe(1);
      expect(token?.user?.id).toBe("u1");
    });

    it("authenticates with the shared basic-auth encoding, so a reserved or non-ASCII secret survives", async () => {
      const clientId = "rs:1";
      const clientSecret = "s3cr3t \u20ac+ ";
      const captured: (string | null)[] = [];
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        clientId,
        clientSecret,
        fetch: (_input, init) => {
          captured.push(new Headers(init?.headers).get("authorization"));
          return Promise.resolve(
            Response.json({
              active: true,
              token_type: "Bearer",
              client_id: "c",
            }),
          );
        },
      });

      await reader.getToken("t");

      expect(captured[0]).toBe(encodeBasicAuth(clientId, clientSecret));
      expect(parseBasicAuth(captured[0]!)).toStrictEqual({
        name: clientId,
        pass: clientSecret,
      });
    });

    it("returns undefined for a 200 inactive response (invalid token)", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () => Promise.resolve(Response.json({ active: false })),
      });
      expect(await reader.getToken("t")).toBe(undefined);
    });

    it("abandons a request the endpoint never answers, at the configured deadline", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetchTimeoutMs: 10,
        fetch: (_input, init) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () =>
              reject(new DOMException("request aborted", "AbortError")),
            );
          }),
      });

      await rejection(
        () => reader.getToken("t"),
        TemporarilyUnavailableError,
        "token introspection request failed",
      );
    });

    it("abandons a response whose body stops arriving, at the same deadline", async () => {
      let failBody!: () => void;
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"active":true,'));
          failBody = () => controller.error(new Error("body abandoned"));
        },
      });
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetchTimeoutMs: 10,
        fetch: (_input, init) => {
          init?.signal?.addEventListener("abort", () => failBody());
          return Promise.resolve(
            new Response(body, {
              status: 200,
              headers: { "content-type": "application/json" },
            }),
          );
        },
      });

      await rejection(
        () => reader.getToken("t"),
        TemporarilyUnavailableError,
        "token introspection request failed",
      );
    });

    it("throws temporarily_unavailable when the endpoint is unreachable", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () => Promise.reject(new TypeError("network down")),
      });
      await rejection(() => reader.getToken("t"), TemporarilyUnavailableError);
    });

    it("throws temporarily_unavailable on a 5xx from the endpoint", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () => Promise.resolve(new Response("boom", { status: 503 })),
      });
      await rejection(() => reader.getToken("t"), TemporarilyUnavailableError);
    });

    it("throws server_error on a 4xx (reader misconfiguration)", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () => Promise.resolve(new Response("nope", { status: 401 })),
      });
      await rejection(() => reader.getToken("t"), ServerError);
    });
  });

  it("sends the request after a timed-out one on a new connection", async () => {
    const reader = new IntrospectionTokenReader<TestClient, TestUser>({
      introspectionEndpoint:
        "https://introspect-reconnect.example.com/introspect",
      clientId: "rs",
      clientSecret: "rs-secret",
      getClient,
      getUser,
    });
    const introspect = () =>
      reader.getToken("token-1").then(
        (found) => (found ? "active" : "inactive"),
        (error: unknown) =>
          error instanceof TemporarilyUnavailableError
            ? "unavailable"
            : String(error),
      );
    using runtime = stubDenoRuntime((_input, init) =>
      runtime.requests.length === 2
        ? hangUntilAborted(init?.signal)
        : Promise.resolve(
            Response.json({
              active: true,
              token_type: "Bearer",
              client_id: "my-client",
            }),
          ),
    );
    using time = new FakeTime();

    const outcomes = [await introspect()];
    const stalled = introspect();
    await time.tickAsync(5_000);
    outcomes.push(await stalled, await introspect());

    expect(outcomes).toStrictEqual(["active", "unavailable", "active"]);
    expect(runtime.clients).toHaveLength(1);
    expect(runtime.requests[2]?.init).toHaveProperty(
      "client",
      runtime.clients[0],
    );
  });
});
