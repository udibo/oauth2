import { assertEquals, assertRejects, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { BasicScope } from "../models/scope.ts";
import { ServerError, TemporarilyUnavailableError } from "../errors.ts";
import { IntrospectionTokenReader } from "./introspection-token-reader.ts";
import { encodeBasicAuth, parseBasicAuth } from "../utils/basic-auth.ts";

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

const getUser = (
  data: { sub?: string; username?: string },
): TestUser | undefined =>
  data.sub ? { id: data.sub, username: data.username } : undefined;

async function withMockServer(
  responses: Map<string, Record<string, unknown>>,
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  let port: number;
  const server = Deno.serve(
    {
      port: 0,
      onListen: (addr) => {
        port = addr.port;
      },
    },
    async (request) => {
      const authorization = request.headers.get("authorization");
      if (!authorization?.startsWith("Basic ")) {
        return Response.json({ error: "invalid_client" }, { status: 401 });
      }

      const body = await request.formData();
      const token = body.get("token") as string;
      const responseData = responses.get(token) ?? { active: false };
      return Response.json(responseData);
    },
  );

  try {
    await fn(`http://localhost:${port!}`);
  } finally {
    await server.shutdown();
  }
}

describe("IntrospectionTokenReader", () => {
  it("should return token for active introspection response", async () => {
    const responses = new Map([
      ["valid-token", {
        active: true,
        token_type: "Bearer",
        client_id: "my-client",
        sub: "user-1",
        username: "testuser",
        scope: "read write",
        exp: Math.floor(Date.now() / 1000) + 3600,
      }],
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

      assertStrictEquals(token?.accessToken, "valid-token");
      assertStrictEquals(token?.client.id, "my-client");
      assertStrictEquals(token?.user?.id, "user-1");
      assertStrictEquals(token?.user?.username, "testuser");
      assertStrictEquals(token?.scope?.toString(), "read write");
      assertEquals(token?.accessTokenExpiresAt instanceof Date, true);
    });
  });

  it("surfaces the introspection response as the token's claims", async () => {
    const responses = new Map([
      ["valid-token", {
        active: true,
        token_type: "Bearer",
        client_id: "my-client",
        sub: "user-1",
        scope: "read",
        exp: Math.floor(Date.now() / 1000) + 3600,
        permissions: ["posts:write"],
        org_id: "org-1",
        org_roles: ["admin"],
      }],
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

      assertEquals(token?.claims?.permissions, ["posts:write"]);
      assertEquals(token?.claims?.org_id, "org-1");
      assertEquals(token?.claims?.org_roles, ["admin"]);
      assertEquals(token?.claims?.sub, "user-1");
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

      assertStrictEquals(token, undefined);
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

      assertStrictEquals(token, undefined);
    });
  });

  it("should handle response without optional fields", async () => {
    const responses = new Map([
      ["minimal-token", {
        active: true,
        token_type: "Bearer",
        client_id: "my-client",
      }],
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

      assertStrictEquals(token?.accessToken, "minimal-token");
      assertStrictEquals(token?.client.id, "my-client");
      assertStrictEquals(token?.user, undefined);
      assertStrictEquals(token?.scope, undefined);
      assertStrictEquals(token?.accessTokenExpiresAt, undefined);
    });
  });

  it("should omit user when getUser is not provided", async () => {
    const responses = new Map([
      ["user-token", {
        active: true,
        token_type: "Bearer",
        client_id: "my-client",
        sub: "user-1",
      }],
    ]);

    await withMockServer(responses, async (baseUrl) => {
      const reader = new IntrospectionTokenReader<TestClient, never>({
        introspectionEndpoint: `${baseUrl}/introspect`,
        clientId: "test-client",
        clientSecret: "test-secret",
        getClient,
      });
      const token = await reader.getToken("user-token");

      assertStrictEquals(token?.client.id, "my-client");
      assertStrictEquals(token?.user, undefined);
    });
  });

  it("should project extension fields via getUser", async () => {
    interface RichUser {
      id: string;
      email: string;
      roles: string[];
    }

    const responses = new Map([
      ["rich-token", {
        active: true,
        token_type: "Bearer",
        client_id: "my-client",
        sub: "user-1",
        email: "alice@example.com",
        roles: ["admin", "editor"],
      }],
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

      assertStrictEquals(token?.user?.id, "user-1");
      assertStrictEquals(token?.user?.email, "alice@example.com");
      assertEquals(token?.user?.roles, ["admin", "editor"]);
    });
  });

  it("should await async mappers", async () => {
    interface EnrichedUser {
      id: string;
      email: string;
    }

    const userDb = new Map([["user-1", { email: "alice@example.com" }]]);

    const responses = new Map([
      ["enrich-token", {
        active: true,
        token_type: "Bearer",
        client_id: "my-client",
        sub: "user-1",
      }],
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

      assertStrictEquals(token?.client.id, "my-client");
      assertStrictEquals(token?.user?.id, "user-1");
      assertStrictEquals(token?.user?.email, "alice@example.com");
    });
  });

  it("should use custom Scope constructor", async () => {
    const responses = new Map([
      ["scoped-token", {
        active: true,
        token_type: "Bearer",
        client_id: "c",
        scope: "admin",
      }],
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

      assertStrictEquals(token?.scope?.toString(), "admin");
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

      assertStrictEquals(await reader.getToken("a-refresh-token"), undefined);
    });

    it("refuses an active response whose token_type is not a bearer token", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () =>
          Promise.resolve(
            Response.json({ active: true, token_type: "mac", client_id: "c" }),
          ),
      });

      assertStrictEquals(await reader.getToken("t"), undefined);
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

      assertStrictEquals((await reader.getToken("t"))?.user?.id, "u1");
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
      assertStrictEquals(called, 1);
      assertStrictEquals(token?.user?.id, "u1");
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

      assertStrictEquals(captured[0], encodeBasicAuth(clientId, clientSecret));
      assertEquals(parseBasicAuth(captured[0]!), {
        name: clientId,
        pass: clientSecret,
      });
    });

    it("returns undefined for a 200 inactive response (invalid token)", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () => Promise.resolve(Response.json({ active: false })),
      });
      assertStrictEquals(await reader.getToken("t"), undefined);
    });

    it("abandons a request the endpoint never answers, at the configured deadline", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetchTimeoutMs: 10,
        fetch: (_input, init) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener(
              "abort",
              () => reject(new DOMException("request aborted", "AbortError")),
            );
          }),
      });

      await assertRejects(
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

      await assertRejects(
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
      await assertRejects(
        () => reader.getToken("t"),
        TemporarilyUnavailableError,
      );
    });

    it("throws temporarily_unavailable on a 5xx from the endpoint", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () => Promise.resolve(new Response("boom", { status: 503 })),
      });
      await assertRejects(
        () => reader.getToken("t"),
        TemporarilyUnavailableError,
      );
    });

    it("throws server_error on a 4xx (reader misconfiguration)", async () => {
      const reader = new IntrospectionTokenReader<TestClient, TestUser>({
        ...baseOptions,
        fetch: () => Promise.resolve(new Response("nope", { status: 401 })),
      });
      await assertRejects(() => reader.getToken("t"), ServerError);
    });
  });
});
