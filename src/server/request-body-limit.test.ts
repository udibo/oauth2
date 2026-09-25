import {
  assert,
  assertEquals,
  assertRejects,
  assertStrictEquals,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import type { BasicScope } from "../models/scope.ts";
import {
  basicAuthHeader,
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../testing/_test_fixtures.ts";
import { AuthorizationServer } from "./authorization-server.ts";
import { ClientCredentialsGrant } from "./grants/client-credentials.ts";
import { DeviceAuthorizationGrant } from "./grants/device-authorization.ts";

const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
const DEFAULT_LIMIT = 64 * 1024;
const CHUNK_BYTES = 16 * 1024;
/**
 * The token endpoints read a clone so the original request stays readable,
 * and the clone's tee pulls a few chunks ahead of the reader.
 */
const TEE_READ_AHEAD_BYTES = 4 * CHUNK_BYTES;

const testUser: TestUser = { id: "user-1", username: "testuser" };
const testClient: TestClient = {
  id: "client-1",
  confidential: true,
  grants: ["client_credentials", DEVICE_GRANT_TYPE],
  redirectUris: ["https://example.com/callback"],
};

async function createServer(maxBodyBytes?: number) {
  const calls = { resolve: 0, endSession: 0 };
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  const deviceAuthorizationService = new MemoryDeviceAuthorizationService({
    clientService,
    userService,
  });
  await userService.add(testUser, "password");
  await clientService.add(testClient, "secret", testUser.id);
  const grantResolve = () => ({ clientService, tokenService });
  const server = new AuthorizationServer<TestClient, TestUser, BasicScope>({
    resolve: () => {
      calls.resolve++;
      return {
        services: { clientService, tokenService },
        issuer: "https://auth.example.com",
        verificationUri: "https://auth.example.com/device",
      };
    },
    grants: {
      client_credentials: new ClientCredentialsGrant({
        resolve: grantResolve,
      }),
      [DEVICE_GRANT_TYPE]: new DeviceAuthorizationGrant({
        resolve: () => ({ ...grantResolve(), deviceAuthorizationService }),
      }),
    },
    endSession: () => {
      calls.endSession++;
      return { fallback: "/signed-out" };
    },
    ...(maxBodyBytes === undefined ? {} : { maxBodyBytes }),
  });
  return { server, calls };
}

type Server = Awaited<ReturnType<typeof createServer>>["server"];

const clientAuthenticatedEndpoints: {
  name: string;
  path: string;
  fields: string;
  handle: (server: Server, request: Request) => Promise<Response>;
}[] = [
  {
    name: "token",
    path: "/token",
    fields: "grant_type=client_credentials",
    handle: (server, request) => server.handleTokenRequest(request),
  },
  {
    name: "revocation",
    path: "/revoke",
    fields: "token=unknown-token",
    handle: (server, request) => server.handleRevocationRequest(request),
  },
  {
    name: "introspection",
    path: "/introspect",
    fields: "token=unknown-token",
    handle: (server, request) => server.handleIntrospectionRequest(request),
  },
  {
    name: "device authorization",
    path: "/device_authorization",
    fields: "",
    handle: (server, request) =>
      server.handleDeviceAuthorizationRequest(request),
  },
];

const endSessionEndpoint = {
  name: "end-session",
  path: "/end_session",
  fields: "client_id=client-1",
  handle: (server: Server, request: Request) =>
    server.handleEndSessionRequest(request),
};

/** `fields` padded with an ignored `pad` parameter to exactly `bytes` bytes. */
function paddedForm(fields: string, bytes: number): string {
  const prefix = fields ? `${fields}&pad=` : "pad=";
  return prefix + "a".repeat(bytes - prefix.length);
}

/**
 * A chunked stream of `form`, counting what the reader pulls, so a test can
 * tell a reader that stopped at the limit from one that drained the stream.
 */
function countingStream(form: string) {
  const bytes = new TextEncoder().encode(form);
  const state = { pulled: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (state.pulled >= bytes.byteLength) return controller.close();
      const chunk = bytes.subarray(state.pulled, state.pulled + CHUNK_BYTES);
      state.pulled += chunk.byteLength;
      controller.enqueue(chunk);
    },
    cancel() {
      state.cancelled = true;
    },
  });
  return { stream, state };
}

function formHeaders(): Record<string, string> {
  return {
    "content-type": "application/x-www-form-urlencoded",
    ...basicAuthHeader("client-1", "secret"),
  };
}

async function withHttpServer(
  server: Server,
  fn: (origin: string) => Promise<void>,
): Promise<void> {
  const routes = new Map(
    [...clientAuthenticatedEndpoints, endSessionEndpoint].map((
      endpoint,
    ) => [endpoint.path, endpoint.handle]),
  );
  const http = Deno.serve(
    { hostname: "127.0.0.1", port: 0, onListen: () => {} },
    (request) => {
      const handle = routes.get(new URL(request.url).pathname);
      return handle
        ? handle(server, request)
        : new Response(null, { status: 404 });
    },
  );
  try {
    await fn(`http://127.0.0.1:${http.addr.port}`);
  } finally {
    await http.shutdown();
  }
}

async function assertTooLarge(response: Response): Promise<void> {
  assertStrictEquals(response.status, 413);
  const body = await response.json();
  assertStrictEquals(body.error, "invalid_request");
}

describe("AuthorizationServer request body limit", () => {
  for (
    const endpoint of [...clientAuthenticatedEndpoints, endSessionEndpoint]
  ) {
    describe(endpoint.name, () => {
      it("accepts a body of exactly the default 64 KiB limit", async () => {
        const { server, calls } = await createServer();
        await withHttpServer(server, async (origin) => {
          const response = await fetch(`${origin}${endpoint.path}`, {
            method: "POST",
            redirect: "manual",
            headers: formHeaders(),
            body: paddedForm(endpoint.fields, DEFAULT_LIMIT),
          });
          await response.body?.cancel();
          assert(
            response.status < 400,
            `expected success, got ${response.status}`,
          );
          assertStrictEquals(calls.resolve, 1);
        });
      });

      it("refuses a body whose Content-Length declares one byte over the limit, before resolving the request context", async () => {
        const { server, calls } = await createServer();
        await withHttpServer(server, async (origin) => {
          const response = await fetch(`${origin}${endpoint.path}`, {
            method: "POST",
            redirect: "manual",
            headers: formHeaders(),
            body: paddedForm(endpoint.fields, DEFAULT_LIMIT + 1),
          });
          await assertTooLarge(response);
          assertStrictEquals(calls.resolve, 0);
          assertStrictEquals(calls.endSession, 0);
        });
      });

      it("counts the bytes of a chunked body that carries no Content-Length", async () => {
        const { server, calls } = await createServer();
        const { stream } = countingStream(
          paddedForm(endpoint.fields, 1024 * 1024),
        );
        await withHttpServer(server, async (origin) => {
          const response = await fetch(`${origin}${endpoint.path}`, {
            method: "POST",
            redirect: "manual",
            headers: formHeaders(),
            body: stream,
          });
          await assertTooLarge(response);
          assertStrictEquals(calls.resolve, 0);
          assertStrictEquals(calls.endSession, 0);
        });
      });

      it("stops reading at the limit when Content-Length understates the body", async () => {
        const { server, calls } = await createServer();
        const { stream, state } = countingStream(
          paddedForm(endpoint.fields, 4 * 1024 * 1024),
        );
        const response = await endpoint.handle(
          server,
          new Request(`http://localhost${endpoint.path}`, {
            method: "POST",
            headers: { ...formHeaders(), "content-length": "64" },
            body: stream,
          }),
        );
        await assertTooLarge(response);
        assert(
          state.pulled <= DEFAULT_LIMIT + TEE_READ_AHEAD_BYTES,
          `read ${state.pulled} bytes past a ${DEFAULT_LIMIT}-byte limit`,
        );
        assert(state.cancelled, "the request body stream was not cancelled");
        assertStrictEquals(calls.resolve, 0);
        assertStrictEquals(calls.endSession, 0);
      });

      it("refuses a body whose Content-Length declares more than the limit without reading it", async () => {
        const { server, calls } = await createServer();
        const { stream, state } = countingStream(
          paddedForm(endpoint.fields, 1024 * 1024),
        );
        const response = await endpoint.handle(
          server,
          new Request(`http://localhost${endpoint.path}`, {
            method: "POST",
            headers: { ...formHeaders(), "content-length": `${1024 * 1024}` },
            body: stream,
          }),
        );
        await assertTooLarge(response);
        assertStrictEquals(state.pulled, 0);
        assertStrictEquals(calls.resolve, 0);
      });

      it("answers a body stream that errors mid-read with 400 invalid_request", async () => {
        const { server, calls } = await createServer();
        const stream = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode(`${endpoint.fields}&`));
            controller.error(new Error("client aborted the upload"));
          },
        });
        const response = await endpoint.handle(
          server,
          new Request(`http://localhost${endpoint.path}`, {
            method: "POST",
            headers: formHeaders(),
            body: stream,
          }),
        );
        assertStrictEquals(response.status, 400);
        const body = await response.json();
        assertStrictEquals(body.error, "invalid_request");
        assertStrictEquals(calls.endSession, 0);
      });

      it("applies a configured maxBodyBytes", async () => {
        const { server } = await createServer(512);
        await withHttpServer(server, async (origin) => {
          const atLimit = await fetch(`${origin}${endpoint.path}`, {
            method: "POST",
            redirect: "manual",
            headers: formHeaders(),
            body: paddedForm(endpoint.fields, 512),
          });
          await atLimit.body?.cancel();
          assert(
            atLimit.status < 400,
            `expected success, got ${atLimit.status}`,
          );

          const overLimit = await fetch(`${origin}${endpoint.path}`, {
            method: "POST",
            redirect: "manual",
            headers: formHeaders(),
            body: paddedForm(endpoint.fields, 513),
          });
          await assertTooLarge(overLimit);
        });
      });
    });
  }

  it("sends the no-store cache headers with a refusal from a client-authenticated endpoint", async () => {
    const { server } = await createServer(128);
    const response = await server.handleTokenRequest(
      new Request("http://localhost/token", {
        method: "POST",
        headers: formHeaders(),
        body: paddedForm("grant_type=client_credentials", 129),
      }),
    );
    await assertTooLarge(response);
    assertStrictEquals(response.headers.get("cache-control"), "no-store");
  });

  it("rejects a maxBodyBytes that is not a positive integer", async () => {
    for (const maxBodyBytes of [0, -1, 1.5, Number.NaN, Infinity]) {
      await assertRejects(
        () => createServer(maxBodyBytes),
        RangeError,
        "maxBodyBytes",
      );
    }
  });

  it("leaves a GET end-session request, which has no body, unaffected", async () => {
    const { server, calls } = await createServer(1);
    const response = await server.handleEndSessionRequest(
      new Request("http://localhost/end_session?client_id=client-1"),
    );
    assertEquals(response.status, 302);
    assertStrictEquals(calls.endSession, 1);
  });
});
