import { assert, beforeEach, describe, expect, it } from "vitest";
import { Hono } from "hono";

import { thrown } from "../_test_assert.ts";
import { HonoResourceServer } from "../adapters/hono/resource-server.ts";
import { BasicScope } from "../models/scope.ts";
import {
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../testing/_test_fixtures.ts";
import { AuthorizationServer } from "./authorization-server.ts";
import { ResourceServer } from "./resource-server.ts";

const DEFAULT_LIMIT = 16 * 1024;
const CHUNK_BYTES = 1024;
/** The clone's tee pulls a few chunks ahead of the reader. */
const TEE_READ_AHEAD_BYTES = 4 * CHUNK_BYTES;
const LARGE_BODY_BYTES = 1024 * 1024;

const testUser: TestUser = { id: "user-1", username: "testuser" };
const testClient: TestClient = { id: "client-1" };

function createServices() {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  return { userService, clientService, tokenService };
}

/**
 * A form body of exactly `bytes` bytes whose `access_token` comes last, so a
 * reader that drained the whole body would find it.
 */
function formEndingInToken(bytes: number, token = "body-token"): string {
  const suffix = `&access_token=${token}`;
  const prefix = "pad=";
  return prefix + "a".repeat(bytes - prefix.length - suffix.length) + suffix;
}

/** A chunked stream of `form` that counts the bytes its reader pulls. */
function countingStream(form: string) {
  const bytes = new TextEncoder().encode(form);
  const state = { pulled: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (state.pulled >= bytes.byteLength) return controller.close();
        const chunk = bytes.subarray(state.pulled, state.pulled + CHUNK_BYTES);
        state.pulled += chunk.byteLength;
        controller.enqueue(chunk);
      },
      cancel() {
        state.cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  return { stream, state };
}

function streamedFormInit(
  stream: ReadableStream<Uint8Array>,
  headers: Record<string, string> = {},
): RequestInit {
  return {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: stream,
    duplex: "half",
  } as RequestInit;
}

function formRequest(body: string): Request {
  return new Request("http://localhost/api", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
}

function assertStoppedAtLimit(pulled: number, limit = DEFAULT_LIMIT): void {
  assert(
    pulled <= limit + TEE_READ_AHEAD_BYTES,
    `read ${pulled} bytes looking for a token under a ${limit}-byte cap`,
  );
}

describe("ResourceServer form-body token read limit", () => {
  let server: ResourceServer<TestClient, TestUser>;

  beforeEach(() => {
    const { tokenService } = createServices();
    server = new ResourceServer<TestClient, TestUser>({
      resolve: () => ({ services: { tokenService } }),
    });
  });

  it("finds an access_token in a form body of exactly the default 16 KiB cap", async () => {
    const token = await server.getAccessToken(
      formRequest(formEndingInToken(DEFAULT_LIMIT)),
    );
    expect(token).toBe("body-token");
  });

  it("does not search a form body one byte over the cap", async () => {
    const token = await server.getAccessToken(
      formRequest(formEndingInToken(DEFAULT_LIMIT + 1)),
    );
    expect(token).toBe(null);
  });

  it("stops reading a chunked form body with no Content-Length at the cap", async () => {
    const { stream, state } = countingStream(
      formEndingInToken(LARGE_BODY_BYTES),
    );
    const request = new Request(
      "http://localhost/api",
      streamedFormInit(stream),
    );

    expect(await server.getAccessToken(request)).toBe(null);
    assertStoppedAtLimit(state.pulled);
  });

  it("stops reading at the cap when Content-Length understates the body", async () => {
    const { stream, state } = countingStream(
      formEndingInToken(LARGE_BODY_BYTES),
    );
    const request = new Request(
      "http://localhost/api",
      streamedFormInit(stream, { "content-length": "64" }),
    );

    expect(await server.getAccessToken(request)).toBe(null);
    assertStoppedAtLimit(state.pulled);
  });

  it("reads nothing from a body whose Content-Length declares more than the cap", async () => {
    const { stream, state } = countingStream(
      formEndingInToken(LARGE_BODY_BYTES),
    );
    const request = new Request(
      "http://localhost/api",
      streamedFormInit(stream, { "content-length": String(LARGE_BODY_BYTES) }),
    );

    expect(await server.getAccessToken(request)).toBe(null);
    expect(state.pulled).toBe(0);
  });

  it("leaves an oversized body readable for the route, uncancelled", async () => {
    const form = formEndingInToken(DEFAULT_LIMIT * 4);
    const { stream, state } = countingStream(form);
    const request = new Request(
      "http://localhost/api",
      streamedFormInit(stream),
    );

    expect(await server.getAccessToken(request)).toBe(null);
    expect(state.cancelled).toBe(false);
    expect(await request.text()).toBe(form);
  });

  it("leaves a body within the cap readable after finding its token", async () => {
    const form = formEndingInToken(1024);
    const request = formRequest(form);

    expect(await server.getAccessToken(request)).toBe("body-token");
    expect(await request.text()).toBe(form);
  });

  it("uses maxTokenBodyBytes in place of the default", async () => {
    const { tokenService } = createServices();
    const small = new ResourceServer<TestClient, TestUser>({
      resolve: () => ({ services: { tokenService } }),
      maxTokenBodyBytes: 1024,
    });

    expect(
      await small.getAccessToken(formRequest(formEndingInToken(1024))),
    ).toBe("body-token");
    expect(
      await small.getAccessToken(formRequest(formEndingInToken(1025))),
    ).toBe(null);
  });

  it("rejects a maxTokenBodyBytes that is not a positive integer", () => {
    const { tokenService } = createServices();
    for (const maxTokenBodyBytes of [0, -1, 1.5, Number.NaN, Infinity]) {
      const error = thrown(
        () =>
          new ResourceServer<TestClient, TestUser>({
            resolve: () => ({ services: { tokenService } }),
            maxTokenBodyBytes,
          }),
      );
      expect(error).toBeInstanceOf(RangeError);
      expect((error as RangeError).message).toContain("maxTokenBodyBytes");
    }
  });

  it("applies an AuthorizationServer's maxTokenBodyBytes to its userinfo token read", async () => {
    const { tokenService, clientService } = createServices();
    const authorizationServer = new AuthorizationServer<
      TestClient,
      TestUser,
      BasicScope
    >({
      resolve: () => ({
        services: { tokenService, clientService },
        issuer: "https://auth.example.com",
      }),
      grants: {},
      maxTokenBodyBytes: 1024,
    });

    expect(
      await authorizationServer.getAccessToken(
        formRequest(formEndingInToken(1024)),
      ),
    ).toBe("body-token");
    expect(
      await authorizationServer.getAccessToken(
        formRequest(formEndingInToken(1025)),
      ),
    ).toBe(null);
  });
});

describe("HonoResourceServer protect() form-body token read limit", () => {
  let server: HonoResourceServer<TestClient, TestUser>;

  beforeEach(async () => {
    const services = createServices();
    server = new HonoResourceServer<TestClient, TestUser>({
      resolve: () => ({ services: { tokenService: services.tokenService } }),
    });
    await services.userService.add(testUser, "password");
    await services.clientService.add(testClient);
    await services.tokenService.save({
      accessToken: "body-token",
      accessTokenExpiresAt: new Date(Date.now() + 3600_000),
      client: testClient,
      user: testUser,
      scope: new BasicScope("read"),
    });
  });

  it("refuses a token at the end of an oversized form body", async () => {
    const { stream, state } = countingStream(
      formEndingInToken(LARGE_BODY_BYTES),
    );

    const response = await protectedApp().request(
      "/api/items",
      streamedFormInit(stream),
    );

    expect(response.status).toBe(401);
    assertStoppedAtLimit(state.pulled);
  });

  function protectedApp(): Hono {
    const app = new Hono();
    app.use("/api/*", server.protect());
    app.post("/api/items", async (c) => c.text(await c.req.text()));
    return app;
  }

  it("answers an anonymous oversized form body with 401 after reading no more than the cap", async () => {
    const { stream, state } = countingStream(
      "pad=" + "a".repeat(LARGE_BODY_BYTES - 4),
    );

    const response = await protectedApp().request(
      "/api/items",
      streamedFormInit(stream),
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toBe(
      'Bearer realm="Service"',
    );
    assertStoppedAtLimit(state.pulled);
  });

  it("authenticates a form body token within the cap and hands the route the whole body", async () => {
    const form = formEndingInToken(DEFAULT_LIMIT);

    const response = await protectedApp().request("/api/items", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form,
    });

    expect(response.status).toBe(200);
    expect(await response.text()).toBe(form);
  });
});
