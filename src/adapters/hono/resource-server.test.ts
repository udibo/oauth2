import {
  assert,
  assertEquals,
  assertFalse,
  assertStrictEquals,
} from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";
import { spy } from "@std/testing/mock";
import { Hono } from "hono";

import { BasicScope } from "../../models/scope.ts";
import {
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../../testing/_test_fixtures.ts";
import {
  HonoResourceServer,
  type HonoResourceServerVariables,
} from "./resource-server.ts";

const testUser: TestUser = { id: "user-1", username: "testuser" };
const testClient: TestClient = { id: "client-1" };

function createTestServices() {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  return { userService, clientService, tokenService };
}

function createTestServer(options: { realm?: string } = {}) {
  const services = createTestServices();
  const server = new HonoResourceServer<TestClient, TestUser>({
    resolve: () => ({ services: { tokenService: services.tokenService } }),
    realm: options.realm,
  });
  return { server, ...services };
}

type Vars = HonoResourceServerVariables<TestClient, TestUser>;

describe("HonoResourceServer", () => {
  let server: HonoResourceServer<TestClient, TestUser>;
  let tokenService: MemoryTokenService<TestClient, TestUser>;

  beforeEach(async () => {
    const result = createTestServer();
    server = result.server;
    tokenService = result.tokenService;
    await result.userService.add(testUser, "password");
    await result.clientService.add(testClient);
  });

  describe("protect middleware", () => {
    it("should pass through when token is valid and set context", async () => {
      await tokenService.save({
        accessToken: "valid",
        accessTokenExpiresAt: new Date(Date.now() + 3600_000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read"),
      });

      const app = new Hono<{ Variables: Vars }>();
      app.use("/api/*", server.protect());
      app.get("/api/me", (c) => {
        const ctx = server.getContext(c);
        return c.json({ userId: ctx.user?.id, clientId: ctx.client.id });
      });

      const res = await app.request("/api/me", {
        headers: { Authorization: "Bearer valid" },
      });

      assertStrictEquals(res.status, 200);
      const body = await res.json();
      assertEquals(body, { userId: testUser.id, clientId: testClient.id });
    });

    it("should return 401 with WWW-Authenticate when no token is present", async () => {
      const app = new Hono();
      app.use("/api/*", server.protect());
      app.get("/api/me", (c) => c.text("ok"));

      const res = await app.request("/api/me");

      assertStrictEquals(res.status, 401);
      // RFC 6750 §3.1: no credentials → bare challenge (realm only, no error code).
      const www = res.headers.get("WWW-Authenticate");
      assertStrictEquals(www, 'Bearer realm="Service"');
    });

    it("should return 401 with invalid_token for bad bearer tokens", async () => {
      const app = new Hono();
      app.use("/api/*", server.protect());
      app.get("/api/me", (c) => c.text("ok"));

      const res = await app.request("/api/me", {
        headers: { Authorization: "Bearer nonsense" },
      });

      assertStrictEquals(res.status, 401);
      const www = res.headers.get("WWW-Authenticate");
      assertEquals(www?.includes("invalid_token"), true);
      const body = await res.json();
      assertStrictEquals(body.error, "invalid_token");
    });

    it("should return 403 with insufficient_scope including required scope", async () => {
      await tokenService.save({
        accessToken: "limited",
        accessTokenExpiresAt: new Date(Date.now() + 3600_000),
        client: testClient,
        user: testUser,
        scope: new BasicScope("read"),
      });

      const app = new Hono();
      app.use("/api/*", server.protect("write"));
      app.get("/api/me", (c) => c.text("ok"));

      const res = await app.request("/api/me", {
        headers: { Authorization: "Bearer limited" },
      });

      assertStrictEquals(res.status, 403);
      const www = res.headers.get("WWW-Authenticate");
      assertEquals(www?.includes("insufficient_scope"), true);
      assertEquals(www?.includes('scope="write"'), true);
    });

    it("should not set WWW-Authenticate for non-401/403 failures", async () => {
      const app = new Hono();
      app.use("/api/*", server.protect());
      app.get("/api/me", () => {
        throw new Error("unexpected");
      });

      const res = await app.request("/api/me", {
        headers: { Authorization: "Bearer anything" },
      });

      assertStrictEquals(res.status, 401);
    });

    it("should rethrow when throwOnError is true", async () => {
      const services = createTestServices();
      const throwing = new HonoResourceServer<TestClient, TestUser>({
        resolve: () => ({ services: { tokenService: services.tokenService } }),
        throwOnError: true,
      });

      const app = new Hono();
      app.use("/api/*", throwing.protect());
      app.get("/api/me", (c) => c.text("ok"));
      app.onError((err, c) => {
        return c.json(
          {
            handled: true,
            error: (err as { extensions?: { error?: string } }).extensions
              ?.error,
          },
          500,
        );
      });

      const res = await app.request("/api/me");

      assertStrictEquals(res.status, 500);
      const body = await res.json();
      assertStrictEquals(body.handled, true);
      assertStrictEquals(body.error, "access_denied");
    });
  });

  describe("authenticate (manual)", () => {
    it("should authenticate a Hono context inline", async () => {
      await tokenService.save({
        accessToken: "manual",
        accessTokenExpiresAt: new Date(Date.now() + 3600_000),
        client: testClient,
        user: testUser,
      });

      const app = new Hono();
      app.get("/api/me", async (c) => {
        try {
          const ctx = await server.authenticate(c);
          return c.json({ userId: ctx.user?.id });
        } catch (error) {
          return server.handleAuthError(error);
        }
      });

      const ok = await app.request("/api/me", {
        headers: { Authorization: "Bearer manual" },
      });
      assertStrictEquals(ok.status, 200);
      const okBody = await ok.json();
      assertStrictEquals(okBody.userId, testUser.id);

      const bad = await app.request("/api/me");
      assertStrictEquals(bad.status, 401);
      assertStrictEquals(
        bad.headers.get("WWW-Authenticate"),
        'Bearer realm="Service"',
      );
    });
  });

  describe("requireScope middleware", () => {
    function scopedApp() {
      const app = new Hono<{ Variables: Vars }>();
      app.use("/api/*", server.protect());
      app.get("/api/items", server.requireScope("read"), (c) => c.text("list"));
      app.post(
        "/api/items",
        server.requireScope("write"),
        (c) => c.text("create"),
      );
      return app;
    }

    async function withToken(scope: string) {
      await tokenService.save({
        accessToken: "tok",
        accessTokenExpiresAt: new Date(Date.now() + 3600_000),
        client: testClient,
        user: testUser,
        scope: new BasicScope(scope),
      });
    }

    it("passes an already-authenticated request that carries the scope", async () => {
      await withToken("read write");
      const res = await scopedApp().request("/api/items", {
        method: "POST",
        headers: { Authorization: "Bearer tok" },
      });
      assertStrictEquals(res.status, 200);
      assertStrictEquals(await res.text(), "create");
    });

    it("returns 403 insufficient_scope (with the required scope) when the token lacks it", async () => {
      await withToken("read");
      const res = await scopedApp().request("/api/items", {
        method: "POST",
        headers: { Authorization: "Bearer tok" },
      });
      assertStrictEquals(res.status, 403);
      const www = res.headers.get("WWW-Authenticate");
      assertEquals(www?.includes("insufficient_scope"), true);
      assertEquals(www?.includes('scope="write"'), true);
    });

    it("enforces different scopes per verb on one authenticated mount", async () => {
      await withToken("read");
      const app = scopedApp();

      const get = await app.request("/api/items", {
        headers: { Authorization: "Bearer tok" },
      });
      assertStrictEquals(get.status, 200);

      const post = await app.request("/api/items", {
        method: "POST",
        headers: { Authorization: "Bearer tok" },
      });
      assertStrictEquals(post.status, 403);
    });

    it("does not re-validate the token — protect() looks it up once, the guard reuses the context", async () => {
      await withToken("read write");
      using getTokenSpy = spy(tokenService, "getToken");

      const res = await scopedApp().request("/api/items", {
        method: "POST",
        headers: { Authorization: "Bearer tok" },
      });

      assertStrictEquals(res.status, 200);
      assertStrictEquals(getTokenSpy.calls.length, 1);
    });

    it("throws a clear developer error when protect did not run first", async () => {
      const app = new Hono();
      app.post("/api/items", server.requireScope("write"), (c) => c.text("ok"));
      app.onError((err, c) => c.json({ message: err.message }, 500));

      const res = await app.request("/api/items", { method: "POST" });
      assertStrictEquals(res.status, 500);
      const body = await res.json();
      assertEquals(
        typeof body.message === "string" && body.message.includes("protect"),
        true,
      );
    });
  });

  describe("getContext", () => {
    it("should throw if protect did not run", async () => {
      const app = new Hono();
      app.get("/api/me", (c) => {
        server.getContext(c);
        return c.text("should not get here");
      });
      app.onError((err, c) => c.json({ message: err.message }, 500));

      const res = await app.request("/api/me");
      assertStrictEquals(res.status, 500);
      const body = await res.json();
      assertEquals(
        typeof body.message === "string" && body.message.includes("protect"),
        true,
      );
    });
  });
});

describe("HonoResourceServer require middleware", () => {
  const tokens = {
    claimed: {
      accessToken: "claimed",
      accessTokenExpiresAt: new Date(Date.now() + 3600_000),
      client: testClient,
      user: testUser,
      scope: new BasicScope("posts:read posts:write"),
      claims: {
        roles: ["editor"],
        permissions: ["posts:write"],
        org_id: "org-1",
        org_slug: "acme",
        org_roles: ["admin"],
      },
    },
    machine: {
      accessToken: "machine",
      accessTokenExpiresAt: new Date(Date.now() + 3600_000),
      client: testClient,
      scope: new BasicScope("identity:users:read"),
    },
  } as const;
  const server = new HonoResourceServer<TestClient, TestUser>({
    resolve: () => ({
      services: {
        tokenService: {
          getToken: (accessToken: string) =>
            Promise.resolve(
              tokens[accessToken as keyof typeof tokens] as
                | typeof tokens[keyof typeof tokens]
                | undefined,
            ),
        },
      },
    }),
  });

  function appRequiring(conditions: Parameters<typeof server.require>[0]) {
    const app = new Hono<{ Variables: Vars }>();
    app.use("/api/*", server.protect());
    app.get("/api/guarded", server.require(conditions), (c) => c.text("ok"));
    return app;
  }

  it("passes when every condition holds", async () => {
    const app = appRequiring({
      scope: "posts:write",
      permission: "posts:write",
      role: "editor",
      orgRole: "admin",
      organization: "acme",
    });
    const res = await app.request("/api/guarded", {
      headers: { Authorization: "Bearer claimed" },
    });
    assertStrictEquals(res.status, 200);
  });

  it("answers a scope failure with the insufficient_scope challenge", async () => {
    const app = appRequiring({ scope: ["posts:read", "posts:delete"] });
    const res = await app.request("/api/guarded", {
      headers: { Authorization: "Bearer claimed" },
    });
    assertStrictEquals(res.status, 403);
    assertEquals((await res.json()).error, "insufficient_scope");
    const challenge = res.headers.get("WWW-Authenticate") ?? "";
    assert(challenge.includes('error="insufficient_scope"'));
  });

  it("answers a permission failure with a plain 403 and no challenge code", async () => {
    const app = appRequiring({ permission: "posts:delete" });
    const res = await app.request("/api/guarded", {
      headers: { Authorization: "Bearer claimed" },
    });
    assertStrictEquals(res.status, 403);
    assertEquals((await res.json()).error, "insufficient_permissions");
    const challenge = res.headers.get("WWW-Authenticate") ?? "";
    assertFalse(challenge.includes("error="));
  });

  it("refuses the wrong organization", async () => {
    const app = appRequiring({ organization: "northwind" });
    const res = await app.request("/api/guarded", {
      headers: { Authorization: "Bearer claimed" },
    });
    assertStrictEquals(res.status, 403);
    assertEquals((await res.json()).error, "insufficient_permissions");
  });

  it("refuses a machine token every non-scope condition", async () => {
    for (
      const conditions of [
        { permission: "posts:write" },
        { role: "editor" },
        { orgRole: "admin" },
        { organization: true as const },
      ]
    ) {
      const res = await appRequiring(conditions).request("/api/guarded", {
        headers: { Authorization: "Bearer machine" },
      });
      assertStrictEquals(res.status, 403);
    }
    const scoped = await appRequiring({ scope: "identity:users:read" })
      .request("/api/guarded", {
        headers: { Authorization: "Bearer machine" },
      });
    assertStrictEquals(scoped.status, 200);
  });

  it("exposes the same authorization on the context", async () => {
    const app = new Hono<{ Variables: Vars }>();
    app.use("/api/*", server.protect());
    app.get("/api/me", (c) => {
      const { authorization } = server.getContext(c);
      return c.json({
        can: authorization.can("posts:write"),
        inOrg: authorization.inOrganization("acme"),
        hasScope: authorization.hasScope("posts:read"),
      });
    });
    const res = await app.request("/api/me", {
      headers: { Authorization: "Bearer claimed" },
    });
    assertEquals(await res.json(), { can: true, inOrg: true, hasScope: true });
  });
});
