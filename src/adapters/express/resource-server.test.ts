import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { BasicScope } from "../../models/scope.ts";
import {
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../../testing/_test_fixtures.ts";

import {
  EXPRESS_VERSIONS,
  type Listening,
  listen,
  recordErrors,
} from "./_test_express.ts";
import { ExpressResourceServer } from "./resource-server.ts";

const testUser: TestUser = { id: "user-1", username: "testuser" };
const testClient: TestClient = { id: "client-1" };
const FORM = { "content-type": "application/x-www-form-urlencoded" };

describe.each(EXPRESS_VERSIONS)("ExpressResourceServer on %s", (_, express) => {
  let server: ExpressResourceServer<TestClient, TestUser>;
  let listening: Listening | undefined;

  beforeEach(async () => {
    const userService = new MemoryUserService();
    const clientService = new MemoryClientService(userService);
    const tokenService = new MemoryTokenService({ clientService, userService });
    await userService.add(testUser, "password");
    await clientService.add(testClient);
    await tokenService.save({
      accessToken: "read-token",
      accessTokenExpiresAt: new Date(Date.now() + 3600_000),
      client: testClient,
      user: testUser,
      scope: new BasicScope("read"),
    });
    server = new ExpressResourceServer<TestClient, TestUser>({
      resolve: () => ({ services: { tokenService } }),
      realm: "example",
    });
  });

  afterEach(async () => {
    await listening?.close();
    listening = undefined;
  });

  async function serve(app: ReturnType<typeof express>): Promise<string> {
    listening = await listen(app);
    return listening.origin;
  }

  function meRoute(app: ReturnType<typeof express>): void {
    app.get("/api/me", (_req, res) => {
      const context = server.getContext(res);
      res.json({ user: context.user?.id, client: context.client.id });
    });
  }

  it("stores the authenticated context for later handlers", async () => {
    const app = express();
    app.use("/api", server.protect());
    meRoute(app);
    const origin = await serve(app);

    const response = await fetch(`${origin}/api/me`, {
      headers: { authorization: "Bearer read-token" },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toStrictEqual({
      user: testUser.id,
      client: testClient.id,
    });
  });

  it("answers 401 with a Bearer challenge when no token is presented", async () => {
    const app = express();
    app.use("/api", server.protect());
    meRoute(app);
    const origin = await serve(app);

    const response = await fetch(`${origin}/api/me`);
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe(
      'Bearer realm="example"',
    );
  });

  it("answers 401 invalid_token for an unknown token", async () => {
    const app = express();
    app.use("/api", server.protect());
    meRoute(app);
    const origin = await serve(app);

    const response = await fetch(`${origin}/api/me`, {
      headers: { authorization: "Bearer unknown" },
    });
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toMatch(
      /error="invalid_token"/,
    );
  });

  it("answers 403 insufficient_scope from protect(scope) and from requireScope", async () => {
    const app = express();
    app.get("/write", server.protect("write"), (_req, res) => {
      res.send("written");
    });
    app.use("/api", server.protect());
    app.get("/api/read", server.requireScope("read"), (_req, res) => {
      res.send("read");
    });
    app.post("/api/write", server.requireScope("write"), (_req, res) => {
      res.send("written");
    });
    const origin = await serve(app);
    const headers = { authorization: "Bearer read-token" };

    const direct = await fetch(`${origin}/write`, { headers });
    expect(direct.status).toBe(403);
    expect(direct.headers.get("www-authenticate")).toBe(
      'Bearer realm="example", error="insufficient_scope", ' +
        'error_description="insufficient scope", scope="write"',
    );

    const allowed = await fetch(`${origin}/api/read`, { headers });
    expect(await allowed.text()).toBe("read");

    const refused = await fetch(`${origin}/api/write`, {
      method: "POST",
      headers,
    });
    expect(refused.status).toBe(403);
    expect(refused.headers.get("www-authenticate")).toBe(
      'Bearer realm="example", error="insufficient_scope", ' +
        'error_description="insufficient scope", scope="write"',
    );
  });

  it("answers require() scope failures with the insufficient_scope challenge", async () => {
    const app = express();
    app.use("/api", server.protect());
    app.get("/api/admin", server.require({ scope: "admin" }), (_req, res) => {
      res.send("admin");
    });
    const origin = await serve(app);

    const response = await fetch(`${origin}/api/admin`, {
      headers: { authorization: "Bearer read-token" },
    });
    expect(response.status).toBe(403);
    expect(response.headers.get("www-authenticate")).toMatch(
      /error="insufficient_scope"/,
    );
  });

  it("passes a developer error to next when requireScope runs without protect", async () => {
    const app = express();
    const { errors, handler } = recordErrors();
    app.get("/api/read", server.requireScope("read"), (_req, res) => {
      res.send("read");
    });
    app.use(handler);
    const origin = await serve(app);

    const response = await fetch(`${origin}/api/read`);
    expect(response.status).toBe(500);
    expect(await response.text()).toMatch(
      /ensure ExpressResourceServer\.protect\(\) middleware runs/,
    );
    expect(errors).toHaveLength(1);
  });

  it("leaves the request body for a parser mounted after protect", async () => {
    const app = express();
    app.use("/api", server.protect());
    app.use(express.json());
    app.post("/api/echo", (req, res) => {
      res.json(req.body);
    });
    const origin = await serve(app);

    const response = await fetch(`${origin}/api/echo`, {
      method: "POST",
      headers: {
        authorization: "Bearer read-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ kept: true }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toStrictEqual({ kept: true });
  });

  it("reads a form-encoded access_token a parser already parsed", async () => {
    const app = express();
    app.use(express.urlencoded({ extended: false }));
    app.use("/api", server.protect());
    app.post("/api/me", (_req, res) => {
      res.json({ user: server.getContext(res).user?.id });
    });
    const origin = await serve(app);

    const response = await fetch(`${origin}/api/me`, {
      method: "POST",
      headers: FORM,
      body: "access_token=read-token&note=hello",
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toStrictEqual({ user: testUser.id });
  });

  it("reads a form-encoded access_token a text parser left as a string", async () => {
    const app = express();
    app.use(express.text({ type: "application/x-www-form-urlencoded" }));
    app.use("/api", server.protect());
    app.post("/api/me", (_req, res) => {
      res.json({ user: server.getContext(res).user?.id });
    });
    const origin = await serve(app);

    const response = await fetch(`${origin}/api/me`, {
      method: "POST",
      headers: FORM,
      body: "access_token=read-token",
    });
    expect(await response.json()).toStrictEqual({ user: testUser.id });
  });

  it("does not drain an unparsed form body to look for an access_token", async () => {
    const app = express();
    app.use("/api", server.protect());
    const origin = await serve(app);

    const response = await fetch(`${origin}/api/me`, {
      method: "POST",
      headers: FORM,
      body: "access_token=read-token",
    });
    expect(response.status).toBe(401);
  });

  it("passes the error to next when throwOnError is set", async () => {
    server.throwOnError = true;
    const app = express();
    const { errors, handler } = recordErrors();
    app.use("/api", server.protect());
    meRoute(app);
    app.use(handler);
    const origin = await serve(app);

    const response = await fetch(`${origin}/api/me`);
    expect(response.status).toBe(500);
    expect(errors).toHaveLength(1);
  });

  it("authenticates an Express request inline", async () => {
    const app = express();
    app.get("/inline", async (req, res) => {
      const context = await server.authenticate(req, "read");
      res.json({ user: context.user?.id });
    });
    const origin = await serve(app);

    const response = await fetch(`${origin}/inline`, {
      headers: { authorization: "Bearer read-token" },
    });
    expect(await response.json()).toStrictEqual({ user: testUser.id });
  });

  it("authenticates a web Request inline", async () => {
    const context = await server.authenticate(
      new Request("http://localhost/", {
        headers: { authorization: "Bearer read-token" },
      }),
    );
    expect(context.user?.id).toBe(testUser.id);
  });
});
