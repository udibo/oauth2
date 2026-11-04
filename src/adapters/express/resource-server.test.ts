import { request as httpRequest } from "node:http";
import { connect } from "node:net";

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

async function rawHttp10(origin: string, path: string): Promise<string> {
  const { hostname, port } = new URL(origin);
  const socket = connect(Number(port), hostname);
  socket.end(
    `GET ${path} HTTP/1.0\r\nAuthorization: Bearer read-token\r\n\r\n`,
  );
  let response = "";
  for await (const chunk of socket) response += String(chunk);
  return response.split("\r\n", 1)[0];
}

function rawGet(
  origin: string,
  path: string,
  headers: Record<string, string>,
): Promise<number> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(`${origin}/`, { path, headers }, (response) => {
      response.resume();
      response.on("end", () => resolve(response.statusCode ?? 0));
    });
    request.on("error", reject);
    request.end();
  });
}

describe.each(EXPRESS_VERSIONS)("ExpressResourceServer on %s", (_, express) => {
  let server: ExpressResourceServer<TestClient, TestUser>;
  let listening: Listening | undefined;
  let resolvedUrls: string[];

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
    resolvedUrls = [];
    server = new ExpressResourceServer<TestClient, TestUser>({
      resolve: (request) => {
        resolvedUrls.push(request.url);
        return { services: { tokenService } };
      },
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

  it("hands the core the Host and the original target under a mount", async () => {
    const app = express();
    app.use("/api", server.protect());
    meRoute(app);
    const origin = await serve(app);

    await fetch(`${origin}/api/me?view=full`, {
      headers: { authorization: "Bearer read-token" },
    });
    expect(resolvedUrls).toStrictEqual([`${origin}/api/me?view=full`]);
  });

  it("takes only an exact https from X-Forwarded-Proto under trust proxy", async () => {
    const app = express();
    app.set("trust proxy", "loopback");
    app.use("/api", server.protect());
    meRoute(app);
    const origin = await serve(app);
    const host = new URL(origin).host;

    for (const proto of [
      "https",
      "https://evil.example/#",
      "http://evil.example/#",
    ]) {
      await rawGet(origin, "/api/me", {
        authorization: "Bearer read-token",
        "x-forwarded-proto": proto,
      });
    }
    expect(resolvedUrls).toStrictEqual([
      `https://${host}/api/me`,
      `http://${host}/api/me`,
      `http://${host}/api/me`,
    ]);
  });

  it("refuses an absolute-form target or a Host carrying more than a host", async () => {
    const app = express();
    app.use("/api", server.protect());
    meRoute(app);
    const origin = await serve(app);

    const absolute = await rawGet(origin, "http://evil.example/api/me", {
      authorization: "Bearer read-token",
    });
    const credentials = await rawGet(origin, "/api/me", {
      authorization: "Bearer read-token",
      host: "app.example@evil.example",
    });
    const path = await rawGet(origin, "/api/me", {
      authorization: "Bearer read-token",
      host: "app.example/evil#",
    });
    expect(absolute).toBe(500);
    expect(credentials).toBe(500);
    expect(path).toBe(500);
    expect(resolvedUrls).toStrictEqual([]);
  });

  it("refuses a backslash target that would resolve to another host", async () => {
    const app = express();
    app.use(server.protect());
    app.get("/:segment/api/me", (_req, res) => {
      res.send("served");
    });
    const origin = await serve(app);

    for (const path of ["/\\evil.example/api/me", "/\\/evil.example/api/me"]) {
      expect(
        await rawGet(origin, path, { authorization: "Bearer read-token" }),
        path,
      ).toBe(500);
    }
    expect(resolvedUrls).toStrictEqual([]);
  });

  it("refuses a dot segment the URL would remove but Express routes on", async () => {
    const app = express();
    const tenant = express.Router({ mergeParams: true });
    tenant.use(server.protect());
    tenant.get("/:collection/:id", (_req, res) => {
      res.send("served");
    });
    app.use("/t/:tenant", tenant);
    const origin = await serve(app);

    for (const path of [
      "/t/a/../b",
      "/t/a/%2e%2E/b",
      "/t/a/./b",
      "/t/a/..\\b",
    ]) {
      expect(
        await rawGet(origin, path, { authorization: "Bearer read-token" }),
        path,
      ).toBe(500);
    }
    expect(resolvedUrls).toStrictEqual([]);
    expect(
      await rawGet(origin, "/t/a/items/1", {
        authorization: "Bearer read-token",
      }),
    ).toBe(200);
  });

  it("refuses an X-Forwarded-Host that makes req.hostname differ from Host under trust proxy", async () => {
    const app = express();
    app.set("trust proxy", "loopback");
    app.use("/api", server.protect());
    meRoute(app);
    const origin = await serve(app);

    const forwarded = await rawGet(origin, "/api/me", {
      authorization: "Bearer read-token",
      "x-forwarded-host": "evil.example",
    });
    const sameHost = await rawGet(origin, "/api/me", {
      authorization: "Bearer read-token",
      "x-forwarded-host": new URL(origin).hostname,
    });
    expect(forwarded).toBe(500);
    expect(sameHost).toBe(200);
    expect(resolvedUrls).toHaveLength(1);
  });

  it("refuses a request with no Host header rather than inventing one", async () => {
    const app = express();
    app.use("/api", server.protect());
    meRoute(app);
    const origin = await serve(app);

    expect(await rawHttp10(origin, "/api/me")).toMatch(/^HTTP\/1\.1 500 /);
    expect(resolvedUrls).toStrictEqual([]);
  });

  it("finds no token in a repeated or nested parsed access_token", async () => {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    app.use("/api", server.protect());
    app.post("/api/me", (_req, res) => {
      res.json({ user: server.getContext(res).user?.id });
    });
    const origin = await serve(app);

    for (const body of [
      "access_token[]=read-token",
      "access_token[0]=read-token",
      "access_token=read-token&access_token=read-token",
    ]) {
      const response = await fetch(`${origin}/api/me`, {
        method: "POST",
        headers: FORM,
        body,
      });
      expect(response.status, body).toBe(401);
    }
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
