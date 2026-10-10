import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { createTestSession } from "@udibo/oauth2/hono/bff/testing";

interface UpstreamRequest {
  method: string | undefined;
  url: string | undefined;
  authorization: string | undefined;
}

async function loadFreshApp() {
  vi.resetModules();
  const { default: app } = await import("./main.ts");
  const { bff } = await import("./oauth2/server.ts");
  return { app, bff };
}

describe("/remote-api/* proxy", () => {
  let upstream: Server;
  const received: UpstreamRequest[] = [];
  let loaded: Awaited<ReturnType<typeof loadFreshApp>>;

  beforeAll(async () => {
    upstream = createServer((req, res) => {
      received.push({
        method: req.method,
        url: req.url,
        authorization: req.headers.authorization,
      });
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ message: "from the api service" }));
    });
    await new Promise<void>((resolve) =>
      upstream.listen(0, "127.0.0.1", resolve),
    );
    const { port } = upstream.address() as AddressInfo;

    vi.stubEnv("API_SERVICE_URL", `http://127.0.0.1:${port}/api`);
    loaded = await loadFreshApp();
  });

  afterAll(async () => {
    vi.unstubAllEnvs();
    await new Promise<void>((resolve, reject) =>
      upstream.close((error) => (error ? reject(error) : resolve())),
    );
  });

  it("forwards the session's access token to the separate API and returns its answer", async () => {
    const { app, bff } = loaded;
    const cookie = await createTestSession(bff, {
      tokens: { accessToken: "session-access-token" },
      user: { sub: "user-1", username: "user" },
    });
    const res = await app.request("/remote-api/private?verbose=1", {
      headers: { cookie, [bff.csrfHeaderName!]: "1" },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ message: "from the api service" });
    expect(received).toEqual([
      {
        method: "GET",
        url: "/api/private?verbose=1",
        authorization: "Bearer session-access-token",
      },
    ]);
  });
});
