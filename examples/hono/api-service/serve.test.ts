import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { type RunningServer, startServer } from "./serve.ts";

describe("startServer", () => {
  let running: RunningServer;

  beforeAll(async () => {
    running = await startServer(0);
  });

  afterAll(async () => {
    await running.close();
  });

  it("serves the app on the port the operating system picked", async () => {
    expect(new URL(running.url).port).not.toBe("0");
    const res = await fetch(`${running.url}/api/public`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      message: "Public endpoint — no token required.",
    });
  });

  it("challenges a request that carries no bearer token", async () => {
    const res = await fetch(`${running.url}/api/private`);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe(
      'Bearer realm="Example API"',
    );
  });
});
