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

  it("serves the SPA homepage on the port the operating system picked", async () => {
    expect(new URL(running.url).port).not.toBe("0");
    const res = await fetch(`${running.url}/`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("App with external auth");
  });

  it("reports an anonymous browser through the BFF session endpoint", async () => {
    const res = await fetch(`${running.url}/auth/session`);
    expect(await res.json()).toStrictEqual({
      isAuthenticated: false,
      user: null,
    });
  });
});
