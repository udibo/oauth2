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
    expect(res.headers.get("content-type")).toContain("text/html");
  });

  it("serves the embedded identity provider's login form", async () => {
    const res = await fetch(`${running.url}/login`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("<form");
  });

  it("sends an anonymous authorize request to the login form", async () => {
    const authorize = new URLSearchParams({
      response_type: "code",
      client_id: "spa",
      redirect_uri: "http://localhost:8001/auth/callback",
      state: "abc",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
    });
    const res = await fetch(`${running.url}/oauth2/authorize?${authorize}`, {
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toMatch(/^\/login\?return_to=/);
  });
});
