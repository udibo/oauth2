import { Hono } from "hono";
import { describe, expect, it } from "vitest";

import { createTestSession } from "@udibo/oauth2/hono/bff/testing";

import { requestContext } from "../app/context.ts";
import { createLoadContext } from "./load-context.ts";
import { bff } from "./oauth2/server.ts";

async function contextFor(headers: HeadersInit = {}) {
  const app = new Hono();
  app.get("/", async (c) => {
    const context = await createLoadContext(c);
    return c.json(context.get(requestContext));
  });
  const res = await app.request("/", { headers });
  return res.json();
}

describe("createLoadContext", () => {
  it("reports an anonymous visitor as signed out", async () => {
    expect(await contextFor()).toEqual({
      session: {
        isAuthenticated: false,
        user: null,
        sessionExpiresIn: null,
        logoutUrl: null,
      },
      demoAccount: true,
    });
  });

  it("reports the BFF session for the request's cookie, without tokens", async () => {
    const cookie = await createTestSession(bff, {
      tokens: { accessToken: "secret-access-token" },
      user: { sub: "user-1", name: "Ada" },
    });
    const { session } = await contextFor({ cookie });
    expect(session.isAuthenticated).toBe(true);
    expect(session.user).toEqual({ sub: "user-1", name: "Ada" });
    expect(JSON.stringify(session)).not.toContain("secret-access-token");
  });
});
