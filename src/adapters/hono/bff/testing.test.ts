import { assertEquals, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { Hono } from "hono";

import { DirectClient } from "../../../client/mod.ts";
import { HonoResourceServer } from "../resource-server.ts";
import { createMemoryAuthorizationServer } from "../../../testing/server.ts";
import type { TestClient, TestUser } from "../../../testing/_test_fixtures.ts";

import { HonoBff } from "./bff.ts";
import {
  EncryptedCookieSessionStore,
  MemorySessionStore,
} from "./session-store.ts";
import {
  createAuthenticatedTestSession,
  createTestSession,
  forceTokenExpiry,
  readTestSession,
  runSessionStoreContractTests,
} from "./testing.ts";

const ISSUER = "http://localhost";

async function buildBff(
  options: {
    sessionStore?: ConstructorParameters<typeof HonoBff>[0]["sessionStore"];
  } = {},
) {
  const oauth = await createMemoryAuthorizationServer<TestClient, TestUser>({
    issuer: ISSUER,
    users: [{ user: { id: "u1", username: "alice" }, password: "pw" }],
    clients: [{
      client: {
        id: "spa",
        grants: ["authorization_code", "refresh_token"],
        redirectUris: [`${ISSUER}/auth/callback`],
      },
      secret: "shh",
      ownerUserId: "u1",
    }],
  });
  const oauthClient = new DirectClient({
    clientId: "spa",
    clientSecret: "shh",
    redirectUri: `${ISSUER}/auth/callback`,
    endpoints: {
      authorization: `${ISSUER}/oauth2/authorize`,
      token: `${ISSUER}/oauth2/token`,
    },
    fetch: oauth.fetch,
  });
  const resourceServer = new HonoResourceServer<TestClient, TestUser>({
    resolve: () => ({
      services: { tokenService: oauth.services.tokenService },
    }),
  });
  const bff = new HonoBff({
    client: oauthClient,
    cookie: { secure: false },
    defaultReturnTo: "/",
    resourceServer,
    sessionStore: options.sessionStore,
  });
  return { oauth, bff, oauthClient, resourceServer };
}

describe("createTestSession", () => {
  it("seeds a session that drives a protected route without the login flow", async () => {
    const { oauth, bff } = await buildBff();
    const accessToken = await oauth.services.tokenService.generateAccessToken(
      (await oauth.services.clientService.get("spa"))!,
      (await oauth.services.userService.get("u1"))!,
    );
    await oauth.services.tokenService.save({
      accessToken,
      client: (await oauth.services.clientService.get("spa"))!,
      user: (await oauth.services.userService.get("u1"))!,
    });

    const cookie = await createTestSession(bff, {
      tokens: { accessToken },
      user: { sub: "u1", name: "Alice" },
    });

    const app = new Hono();
    app.use("/api/*", bff.protect());
    app.get("/api/me", (c) => c.json({ ok: true, sub: "u1" }));

    const res = await app.request("/api/me", {
      headers: { cookie, [bff.csrfHeaderName!]: "1" },
    });
    assertStrictEquals(res.status, 200);
    assertEquals(await res.json(), { ok: true, sub: "u1" });
  });

  it("readTestSession returns the data we just stored", async () => {
    const { bff } = await buildBff();
    const cookie = await createTestSession(bff, {
      tokens: { accessToken: "tok-1" },
      refreshToken: "ref-1",
      user: { sub: "u9" },
    });
    const data = await readTestSession(bff, cookie);
    assertEquals(data?.tokens.accessToken, "tok-1");
    assertEquals(data?.refreshToken, "ref-1");
    assertEquals(data?.user, { sub: "u9" });
  });
});

describe("createAuthenticatedTestSession", () => {
  it("mints+registers a token and seeds a session for a protected route in one call", async () => {
    const { oauth, bff } = await buildBff();
    const client = (await oauth.services.clientService.get("spa"))!;
    const user = (await oauth.services.userService.get("u1"))!;

    const cookie = await createAuthenticatedTestSession(bff, {
      tokenService: oauth.services.tokenService,
      client,
      user,
      claims: { sub: "u1", name: "Alice" },
    });

    const app = new Hono();
    app.use("/api/*", bff.protect());
    app.get("/api/me", (c) => c.json({ ok: true, sub: "u1" }));

    const res = await app.request("/api/me", {
      headers: { cookie, [bff.csrfHeaderName!]: "1" },
    });
    assertStrictEquals(res.status, 200);
    assertEquals(await res.json(), { ok: true, sub: "u1" });
  });
});

describe("forceTokenExpiry", () => {
  it("ages the token so attachToken triggers a refresh", async () => {
    const { oauth, bff } = await buildBff();
    const client = (await oauth.services.clientService.get("spa"))!;
    const user = (await oauth.services.userService.get("u1"))!;
    const accessToken = await oauth.services.tokenService.generateAccessToken(
      client,
      user,
    );
    const refreshToken = await oauth.services.tokenService.generateRefreshToken(
      client,
      user,
    );
    await oauth.services.tokenService.save({
      accessToken,
      accessTokenExpiresAt: new Date(Date.now() + 60_000),
      refreshToken: refreshToken!,
      refreshTokenExpiresAt: new Date(Date.now() + 600_000),
      client,
      user,
    });

    const cookie = await createTestSession(bff, {
      tokens: { accessToken },
      refreshToken: refreshToken!,
    });

    const aged = await forceTokenExpiry(bff, cookie);
    const sessionAfterAging = await readTestSession(bff, aged);
    assertEquals(
      sessionAfterAging!.tokens.accessTokenExpiresAt! < Date.now(),
      true,
    );

    const app = new Hono();
    const inboundTokensSeen: string[] = [];
    app.use("/api/*", bff.attachToken(), async (c, next) => {
      inboundTokensSeen.push(c.req.raw.headers.get("Authorization") ?? "");
      await next();
    });
    app.get("/api/probe", (c) => c.text("ok"));

    const res = await app.request("/api/probe", {
      headers: { cookie: aged, [bff.csrfHeaderName!]: "1" },
    });
    assertStrictEquals(res.status, 200);
    assertStrictEquals(inboundTokensSeen.length, 1);
    const authHeader = inboundTokensSeen[0];
    assertEquals(authHeader.startsWith("Bearer "), true);
    assertEquals(
      authHeader === `Bearer ${accessToken}`,
      false,
      "expected attachToken to swap the expired token for the refreshed one",
    );
  });
});

runSessionStoreContractTests({
  describeName: "MemorySessionStore satisfies SessionStore contract",
  makeStore: () => new MemorySessionStore(),
});

runSessionStoreContractTests({
  describeName: "EncryptedCookieSessionStore satisfies SessionStore contract",
  makeStore: () =>
    new EncryptedCookieSessionStore({
      secret: crypto.getRandomValues(new Uint8Array(32)),
    }),
  destroyClearsRead: false,
  makeBoundedStore: (maxAgeMs) =>
    new EncryptedCookieSessionStore({
      secret: crypto.getRandomValues(new Uint8Array(32)),
      maxAgeMs,
    }),
});
