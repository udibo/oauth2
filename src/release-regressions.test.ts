import { stub } from "@std/testing/mock";
import { Hono } from "hono";
import { HonoBff } from "./adapters/hono/bff/bff.ts";
import { IdentityService } from "./identity/service.ts";
import type {
  PasswordCredential,
  PasswordHasherLike,
} from "./identity/password.ts";
import {
  MemoryTokenFlowStore,
  TokenFlowService,
  TokenPurpose,
} from "./identity/token-flow.ts";
import { assertEquals, assertRejects } from "@std/assert";
import { DirectClient } from "./client/direct-client.ts";
import {
  MemoryRefreshTokenStorage,
  MemoryTokenStorage,
} from "./client/storage.ts";
import { InvalidGrantError } from "./errors.ts";
import { oidcProvider } from "./identity/external/oidc.ts";
import { ExternalAuthError } from "./identity/external/errors.ts";
import { EmailOtpService, MemoryOtpStore } from "./identity/otp.ts";
import {
  MemorySessionStore,
  type SessionData,
} from "./adapters/hono/bff/session-store.ts";
import { RefreshTokenGrant } from "./server/grants/refresh-token.ts";
import {
  exchangeToken,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
  tokenRequest,
} from "./testing/_test_fixtures.ts";

async function refreshFixture() {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  const client: TestClient = { id: "client-1", confidential: true };
  const user: TestUser = { id: "user-1", username: "user" };
  await userService.add(user, "password");
  await clientService.add(client, "secret");
  const grant = new RefreshTokenGrant<TestClient, TestUser>({
    resolve: () => ({ clientService, tokenService }),
  });
  const token = await tokenService.save(
    await grant.generateToken(client, user, undefined, tokenService),
  );
  if (!("refreshToken" in token)) {
    throw new Error("fixture needs a refresh token");
  }
  const refreshToken = token.refreshToken;
  if (typeof refreshToken !== "string") {
    throw new Error("fixture needs refresh token text");
  }
  return { grant, tokenService, client, token: { ...token, refreshToken } };
}

Deno.test("release: a refresh token has only one concurrent successor", async () => {
  const { grant, tokenService, client, token } = await refreshFixture();
  const results = await Promise.allSettled(
    [1, 2].map(() =>
      exchangeToken(
        grant,
        tokenRequest({ refresh_token: token.refreshToken }),
        client,
      )
    ),
  );
  assertEquals(results.filter((r) => r.status === "fulfilled").length, 1);
  const failure = results.find((r) => r.status === "rejected");
  assertEquals(
    failure?.status === "rejected" &&
      failure.reason instanceof InvalidGrantError,
    true,
  );
  assertEquals(
    await tokenService.getRefreshToken(token.refreshToken),
    undefined,
  );
});

Deno.test("release: another client cannot revoke a replayed token's family", async () => {
  const { grant, tokenService, client, token } = await refreshFixture();
  const successor = await exchangeToken(
    grant,
    tokenRequest({ refresh_token: token.refreshToken }),
    client,
  );
  await assertRejects(() =>
    exchangeToken(grant, tokenRequest({ refresh_token: token.refreshToken }), {
      id: "client-2",
      confidential: true,
    })
  );
  assertEquals(
    Boolean(await tokenService.getToken(successor.accessToken)),
    true,
  );
});

Deno.test("release: a fresh login clears the previous grant's refresh token", async () => {
  const refreshTokenStorage = new MemoryRefreshTokenStorage();
  await refreshTokenStorage.set("alice-refresh");
  const client = new DirectClient({
    clientId: "app",
    redirectUri: "https://app.test/callback",
    endpoints: {
      authorization: "https://server.test/authorize",
      token: "https://server.test/token",
    },
    refreshTokenStorage,
    fetch: () =>
      Promise.resolve(
        Response.json({ access_token: "bob-access", token_type: "Bearer" }),
      ),
  });
  const { state } = await client.login();
  await client.handleAuthorizationCallback(
    new URLSearchParams({ code: "bob-code", state }),
  );
  assertEquals(await refreshTokenStorage.get(), null);
});

Deno.test("release: an email code succeeds only once under concurrency", async () => {
  const service = new EmailOtpService({ store: new MemoryOtpStore() });
  let code = "";
  const email = "user@example.test";
  await service.request({
    email,
    purpose: "signin",
    onDeliver: (value) => {
      code = value;
    },
  });
  const results = await Promise.all(
    [1, 2].map(() => service.verify({ email, purpose: "signin", code })),
  );
  assertEquals(results.filter((r) => r.status === "success").length, 1);
});

Deno.test("release: a session update cannot restore a destroyed session", async () => {
  const store = new MemorySessionStore();
  const data: SessionData = {
    tokens: { accessToken: "access", tokenType: "Bearer" },
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  const cookie = await store.create(data);
  await store.destroy(cookie);
  await assertRejects(() => store.update(cookie, data), InvalidGrantError);
  assertEquals(await store.read(cookie), null);
});

for (
  const endpoint of [
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
  ]
) {
  Deno.test(`release: OIDC rejects insecure ${endpoint} before credential exchange`, async () => {
    let calls = 0;
    const issuer = "https://issuer.example";
    const provider = oidcProvider({
      issuer,
      clientId: "app",
      clientSecret: "secret",
      fetch: () => {
        calls++;
        return Promise.resolve(
          Response.json({
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            [endpoint]: "http://issuer.example/insecure",
          }),
        );
      },
    });
    await assertRejects(
      () =>
        provider.buildAuthorizationUrl({
          redirectUri: "https://app.example/callback",
          state: "state",
          scopes: ["openid"],
        }),
      ExternalAuthError,
    );
    assertEquals(calls, 1);
  });
}

Deno.test("release: revoking a hydrated refresh record removes its paired access token", async () => {
  const { tokenService, token } = await refreshFixture();
  const hydrated = await tokenService.getRefreshToken(token.refreshToken);
  if (!hydrated) throw new Error("missing fixture token");
  await tokenService.revoke(hydrated);
  assertEquals(await tokenService.getToken(token.accessToken), undefined);
});

Deno.test("release: an outstanding refresh cannot reverse logout", async () => {
  const refreshTokenStorage = new MemoryRefreshTokenStorage();
  await refreshTokenStorage.set("refresh");
  const pending = Promise.withResolvers<Response>();
  const started = Promise.withResolvers<void>();
  const client = new DirectClient({
    clientId: "app",
    endpoints: {
      token: "https://server.test/token",
      revocation: "https://server.test/revoke",
    },
    refreshTokenStorage,
    fetch: (input) => {
      if (String(input).endsWith("/revoke")) {
        return Promise.resolve(new Response(null, { status: 200 }));
      }
      started.resolve();
      return pending.promise;
    },
  });
  const refreshing = client.refresh();
  const rejected = assertRejects(() => refreshing, InvalidGrantError);
  await started.promise;
  await client.logout();
  pending.resolve(
    Response.json({
      access_token: "new-access",
      refresh_token: "new-refresh",
      token_type: "Bearer",
    }),
  );
  await rejected;
  assertEquals(await refreshTokenStorage.get(), null);
});

for (const legacy of [false, true]) {
  Deno.test(`release: a ${legacy ? "legacy upgrade" : "password rehash"} cannot overwrite a completed password reset`, async () => {
    const started = Promise.withResolvers<void>();
    const resume = Promise.withResolvers<void>();
    const user = { id: "user" };
    let credential: PasswordCredential | undefined = legacy
      ? undefined
      : { hash: "old-password", salt: "salt" };
    const users = {
      create: () => Promise.resolve(user),
      findByIdentifier: () => Promise.resolve(user),
      findByEmail: () => Promise.resolve(user),
      getCredential: () => Promise.resolve(credential),
      getLegacyCredential: () =>
        Promise.resolve(legacy ? "legacy-password" : null),
      setCredential: (_id: string, value: PasswordCredential) => {
        credential = value;
        return Promise.resolve();
      },
      replaceCredential: (
        _id: string,
        expected: PasswordCredential | undefined,
        value: PasswordCredential,
      ) => {
        if (credential !== expected) return Promise.resolve(false);
        credential = value;
        return Promise.resolve(true);
      },
    };
    const passwords: PasswordHasherLike = {
      verify: (password, stored) => Promise.resolve(password === stored.hash),
      needsRehash: () => true,
      async hash(password) {
        if (password === "old-password") {
          started.resolve();
          await resume.promise;
        }
        return { hash: password, salt: "salt" };
      },
    };
    const tokens = new TokenFlowService(new MemoryTokenFlowStore());
    const identity = new IdentityService({
      users,
      passwords,
      tokens,
      failedSignInFloorMs: 0,
      legacyVerifiers: [{
        id: "legacy-test",
        canVerify: () => true,
        verify: () => Promise.resolve(true),
      }],
    });
    const reset = await tokens.create({
      purpose: TokenPurpose.PasswordReset,
      subject: user.id,
      ttlMs: 60000,
    });
    const signingIn = identity.signIn({
      identifier: user.id,
      password: "old-password",
    });
    await started.promise;
    try {
      await identity.resetPassword({
        token: reset.token,
        password: "new-password",
      });
    } finally {
      resume.resolve();
    }
    assertEquals(await signingIn, null);
    assertEquals(credential?.hash, "new-password");
  });
}

Deno.test("release: backchannel logout wins against an in-flight BFF refresh", async () => {
  const started = Promise.withResolvers<void>();
  const resume = Promise.withResolvers<void>();
  const store = new MemorySessionStore();
  const client = new DirectClient({
    clientId: "bff",
    clientSecret: "secret",
    endpoints: { token: "https://issuer.test/token" },
  });
  using _refresh = stub(client, "exchangeRefreshToken", async () => {
    started.resolve();
    await resume.promise;
    return {
      tokens: { accessToken: "renewed", tokenType: "Bearer" as const },
      raw: { access_token: "renewed", token_type: "Bearer" as const },
    };
  });
  const bff = new HonoBff({
    client,
    sessionStore: store,
    cookie: { secure: false },
    backchannelLogout: { verifyLogoutToken: () => ({ sub: "victim" }) },
  });
  const app = new Hono();
  app.route("/auth", bff.routes());
  app.use("/protected", bff.attachToken());
  app.get("/protected", (c) => c.text(c.req.header("authorization") ?? "none"));
  const now = Date.now();
  const cookie = await store.create({
    tokens: {
      accessToken: "old",
      tokenType: "Bearer",
      accessTokenExpiresAt: now - 1,
    },
    refreshToken: "refresh",
    user: { sub: "victim" },
    createdAt: now,
    updatedAt: now,
  });
  const pending = app.request("https://app.test/protected", {
    headers: { Cookie: `${bff.cookieName}=${cookie}`, "x-csrf": "1" },
  });
  await started.promise;
  try {
    const logout = await app.request("https://app.test/auth/backchannel", {
      method: "POST",
      body: new URLSearchParams({ logout_token: "verified" }),
    });
    assertEquals(logout.status, 200);
    await logout.body?.cancel();
    assertEquals(await store.read(cookie), null);
  } finally {
    resume.resolve();
  }
  const response = await pending;
  assertEquals(await response.text(), "none");
  assertEquals(await store.read(cookie), null);
});

Deno.test("release: a rotation-specific claim also permits only one successor", async () => {
  const { grant, tokenService, client, token } = await refreshFixture();
  Object.assign(tokenService, {
    revokeRotated: tokenService.revoke.bind(tokenService),
  });
  const results = await Promise.allSettled(
    [1, 2].map(() =>
      exchangeToken(
        grant,
        tokenRequest({ refresh_token: token.refreshToken }),
        client,
      )
    ),
  );
  assertEquals(results.filter((r) => r.status === "fulfilled").length, 1);
});

for (const fails of [false, true]) {
  Deno.test(`release: a refresh started during replacement cannot ${fails ? "clear" : "overwrite"} the new login`, async () => {
    const refreshTokenStorage = new MemoryRefreshTokenStorage();
    const tokenStorage = new MemoryTokenStorage();
    await refreshTokenStorage.set("alice-refresh");
    const codeStarted = Promise.withResolvers<void>();
    const refreshStarted = Promise.withResolvers<void>();
    const codeResponse = Promise.withResolvers<Response>();
    const refreshResponse = Promise.withResolvers<Response>();
    const client = new DirectClient({
      clientId: "app",
      redirectUri: "https://app.test/callback",
      endpoints: {
        authorization: "https://server.test/authorize",
        token: "https://server.test/token",
      },
      refreshTokenStorage,
      tokenStorage,
      fetch: (_url, init) => {
        if (
          new URLSearchParams(String(init?.body)).get("grant_type") ===
            "refresh_token"
        ) {
          refreshStarted.resolve();
          return refreshResponse.promise;
        }
        codeStarted.resolve();
        return codeResponse.promise;
      },
    });
    const { state } = await client.login();
    const loggingIn = client.handleAuthorizationCallback(
      new URLSearchParams({ code: "bob-code", state }),
    );
    await codeStarted.promise;
    const refreshing = client.refresh();
    const rejected = assertRejects(() => refreshing, InvalidGrantError);
    await refreshStarted.promise;
    codeResponse.resolve(
      Response.json({
        access_token: "bob-access",
        refresh_token: "bob-refresh",
        token_type: "Bearer",
      }),
    );
    await loggingIn;
    refreshResponse.resolve(
      fails
        ? Response.json({ error: "invalid_grant" }, { status: 400 })
        : Response.json({
          access_token: "alice-new",
          refresh_token: "alice-refresh-new",
          token_type: "Bearer",
        }),
    );
    await rejected;
    assertEquals((await tokenStorage.get())?.accessToken, "bob-access");
    assertEquals(await refreshTokenStorage.get(), "bob-refresh");
  });
}

Deno.test("release: refresh waits for an asynchronous login save to finish", async () => {
  const written = Promise.withResolvers<void>();
  const finishSet = Promise.withResolvers<void>();
  class PausedRefreshStorage extends MemoryRefreshTokenStorage {
    override async set(value: string): Promise<void> {
      await super.set(value);
      if (value === "bob-refresh") {
        written.resolve();
        await finishSet.promise;
      }
    }
  }
  const tokenStorage = new MemoryTokenStorage();
  const refreshTokenStorage = new PausedRefreshStorage();
  const requests: string[] = [];
  const client = new DirectClient({
    clientId: "app",
    redirectUri: "https://app.test/callback",
    endpoints: {
      authorization: "https://server.test/authorize",
      token: "https://server.test/token",
    },
    tokenStorage,
    refreshTokenStorage,
    fetch: (_url, init) => {
      const body = new URLSearchParams(String(init?.body));
      const refresh = body.get("grant_type") === "refresh_token";
      if (refresh) requests.push(body.get("refresh_token")!);
      return Promise.resolve(Response.json({
        access_token: refresh ? "bob-new-access" : "bob-access",
        refresh_token: refresh ? "bob-new-refresh" : "bob-refresh",
        token_type: "Bearer",
      }));
    },
  });
  const { state } = await client.login();
  const loggingIn = client.handleAuthorizationCallback(
    new URLSearchParams({ code: "bob-code", state }),
  );
  await written.promise;
  const refreshing = client.refresh();
  finishSet.resolve();
  const [, accessToken] = await Promise.all([loggingIn, refreshing]);
  assertEquals(accessToken, "bob-new-access");
  assertEquals(requests, ["bob-refresh"]);
  assertEquals(await refreshTokenStorage.get(), "bob-new-refresh");
  assertEquals((await tokenStorage.get())?.accessToken, "bob-new-access");
});

Deno.test("release: refresh queued behind login remains single-flight", async () => {
  const written = Promise.withResolvers<void>();
  const finishSet = Promise.withResolvers<void>();
  const readStarted = Promise.withResolvers<void>();
  const finishRead = Promise.withResolvers<void>();
  class PausedRefreshStorage {
    storage = new MemoryRefreshTokenStorage();
    clear(): void {
      this.storage.clear();
    }
    reads = 0;
    async get(): Promise<string | null> {
      if (++this.reads === 1) {
        readStarted.resolve();
        await finishRead.promise;
      }
      return this.storage.get();
    }
    async set(value: string): Promise<void> {
      this.storage.set(value);
      if (value === "bob-refresh") {
        written.resolve();
        await finishSet.promise;
      }
    }
  }
  const tokenStorage = new MemoryTokenStorage();
  const refreshTokenStorage = new PausedRefreshStorage();
  const requests: string[] = [];
  const client = new DirectClient({
    clientId: "app",
    redirectUri: "https://app.test/callback",
    endpoints: {
      authorization: "https://server.test/authorize",
      token: "https://server.test/token",
    },
    tokenStorage,
    refreshTokenStorage,
    fetch: (_url, init) => {
      const body = new URLSearchParams(String(init?.body));
      const refresh = body.get("grant_type") === "refresh_token";
      if (refresh) requests.push(body.get("refresh_token")!);
      return Promise.resolve(Response.json({
        access_token: refresh ? "bob-new-access" : "bob-access",
        refresh_token: refresh ? "bob-new-refresh" : "bob-refresh",
        token_type: "Bearer",
      }));
    },
  });
  const { state } = await client.login();
  const loggingIn = client.handleAuthorizationCallback(
    new URLSearchParams({ code: "bob-code", state }),
  );
  await written.promise;
  const refreshing = client.refresh();
  finishSet.resolve();
  await loggingIn;
  await readStarted.promise;
  const second = client.refresh();
  try {
    assertEquals(refreshing === second, true);
  } finally {
    finishRead.resolve();
    await Promise.allSettled([refreshing, second]);
  }
  const accessToken = await refreshing;
  assertEquals(accessToken, "bob-new-access");
  assertEquals(requests, ["bob-refresh"]);
  assertEquals(await refreshTokenStorage.get(), "bob-new-refresh");
  assertEquals((await tokenStorage.get())?.accessToken, "bob-new-access");
});
