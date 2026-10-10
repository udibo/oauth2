import { assert, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeTime } from "../_test_fake-time.ts";
import { rejection, thrown } from "../_test_assert.ts";
import type { OAuth2ErrorCode } from "../models/responses.ts";
import { AuthorizationCodeGrant } from "../server/grants/authorization-code.ts";
import { ClientCredentialsGrant } from "../server/grants/client-credentials.ts";
import { DeviceAuthorizationGrant } from "../server/grants/device-authorization.ts";
import { RefreshTokenGrant } from "../server/grants/refresh-token.ts";
import {
  AuthorizationServer,
  localAuthServerFetch,
} from "../server/authorization-server.ts";
import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../testing/_test_fixtures.ts";
import {
  AccessDeniedError,
  InvalidGrantError,
  ServerError,
  TemporarilyUnavailableError,
} from "../errors.ts";
import { base64urlEncode } from "../utils/crypto.ts";

import { DirectClient } from "./direct-client.ts";
import {
  type AuthRequestRecord,
  type AuthRequestStorage,
  MemoryAuthRequestStorage,
  MemoryRefreshTokenStorage,
  MemoryTokenStorage,
} from "./storage.ts";
import { MAX_RESPONSE_BYTES, REQUEST_TIMEOUT_MS } from "./_http.ts";
import { controlTimeouts } from "../_test_timeouts.ts";
import { serveNoHeaders, serveStalledBody } from "./_test_interrupted_body.ts";
import type { OAuth2ClientEvent } from "./events.ts";

const ISSUER = "http://localhost";
const TOKEN_URL = `${ISSUER}/token`;
const AUTHORIZE_URL = `${ISSUER}/authorize`;
const REVOKE_URL = `${ISSUER}/revoke`;
const INTROSPECT_URL = `${ISSUER}/introspect`;
const DEVICE_URL = `${ISSUER}/device_authorization`;
const METADATA_URL = `${ISSUER}/.well-known/oauth-authorization-server`;
const REDIRECT_URI = "http://app.example/callback";

const testUser: TestUser = { id: "user-1", username: "demo" };
const testClient: TestClient = {
  id: "client-1",
  confidential: true,
  grants: [
    "client_credentials",
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
  ],
  redirectUris: [REDIRECT_URI],
};
const CLIENT_SECRET = "secret";

const testPublicClient: TestClient = {
  id: "spa-client",
  confidential: false,
  grants: [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
  ],
  redirectUris: [REDIRECT_URI],
};

async function buildFixture() {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  const authorizationCodeService = new MemoryAuthorizationCodeService({
    clientService,
    userService,
  });
  const deviceAuthorizationService = new MemoryDeviceAuthorizationService({
    clientService,
    userService,
  });

  await userService.add(testUser, "password");
  await clientService.add(testClient, CLIENT_SECRET, testUser.id);
  await clientService.add(testPublicClient, undefined, testUser.id);

  const authorizationCodeGrant = new AuthorizationCodeGrant({
    resolve: () => ({ clientService, tokenService, authorizationCodeService }),
    allowRefreshToken: true,
  });
  const clientCredentialsGrant = new ClientCredentialsGrant({
    resolve: () => ({ clientService, tokenService }),
  });
  const refreshTokenGrant = new RefreshTokenGrant({
    resolve: () => ({ clientService, tokenService }),
  });
  const deviceAuthorizationGrant = new DeviceAuthorizationGrant({
    resolve: () => ({
      clientService,
      tokenService,
      deviceAuthorizationService,
    }),
    allowRefreshToken: true,
  });

  const authServer = new AuthorizationServer({
    resolve: () => ({
      services: { clientService, tokenService },
      issuer: ISSUER,
      tokenEndpoint: TOKEN_URL,
      authorizationEndpoint: AUTHORIZE_URL,
      revocationEndpoint: REVOKE_URL,
      introspectionEndpoint: INTROSPECT_URL,
      deviceAuthorizationEndpoint: DEVICE_URL,
      verificationUri: `${ISSUER}/device`,
    }),
    grants: {
      authorization_code: authorizationCodeGrant,
      client_credentials: clientCredentialsGrant,
      refresh_token: refreshTokenGrant,
      "urn:ietf:params:oauth:grant-type:device_code": deviceAuthorizationGrant,
    },
    scopesSupported: ["read", "write"],
  });

  return {
    authServer,
    clientService,
    tokenService,
    authorizationCodeService,
    deviceAuthorizationService,
    userService,
    fetchImpl: localAuthServerFetch(authServer),
  };
}

async function performAuthorizeRedirect(
  authServer: Awaited<ReturnType<typeof buildFixture>>["authServer"],
  authorizeUrl: string,
): Promise<string> {
  const request = new Request(authorizeUrl);
  const response = await authServer.handleAuthorizeRequest(request, () =>
    Promise.resolve({ user: testUser }),
  );
  expect(response.status).toBe(302);
  const location = response.headers.get("Location");
  if (!location) throw new Error("missing redirect location");
  return location;
}

function urlOf(input: RequestInfo | URL): string {
  return typeof input === "string" || input instanceof URL
    ? input.toString()
    : input.url;
}

function fakeSessionStorage(): {
  storage: Storage;
  entries: Map<string, string>;
} {
  const entries = new Map<string, string>();
  const storage = {
    get length(): number {
      return entries.size;
    },
    getItem: (key: string) => entries.get(key) ?? null,
    setItem: (key: string, value: string) => {
      entries.set(key, value);
    },
    removeItem: (key: string) => {
      entries.delete(key);
    },
    clear: () => entries.clear(),
    key: (index: number) => Array.from(entries.keys())[index] ?? null,
  };
  return { storage: storage as Storage, entries };
}

function defineGlobal(name: string, value: unknown): () => void {
  const previous = Object.getOwnPropertyDescriptor(globalThis, name);
  Object.defineProperty(globalThis, name, {
    value,
    configurable: true,
    writable: true,
  });
  return () => {
    delete (globalThis as Record<string, unknown>)[name];
    if (previous) Object.defineProperty(globalThis, name, previous);
  };
}

function simulateBrowser(sessionStorage: Storage): Disposable {
  const restoreDocument = defineGlobal("document", {});
  const restoreSessionStorage = defineGlobal("sessionStorage", sessionStorage);
  return {
    [Symbol.dispose]() {
      restoreSessionStorage();
      restoreDocument();
    },
  };
}

describe("DirectClient", () => {
  let fixture: Awaited<ReturnType<typeof buildFixture>>;

  beforeEach(async () => {
    fixture = await buildFixture();
  });

  describe("authorization code + PKCE", () => {
    it("uses an explicit redirectUri override verbatim", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: "https://app.example/configured/cb",
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
      });
      const { url } = await client.login({
        redirectUri: "https://app.example/derived/cb",
      });
      expect(new URL(url).searchParams.get("redirect_uri")).toBe(
        "https://app.example/derived/cb",
      );
    });

    it("performs a full auth-code round trip and persists the token bundle", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });

      const begin = await client.login({
        returnTo: "/dashboard",
        scope: "read",
      });

      const begUrl = new URL(begin.url);
      expect(begUrl.searchParams.get("response_type")).toBe("code");
      expect(begUrl.searchParams.get("client_id")).toBe(testPublicClient.id);
      expect(begUrl.searchParams.get("code_challenge_method")).toBe("S256");

      const callback = await performAuthorizeRedirect(
        fixture.authServer,
        begin.url,
      );

      const events: OAuth2ClientEvent[] = [];
      const unsubscribe = client.subscribe((e) => events.push(e));

      const result = await client.handleAuthorizationCallback(callback);
      unsubscribe();

      expect(result.returnTo).toBe("/dashboard");
      expect(typeof result.tokens.accessToken).toBe("string");
      expect(events[0]?.type).toBe("authenticated");
    });

    it("is idempotent on duplicate callbacks for the same code (strict-mode guard)", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      const begin = await client.login();
      const callback = await performAuthorizeRedirect(
        fixture.authServer,
        begin.url,
      );

      const [a, b] = await Promise.all([
        client.handleAuthorizationCallback(callback),
        client.handleAuthorizationCallback(callback),
      ]);
      expect(a.tokens.accessToken).toBe(b.tokens.accessToken);
    });

    it("surfaces the OAuth2 error when the callback URL has ?error=…", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      await rejection(
        () =>
          client.handleAuthorizationCallback(
            `${REDIRECT_URI}?error=access_denied&error_description=nope`,
          ),
        Error,
        "nope",
      );
    });
  });

  describe("refresh flow", () => {
    it("deduplicates concurrent refreshes and rotates the refresh token", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      const begin = await client.login();
      const callback = await performAuthorizeRedirect(
        fixture.authServer,
        begin.url,
      );
      await client.handleAuthorizationCallback(callback);

      const events: OAuth2ClientEvent[] = [];
      client.subscribe((e) => events.push(e));

      const [a, b] = await Promise.all([client.refresh(), client.refresh()]);
      expect(a, "single-flight refresh should share promise").toBe(b);
      expect(events.filter((e) => e.type === "token_refreshed").length).toBe(1);
    });

    it("clears session and emits logged_out on invalid_grant", async () => {
      const refreshStore = new MemoryRefreshTokenStorage();
      await refreshStore.set("bogus-refresh");
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
        refreshTokenStorage: refreshStore,
      });

      const events: OAuth2ClientEvent[] = [];
      client.subscribe((e) => events.push(e));

      await rejection(() => client.refresh(), InvalidGrantError);
      expect(
        events.some(
          (e) => e.type === "logged_out" && e.reason === "invalid_grant",
        ),
      ).toBe(true);
    });

    it("refuses the refresh when the refresh token store cannot be read", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
        refreshTokenStorage: {
          get: () => Promise.reject(new Error("indexeddb unavailable")),
          set: () => {},
          clear: () => {},
        },
      });

      const events: OAuth2ClientEvent[] = [];
      client.subscribe((e) => events.push(e));

      await rejection(() => client.refresh(), Error, "indexeddb unavailable");
      expect(
        events.filter((e) => e.type === "error").length,
        "a store that cannot be read is reported, not thrown past the client",
      ).toBe(1);
      expect(
        events.some((e) => e.type === "logged_out"),
        "a broken store is not evidence the grant died",
      ).toBe(false);
    });

    it("stays quiet about an unreadable store on the background renew path", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
        refreshTokenStorage: {
          get: () => Promise.reject(new Error("indexeddb unavailable")),
          set: () => {},
          clear: () => {},
        },
      });

      const events: OAuth2ClientEvent[] = [];
      client.subscribe((e) => events.push(e));

      const session = await client.renewSession();
      expect(session.isAuthenticated).toBe(false);
      expect(events.filter((e) => e.type === "error").length).toBe(0);
    });
  });

  describe("client credentials", () => {
    it("issues a token for a confidential client", async () => {
      const client = new DirectClient({
        clientId: testClient.id,
        clientSecret: CLIENT_SECRET,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      const tokens = await client.getClientCredentialsToken({ scope: "read" });
      expect(typeof tokens.accessToken).toBe("string");
      expect(tokens.scope).toBe("read");
    });

    it("rejects without a clientSecret", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      expect(client.isConfidential).toBe(false);
      await rejection(
        () => client.getClientCredentialsToken(),
        Error,
        "clientSecret",
      );
    });

    it("authenticates a confidential client via Basic only, never duplicating client_id (RFC 6749 §2.3.1)", async () => {
      await fixture.tokenService.save({
        accessToken: "at-conf",
        accessTokenExpiresAt: new Date(Date.now() + 3600_000),
        refreshToken: "rt-conf",
        refreshTokenExpiresAt: new Date(Date.now() + 86_400_000),
        client: testClient,
        user: testUser,
      });

      let capturedBody: URLSearchParams | undefined;
      let capturedAuth: string | null = null;
      const spyFetch: typeof fetch = (input, init) => {
        if (urlOf(input) === TOKEN_URL && init?.method === "POST") {
          capturedBody =
            init.body instanceof URLSearchParams
              ? init.body
              : new URLSearchParams(String(init.body));
          capturedAuth = new Headers(init.headers).get("authorization");
        }
        return fixture.fetchImpl(input, init);
      };

      const client = new DirectClient({
        clientId: testClient.id,
        clientSecret: CLIENT_SECRET,
        endpoints: { token: TOKEN_URL },
        fetch: spyFetch,
      });

      await client.exchangeRefreshToken("rt-conf");

      expect(capturedAuth ?? "").toContain("Basic ");
      expect(capturedBody?.has("client_id")).toBe(false);
    });

    it("strips a caller-set body client_id for confidential clients (#postToken, RFC 6749 §2.3.1)", async () => {
      // Guards #postToken's body.delete: pollDeviceToken sets a body client_id
      // that must be dropped when authenticating via Basic.
      let capturedBody: URLSearchParams | undefined;
      let capturedAuth: string | null = null;
      const spyFetch: typeof fetch = (input, init) => {
        if (urlOf(input) === TOKEN_URL && init?.method === "POST") {
          capturedBody =
            init.body instanceof URLSearchParams
              ? init.body
              : new URLSearchParams(String(init.body));
          capturedAuth = new Headers(init.headers).get("authorization");
          return Promise.resolve(
            new Response(
              JSON.stringify({ access_token: "dev-at", token_type: "Bearer" }),
              { status: 200, headers: { "content-type": "application/json" } },
            ),
          );
        }
        return Promise.resolve(new Response(null, { status: 404 }));
      };

      const client = new DirectClient({
        clientId: testClient.id,
        clientSecret: CLIENT_SECRET,
        endpoints: { token: TOKEN_URL },
        fetch: spyFetch,
      });

      await client.pollDeviceToken("device-code", { interval: 1 });

      expect(capturedAuth ?? "").toContain("Basic ");
      expect(capturedBody?.has("client_id")).toBe(false);
    });
  });

  describe("introspection and revocation", () => {
    it("introspects an active token and revokes it", async () => {
      const client = new DirectClient({
        clientId: testClient.id,
        clientSecret: CLIENT_SECRET,
        endpoints: {
          token: TOKEN_URL,
          introspection: INTROSPECT_URL,
          revocation: REVOKE_URL,
        },
        fetch: fixture.fetchImpl,
      });
      const { accessToken } = await client.getClientCredentialsToken();

      const active = await client.introspect(accessToken);
      expect(active.active).toBe(true);
      expect(active.client_id).toBe(testClient.id);

      await client.revoke(accessToken);
    });
  });

  describe("device authorization", () => {
    it("starts a device authorization request", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL, deviceAuthorization: DEVICE_URL },
        fetch: fixture.fetchImpl,
      });
      const res = await client.startDeviceAuthorization({ scope: "read" });
      expect(typeof res.device_code).toBe("string");
      expect(typeof res.user_code).toBe("string");
      expect(res.verification_uri).toBe(`${ISSUER}/device`);
    });

    it("authenticates a confidential client at the device endpoint (RFC 8628 §3.1)", async () => {
      const client = new DirectClient({
        clientId: testClient.id,
        clientSecret: CLIENT_SECRET,
        endpoints: { token: TOKEN_URL, deviceAuthorization: DEVICE_URL },
        fetch: fixture.fetchImpl,
      });
      const res = await client.startDeviceAuthorization({ scope: "read" });
      expect(typeof res.device_code).toBe("string");
      expect(typeof res.user_code).toBe("string");
    });

    it("polls through authorization_pending and slow_down to a token (RFC 8628 §3.4)", async () => {
      using time = new FakeTime();
      let calls = 0;
      const pendingError = (code: string) =>
        new Response(JSON.stringify({ error: code }), {
          status: 400,
          headers: { "content-type": "application/json" },
        });
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: (input, init) => {
          if (urlOf(input) === TOKEN_URL && init?.method === "POST") {
            const body =
              init.body instanceof URLSearchParams
                ? init.body
                : new URLSearchParams(String(init.body));
            expect(body.get("client_id")).toBe(testPublicClient.id);
            calls++;
            if (calls === 1) {
              return Promise.resolve(pendingError("authorization_pending"));
            }
            if (calls === 2) return Promise.resolve(pendingError("slow_down"));
            return Promise.resolve(
              new Response(
                JSON.stringify({
                  access_token: "device-at",
                  token_type: "Bearer",
                }),
                {
                  status: 200,
                  headers: { "content-type": "application/json" },
                },
              ),
            );
          }
          return Promise.resolve(new Response(null, { status: 404 }));
        },
      });

      const promise = client.pollDeviceToken("device-code", { interval: 2 });
      await time.tickAsync(2000);
      await time.tickAsync(7000);
      const tokens = await promise;

      expect(tokens.accessToken).toBe("device-at");
      expect(calls).toBe(3);
    });

    it("rejects with access_denied when aborted mid-wait", async () => {
      using time = new FakeTime();
      const controller = new AbortController();
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: () =>
          Promise.resolve(
            new Response(JSON.stringify({ error: "authorization_pending" }), {
              status: 400,
              headers: { "content-type": "application/json" },
            }),
          ),
      });

      const promise = client.pollDeviceToken("device-code", {
        interval: 5,
        signal: controller.signal,
      });
      await time.tickAsync(0);
      controller.abort();
      await rejection(() => promise, AccessDeniedError);
    });
  });

  describe("exchangeAuthorizationCode (auth-request TTL)", () => {
    it("rejects and clears a stale pending auth-request", async () => {
      const storage = new MemoryAuthRequestStorage();
      await storage.set("state-1", {
        codeVerifier: "v".repeat(43),
        // 11 minutes old — past the 10-minute default TTL.
        createdAt: Date.now() - 11 * 60 * 1000,
      });
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        authRequestStorage: storage,
      });
      await rejection(
        () => client.exchangeAuthorizationCode("code-1", "state-1"),
        InvalidGrantError,
        "authorization request expired",
      );
      expect(await storage.get("state-1")).toStrictEqual(null);
    });
  });

  describe("exchangeAuthorizationCode (configured auth-request TTL)", () => {
    it("keeps a pending login past 10 minutes in the default memory store when authRequestTtlMs allows it", async () => {
      using time = new FakeTime();
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        authRequestTtlMs: 30 * 60_000,
        fetch: respondingWith(() =>
          jsonResponse({ access_token: "at-1", token_type: "Bearer" }),
        ).fetch,
      });
      const { url } = await client.login();
      const state = new URL(url).searchParams.get("state")!;

      time.tick(11 * 60_000);
      await client.login();

      const result = await client.exchangeAuthorizationCode("code-1", state);
      expect(result.tokens.accessToken).toStrictEqual("at-1");
    });

    it("keeps a pending login past 10 minutes in the default browser store when authRequestTtlMs allows it", async () => {
      using time = new FakeTime();
      using _browser = simulateBrowser(fakeSessionStorage().storage);
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        authRequestTtlMs: 30 * 60_000,
        fetch: respondingWith(() =>
          jsonResponse({ access_token: "at-1", token_type: "Bearer" }),
        ).fetch,
      });
      const { url } = await client.login();
      const state = new URL(url).searchParams.get("state")!;

      time.tick(11 * 60_000);

      const result = await client.exchangeAuthorizationCode("code-1", state);
      expect(result.tokens.accessToken).toStrictEqual("at-1");
    });
  });

  describe("exchangeAuthorizationCode (single-use state)", () => {
    it("redeems a pending auth request once when two callbacks race on one state", async () => {
      const storage = new MemoryAuthRequestStorage();
      await storage.set("state-1", {
        codeVerifier: "v".repeat(43),
        createdAt: Date.now(),
      });
      const sink = respondingWith(() =>
        jsonResponse({ access_token: "at-1", token_type: "Bearer" }),
      );
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        authRequestStorage: storage,
        fetch: sink.fetch,
      });

      const outcomes = await Promise.allSettled([
        client.exchangeAuthorizationCode("code-1", "state-1"),
        client.exchangeAuthorizationCode("code-2", "state-1"),
      ]);

      expect(
        sink.calls,
        "a state must reach the token endpoint at most once",
      ).toStrictEqual([TOKEN_URL]);
      expect(outcomes.map((outcome) => outcome.status).sort()).toStrictEqual([
        "fulfilled",
        "rejected",
      ]);
      const rejected = outcomes.find(
        (outcome) => outcome.status === "rejected",
      ) as PromiseRejectedResult;
      assert(rejected.reason instanceof InvalidGrantError);
    });

    it("consumes the pending auth request even when the token call fails", async () => {
      const storage = new MemoryAuthRequestStorage();
      await storage.set("state-1", {
        codeVerifier: "v".repeat(43),
        createdAt: Date.now(),
      });
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        authRequestStorage: storage,
        fetch: respondingWith(() =>
          jsonResponse({ error: "invalid_grant" }, 400),
        ).fetch,
      });

      await rejection(
        () => client.exchangeAuthorizationCode("code-1", "state-1"),
        InvalidGrantError,
      );
      expect(await storage.get("state-1")).toStrictEqual(null);
    });

    it("removes the record before the token call from a store that has no take", async () => {
      const records = new Map<string, AuthRequestRecord>();
      const log: string[] = [];
      const storage: AuthRequestStorage = {
        get: (state) => {
          log.push("get");
          return records.get(state) ?? null;
        },
        set: (state, value) => {
          records.set(state, value);
        },
        delete: (state) => {
          log.push("delete");
          records.delete(state);
        },
        clear: () => records.clear(),
      };
      records.set("state-1", {
        codeVerifier: "v".repeat(43),
        createdAt: Date.now(),
      });
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        authRequestStorage: storage,
        fetch: ((input: RequestInfo | URL) => {
          log.push(`fetch ${urlOf(input)}`);
          return Promise.resolve(
            jsonResponse({ access_token: "at-1", token_type: "Bearer" }),
          );
        }) as typeof fetch,
      });

      await client.exchangeAuthorizationCode("code-1", "state-1");

      expect(log).toStrictEqual(["get", "delete", `fetch ${TOKEN_URL}`]);
    });
  });

  describe("wrapped fetch", () => {
    it("attaches Authorization: Bearer and refreshes on 401 invalid_token", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        fetch: (input, init) => {
          const url = new URL(
            typeof input === "string" || input instanceof URL
              ? input.toString()
              : input.url,
          );
          if (url.pathname === "/api/me") {
            const auth = new Headers(init?.headers).get("Authorization");
            if (!auth) {
              return Promise.resolve(
                new Response(null, {
                  status: 401,
                  headers: {
                    "WWW-Authenticate":
                      'Bearer realm="Service", error="invalid_token"',
                  },
                }),
              );
            }
            return Promise.resolve(
              new Response(JSON.stringify({ ok: true }), { status: 200 }),
            );
          }
          return fixture.fetchImpl(input, init);
        },
      });

      const begin = await client.login();
      const callback = await performAuthorizeRedirect(
        fixture.authServer,
        begin.url,
      );
      await client.handleAuthorizationCallback(callback);

      const res = await client.fetch(`${ISSUER}/api/me`);
      expect(res.status).toBe(200);
    });

    it("sends the headers a Request input was built with", async () => {
      let sent: Headers | undefined;
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: (input, init) => {
          sent = new Request(input, init).headers;
          return Promise.resolve(new Response(null, { status: 204 }));
        },
      });

      await client.fetch(
        new Request(`${ISSUER}/api/me`, {
          headers: { "x-trace": "abc", accept: "application/json" },
        }),
      );

      expect(sent?.get("x-trace")).toBe("abc");
      expect(sent?.get("accept")).toBe("application/json");
    });

    it("lets init.headers override a same-named Request header, keeping the rest", async () => {
      let sent: Headers | undefined;
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: (input, init) => {
          sent = new Request(input, init).headers;
          return Promise.resolve(new Response(null, { status: 204 }));
        },
      });

      await client.fetch(
        new Request(`${ISSUER}/api/me`, {
          headers: { "x-trace": "from-request", "x-keep": "kept" },
        }),
        { headers: { "x-trace": "from-init" } },
      );

      expect(sent?.get("x-trace")).toBe("from-init");
      expect(sent?.get("x-keep")).toBe("kept");
    });

    it("leaves an Authorization header set on a Request input alone", async () => {
      let sent: Headers | undefined;
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        fetch: (input, init) => {
          if (urlOf(input) === `${ISSUER}/api/me`) {
            sent = new Request(input, init).headers;
            return Promise.resolve(new Response(null, { status: 204 }));
          }
          return fixture.fetchImpl(input, init);
        },
      });

      const begin = await client.login();
      await client.handleAuthorizationCallback(
        await performAuthorizeRedirect(fixture.authServer, begin.url),
      );

      await client.fetch(
        new Request(`${ISSUER}/api/me`, {
          headers: { Authorization: "Bearer caller-supplied" },
        }),
      );

      expect(sent?.get("Authorization")).toBe("Bearer caller-supplied");
    });

    it("replays a Request-shaped POST body on the retry after refreshing", async () => {
      const bodies: string[] = [];
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        fetch: async (input, init) => {
          if (urlOf(input) !== `${ISSUER}/api/items`) {
            return await fixture.fetchImpl(input, init);
          }
          bodies.push(await new Request(input, init).text());
          if (bodies.length === 1) {
            return new Response(null, {
              status: 401,
              headers: {
                "WWW-Authenticate": 'Bearer error="invalid_token"',
              },
            });
          }
          return new Response(JSON.stringify({ ok: true }), { status: 200 });
        },
      });

      const begin = await client.login();
      await client.handleAuthorizationCallback(
        await performAuthorizeRedirect(fixture.authServer, begin.url),
      );

      const res = await client.fetch(
        new Request(`${ISSUER}/api/items`, {
          method: "POST",
          body: JSON.stringify({ name: "widget" }),
          headers: { "content-type": "application/json" },
        }),
      );

      expect(res.status).toBe(200);
      expect(bodies).toStrictEqual([
        JSON.stringify({ name: "widget" }),
        JSON.stringify({ name: "widget" }),
      ]);
    });

    it("rejects when the retry itself fails rather than reporting the stale 401", async () => {
      let apiCalls = 0;
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        fetch: (input, init) => {
          if (urlOf(input) !== `${ISSUER}/api/me`) {
            return fixture.fetchImpl(input, init);
          }
          apiCalls++;
          if (apiCalls === 1) {
            return Promise.resolve(
              new Response(null, {
                status: 401,
                headers: {
                  "WWW-Authenticate": 'Bearer error="invalid_token"',
                },
              }),
            );
          }
          return Promise.reject(new TypeError("network down"));
        },
      });

      const begin = await client.login();
      await client.handleAuthorizationCallback(
        await performAuthorizeRedirect(fixture.authServer, begin.url),
      );

      await rejection(
        () => client.fetch(`${ISSUER}/api/me`),
        TypeError,
        "network down",
      );
    });

    it("reports the original 401 when no new token can be minted", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: () =>
          Promise.resolve(
            new Response(null, {
              status: 401,
              headers: {
                "WWW-Authenticate": 'Bearer error="invalid_token"',
              },
            }),
          ),
      });

      const res = await client.fetch(`${ISSUER}/api/me`);
      expect(res.status).toBe(401);
    });
  });

  describe("session state", () => {
    it("reports signed out before any token is stored", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      expect(await client.getSession()).toStrictEqual({
        isAuthenticated: false,
        user: null,
        sessionExpiresIn: null,
        logoutUrl: null,
      });
    });

    it("reports authenticated from a stored token even with no id_token or userinfo", async () => {
      const client = new DirectClient({
        clientId: testClient.id,
        clientSecret: CLIENT_SECRET,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      await client.getClientCredentialsToken({ scope: "read" });

      const session = await client.getSession();
      expect(session.isAuthenticated).toBe(true);
      expect(session.user).toBe(null);
      expect(session.logoutUrl).toBe(null);
      expect(typeof session.sessionExpiresIn).toBe("number");
    });

    it("renewSession rotates the token and reports the fresh session", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      const begin = await client.login();
      const callback = await performAuthorizeRedirect(
        fixture.authServer,
        begin.url,
      );
      const { tokens } = await client.handleAuthorizationCallback(callback);

      const session = await client.renewSession();
      expect(session.isAuthenticated).toBe(true);
      expect(
        (await client.getAccessToken()) === tokens.accessToken,
        "renewSession must leave a rotated access token behind",
      ).toBe(false);
    });

    it("reports signed out for an expired token with nothing to revive it", async () => {
      const store = new MemoryTokenStorage();
      await store.set({
        accessToken: "at-stale",
        tokenType: "Bearer",
        accessTokenExpiresAt: Date.now() - 1_000,
      });
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        tokenStorage: store,
        fetch: fixture.fetchImpl,
      });
      expect((await client.getSession()).isAuthenticated).toBe(false);
    });

    it("reports signed in for an expired token a refresh token can revive", async () => {
      const tokens = new MemoryTokenStorage();
      await tokens.set({
        accessToken: "at-stale",
        tokenType: "Bearer",
        accessTokenExpiresAt: Date.now() - 1_000,
      });
      const refresh = new MemoryRefreshTokenStorage();
      await refresh.set("rt-live");
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        tokenStorage: tokens,
        refreshTokenStorage: refresh,
        fetch: fixture.fetchImpl,
      });
      const session = await client.getSession();
      expect(session.isAuthenticated).toBe(true);
      expect(session.sessionExpiresIn).toBe(0);
    });

    it("reports signed out for a bundle with an empty accessToken", async () => {
      const store = new MemoryTokenStorage();
      await store.set({ accessToken: "", tokenType: "Bearer" });
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        tokenStorage: store,
        fetch: fixture.fetchImpl,
      });
      expect((await client.getSession()).isAuthenticated).toBe(false);
    });

    it("reports signed out and emits error rather than rejecting on a broken id_token", async () => {
      const store = new MemoryTokenStorage();
      await store.set({
        accessToken: "at-ok",
        tokenType: "Bearer",
        accessTokenExpiresAt: Date.now() + 3600_000,
        idToken: "not-a-jwt",
      });
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        tokenStorage: store,
        fetch: fixture.fetchImpl,
      });
      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      const session = await client.getSession();
      expect(session.isAuthenticated).toBe(false);
      expect(events.filter((e) => e.type === "error").length).toBe(1);
    });

    it("stays quiet about a transport failure during a background renew", async () => {
      const refresh = new MemoryRefreshTokenStorage();
      await refresh.set("rt-live");
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        refreshTokenStorage: refresh,
        fetch: (() => Promise.reject(new TypeError("offline"))) as typeof fetch,
      });
      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      await client.renewSession();
      expect(
        events,
        "a blip on a background timer must not paint a user-visible error",
      ).toStrictEqual([]);

      await rejection(() => client.refresh(), TemporarilyUnavailableError);
      expect(
        events.map((event) => event.type),
        "an explicit refresh still reports the same failure",
      ).toStrictEqual(["error"]);
    });

    it("stays quiet when a background renew cannot resolve the user either", async () => {
      const tokens = new MemoryTokenStorage();
      await tokens.set({
        accessToken: "at-ok",
        tokenType: "Bearer",
        accessTokenExpiresAt: Date.now() + 3600_000,
        idToken: "not-a-jwt",
      });
      const refresh = new MemoryRefreshTokenStorage();
      await refresh.set("rt-live");
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        tokenStorage: tokens,
        refreshTokenStorage: refresh,
        fetch: (() => Promise.reject(new TypeError("offline"))) as typeof fetch,
      });
      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      await client.renewSession();
      expect(
        events,
        "the whole background path owes no error event, probe included",
      ).toStrictEqual([]);

      await client.getSession();
      expect(
        events.map((event) => event.type),
        "a foreground probe still reports the same failure",
      ).toStrictEqual(["error"]);
    });

    it("is a documented no-op for a client_credentials-only client", async () => {
      const client = new DirectClient({
        clientId: testClient.id,
        clientSecret: CLIENT_SECRET,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      const before = await client.getClientCredentialsToken({ scope: "read" });

      const session = await client.renewSession();
      expect(
        session.isAuthenticated,
        "the still-valid token keeps the session alive",
      ).toBe(true);
      expect(
        await client.getAccessToken(),
        "renewSession never re-runs the grant; that would swap identities",
      ).toBe(before.accessToken);
    });

    it("renewSession reports signed out when the refresh token is dead", async () => {
      const refreshStore = new MemoryRefreshTokenStorage();
      await refreshStore.set("bogus-refresh");
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
        refreshTokenStorage: refreshStore,
      });

      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      const session = await client.renewSession();
      expect(
        session.isAuthenticated,
        "renewSession must not reject; it reports what the failure left",
      ).toBe(false);
      expect(
        events.some(
          (event) =>
            event.type === "logged_out" && event.reason === "invalid_grant",
        ),
      ).toStrictEqual(true);
    });
  });

  describe("decodeIdToken", () => {
    it("decodes a JWT payload without verifying signature", () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
      });
      const payload = { sub: "user-1", name: "Demo" };
      const encoded = [
        base64urlEncode(
          new TextEncoder().encode(
            JSON.stringify({
              alg: "none",
            }),
          ),
        ),
        base64urlEncode(new TextEncoder().encode(JSON.stringify(payload))),
        "signature",
      ].join(".");
      const decoded = client.decodeIdToken(encoded);
      expect(decoded).toStrictEqual(payload);
    });

    it("decodes an unpadded payload segment", () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
      });
      const payload = { sub: "123" };
      const segment = base64urlEncode(
        new TextEncoder().encode(JSON.stringify(payload)),
      );
      expect(segment.length % 4).toStrictEqual(2);
      expect(client.decodeIdToken(`header.${segment}.sig`)).toStrictEqual(
        payload,
      );
    });

    it("decodes non-ASCII claims as UTF-8 (not Latin-1)", () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
      });
      const payload = { sub: "user-1", name: "José Müller 日本語" };
      const claims = base64urlEncode(
        new TextEncoder().encode(JSON.stringify(payload)),
      );
      expect(client.decodeIdToken(`header.${claims}.sig`)).toStrictEqual(
        payload,
      );
    });
  });

  describe("default auth-request storage", () => {
    it("keeps a pending authorization readable by the next page load in a browser", async () => {
      const { storage, entries } = fakeSessionStorage();
      using _browser = simulateBrowser(storage);

      const options = {
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      };

      const before = new DirectClient(options);
      const begin = await before.login({ returnTo: "/dashboard" });
      const callback = await performAuthorizeRedirect(
        fixture.authServer,
        begin.url,
      );

      expect(entries.size).toBe(1);

      const afterNavigation = new DirectClient(options);
      const result =
        await afterNavigation.handleAuthorizationCallback(callback);
      expect(result.returnTo).toBe("/dashboard");
    });

    it("keeps a pending authorization in memory outside a browser document", async () => {
      const { storage, entries } = fakeSessionStorage();
      const restore = defineGlobal("sessionStorage", storage);
      try {
        const client = new DirectClient({
          clientId: testPublicClient.id,
          redirectUri: REDIRECT_URI,
          endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
          fetch: fixture.fetchImpl,
        });

        const begin = await client.login({ returnTo: "/dashboard" });
        expect(entries.size).toBe(0);

        const result = await client.handleAuthorizationCallback(
          await performAuthorizeRedirect(fixture.authServer, begin.url),
        );
        expect(result.returnTo).toBe("/dashboard");
      } finally {
        restore();
      }
    });
  });

  describe("discovery", () => {
    it("fetches and caches metadata on first endpoint need", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        issuer: ISSUER,
        fetch: fixture.fetchImpl,
      });
      const meta = await client.discover();
      expect(meta.issuer).toBe(ISSUER);
      expect(meta.token_endpoint).toBe(TOKEN_URL);

      let fetchCount = 0;
      const spyClient = new DirectClient({
        clientId: testPublicClient.id,
        issuer: ISSUER,
        fetch: (input, init) => {
          fetchCount++;
          return fixture.fetchImpl(input, init);
        },
      });
      await spyClient.discover();
      await spyClient.discover();
      expect(fetchCount).toBe(1);
    });

    it("resolves the introspection endpoint from discovery (introspection_endpoint, M2)", async () => {
      const client = new DirectClient({
        clientId: testClient.id,
        clientSecret: CLIENT_SECRET,
        issuer: ISSUER,
        fetch: fixture.fetchImpl,
      });
      const { accessToken } = await client.getClientCredentialsToken();
      const result = await client.introspect(accessToken);
      expect(result.active).toBe(true);
    });

    it("maps userinfo_endpoint and end_session_endpoint, and logout uses end-session (C1)", async () => {
      const USERINFO_URL = `${ISSUER}/userinfo`;
      const END_SESSION_URL = `${ISSUER}/logout`;
      const metadataFetch: typeof fetch = (input) => {
        if (urlOf(input) === METADATA_URL) {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                issuer: ISSUER,
                token_endpoint: TOKEN_URL,
                introspection_endpoint: INTROSPECT_URL,
                userinfo_endpoint: USERINFO_URL,
                end_session_endpoint: END_SESSION_URL,
              }),
              { status: 200, headers: { "content-type": "application/json" } },
            ),
          );
        }
        return Promise.resolve(new Response(null, { status: 404 }));
      };

      const client = new DirectClient({
        clientId: testPublicClient.id,
        issuer: ISSUER,
        fetch: metadataFetch,
      });

      const meta = await client.discover();
      expect(meta.userinfo_endpoint).toBe(USERINFO_URL);
      expect(meta.end_session_endpoint).toBe(END_SESSION_URL);

      const { url } = await client.logout({
        returnTo: "https://app.example/bye",
      });
      expect(typeof url).toStrictEqual("string");
      const logoutUrl = new URL(url!);
      expect(`${logoutUrl.origin}${logoutUrl.pathname}`).toBe(END_SESSION_URL);
      expect(logoutUrl.searchParams.get("post_logout_redirect_uri")).toBe(
        "https://app.example/bye",
      );
    });

    it("falls back to .well-known/openid-configuration when oauth-authorization-server 404s", async () => {
      const OIDC_METADATA_URL = `${ISSUER}/.well-known/openid-configuration`;
      let triedOAuth = false;
      const fetchImpl: typeof fetch = (input) => {
        const url = urlOf(input);
        if (url === METADATA_URL) {
          triedOAuth = true;
          return Promise.resolve(new Response(null, { status: 404 }));
        }
        if (url === OIDC_METADATA_URL) {
          return Promise.resolve(
            new Response(
              JSON.stringify({ issuer: ISSUER, token_endpoint: TOKEN_URL }),
              { status: 200, headers: { "content-type": "application/json" } },
            ),
          );
        }
        return Promise.resolve(new Response(null, { status: 404 }));
      };
      const client = new DirectClient({
        clientId: testPublicClient.id,
        issuer: ISSUER,
        fetch: fetchImpl,
      });
      const meta = await client.discover();
      expect(triedOAuth).toBe(true);
      expect(meta.token_endpoint).toBe(TOKEN_URL);
    });

    it("getUser falls back to the discovered userinfo endpoint (C1 mapping)", async () => {
      const USERINFO_URL = `${ISSUER}/userinfo`;
      const claims = { sub: "u-1", name: "Alice" };
      let userinfoBearer: string | null = null;
      const json = (body: unknown) =>
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      const fetchImpl: typeof fetch = (input, init) => {
        const url = urlOf(input);
        if (url === METADATA_URL) {
          return Promise.resolve(
            json({
              issuer: ISSUER,
              authorization_endpoint: AUTHORIZE_URL,
              token_endpoint: TOKEN_URL,
              userinfo_endpoint: USERINFO_URL,
            }),
          );
        }
        if (url === TOKEN_URL) {
          return Promise.resolve(
            json({
              access_token: "at-userinfo",
              token_type: "Bearer",
              expires_in: 3600,
            }),
          );
        }
        if (url.startsWith(USERINFO_URL)) {
          userinfoBearer = new Headers(init?.headers).get("authorization");
          return Promise.resolve(json(claims));
        }
        return Promise.resolve(new Response(null, { status: 404 }));
      };

      const client = new DirectClient({
        clientId: testPublicClient.id,
        redirectUri: REDIRECT_URI,
        issuer: ISSUER,
        fetch: fetchImpl,
      });

      const begin = await client.login();
      const state = new URL(begin.url).searchParams.get("state")!;
      await client.handleAuthorizationCallback(
        `${REDIRECT_URI}?code=abc&state=${state}`,
      );

      const user = await client.getUser();
      expect(user).toStrictEqual(claims);
      expect(userinfoBearer ?? "").toContain("Bearer at-userinfo");
    });
  });

  describe("localAuthServerFetch", () => {
    it("dispatches POST /token to handleTokenRequest", async () => {
      const f = fixture.fetchImpl;
      const res = await f(TOKEN_URL, {
        method: "POST",
        headers: {
          Authorization: `Basic ${btoa(`${testClient.id}:${CLIENT_SECRET}`)}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ grant_type: "client_credentials" }),
      });
      expect(res.status).toBe(200);
    });

    it("serves metadata at the .well-known path", async () => {
      const f = fixture.fetchImpl;
      const res = await f(METADATA_URL);
      expect(res.status).toBe(200);
      const meta = await res.json();
      expect(meta.issuer).toBe(ISSUER);
    });

    it("throws on unmapped paths", async () => {
      const f = fixture.fetchImpl;
      await rejection(() => f(`${ISSUER}/unknown`), Error, "no handler");
    });
  });
});

function respondingWith(response: () => Response): {
  fetch: typeof fetch;
  calls: string[];
} {
  const calls: string[] = [];
  const fetchImpl = ((input: RequestInfo | URL) => {
    calls.push(urlOf(input));
    return Promise.resolve(response());
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function publicClient(fetchImpl: typeof fetch): DirectClient {
  return new DirectClient({
    clientId: "spa",
    endpoints: {
      token: TOKEN_URL,
      revocation: REVOKE_URL,
      userInfo: `${ISSUER}/userinfo`,
      deviceAuthorization: DEVICE_URL,
    },
    fetch: fetchImpl,
    refreshTokenStorage: seededRefreshStore(),
  });
}

function seededRefreshStore(): MemoryRefreshTokenStorage {
  const store = new MemoryRefreshTokenStorage();
  store.set("rt-seed");
  return store;
}

describe("DirectClient response hardening", () => {
  it("refuses an HTML page where a token response was required", async () => {
    const client = publicClient(
      respondingWith(
        () =>
          new Response("<!doctype html><h1>Gateway</h1>", {
            status: 200,
            headers: { "Content-Type": "text/html" },
          }),
      ).fetch,
    );
    const error = await rejection(() => client.refresh(), ServerError);
    expect(error.message).toContain("text/html");
    expect(error.message).toContain("not valid JSON");
  });

  it("refuses JSON that is not an object", async () => {
    const client = publicClient(
      respondingWith(() => jsonResponse([1, 2])).fetch,
    );
    const error = await rejection(() => client.refresh(), ServerError);
    expect(error.message).toContain("a JSON array");
  });

  it("refuses a 200 that reports an error alongside a token (RFC 6749 §5.2)", async () => {
    const client = publicClient(
      respondingWith(() =>
        jsonResponse({ error: "invalid_grant", access_token: "at-decoy" }),
      ).fetch,
    );
    await rejection(() => client.refresh(), InvalidGrantError);
  });

  it("refuses a 200 carrying no access_token rather than persisting one", async () => {
    const client = publicClient(
      respondingWith(() => jsonResponse({ token_type: "Bearer" })).fetch,
    );
    const error = await rejection(() => client.refresh(), ServerError);
    expect(error.message).toContain('no "access_token"');
    expect(
      (await client.getSession()).isAuthenticated,
      "a response with no access_token must leave nothing persisted",
    ).toBe(false);
  });

  it("refuses to replay a credentialed POST at a redirect target", async () => {
    const sink = respondingWith(
      () =>
        new Response(null, {
          status: 307,
          headers: { Location: "https://attacker.example/token" },
        }),
    );
    const client = publicClient(sink.fetch);
    const error = await rejection(() => client.refresh(), ServerError);
    expect(error.message).toContain("refuses to follow");
    expect(
      sink.calls,
      "the redirect target must never receive the refresh token",
    ).toStrictEqual([TOKEN_URL]);
  });

  it("refuses a token response larger than the byte cap", async () => {
    const oversized = "x".repeat(MAX_RESPONSE_BYTES + 1);
    const client = publicClient(
      respondingWith(
        () =>
          new Response(JSON.stringify({ access_token: oversized }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
      ).fetch,
    );
    const error = await rejection(() => client.refresh(), ServerError);
    expect(error.message).toContain("exceeded");
  });

  it("accepts a token response exactly at the byte cap", async () => {
    const padding = "y".repeat(
      MAX_RESPONSE_BYTES - JSON.stringify({ access_token: "" }).length,
    );
    const body = JSON.stringify({ access_token: padding });
    expect(new TextEncoder().encode(body).byteLength).toBe(MAX_RESPONSE_BYTES);
    const client = publicClient(
      respondingWith(
        () =>
          new Response(body, {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
      ).fetch,
    );
    expect(await client.refresh()).toBe(padding);
  });

  it("still reads the OAuth2 code out of an oversized error body", async () => {
    const filler = "z".repeat(MAX_RESPONSE_BYTES);
    const client = publicClient(
      respondingWith(
        () =>
          new Response(
            JSON.stringify({
              error: "invalid_grant",
              error_description: filler,
            }),
            { status: 400, headers: { "Content-Type": "application/json" } },
          ),
      ).fetch,
    );
    const events: OAuth2ClientEvent[] = [];
    client.subscribe((event) => events.push(event));

    await rejection(() => client.refresh(), InvalidGrantError);
    expect(
      events.some(
        (event) =>
          event.type === "logged_out" && event.reason === "invalid_grant",
      ),
      "a dead grant must be recognised even when the body arrives oversized",
    ).toStrictEqual(true);
  });

  it("caps a hostile error_description instead of echoing it whole", async () => {
    const client = publicClient(
      respondingWith(() =>
        jsonResponse(
          {
            error: "invalid_grant",
            error_description: `${"A".repeat(50_000)}\nX\u001b[31m`,
          },
          400,
        ),
      ).fetch,
    );
    const error = await rejection(() => client.refresh(), InvalidGrantError);
    assert(
      error.message.length <= 200,
      `expected a capped message, got ${error.message.length} chars`,
    );
    // oxlint-disable-next-line no-control-regex
    expect(/[\u0000-\u001f]/.test(error.message)).toStrictEqual(false);
  });

  it("gives up on an endpoint that never answers", async () => {
    using timeouts = controlTimeouts();
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: TOKEN_URL },
      refreshTokenStorage: seededRefreshStore(),
      fetch: ((_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(init.signal!.reason);
          });
        })) as typeof fetch,
    });
    const pending = rejection(
      () => client.refresh(),
      TemporarilyUnavailableError,
    );
    await timeouts.expireOnceRequested(1);
    const error = await pending;

    expect(timeouts.requested).toStrictEqual([REQUEST_TIMEOUT_MS]);
    expect(error.message).toContain("timed out");
  });

  it("hardens the introspection endpoint like every other call", async () => {
    const sink = respondingWith(
      () =>
        new Response(null, {
          status: 307,
          headers: { Location: "https://attacker.example/introspect" },
        }),
    );
    const client = new DirectClient({
      clientId: "svc",
      clientSecret: "s3cret",
      endpoints: { token: TOKEN_URL, introspection: INTROSPECT_URL },
      fetch: sink.fetch,
    });
    const error = await rejection(
      () => client.introspect("at-probe"),
      ServerError,
    );
    expect(error.message).toContain("refuses to follow");
    expect(
      sink.calls,
      "the redirect target must never receive the introspected token",
    ).toStrictEqual([INTROSPECT_URL]);
  });

  it("refuses an HTML introspection response", async () => {
    const client = new DirectClient({
      clientId: "svc",
      clientSecret: "s3cret",
      endpoints: { token: TOKEN_URL, introspection: INTROSPECT_URL },
      fetch: respondingWith(
        () =>
          new Response("<html>nope</html>", {
            status: 200,
            headers: { "Content-Type": "text/html" },
          }),
      ).fetch,
    });
    await rejection(
      () => client.introspect("at-probe"),
      ServerError,
      "not valid JSON",
    );
  });

  it("reports an unreachable endpoint as temporarily unavailable, caused by the transport failure", async () => {
    const refused = new TypeError("connection refused");
    const client = publicClient((() =>
      Promise.reject(refused)) as typeof fetch);
    const error = await rejection(
      () => client.refresh(),
      TemporarilyUnavailableError,
    );
    expect(error.message).toContain("could not reach the token endpoint");
    expect(error.cause).toBe(refused);
  });

  it("refuses a device authorization response with no device_code", async () => {
    const client = publicClient(
      respondingWith(() => jsonResponse({ user_code: "ABCD" })).fetch,
    );
    const error = await rejection(
      () => client.startDeviceAuthorization(),
      ServerError,
    );
    expect(error.message).toContain('no "device_code"');
  });

  it("refuses to replay a revocation at a redirect target", async () => {
    const sink = respondingWith(
      () =>
        new Response(null, {
          status: 302,
          headers: { Location: "https://attacker.example/revoke" },
        }),
    );
    const client = publicClient(sink.fetch);
    await rejection(() => client.revoke("rt-seed"), ServerError);
    expect(sink.calls).toStrictEqual([REVOKE_URL]);
  });

  it("reports a token response that stalls past the deadline as temporarily unavailable", async () => {
    using timeouts = controlTimeouts();
    await using endpoint = await serveStalledBody('{"access_token":"at-');
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: endpoint.url },
      refreshTokenStorage: seededRefreshStore(),
    });
    let settled = false;
    const pending = rejection(() => client.refresh()).finally(() => {
      settled = true;
    });
    await vi.waitFor(() => expect(endpoint.requests).toBe(1));
    expect(settled, "the call must not end before the deadline").toBe(false);
    await timeouts.expireOnceRequested(1);
    const error = await pending;

    expect(timeouts.requested).toStrictEqual([REQUEST_TIMEOUT_MS]);
    assert(
      error instanceof TemporarilyUnavailableError,
      `expected a TemporarilyUnavailableError, got ${error}`,
    );
  });

  it("refuses an HTML userinfo response", async () => {
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: TOKEN_URL, userInfo: `${ISSUER}/userinfo` },
      tokenStorage: seededTokenStore(),
      fetch: respondingWith(
        () =>
          new Response("<html>nope</html>", {
            status: 200,
            headers: { "Content-Type": "text/html" },
          }),
      ).fetch,
    });
    const error = await rejection(() => client.getUserInfo(), ServerError);
    expect(error.message).toContain("not valid JSON");
  });
});

function seededTokenStore(): MemoryTokenStorage {
  const store = new MemoryTokenStorage();
  store.set({
    accessToken: "at-seed",
    tokenType: "Bearer",
    accessTokenExpiresAt: Date.now() + 3600_000,
  });
  return store;
}

describe("DirectClient unavailable endpoints", () => {
  it("reports every call whose response headers never arrive as temporarily unavailable, caused by the timeout", async () => {
    using timeouts = controlTimeouts();
    await using endpoint = await serveNoHeaders();
    const confidential = new DirectClient({
      clientId: "svc",
      clientSecret: CLIENT_SECRET,
      endpoints: {
        token: `${endpoint.url}token`,
        introspection: `${endpoint.url}introspect`,
        revocation: `${endpoint.url}revoke`,
        userInfo: `${endpoint.url}userinfo`,
        deviceAuthorization: `${endpoint.url}device_authorization`,
      },
      tokenStorage: seededTokenStore(),
      refreshTokenStorage: seededRefreshStore(),
    });
    const discovering = new DirectClient({
      clientId: "spa",
      issuer: endpoint.url,
    });
    const calls: Record<string, () => Promise<unknown>> = {
      discover: () => discovering.discover(),
      refresh: () => confidential.refresh(),
      exchangeRefreshToken: () => confidential.exchangeRefreshToken("rt"),
      getClientCredentialsToken: () => confidential.getClientCredentialsToken(),
      startDeviceAuthorization: () => confidential.startDeviceAuthorization(),
      pollDeviceToken: () =>
        confidential.pollDeviceToken("device-code", { interval: 1 }),
      introspect: () => confidential.introspect("at-probe"),
      revoke: () => confidential.revoke("rt-seed"),
      getUserInfo: () => confidential.getUserInfo(),
    };
    const pending = Promise.all(
      Object.entries(calls).map(async ([name, call]) => {
        try {
          await call();
          return { name, error: undefined as unknown };
        } catch (error) {
          return { name, error };
        }
      }),
    );
    const callCount = Object.keys(calls).length;
    await vi.waitFor(() => expect(endpoint.requests).toBe(callCount));
    await timeouts.expireOnceRequested(callCount);
    await timeouts.expireOnceRequested(callCount + 1);
    const outcomes = await pending;

    expect(
      timeouts.requested,
      "every request, including discovery's fallback path, is bounded by the request timeout",
    ).toStrictEqual(Array(callCount + 1).fill(REQUEST_TIMEOUT_MS));
    for (const { name, error } of outcomes) {
      assert(
        error instanceof TemporarilyUnavailableError,
        `${name}: expected a TemporarilyUnavailableError, got ${error}`,
      );
      assert(
        error.cause instanceof DOMException &&
          error.cause.name === "TimeoutError",
        `${name}: expected the deadline's TimeoutError as the cause, got ${error.cause}`,
      );
    }
  });
});

describe("DirectClient logout", () => {
  it("revokes the refresh token, clears state, and emits logged_out", async () => {
    const revoked: string[] = [];
    const tokens = seededTokenStore();
    const refresh = seededRefreshStore();
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: TOKEN_URL, revocation: REVOKE_URL },
      tokenStorage: tokens,
      refreshTokenStorage: refresh,
      fetch: ((_input: RequestInfo | URL, init?: RequestInit) => {
        revoked.push(
          String(new URLSearchParams(init?.body as string).get("token")),
        );
        return Promise.resolve(new Response(null, { status: 200 }));
      }) as typeof fetch,
    });
    const events: OAuth2ClientEvent[] = [];
    client.subscribe((event) => events.push(event));

    expect(await client.logout()).toStrictEqual({});
    expect(revoked).toStrictEqual(["rt-seed"]);
    expect(
      events.map((event) =>
        event.type === "logged_out" ? event.reason : event.type,
      ),
    ).toStrictEqual(["user"]);
    expect(await tokens.get()).toBe(null);
    expect(await refresh.get()).toBe(null);
  });

  it("clears the session even when revocation fails", async () => {
    const tokens = seededTokenStore();
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: TOKEN_URL, revocation: REVOKE_URL },
      tokenStorage: tokens,
      refreshTokenStorage: seededRefreshStore(),
      fetch: (() => Promise.reject(new TypeError("offline"))) as typeof fetch,
    });
    expect(await client.logout()).toStrictEqual({});
    expect(await tokens.get()).toBe(null);
  });

  it("signs out locally even when the refresh token store cannot be read", async () => {
    const tokens = seededTokenStore();
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: TOKEN_URL, revocation: REVOKE_URL },
      tokenStorage: tokens,
      refreshTokenStorage: {
        get: () => Promise.reject(new Error("indexeddb unavailable")),
        set: () => {},
        clear: () => {},
      },
      fetch: (() =>
        Promise.reject(new TypeError("unreachable"))) as typeof fetch,
    });
    const events: OAuth2ClientEvent[] = [];
    client.subscribe((event) => events.push(event));

    expect(await client.logout()).toStrictEqual({});
    expect(await tokens.get()).toBe(null);
    expect(events.some((event) => event.type === "logged_out")).toBe(true);
  });

  it("signs out locally even when the token store cannot be read", async () => {
    const refresh = seededRefreshStore();
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: TOKEN_URL, revocation: REVOKE_URL },
      tokenStorage: {
        get: () => Promise.reject(new Error("token store unavailable")),
        set: () => {},
        clear: () => {},
      },
      refreshTokenStorage: refresh,
      fetch: (() =>
        Promise.resolve(new Response(null, { status: 200 }))) as typeof fetch,
    });
    const events: OAuth2ClientEvent[] = [];
    client.subscribe((event) => events.push(event));

    expect(await client.logout()).toStrictEqual({});
    expect(await refresh.get()).toBe(null);
    expect(events.map((event) => event.type)).toStrictEqual(["logged_out"]);
  });

  it("signs out locally even when the token store throws synchronously", async () => {
    const refresh = seededRefreshStore();
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: TOKEN_URL },
      tokenStorage: {
        get: () => {
          throw new Error("token store unavailable");
        },
        set: () => {},
        clear: () => {},
      },
      refreshTokenStorage: refresh,
    });

    expect(await client.logout()).toStrictEqual({});
    expect(await refresh.get()).toBe(null);
  });

  it("returns the end-session URL with id_token_hint when one is configured", async () => {
    const tokens = new MemoryTokenStorage();
    await tokens.set({
      accessToken: "at-seed",
      tokenType: "Bearer",
      idToken: "hint-token",
    });
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: TOKEN_URL, endSession: `${ISSUER}/end-session` },
      tokenStorage: tokens,
    });
    const { url } = await client.logout({ returnTo: "https://app.test/" });
    const parsed = new URL(url!);
    expect(parsed.searchParams.get("id_token_hint")).toBe("hint-token");
    expect(parsed.searchParams.get("post_logout_redirect_uri")).toBe(
      "https://app.test/",
    );
  });
});

describe("DirectClient client authentication (RFC 6749 §2.3.1)", () => {
  it("sends no Authorization header for a public client, only a body client_id", async () => {
    let captured: RequestInit | undefined;
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: TOKEN_URL, revocation: REVOKE_URL },
      refreshTokenStorage: seededRefreshStore(),
      fetch: ((_input: RequestInfo | URL, init?: RequestInit) => {
        captured = init;
        return Promise.resolve(new Response(null, { status: 200 }));
      }) as typeof fetch,
    });
    await client.revoke("rt-seed");

    const headers = new Headers(captured?.headers);
    expect(
      headers.has("Authorization"),
      "a public client must not send Basic credentials it does not have",
    ).toBe(false);
    expect(new URLSearchParams(captured?.body as string).get("client_id")).toBe(
      "spa",
    );
  });
});

describe("DirectClient construction guards", () => {
  it("accepts an omitted clientSecret as a public client", () => {
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: TOKEN_URL },
    });
    expect(client.isConfidential).toBe(false);
  });

  it("reads an explicitly-undefined clientSecret as omitted", () => {
    const client = new DirectClient({
      clientId: "svc",
      clientSecret: undefined,
      endpoints: { token: TOKEN_URL },
    });
    expect(
      client.isConfidential,
      "forwarding an optional secret is how every wrapper spells `public`",
    ).toBe(false);
  });

  it("refuses an empty clientSecret rather than authenticating with a blank", () => {
    thrown(
      () =>
        new DirectClient({
          clientId: "svc",
          clientSecret: "",
          endpoints: { token: TOKEN_URL },
        }),
      TypeError,
      "empty string",
    );
  });

  it("refuses a confidential client in a document context", () => {
    const globals = globalThis as { document?: unknown };
    globals.document = {};
    try {
      thrown(
        () =>
          new DirectClient({
            clientId: "svc",
            clientSecret: "s3cret",
            endpoints: { token: TOKEN_URL },
          }),
        Error,
        "document context",
      );
    } finally {
      delete globals.document;
    }
  });

  it("still allows a public client in a document context", () => {
    const globals = globalThis as { document?: unknown };
    globals.document = {};
    try {
      const client = new DirectClient({
        clientId: "spa",
        endpoints: { token: TOKEN_URL },
      });
      expect(client.isConfidential).toBe(false);
    } finally {
      delete globals.document;
    }
  });
});

describe("DirectClient discovery issuer validation (RFC 8414 §3.3)", () => {
  it("refuses metadata that names a different issuer", async () => {
    const client = new DirectClient({
      clientId: "spa",
      issuer: "https://good.example",
      fetch: respondingWith(() =>
        jsonResponse({
          issuer: "https://evil.example",
          token_endpoint: "https://evil.example/token",
        }),
      ).fetch,
    });
    const error = await rejection(() => client.discover(), ServerError);
    expect(error.message).toContain("RFC 8414 §3.3");
  });

  it("refuses metadata with no issuer at all", async () => {
    const client = new DirectClient({
      clientId: "spa",
      issuer: "https://good.example",
      fetch: respondingWith(() =>
        jsonResponse({ token_endpoint: "https://good.example/token" }),
      ).fetch,
    });
    await rejection(() => client.discover(), ServerError, "no `issuer`");
  });

  it("accepts metadata whose issuer differs only by a trailing slash", async () => {
    const client = new DirectClient({
      clientId: "spa",
      issuer: "https://good.example/",
      fetch: respondingWith(() =>
        jsonResponse({
          issuer: "https://good.example",
          token_endpoint: "https://good.example/token",
        }),
      ).fetch,
    });
    const meta = await client.discover();
    expect(meta.issuer).toBe("https://good.example");
  });
});

describe("OAuth2ErrorCode", () => {
  it("includes the RFC 6750 bearer-token error codes (M1)", () => {
    // Type-level guard: compiles only if the union covers both codes.
    const codes: OAuth2ErrorCode[] = ["invalid_token", "insufficient_scope"];
    expect(codes).toStrictEqual(["invalid_token", "insufficient_scope"]);
  });
});
