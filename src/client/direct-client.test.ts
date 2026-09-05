import {
  assert,
  assertEquals,
  assertRejects,
  assertStrictEquals,
  assertStringIncludes,
  assertThrows,
} from "@std/assert";
import { beforeEach, describe, it } from "@std/testing/bdd";
import { FakeTime } from "@std/testing/time";

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
} from "../errors.ts";
import { base64urlEncode } from "../utils/crypto.ts";

import { DirectClient } from "./direct-client.ts";
import {
  MemoryAuthRequestStorage,
  MemoryRefreshTokenStorage,
  MemoryTokenStorage,
} from "./storage.ts";
import { MAX_RESPONSE_BYTES } from "./_http.ts";
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
  const response = await authServer.handleAuthorizeRequest(
    request,
    () => Promise.resolve({ user: testUser }),
  );
  assertStrictEquals(response.status, 302);
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
      assertStrictEquals(
        new URL(url).searchParams.get("redirect_uri"),
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
      assertStrictEquals(begUrl.searchParams.get("response_type"), "code");
      assertStrictEquals(
        begUrl.searchParams.get("client_id"),
        testPublicClient.id,
      );
      assertStrictEquals(
        begUrl.searchParams.get("code_challenge_method"),
        "S256",
      );

      const callback = await performAuthorizeRedirect(
        fixture.authServer,
        begin.url,
      );

      const events: OAuth2ClientEvent[] = [];
      const unsubscribe = client.subscribe((e) => events.push(e));

      const result = await client.handleAuthorizationCallback(callback);
      unsubscribe();

      assertStrictEquals(result.returnTo, "/dashboard");
      assertStrictEquals(typeof result.tokens.accessToken, "string");
      assertStrictEquals(events[0]?.type, "authenticated");
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
      assertStrictEquals(a.tokens.accessToken, b.tokens.accessToken);
    });

    it("surfaces the OAuth2 error when the callback URL has ?error=…", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      await assertRejects(
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
      assertStrictEquals(a, b, "single-flight refresh should share promise");
      assertStrictEquals(
        events.filter((e) => e.type === "token_refreshed").length,
        1,
      );
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

      await assertRejects(() => client.refresh(), InvalidGrantError);
      assertStrictEquals(
        events.some((e) =>
          e.type === "logged_out" && e.reason === "invalid_grant"
        ),
        true,
      );
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

      await assertRejects(
        () => client.refresh(),
        Error,
        "indexeddb unavailable",
      );
      assertStrictEquals(
        events.filter((e) => e.type === "error").length,
        1,
        "a store that cannot be read is reported, not thrown past the client",
      );
      assertStrictEquals(
        events.some((e) => e.type === "logged_out"),
        false,
        "a broken store is not evidence the grant died",
      );
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
      assertStrictEquals(session.isAuthenticated, false);
      assertStrictEquals(events.filter((e) => e.type === "error").length, 0);
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
      assertStrictEquals(typeof tokens.accessToken, "string");
      assertStrictEquals(tokens.scope, "read");
    });

    it("rejects without a clientSecret", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      assertStrictEquals(client.isConfidential, false);
      await assertRejects(
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
          capturedBody = init.body instanceof URLSearchParams
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

      assertStringIncludes(capturedAuth ?? "", "Basic ");
      assertStrictEquals(capturedBody?.has("client_id"), false);
    });

    it("strips a caller-set body client_id for confidential clients (#postToken, RFC 6749 §2.3.1)", async () => {
      // Guards #postToken's body.delete: pollDeviceToken sets a body client_id
      // that must be dropped when authenticating via Basic.
      let capturedBody: URLSearchParams | undefined;
      let capturedAuth: string | null = null;
      const spyFetch: typeof fetch = (input, init) => {
        if (urlOf(input) === TOKEN_URL && init?.method === "POST") {
          capturedBody = init.body instanceof URLSearchParams
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

      assertStringIncludes(capturedAuth ?? "", "Basic ");
      assertStrictEquals(capturedBody?.has("client_id"), false);
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
      assertStrictEquals(active.active, true);
      assertStrictEquals(active.client_id, testClient.id);

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
      assertStrictEquals(typeof res.device_code, "string");
      assertStrictEquals(typeof res.user_code, "string");
      assertStrictEquals(res.verification_uri, `${ISSUER}/device`);
    });

    it("authenticates a confidential client at the device endpoint (RFC 8628 §3.1)", async () => {
      const client = new DirectClient({
        clientId: testClient.id,
        clientSecret: CLIENT_SECRET,
        endpoints: { token: TOKEN_URL, deviceAuthorization: DEVICE_URL },
        fetch: fixture.fetchImpl,
      });
      const res = await client.startDeviceAuthorization({ scope: "read" });
      assertStrictEquals(typeof res.device_code, "string");
      assertStrictEquals(typeof res.user_code, "string");
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
            const body = init.body instanceof URLSearchParams
              ? init.body
              : new URLSearchParams(String(init.body));
            assertStrictEquals(body.get("client_id"), testPublicClient.id);
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

      assertStrictEquals(tokens.accessToken, "device-at");
      assertStrictEquals(calls, 3);
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
      await assertRejects(() => promise, AccessDeniedError);
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
      await assertRejects(
        () => client.exchangeAuthorizationCode("code-1", "state-1"),
        InvalidGrantError,
        "authorization request expired",
      );
      assertEquals(await storage.get("state-1"), null);
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
      assertStrictEquals(res.status, 200);
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

      assertStrictEquals(sent?.get("x-trace"), "abc");
      assertStrictEquals(sent?.get("accept"), "application/json");
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

      assertStrictEquals(sent?.get("x-trace"), "from-init");
      assertStrictEquals(sent?.get("x-keep"), "kept");
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

      assertStrictEquals(sent?.get("Authorization"), "Bearer caller-supplied");
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

      assertStrictEquals(res.status, 200);
      assertEquals(bodies, [
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

      await assertRejects(
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
      assertStrictEquals(res.status, 401);
    });
  });

  describe("session state", () => {
    it("reports signed out before any token is stored", async () => {
      const client = new DirectClient({
        clientId: testPublicClient.id,
        endpoints: { token: TOKEN_URL },
        fetch: fixture.fetchImpl,
      });
      assertEquals(await client.getSession(), {
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
      assertStrictEquals(session.isAuthenticated, true);
      assertStrictEquals(session.user, null);
      assertStrictEquals(session.logoutUrl, null);
      assertStrictEquals(typeof session.sessionExpiresIn, "number");
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
      assertStrictEquals(session.isAuthenticated, true);
      assertStrictEquals(
        (await client.getAccessToken()) === tokens.accessToken,
        false,
        "renewSession must leave a rotated access token behind",
      );
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
      assertStrictEquals((await client.getSession()).isAuthenticated, false);
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
      assertStrictEquals(session.isAuthenticated, true);
      assertStrictEquals(session.sessionExpiresIn, 0);
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
      assertStrictEquals((await client.getSession()).isAuthenticated, false);
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
      assertStrictEquals(session.isAuthenticated, false);
      assertStrictEquals(events.filter((e) => e.type === "error").length, 1);
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
      assertEquals(
        events,
        [],
        "a blip on a background timer must not paint a user-visible error",
      );

      await assertRejects(() => client.refresh(), ServerError);
      assertEquals(
        events.map((event) => event.type),
        ["error"],
        "an explicit refresh still reports the same failure",
      );
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
      assertEquals(
        events,
        [],
        "the whole background path owes no error event, probe included",
      );

      await client.getSession();
      assertEquals(
        events.map((event) => event.type),
        ["error"],
        "a foreground probe still reports the same failure",
      );
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
      assertStrictEquals(
        session.isAuthenticated,
        true,
        "the still-valid token keeps the session alive",
      );
      assertStrictEquals(
        await client.getAccessToken(),
        before.accessToken,
        "renewSession never re-runs the grant; that would swap identities",
      );
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
      assertStrictEquals(
        session.isAuthenticated,
        false,
        "renewSession must not reject; it reports what the failure left",
      );
      assertEquals(
        events.some((event) =>
          event.type === "logged_out" && event.reason === "invalid_grant"
        ),
        true,
      );
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
        base64urlEncode(new TextEncoder().encode(JSON.stringify({
          alg: "none",
        }))),
        base64urlEncode(new TextEncoder().encode(JSON.stringify(payload))),
        "signature",
      ].join(".");
      const decoded = client.decodeIdToken(encoded);
      assertEquals(decoded, payload);
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
      assertEquals(segment.length % 4, 2);
      assertEquals(client.decodeIdToken(`header.${segment}.sig`), payload);
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
      assertEquals(client.decodeIdToken(`header.${claims}.sig`), payload);
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

      assertStrictEquals(entries.size, 1);

      const afterNavigation = new DirectClient(options);
      const result = await afterNavigation.handleAuthorizationCallback(
        callback,
      );
      assertStrictEquals(result.returnTo, "/dashboard");
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
        assertStrictEquals(entries.size, 0);

        const result = await client.handleAuthorizationCallback(
          await performAuthorizeRedirect(fixture.authServer, begin.url),
        );
        assertStrictEquals(result.returnTo, "/dashboard");
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
      assertStrictEquals(meta.issuer, ISSUER);
      assertStrictEquals(meta.token_endpoint, TOKEN_URL);

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
      assertStrictEquals(fetchCount, 1);
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
      assertStrictEquals(result.active, true);
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
      assertStrictEquals(meta.userinfo_endpoint, USERINFO_URL);
      assertStrictEquals(meta.end_session_endpoint, END_SESSION_URL);

      const { url } = await client.logout({
        returnTo: "https://app.example/bye",
      });
      assertEquals(typeof url, "string");
      const logoutUrl = new URL(url!);
      assertStrictEquals(
        `${logoutUrl.origin}${logoutUrl.pathname}`,
        END_SESSION_URL,
      );
      assertStrictEquals(
        logoutUrl.searchParams.get("post_logout_redirect_uri"),
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
      assertStrictEquals(triedOAuth, true);
      assertStrictEquals(meta.token_endpoint, TOKEN_URL);
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
          return Promise.resolve(json({
            issuer: ISSUER,
            authorization_endpoint: AUTHORIZE_URL,
            token_endpoint: TOKEN_URL,
            userinfo_endpoint: USERINFO_URL,
          }));
        }
        if (url === TOKEN_URL) {
          return Promise.resolve(json({
            access_token: "at-userinfo",
            token_type: "Bearer",
            expires_in: 3600,
          }));
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
      assertEquals(user, claims);
      assertStringIncludes(userinfoBearer ?? "", "Bearer at-userinfo");
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
      assertStrictEquals(res.status, 200);
    });

    it("serves metadata at the .well-known path", async () => {
      const f = fixture.fetchImpl;
      const res = await f(METADATA_URL);
      assertStrictEquals(res.status, 200);
      const meta = await res.json();
      assertStrictEquals(meta.issuer, ISSUER);
    });

    it("throws on unmapped paths", async () => {
      const f = fixture.fetchImpl;
      await assertRejects(
        () => f(`${ISSUER}/unknown`),
        Error,
        "no handler",
      );
    });
  });
});

function respondingWith(
  response: () => Response,
): { fetch: typeof fetch; calls: string[] } {
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
      respondingWith(() =>
        new Response("<!doctype html><h1>Gateway</h1>", {
          status: 200,
          headers: { "Content-Type": "text/html" },
        })
      ).fetch,
    );
    const error = await assertRejects(() => client.refresh(), ServerError);
    assertStringIncludes(error.message, "text/html");
    assertStringIncludes(error.message, "not valid JSON");
  });

  it("refuses JSON that is not an object", async () => {
    const client = publicClient(
      respondingWith(() => jsonResponse([1, 2])).fetch,
    );
    const error = await assertRejects(() => client.refresh(), ServerError);
    assertStringIncludes(error.message, "a JSON array");
  });

  it("refuses a 200 that reports an error alongside a token (RFC 6749 §5.2)", async () => {
    const client = publicClient(
      respondingWith(() =>
        jsonResponse({ error: "invalid_grant", access_token: "at-decoy" })
      ).fetch,
    );
    await assertRejects(() => client.refresh(), InvalidGrantError);
  });

  it("refuses a 200 carrying no access_token rather than persisting one", async () => {
    const client = publicClient(
      respondingWith(() => jsonResponse({ token_type: "Bearer" })).fetch,
    );
    const error = await assertRejects(() => client.refresh(), ServerError);
    assertStringIncludes(error.message, 'no "access_token"');
    assertStrictEquals(
      (await client.getSession()).isAuthenticated,
      false,
      "a response with no access_token must leave nothing persisted",
    );
  });

  it("refuses to replay a credentialed POST at a redirect target", async () => {
    const sink = respondingWith(() =>
      new Response(null, {
        status: 307,
        headers: { Location: "https://attacker.example/token" },
      })
    );
    const client = publicClient(sink.fetch);
    const error = await assertRejects(() => client.refresh(), ServerError);
    assertStringIncludes(error.message, "refuses to follow");
    assertEquals(
      sink.calls,
      [TOKEN_URL],
      "the redirect target must never receive the refresh token",
    );
  });

  it("refuses a token response larger than the byte cap", async () => {
    const oversized = "x".repeat(MAX_RESPONSE_BYTES + 1);
    const client = publicClient(
      respondingWith(() =>
        new Response(JSON.stringify({ access_token: oversized }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      ).fetch,
    );
    const error = await assertRejects(() => client.refresh(), ServerError);
    assertStringIncludes(error.message, "exceeded");
  });

  it("accepts a token response exactly at the byte cap", async () => {
    const padding = "y".repeat(
      MAX_RESPONSE_BYTES - JSON.stringify({ access_token: "" }).length,
    );
    const body = JSON.stringify({ access_token: padding });
    assertStrictEquals(
      new TextEncoder().encode(body).byteLength,
      MAX_RESPONSE_BYTES,
    );
    const client = publicClient(
      respondingWith(() =>
        new Response(body, {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      ).fetch,
    );
    assertStrictEquals(await client.refresh(), padding);
  });

  it("still reads the OAuth2 code out of an oversized error body", async () => {
    const filler = "z".repeat(MAX_RESPONSE_BYTES);
    const client = publicClient(
      respondingWith(() =>
        new Response(
          JSON.stringify({ error: "invalid_grant", error_description: filler }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        )
      ).fetch,
    );
    const events: OAuth2ClientEvent[] = [];
    client.subscribe((event) => events.push(event));

    await assertRejects(() => client.refresh(), InvalidGrantError);
    assertEquals(
      events.some((event) =>
        event.type === "logged_out" && event.reason === "invalid_grant"
      ),
      true,
      "a dead grant must be recognised even when the body arrives oversized",
    );
  });

  it("caps a hostile error_description instead of echoing it whole", async () => {
    const client = publicClient(
      respondingWith(() =>
        jsonResponse({
          error: "invalid_grant",
          error_description: `${"A".repeat(50_000)}\nX\u001b[31m`,
        }, 400)
      ).fetch,
    );
    const error = await assertRejects(
      () => client.refresh(),
      InvalidGrantError,
    );
    assert(
      error.message.length <= 200,
      `expected a capped message, got ${error.message.length} chars`,
    );
    // deno-lint-ignore no-control-regex -- asserting control chars are gone
    assertEquals(/[\u0000-\u001f]/.test(error.message), false);
  });

  it("gives up on an endpoint that never answers", async () => {
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
    const error = await assertRejects(() => client.refresh(), ServerError);
    assertStringIncludes(error.message, "timed out");
  });

  it("hardens the introspection endpoint like every other call", async () => {
    const sink = respondingWith(() =>
      new Response(null, {
        status: 307,
        headers: { Location: "https://attacker.example/introspect" },
      })
    );
    const client = new DirectClient({
      clientId: "svc",
      clientSecret: "s3cret",
      endpoints: { token: TOKEN_URL, introspection: INTROSPECT_URL },
      fetch: sink.fetch,
    });
    const error = await assertRejects(
      () => client.introspect("at-probe"),
      ServerError,
    );
    assertStringIncludes(error.message, "refuses to follow");
    assertEquals(
      sink.calls,
      [INTROSPECT_URL],
      "the redirect target must never receive the introspected token",
    );
  });

  it("refuses an HTML introspection response", async () => {
    const client = new DirectClient({
      clientId: "svc",
      clientSecret: "s3cret",
      endpoints: { token: TOKEN_URL, introspection: INTROSPECT_URL },
      fetch: respondingWith(() =>
        new Response("<html>nope</html>", {
          status: 200,
          headers: { "Content-Type": "text/html" },
        })
      ).fetch,
    });
    await assertRejects(
      () => client.introspect("at-probe"),
      ServerError,
      "not valid JSON",
    );
  });

  it("reports an unreachable endpoint instead of leaking the raw failure", async () => {
    const client = publicClient(
      (() =>
        Promise.reject(new TypeError("connection refused"))) as typeof fetch,
    );
    const error = await assertRejects(() => client.refresh(), ServerError);
    assertStringIncludes(error.message, "could not reach the token endpoint");
  });

  it("refuses a device authorization response with no device_code", async () => {
    const client = publicClient(
      respondingWith(() => jsonResponse({ user_code: "ABCD" })).fetch,
    );
    const error = await assertRejects(
      () => client.startDeviceAuthorization(),
      ServerError,
    );
    assertStringIncludes(error.message, 'no "device_code"');
  });

  it("refuses to replay a revocation at a redirect target", async () => {
    const sink = respondingWith(() =>
      new Response(null, {
        status: 302,
        headers: { Location: "https://attacker.example/revoke" },
      })
    );
    const client = publicClient(sink.fetch);
    await assertRejects(() => client.revoke("rt-seed"), ServerError);
    assertEquals(sink.calls, [REVOKE_URL]);
  });

  it("refuses an HTML userinfo response", async () => {
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { token: TOKEN_URL, userInfo: `${ISSUER}/userinfo` },
      tokenStorage: seededTokenStore(),
      fetch: respondingWith(() =>
        new Response("<html>nope</html>", {
          status: 200,
          headers: { "Content-Type": "text/html" },
        })
      ).fetch,
    });
    const error = await assertRejects(() => client.getUserInfo(), ServerError);
    assertStringIncludes(error.message, "not valid JSON");
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

    assertEquals(await client.logout(), {});
    assertEquals(revoked, ["rt-seed"]);
    assertEquals(
      events.map((event) =>
        event.type === "logged_out" ? event.reason : event.type
      ),
      ["user"],
    );
    assertStrictEquals(await tokens.get(), null);
    assertStrictEquals(await refresh.get(), null);
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
    assertEquals(await client.logout(), {});
    assertStrictEquals(await tokens.get(), null);
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

    assertEquals(await client.logout(), {});
    assertStrictEquals(await tokens.get(), null);
    assertStrictEquals(
      events.some((event) => event.type === "logged_out"),
      true,
    );
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
    assertStrictEquals(parsed.searchParams.get("id_token_hint"), "hint-token");
    assertStrictEquals(
      parsed.searchParams.get("post_logout_redirect_uri"),
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
    assertStrictEquals(
      headers.has("Authorization"),
      false,
      "a public client must not send Basic credentials it does not have",
    );
    assertStrictEquals(
      new URLSearchParams(captured?.body as string).get("client_id"),
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
    assertStrictEquals(client.isConfidential, false);
  });

  it("reads an explicitly-undefined clientSecret as omitted", () => {
    const client = new DirectClient({
      clientId: "svc",
      clientSecret: undefined,
      endpoints: { token: TOKEN_URL },
    });
    assertStrictEquals(
      client.isConfidential,
      false,
      "forwarding an optional secret is how every wrapper spells `public`",
    );
  });

  it("refuses an empty clientSecret rather than authenticating with a blank", () => {
    assertThrows(
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
      assertThrows(
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
      assertStrictEquals(client.isConfidential, false);
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
        })
      ).fetch,
    });
    const error = await assertRejects(() => client.discover(), ServerError);
    assertStringIncludes(error.message, "RFC 8414 §3.3");
  });

  it("refuses metadata with no issuer at all", async () => {
    const client = new DirectClient({
      clientId: "spa",
      issuer: "https://good.example",
      fetch: respondingWith(() =>
        jsonResponse({ token_endpoint: "https://good.example/token" })
      ).fetch,
    });
    await assertRejects(() => client.discover(), ServerError, "no `issuer`");
  });

  it("accepts metadata whose issuer differs only by a trailing slash", async () => {
    const client = new DirectClient({
      clientId: "spa",
      issuer: "https://good.example/",
      fetch: respondingWith(() =>
        jsonResponse({
          issuer: "https://good.example",
          token_endpoint: "https://good.example/token",
        })
      ).fetch,
    });
    const meta = await client.discover();
    assertStrictEquals(meta.issuer, "https://good.example");
  });
});

describe("OAuth2ErrorCode", () => {
  it("includes the RFC 6750 bearer-token error codes (M1)", () => {
    // Type-level guard: compiles only if the union covers both codes.
    const codes: OAuth2ErrorCode[] = ["invalid_token", "insufficient_scope"];
    assertEquals(codes, ["invalid_token", "insufficient_scope"]);
  });
});
