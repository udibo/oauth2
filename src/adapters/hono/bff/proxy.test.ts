import { describe, expect, it } from "vitest";
import { Hono } from "hono";

import { DirectClient } from "../../../client/mod.ts";

import { HonoBff, type HonoBffOptions } from "./bff.ts";
import {
  DEFAULT_PROXY_FORWARD_HEADERS,
  type HonoBffProxyOptions,
} from "./proxy.ts";
import {
  EncryptedCookieSessionStore,
  MemorySessionStore,
  type SessionData,
  type SessionStore,
} from "./session-store.ts";

const ISSUER = "http://localhost";
const UPSTREAM = "https://api.example.test/v1";
const COOKIE_NAME = "oauth2_session";
const CSRF = { "x-csrf": "1" };

interface UpstreamCall {
  url: URL;
  init: RequestInit;
}

interface Upstream {
  calls: UpstreamCall[];
  fetch: (input: URL, init: RequestInit) => Promise<Response>;
}

/** Records every proxied call and answers with `respond(attempt, call)`. */
function createUpstream(
  respond: (attempt: number, call: UpstreamCall) => Response | Error,
): Upstream {
  const calls: UpstreamCall[] = [];
  return {
    calls,
    fetch: (url, init) => {
      calls.push({ url, init });
      const result = respond(calls.length, { url, init });
      if (result instanceof Error) return Promise.reject(result);
      return Promise.resolve(result);
    },
  };
}

interface Idp {
  refreshTokensSeen: string[];
  fetch: typeof fetch;
}

/**
 * Stands in for the authorization server's token endpoint. `fails` rejects the
 * grant outright (`invalid_grant`); `unavailable` fails to answer, the way a
 * blip or an overloaded IdP does.
 */
function createIdp(
  options: { fails?: boolean; unavailable?: "transport" | "server" } = {},
): Idp {
  const refreshTokensSeen: string[] = [];
  let issued = 1;
  return {
    refreshTokensSeen,
    fetch: (_input, init) => {
      const params = new URLSearchParams(String(init?.body));
      refreshTokensSeen.push(params.get("refresh_token") ?? "");
      if (options.unavailable === "transport") {
        return Promise.reject(new TypeError("connection reset"));
      }
      if (options.unavailable === "server") {
        return Promise.resolve(
          new Response("upstream is having a moment", { status: 503 }),
        );
      }
      if (options.fails) {
        return Promise.resolve(
          new Response(JSON.stringify({ error: "invalid_grant" }), {
            status: 400,
            headers: { "content-type": "application/json" },
          }),
        );
      }
      issued++;
      return Promise.resolve(
        new Response(
          JSON.stringify({
            access_token: `access-${issued}`,
            token_type: "Bearer",
            expires_in: 3600,
            refresh_token: `refresh-${issued}`,
          }),
          { headers: { "content-type": "application/json" } },
        ),
      );
    },
  };
}

function makeBff(idp: Idp, overrides: Partial<HonoBffOptions> = {}): HonoBff {
  return new HonoBff({
    client: new DirectClient({
      clientId: "bff-client",
      clientSecret: "shh",
      redirectUri: `${ISSUER}/auth/callback`,
      endpoints: {
        authorization: `${ISSUER}/authorize`,
        token: `${ISSUER}/token`,
        revocation: `${ISSUER}/revoke`,
      },
      fetch: idp.fetch,
    }),
    cookie: { secure: false },
    ...overrides,
  });
}

function makeApp(
  bff: HonoBff,
  target: string,
  options: HonoBffProxyOptions,
): Hono {
  const app = new Hono();
  app.all("/api/*", bff.proxy(target, options));
  return app;
}

function session(overrides: Partial<SessionData> = {}): SessionData {
  const now = Date.now();
  return {
    tokens: {
      accessToken: "access-1",
      tokenType: "Bearer",
      accessTokenExpiresAt: now + 60 * 60 * 1000,
      ...overrides.tokens,
    },
    refreshToken: "refresh-1",
    user: { sub: "user-1" },
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

async function seed(
  store: SessionStore,
  overrides: Partial<SessionData> = {},
): Promise<string> {
  return await store.create(session(overrides));
}

function cookieHeader(value: string): Record<string, string> {
  return { cookie: `${COOKIE_NAME}=${value}` };
}

function authorization(call: UpstreamCall): string | null {
  return new Headers(call.init.headers).get("authorization");
}

describe("HonoBff.proxy", () => {
  describe("request passthrough", () => {
    it("maps method, path and query onto the configured target", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things?page=2&q=a%20b", {
        method: "DELETE",
        headers: {
          ...cookieHeader(await seed(bff.sessionStore)),
          ...CSRF,
        },
      });

      expect(res.status).toBe(200);
      await res.text();
      expect(upstream.calls.length).toBe(1);
      expect(upstream.calls[0].url.href).toBe(
        "https://api.example.test/v1/things?page=2&q=a%20b",
      );
      expect(upstream.calls[0].init.method).toBe("DELETE");
    });

    it("appends the whole request path when no prefix is stripped", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, { fetch: upstream.fetch });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      await res.text();
      expect(upstream.calls[0].url.href).toBe(
        "https://api.example.test/v1/api/things",
      );
    });

    it("normalizes a target with a trailing slash", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, `${UPSTREAM}/`, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      await res.text();
      expect(upstream.calls[0].url.href).toBe(
        "https://api.example.test/v1/things",
      );
    });

    it("maps a bare mount prefix onto the target root", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = new Hono();
      app.all(
        "/api",
        bff.proxy(UPSTREAM, { stripPrefix: "/api", fetch: upstream.fetch }),
      );

      const res = await app.request("/api", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      await res.text();
      expect(upstream.calls[0].url.href).toBe("https://api.example.test/v1/");
    });

    it("forwards the request body as a stream", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () => new Response("created", { status: 201 }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        method: "POST",
        headers: {
          ...cookieHeader(await seed(bff.sessionStore)),
          ...CSRF,
          "content-type": "application/json",
        },
        body: JSON.stringify({ name: "widget" }),
      });

      expect(res.status).toBe(201);
      await res.text();
      const forwarded = upstream.calls[0].init.body;
      expect(forwarded instanceof ReadableStream).toStrictEqual(true);
      expect(
        await new Response(forwarded as ReadableStream).json(),
      ).toStrictEqual({ name: "widget" });
    });

    it("keeps encoded dot segments under the target base", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things/%2e%2e/secret", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      await res.text();
      expect(upstream.calls[0].url.href).toBe(
        "https://api.example.test/v1/secret",
      );
    });

    it("merges the target's own query, which wins over an inbound parameter", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, `${UPSTREAM}?tenant=acme`, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });
      const cookie = cookieHeader(await seed(bff.sessionStore));

      const kept = await app.request("/api/things?page=2", {
        headers: { ...cookie, ...CSRF },
      });
      await kept.text();
      expect(upstream.calls[0].url.href).toBe(
        "https://api.example.test/v1/things?page=2&tenant=acme",
      );

      const overridden = await app.request("/api/things?tenant=evil", {
        headers: { ...cookie, ...CSRF },
      });
      await overridden.text();
      expect(upstream.calls[1].url.searchParams.getAll("tenant").join()).toBe(
        "acme",
      );
    });

    it("forwards an encoded separator inside a resource id", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/files/a%2Fb", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(200);
      await res.text();
      expect(upstream.calls[0].url.href).toBe(
        "https://api.example.test/v1/files/a%2Fb",
      );
    });

    it("forwards an encoded separator in a repo-style id", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/repos/octo%2Fcat", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(200);
      await res.text();
      expect(upstream.calls[0].url.href).toBe(
        "https://api.example.test/v1/repos/octo%2Fcat",
      );
    });

    it("rejects a segment whose percent-escape is malformed", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things/%C0%AF%C0%AE%C0%AE", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_request");
      expect(upstream.calls.length).toBe(0);
    });

    it("rejects a segment that hides a separator from the URL parser", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/%2e%2e%2f%2e%2e%2fadmin", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_request");
      expect(upstream.calls.length).toBe(0);
    });
  });

  describe("request header hygiene", () => {
    it("attaches the session's access token", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      await res.text();
      expect(authorization(upstream.calls[0])).toBe("Bearer access-1");
    });

    it("never forwards the session cookie, the CSRF header, or an inbound Authorization", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: {
          ...cookieHeader(await seed(bff.sessionStore)),
          ...CSRF,
          authorization: "Bearer attacker-supplied",
        },
      });

      await res.text();
      const headers = new Headers(upstream.calls[0].init.headers);
      expect(headers.get("cookie")).toBe(null);
      expect(headers.get("x-csrf")).toBe(null);
      expect(headers.get("authorization")).toBe("Bearer access-1");
    });

    it("strips hop-by-hop headers and forwards the allowlisted ones", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: {
          ...cookieHeader(await seed(bff.sessionStore)),
          ...CSRF,
          accept: "application/json",
          "accept-language": "en-US",
          "if-none-match": '"abc"',
          te: "trailers",
          "proxy-authorization": "Basic abc",
          "x-internal-note": "secret",
        },
      });

      await res.text();
      const headers = new Headers(upstream.calls[0].init.headers);
      expect(headers.get("accept")).toBe("application/json");
      expect(headers.get("accept-language")).toBe("en-US");
      expect(headers.get("if-none-match")).toBe('"abc"');
      expect(headers.get("te")).toBe(null);
      expect(headers.get("proxy-authorization")).toBe(null);
      expect(headers.get("x-internal-note")).toBe(null);
    });

    it("forwards extra headers named in forwardHeaders, but never the denied ones", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
        forwardHeaders: [
          ...DEFAULT_PROXY_FORWARD_HEADERS,
          "x-tenant",
          "cookie",
          "x-csrf",
        ],
      });

      const res = await app.request("/api/things", {
        headers: {
          ...cookieHeader(await seed(bff.sessionStore)),
          ...CSRF,
          "x-tenant": "acme",
        },
      });

      await res.text();
      const headers = new Headers(upstream.calls[0].init.headers);
      expect(headers.get("x-tenant")).toBe("acme");
      expect(headers.get("cookie")).toBe(null);
      expect(headers.get("x-csrf")).toBe(null);
    });

    it("does not follow upstream redirects", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () =>
          new Response(null, {
            status: 302,
            headers: { location: "https://elsewhere.test/" },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(302);
      expect(res.headers.get("location")).toBe("https://elsewhere.test/");
      await res.body?.cancel();
      expect(upstream.calls[0].init.redirect).toBe("manual");
    });
  });

  describe("response header hygiene", () => {
    it("passes upstream headers through but drops Set-Cookie, hop-by-hop and content coding", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () =>
          new Response('{"ok":true}', {
            headers: {
              "content-type": "application/json",
              "x-total-count": "17",
              "set-cookie": "upstream=1; Path=/",
              connection: "keep-alive",
              "transfer-encoding": "chunked",
              "content-encoding": "gzip",
              "content-length": "11",
            },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.headers.get("content-type")).toBe("application/json");
      expect(res.headers.get("x-total-count")).toBe("17");
      expect(res.headers.get("set-cookie")).toBe(null);
      expect(res.headers.get("connection")).toBe(null);
      expect(res.headers.get("transfer-encoding")).toBe(null);
      expect(res.headers.get("content-encoding")).toBe(null);
      expect(res.headers.get("content-length")).toBe(null);
      expect(await res.text()).toBe('{"ok":true}');
    });

    it("drops headers the upstream Connection field names", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () =>
          new Response("[]", {
            headers: {
              connection: "x-internal-hop, close",
              "x-internal-hop": "leaked",
              "x-kept": "yes",
            },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      await res.text();
      expect(res.headers.get("x-internal-hop")).toBe(null);
      expect(res.headers.get("connection")).toBe(null);
      expect(res.headers.get("x-kept")).toBe("yes");
    });

    it("rewrites an upstream Location into the mount's namespace", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        (attempt) =>
          new Response(null, {
            status: 201,
            headers: {
              location:
                attempt === 1
                  ? "https://api.example.test/v1/things/42"
                  : "/v1/things/43",
              "content-location":
                "https://api.example.test/v1/things/42?full=1",
            },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });
      const headers = {
        ...cookieHeader(await seed(bff.sessionStore)),
        ...CSRF,
      };

      const absolute = await app.request("/api/things", {
        method: "POST",
        headers,
      });
      expect(absolute.headers.get("location")).toBe("/api/things/42");
      expect(absolute.headers.get("content-location")).toBe(
        "/api/things/42?full=1",
      );
      await absolute.body?.cancel();

      const relative = await app.request("/api/things", {
        method: "POST",
        headers,
      });
      expect(relative.headers.get("location")).toBe("/api/things/43");
      await relative.body?.cancel();
    });

    it("leaves a genuinely external Location alone", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () =>
          new Response(null, {
            status: 302,
            headers: { location: "https://cdn.example.com/blob/1" },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.headers.get("location")).toBe(
        "https://cdn.example.com/blob/1",
      );
      await res.body?.cancel();
    });

    it("marks the response private, cookie-varying and nosniff", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () =>
          new Response("[]", {
            headers: {
              "cache-control": "public, max-age=60",
              vary: "Accept-Encoding",
            },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      await res.text();
      expect(res.headers.get("cache-control")).toBe(
        "private, public, max-age=60",
      );
      expect(res.headers.get("vary")).toBe("Accept-Encoding, Cookie");
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    });

    it("does not double up an upstream that is already private", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () => new Response("[]", { headers: { "cache-control": "no-store" } }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      await res.text();
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(res.headers.get("vary")).toBe("Cookie");
    });

    it("keeps Content-Length on a body-less response", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () =>
          new Response(null, {
            status: 200,
            headers: { "content-length": "42", "content-type": "text/plain" },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        method: "HEAD",
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(200);
      expect(res.headers.get("content-length")).toBe("42");
      expect(res.headers.get("content-type")).toBe("text/plain");
      await res.body?.cancel();
    });

    it("streams the response body back without buffering it", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const chunks = ["one|", "two|", "three"];
      const upstream = createUpstream(
        () =>
          new Response(
            new ReadableStream<Uint8Array>({
              start(controller) {
                for (const chunk of chunks) {
                  controller.enqueue(new TextEncoder().encode(chunk));
                }
                controller.close();
              },
            }),
          ),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/stream", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(await res.text()).toBe("one|two|three");
    });

    it("passes an upstream 5xx problem-details body through verbatim", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const problem = {
        type: "https://api.example.test/errors/overloaded",
        title: "Service Unavailable",
        status: 503,
      };
      const upstream = createUpstream(
        () =>
          new Response(JSON.stringify(problem), {
            status: 503,
            headers: {
              "content-type": "application/problem+json",
              "retry-after": "30",
            },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(503);
      expect(res.headers.get("content-type")).toBe("application/problem+json");
      expect(res.headers.get("retry-after")).toBe("30");
      expect(await res.json()).toStrictEqual(problem);
    });

    it("answers 502 when the upstream cannot be reached", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () => new TypeError("connection refused"),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(502);
      expect((await res.json()).error).toBe("temporarily_unavailable");
    });
  });

  describe("session and refresh", () => {
    it("answers 401 without calling upstream when there is no session", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", { headers: CSRF });

      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toBe(
        'Bearer error="invalid_token"',
      );
      expect((await res.json()).error).toBe("invalid_token");
      expect(upstream.calls.length).toBe(0);
    });

    it("refreshes proactively when the access token is near expiry", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });
      const cookie = await seed(bff.sessionStore, {
        tokens: {
          accessToken: "access-1",
          tokenType: "Bearer",
          accessTokenExpiresAt: Date.now() + 5_000,
        },
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(cookie), ...CSRF },
      });

      await res.text();
      expect(idp.refreshTokensSeen).toStrictEqual(["refresh-1"]);
      expect(authorization(upstream.calls[0])).toBe("Bearer access-2");
    });

    it("answers 502 temporarily_unavailable when a proactive refresh cannot reach the IdP", async () => {
      for (const unavailable of ["transport", "server"] as const) {
        const idp = createIdp({ unavailable });
        const store = new MemorySessionStore();
        const bff = makeBff(idp, { sessionStore: store });
        const upstream = createUpstream(() => new Response("[]"));
        const app = makeApp(bff, UPSTREAM, {
          stripPrefix: "/api",
          fetch: upstream.fetch,
        });
        const cookie = await seed(store, {
          tokens: {
            accessToken: "access-1",
            tokenType: "Bearer",
            accessTokenExpiresAt: Date.now() + 5_000,
          },
        });

        const res = await app.request("/api/things", {
          headers: { ...cookieHeader(cookie), ...CSRF },
        });

        expect(res.status).toBe(502);
        expect((await res.json()).error).toBe("temporarily_unavailable");
        expect(upstream.calls.length).toBe(0);
        expect(
          (await store.read(cookie))?.tokens.accessToken,
          "a refresh the IdP never answered must leave the session signed in",
        ).toBe("access-1");
        expect(res.headers.get("set-cookie")).toBe(null);
      }
    });

    it("answers 401 and clears the session when a proactive refresh is rejected", async () => {
      const idp = createIdp({ fails: true });
      const store = new MemorySessionStore();
      const bff = makeBff(idp, { sessionStore: store });
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });
      const cookie = await seed(store, {
        tokens: {
          accessToken: "access-1",
          tokenType: "Bearer",
          accessTokenExpiresAt: Date.now() + 5_000,
        },
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(cookie), ...CSRF },
      });

      expect(res.status).toBe(401);
      expect((await res.json()).error).toBe("invalid_token");
      expect(upstream.calls.length).toBe(0);
      expect(await store.read(cookie)).toBe(null);
    });

    it("retries once with a refreshed token after an invalid_token 401", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream((attempt) =>
        attempt === 1
          ? new Response('{"error":"invalid_token"}', {
              status: 401,
              headers: {
                "www-authenticate": 'Bearer error="invalid_token"',
                "content-type": "application/json",
              },
            })
          : new Response('{"ok":true}', {
              headers: { "content-type": "application/json" },
            }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(200);
      expect(await res.json()).toStrictEqual({ ok: true });
      expect(upstream.calls.length).toBe(2);
      expect(authorization(upstream.calls[0])).toBe("Bearer access-1");
      expect(authorization(upstream.calls[1])).toBe("Bearer access-2");
      expect(upstream.calls[1].init.body).toBe(null);
      expect(idp.refreshTokensSeen).toStrictEqual(["refresh-1"]);
    });

    it("retries at most once", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () =>
          new Response(null, {
            status: 401,
            headers: { "www-authenticate": 'Bearer error="invalid_token"' },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(401);
      await res.body?.cancel();
      expect(upstream.calls.length).toBe(2);
      expect(idp.refreshTokensSeen.length).toBe(1);
    });

    it("clears the session and answers 401 when the refresh fails", async () => {
      const idp = createIdp({ fails: true });
      const store = new MemorySessionStore();
      const bff = makeBff(idp, { sessionStore: store });
      const upstream = createUpstream(
        () =>
          new Response(null, {
            status: 401,
            headers: { "www-authenticate": 'Bearer error="invalid_token"' },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });
      const cookie = await seed(store);

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(cookie), ...CSRF },
      });

      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toBe(
        'Bearer error="invalid_token"',
      );
      expect((await res.json()).error).toBe("invalid_token");
      expect(upstream.calls.length).toBe(1);
      expect(await store.read(cookie)).toBe(null);
      expect(
        res.headers.get("set-cookie")?.includes(`${COOKIE_NAME}=`),
      ).toStrictEqual(true);
    });

    it("shares one refresh across concurrent requests instead of racing the token", async () => {
      const idp = createIdp();
      const store = new MemorySessionStore();
      const bff = makeBff(idp, { sessionStore: store });
      const seen = new Set<string>();
      const upstream = createUpstream((_attempt, call) => {
        const token = new Headers(call.init.headers).get("authorization");
        if (token === "Bearer access-1") {
          return new Response(null, {
            status: 401,
            headers: { "www-authenticate": 'Bearer error="invalid_token"' },
          });
        }
        seen.add(token ?? "");
        return new Response('{"ok":true}', {
          headers: { "content-type": "application/json" },
        });
      });
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });
      const cookie = await seed(store);
      const headers = { ...cookieHeader(cookie), ...CSRF };

      const responses = await Promise.all([
        app.request("/api/things", { headers }),
        app.request("/api/things", { headers }),
        app.request("/api/things", { headers }),
      ]);

      for (const res of responses) {
        expect(res.status).toBe(200);
        expect(await res.json()).toStrictEqual({ ok: true });
      }
      expect(idp.refreshTokensSeen).toStrictEqual(["refresh-1"]);
      expect([...seen]).toStrictEqual(["Bearer access-2"]);
      expect((await store.read(cookie))?.tokens.accessToken).toBe("access-2");
    });

    it("keeps the session alive when the IdP cannot answer the refresh", async () => {
      for (const unavailable of ["transport", "server"] as const) {
        const idp = createIdp({ unavailable });
        const store = new MemorySessionStore();
        const bff = makeBff(idp, { sessionStore: store });
        const upstream = createUpstream(
          () =>
            new Response(null, {
              status: 401,
              headers: { "www-authenticate": 'Bearer error="invalid_token"' },
            }),
        );
        const app = makeApp(bff, UPSTREAM, {
          stripPrefix: "/api",
          fetch: upstream.fetch,
        });
        const cookie = await seed(store);

        const res = await app.request("/api/things", {
          headers: { ...cookieHeader(cookie), ...CSRF },
        });

        expect(res.status).toBe(502);
        expect((await res.json()).error).toBe("temporarily_unavailable");
        expect((await store.read(cookie))?.tokens.accessToken).toBe("access-1");
        expect(res.headers.get("set-cookie")).toBe(null);
      }
    });

    it("adopts the current session when another request rotated the token mid-exchange", async () => {
      const store = new MemorySessionStore();
      let cookie = "";
      const idp: Idp = {
        refreshTokensSeen: [],
        fetch: async (_input, init) => {
          const params = new URLSearchParams(String(init?.body));
          idp.refreshTokensSeen.push(params.get("refresh_token") ?? "");
          const live = await store.read(cookie);
          await store.update(cookie, {
            ...live!,
            tokens: { ...live!.tokens, accessToken: "access-9" },
            refreshToken: "refresh-9",
          });
          return new Response(JSON.stringify({ error: "invalid_grant" }), {
            status: 400,
            headers: { "content-type": "application/json" },
          });
        },
      };
      const bff = makeBff(idp, { sessionStore: store });
      const upstream = createUpstream((attempt) =>
        attempt === 1
          ? new Response(null, {
              status: 401,
              headers: { "www-authenticate": 'Bearer error="invalid_token"' },
            })
          : new Response('{"ok":true}', {
              headers: { "content-type": "application/json" },
            }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });
      cookie = await seed(store);

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(cookie), ...CSRF },
      });

      expect(res.status).toBe(200);
      await res.text();
      expect(authorization(upstream.calls[1])).toBe("Bearer access-9");
      expect((await store.read(cookie))?.refreshToken).toBe("refresh-9");
    });

    it("passes a 401 that is not an invalid_token challenge straight through", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () =>
          new Response('{"error":"nope"}', {
            status: 401,
            headers: { "content-type": "application/json" },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(401);
      expect(await res.json()).toStrictEqual({ error: "nope" });
      expect(upstream.calls.length).toBe(1);
      expect(idp.refreshTokensSeen).toStrictEqual([]);
    });

    it("does not retry a request that carried a body", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () =>
          new Response(null, {
            status: 401,
            headers: { "www-authenticate": 'Bearer error="invalid_token"' },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        method: "POST",
        headers: {
          ...cookieHeader(await seed(bff.sessionStore)),
          ...CSRF,
          "content-type": "application/json",
        },
        body: "{}",
      });

      expect(res.status).toBe(401);
      await res.body?.cancel();
      expect(upstream.calls.length).toBe(1);
      expect(idp.refreshTokensSeen).toStrictEqual([]);
    });

    it("skips the retry when retryOn401 is false", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(
        () =>
          new Response(null, {
            status: 401,
            headers: { "www-authenticate": 'Bearer error="invalid_token"' },
          }),
      );
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
        retryOn401: false,
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(await seed(bff.sessionStore)), ...CSRF },
      });

      expect(res.status).toBe(401);
      await res.body?.cancel();
      expect(upstream.calls.length).toBe(1);
      expect(idp.refreshTokensSeen).toStrictEqual([]);
    });

    it("rotates the session cookie onto the proxied response", async () => {
      const idp = createIdp();
      const store = new EncryptedCookieSessionStore({
        secret: "0123456789abcdef0123456789abcdef",
      });
      const bff = makeBff(idp, { sessionStore: store });
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });
      const cookie = await seed(store, {
        tokens: {
          accessToken: "access-1",
          tokenType: "Bearer",
          accessTokenExpiresAt: Date.now() + 5_000,
        },
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(cookie), ...CSRF },
      });

      await res.text();
      const setCookie = res.headers.get("set-cookie") ?? "";
      expect(setCookie.startsWith(`${COOKIE_NAME}=`)).toStrictEqual(true);
      expect(setCookie.includes(cookie)).toStrictEqual(false);
      const rotated = /oauth2_session=([^;]+)/.exec(setCookie)![1];
      expect((await store.read(rotated))?.tokens.accessToken).toBe("access-2");
    });

    it("keeps the OP session id across a refresh", async () => {
      const idp = createIdp();
      const store = new MemorySessionStore();
      const bff = makeBff(idp, { sessionStore: store });
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });
      const cookie = await seed(store, {
        sid: "op-session-1",
        tokens: {
          accessToken: "access-1",
          tokenType: "Bearer",
          accessTokenExpiresAt: Date.now() + 5_000,
        },
      });

      const res = await app.request("/api/things", {
        headers: { ...cookieHeader(cookie), ...CSRF },
      });

      await res.text();
      expect(await store.destroyByLogout({ sid: "op-session-1" })).toBe(1);
      expect(await store.read(cookie)).toBe(null);
    });
  });

  describe("CSRF parity", () => {
    it("rejects a credentialed request without the CSRF header", async () => {
      const idp = createIdp();
      const bff = makeBff(idp);
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: cookieHeader(await seed(bff.sessionStore)),
      });

      expect(res.status).toBe(403);
      expect((await res.json()).error).toBe("csrf_validation_failed");
      expect(upstream.calls.length).toBe(0);
    });

    it("honors a custom CSRF header name", async () => {
      const idp = createIdp();
      const bff = makeBff(idp, { csrf: { headerName: "x-handler" } });
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });
      const cookie = cookieHeader(await seed(bff.sessionStore));

      const rejected = await app.request("/api/things", { headers: cookie });
      expect(rejected.status).toBe(403);
      await rejected.body?.cancel();

      const accepted = await app.request("/api/things", {
        headers: { ...cookie, "x-handler": "1" },
      });
      expect(accepted.status).toBe(200);
      await accepted.text();
      expect(new Headers(upstream.calls[0].init.headers).get("x-handler")).toBe(
        null,
      );
    });

    it("forwards without a CSRF header when CSRF is disabled", async () => {
      const idp = createIdp();
      const bff = makeBff(idp, { csrf: false });
      const upstream = createUpstream(() => new Response("[]"));
      const app = makeApp(bff, UPSTREAM, {
        stripPrefix: "/api",
        fetch: upstream.fetch,
      });

      const res = await app.request("/api/things", {
        headers: cookieHeader(await seed(bff.sessionStore)),
      });

      expect(res.status).toBe(200);
      await res.text();
      expect(upstream.calls.length).toBe(1);
    });
  });
});
