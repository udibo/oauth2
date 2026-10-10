import { describe, expect, it } from "vitest";
import { thrown } from "../_test_assert.ts";
import { BffClient } from "./bff-client.ts";
import type { OAuth2ClientEvent } from "./events.ts";

const BASE_URL = "https://app.example";

function urlOf(input: RequestInfo | URL): string {
  return typeof input === "string" || input instanceof URL
    ? input.toString()
    : input.url;
}

interface Capture {
  url: string;
  init?: RequestInit;
}

function sessionResponder(
  body: unknown,
  captures: Capture[] = [],
  status = 200,
): typeof fetch {
  return ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = urlOf(input);
    captures.push({ url, init });
    if (url.endsWith("/auth/session")) {
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }
    return Promise.resolve(new Response(null, { status: 404 }));
  }) as typeof fetch;
}

describe("BffClient", () => {
  describe("login", () => {
    it("builds the configured login URL with return_to", async () => {
      const client = new BffClient({ endpoints: { baseUrl: BASE_URL } });
      const { url } = await client.login({ returnTo: "/dashboard" });
      const parsed = new URL(url);
      expect(parsed.origin).toBe(BASE_URL);
      expect(parsed.pathname).toBe("/auth/login");
      expect(parsed.searchParams.get("return_to")).toBe("/dashboard");
    });

    it("defaults to the same-origin /auth/login path", async () => {
      const client = new BffClient();
      const { url } = await client.login();
      expect(new URL(url).pathname).toBe("/auth/login");
      expect(new URL(url).searchParams.get("return_to")).toBe(null);
    });
  });

  describe("logout", () => {
    it("builds the logout URL and emits logged_out", async () => {
      const client = new BffClient({ endpoints: { baseUrl: BASE_URL } });
      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      const { url } = await client.logout({ returnTo: "/bye" });
      expect(url).toBe(`${BASE_URL}/auth/logout?return_to=%2Fbye`);
      expect(events.length).toBe(1);
      expect(events[0].type).toBe("logged_out");
    });
  });

  describe("getSession", () => {
    it("returns the enriched probe (expiry + logout URL)", async () => {
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: sessionResponder({
          isAuthenticated: true,
          user: { sub: "u1" },
          sessionExpiresIn: 300,
          logoutUrl: "/auth/logout",
        }),
      });
      expect(await client.getSession()).toStrictEqual({
        isAuthenticated: true,
        user: { sub: "u1" },
        sessionExpiresIn: 300,
        logoutUrl: "/auth/logout",
      });
    });

    it("returns an anonymous session when not authenticated", async () => {
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: sessionResponder({ isAuthenticated: false, user: null }),
      });
      expect(await client.getSession()).toStrictEqual({
        isAuthenticated: false,
        user: null,
        sessionExpiresIn: null,
        logoutUrl: null,
      });
    });

    it("reads a 401 as signed out without crying error", async () => {
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: sessionResponder({}, [], 401),
      });
      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      expect((await client.getSession()).isAuthenticated).toBe(false);
      expect(events, "401 is the normal anonymous answer").toStrictEqual([]);
    });

    it("reads a 503 as signed out and reports it", async () => {
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: sessionResponder({}, [], 503),
      });
      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      expect((await client.getSession()).isAuthenticated).toBe(false);
      expect(
        events.map((event) => event.type),
        "a broken BFF is not the same as an anonymous visitor",
      ).toStrictEqual(["error"]);
    });

    it("reads an HTML 200 as signed out rather than rejecting", async () => {
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: (() =>
          Promise.resolve(
            new Response("<!doctype html><h1>Not found</h1>", {
              status: 200,
              headers: { "Content-Type": "text/html" },
            }),
          )) as typeof fetch,
      });
      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      expect((await client.getSession()).isAuthenticated).toBe(false);
      expect(
        events.map((event) => event.type),
        "an unparseable probe is reported, not swallowed silently",
      ).toStrictEqual(["error"]);
    });

    it("reads an unreachable BFF as signed out and emits error", async () => {
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: (() => Promise.reject(new TypeError("offline"))) as typeof fetch,
      });
      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      expect((await client.getSession()).isAuthenticated).toBe(false);
      expect(events.map((event) => event.type)).toStrictEqual(["error"]);
    });

    it("drops user, expiry, and logoutUrl from an anonymous payload", async () => {
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: sessionResponder({
          isAuthenticated: false,
          user: { sub: "leaked" },
          sessionExpiresIn: 300,
          logoutUrl: "/auth/logout",
        }),
      });
      expect(await client.getSession()).toStrictEqual({
        isAuthenticated: false,
        user: null,
        sessionExpiresIn: null,
        logoutUrl: null,
      });
    });

    it("returns a signed-out snapshot no caller can mutate for the next one", async () => {
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: sessionResponder({ isAuthenticated: false }),
      });
      const first = (await client.getSession()) as { isAuthenticated: boolean };
      thrown(() => {
        first.isAuthenticated = true;
      });
      expect((await client.getSession()).isAuthenticated).toBe(false);
    });

    it("sends credentials and the CSRF header on the probe", async () => {
      const captures: Capture[] = [];
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: sessionResponder(
          { isAuthenticated: false, user: null },
          captures,
        ),
      });
      await client.getSession();
      expect(captures[0].init?.credentials).toBe("include");
      expect(new Headers(captures[0].init?.headers).get("x-csrf")).toBe("1");
    });

    it("honors a custom CSRF header name and value", async () => {
      const captures: Capture[] = [];
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        csrfHeader: { name: "x-requested-with", value: "spa" },
        fetch: sessionResponder(
          { isAuthenticated: false, user: null },
          captures,
        ),
      });
      await client.getSession();
      const headers = new Headers(captures[0].init?.headers);
      expect(headers.get("x-requested-with")).toBe("spa");
      expect(headers.get("x-csrf")).toBe(null);
    });

    it("sends no CSRF header when the guard is disabled", async () => {
      const captures: Capture[] = [];
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        csrfHeader: false,
        fetch: sessionResponder(
          { isAuthenticated: false, user: null },
          captures,
        ),
      });
      await client.getSession();
      expect(new Headers(captures[0].init?.headers).get("x-csrf")).toBe(null);
    });
  });

  describe("getUser", () => {
    it("parses the session endpoint response", async () => {
      const sessionUser = { id: "user-1", username: "demo" };
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: sessionResponder({ isAuthenticated: true, user: sessionUser }),
      });
      expect(await client.getUser()).toStrictEqual(sessionUser);
    });

    it("returns null when the probe says signed out", async () => {
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: sessionResponder({ isAuthenticated: false, user: { sub: "x" } }),
      });
      expect(await client.getUser()).toBe(null);
    });
  });

  describe("renewSession", () => {
    it("emits no error event when a background probe fails", async () => {
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: (() => Promise.reject(new TypeError("offline"))) as typeof fetch,
      });
      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      expect((await client.renewSession()).isAuthenticated).toBe(false);
      expect(
        events,
        "a background renew owes the UI no error state for a blip",
      ).toStrictEqual([]);

      await client.getSession();
      expect(
        events.map((event) => event.type),
        "a foreground probe still reports it",
      ).toStrictEqual(["error"]);
    });

    it("re-probes the session endpoint", async () => {
      const captures: Capture[] = [];
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL },
        fetch: sessionResponder(
          { isAuthenticated: true, user: null, sessionExpiresIn: 60 },
          captures,
        ),
      });
      const session = await client.renewSession();
      expect(session.sessionExpiresIn).toBe(60);
      expect(captures.length).toBe(1);
    });
  });

  describe("fetch", () => {
    it("includes credentials and the CSRF header", async () => {
      const captures: Capture[] = [];
      const client = new BffClient({
        fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
          captures.push({ url: urlOf(input), init });
          return Promise.resolve(new Response("ok"));
        }) as typeof fetch,
      });
      await client.fetch("/api/items");
      expect(captures[0].init?.credentials).toBe("include");
      expect(new Headers(captures[0].init?.headers).get("x-csrf")).toBe("1");
    });

    it("leaves a caller-set CSRF header alone", async () => {
      const captures: Capture[] = [];
      const client = new BffClient({
        fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
          captures.push({ url: urlOf(input), init });
          return Promise.resolve(new Response("ok"));
        }) as typeof fetch,
      });
      await client.fetch("/api/items", { headers: { "x-csrf": "custom" } });
      expect(new Headers(captures[0].init?.headers).get("x-csrf")).toBe(
        "custom",
      );
    });

    it("sends the headers a Request input was built with, plus the CSRF header", async () => {
      let sent: Headers | undefined;
      const client = new BffClient({
        fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
          sent = new Request(input, init).headers;
          return Promise.resolve(new Response("ok"));
        }) as typeof fetch,
      });

      await client.fetch(
        new Request(`${BASE_URL}/api/items`, {
          headers: { "x-trace": "abc", accept: "application/json" },
        }),
      );

      expect(sent?.get("x-trace")).toBe("abc");
      expect(sent?.get("accept")).toBe("application/json");
      expect(sent?.get("x-csrf")).toBe("1");
    });

    it("lets init.headers override a same-named Request header, keeping the rest", async () => {
      let sent: Headers | undefined;
      const client = new BffClient({
        fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
          sent = new Request(input, init).headers;
          return Promise.resolve(new Response("ok"));
        }) as typeof fetch,
      });

      await client.fetch(
        new Request(`${BASE_URL}/api/items`, {
          headers: { "x-trace": "from-request", "x-keep": "kept" },
        }),
        { headers: { "x-trace": "from-init" } },
      );

      expect(sent?.get("x-trace")).toBe("from-init");
      expect(sent?.get("x-keep")).toBe("kept");
    });

    it("leaves a CSRF header set on a Request input alone", async () => {
      let sent: Headers | undefined;
      const client = new BffClient({
        fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
          sent = new Request(input, init).headers;
          return Promise.resolve(new Response("ok"));
        }) as typeof fetch,
      });

      await client.fetch(
        new Request(`${BASE_URL}/api/items`, {
          headers: { "x-csrf": "custom" },
        }),
      );

      expect(sent?.get("x-csrf")).toBe("custom");
    });

    it("emits logged_out on a 401 and returns the response as-is", async () => {
      const client = new BffClient({
        fetch: (() =>
          Promise.resolve(new Response(null, { status: 401 }))) as typeof fetch,
      });
      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      const res = await client.fetch("/api/items");
      expect(res.status).toBe(401);
      expect(
        events.map((event) =>
          event.type === "logged_out" ? event.reason : event.type,
        ),
      ).toStrictEqual(["session_expired"]);
    });

    it("leaves a non-401 response untouched", async () => {
      const client = new BffClient({
        fetch: (() =>
          Promise.resolve(new Response(null, { status: 403 }))) as typeof fetch,
      });
      const events: OAuth2ClientEvent[] = [];
      client.subscribe((event) => events.push(event));

      expect((await client.fetch("/api/items")).status).toBe(403);
      expect(events.length).toBe(0);
    });
  });

  describe("loginContinuation", () => {
    it("resumes an authorize URL or starts a fresh login", () => {
      const client = new BffClient({
        authorizePath: "/api/oauth2/authorize",
      });
      const authorizeUrl = "/api/oauth2/authorize?response_type=code&state=s";
      expect(client.loginContinuation(authorizeUrl)).toBe(authorizeUrl);
      expect(client.loginContinuation("/dashboard")).toBe(
        "/auth/login?return_to=%2Fdashboard",
      );
    });

    it("uses the configured bff login path", () => {
      const client = new BffClient({
        endpoints: { baseUrl: BASE_URL, login: "/auth/signin" },
      });
      expect(client.loginContinuation("/x")).toBe(
        `${BASE_URL}/auth/signin?return_to=%2Fx`,
      );
    });

    it("starts a fresh login for an authorize URL when authorizePath is unset", () => {
      const client = new BffClient();
      expect(client.loginContinuation("/api/oauth2/authorize?state=s")).toBe(
        "/auth/login?return_to=%2Fapi%2Foauth2%2Fauthorize%3Fstate%3Ds",
      );
    });
  });
});
