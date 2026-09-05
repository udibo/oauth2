/**
 * Hermetic tests for the app's auth flows. Everything runs in-process via
 * `server.request(...)` — no sockets, no external services. The flow tests
 * drive the real redirect chain (BFF login → authorize → IDP form →
 * callback) with a small cookie-jar `Session` helper.
 *
 * @module
 */

import { assert, assertEquals, assertStringIncludes } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { spy } from "@std/testing/mock";

import { DEMO_USER, passwords } from "@/oauth2/server.ts";
import { server } from "./main.ts";

const ORIGIN = "http://localhost:8000";

/** Request options for {@link Session}, with headers narrowed to a plain record. */
type SessionInit = Omit<RequestInit, "headers"> & {
  headers?: Record<string, string>;
};

/** A browser stand-in: carries cookies across requests and follows redirects. */
class Session {
  #cookies = new Map<string, string>();

  get cookieHeader(): string {
    return [...this.#cookies]
      .map(([name, value]) => `${name}=${value}`)
      .join("; ");
  }

  async request(
    path: string,
    init: SessionInit = {},
  ): Promise<Response> {
    const res = await server.request(new URL(path, ORIGIN).href, {
      ...init,
      headers: { ...init.headers, cookie: this.cookieHeader },
    });
    for (const setCookie of res.headers.getSetCookie()) {
      const [pair] = setCookie.split(";");
      const separator = pair.indexOf("=");
      const name = pair.slice(0, separator).trim();
      const value = pair.slice(separator + 1).trim();
      if (!value || /max-age=0/i.test(setCookie)) {
        this.#cookies.delete(name);
      } else {
        this.#cookies.set(name, value);
      }
    }
    return res;
  }

  /**
   * Requests `path` as a same-origin browser navigation — carrying the
   * `Sec-Fetch-Site` metadata a browser attaches, which the BFF's `GET`
   * logout guard requires — then follows redirects until a non-3xx response.
   */
  async navigate(
    path: string,
    init?: SessionInit,
  ): Promise<Response> {
    const navigation = { "sec-fetch-site": "same-origin" };
    let res = await this.request(path, {
      ...init,
      headers: { ...navigation, ...init?.headers },
    });
    for (let hop = 0; res.status >= 300 && res.status < 400; hop++) {
      assert(hop < 10, "too many redirects");
      const location = res.headers.get("location");
      assert(location, "redirect without a location header");
      await res.body?.cancel();
      res = await this.request(location, { headers: navigation });
    }
    return res;
  }
}

describe("app", () => {
  it("renders the app shell at /", async () => {
    const res = await server.request(`${ORIGIN}/`);
    assertEquals(res.status, 200);
    assertStringIncludes(res.headers.get("content-type") ?? "", "text/html");
    assertStringIncludes(await res.text(), "My App");
  });

  it("serves the sign-in and sign-up forms", async () => {
    const login = await server.request(`${ORIGIN}/login`);
    assertEquals(login.status, 200);
    assertStringIncludes(await login.text(), "Sign in");

    const signup = await server.request(`${ORIGIN}/signup`);
    assertEquals(signup.status, 200);
    assertStringIncludes(await signup.text(), "Create account");
  });

  it("reports an unauthenticated session and rejects API calls without one", async () => {
    const probe = await server.request(`${ORIGIN}/auth/session`);
    assertEquals(probe.status, 200);
    assertEquals(await probe.json(), { isAuthenticated: false, user: null });

    const me = await server.request(`${ORIGIN}/api/me`);
    assertEquals(me.status, 401);
    await me.body?.cancel();
  });

  it("signs up, lands signed in, calls the protected API, and signs out", async () => {
    const session = new Session();

    const landing = await session.navigate("/signup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "ada",
        name: "Ada Lovelace",
        password: "correct-horse-battery",
        return_to: "/",
      }).toString(),
    });
    assertEquals(landing.status, 200);
    assertStringIncludes(await landing.text(), "My App");

    const probe = await session.request("/auth/session", {
      headers: { "x-csrf": "1" },
    });
    const data = await probe.json();
    assertEquals(data.isAuthenticated, true);
    assertEquals(data.user.username, "ada");

    const me = await session.request("/api/me", {
      headers: { "x-csrf": "1" },
    });
    assertEquals(me.status, 200);
    assertEquals((await me.json()).name, "Ada Lovelace");

    const out = await session.navigate("/auth/logout?return_to=%2Flogout");
    assertEquals(out.status, 200);
    await out.body?.cancel();

    const after = await session.request("/auth/session");
    assertEquals(await after.json(), { isAuthenticated: false, user: null });
  });

  it("signs in the seeded demo user and resumes the requested page", async () => {
    const session = new Session();

    const start = await session.request("/auth/login?return_to=%2Fprofile");
    assertEquals(start.status, 302);
    const authorizeUrl = start.headers.get("location")!;
    assertStringIncludes(authorizeUrl, "/oauth2/authorize");
    await start.body?.cancel();

    const authorize = await session.request(authorizeUrl);
    assertEquals(authorize.status, 302);
    const loginUrl = authorize.headers.get("location")!;
    assertStringIncludes(loginUrl, "/login?return_to=");
    await authorize.body?.cancel();
    const returnTo = new URL(loginUrl, ORIGIN).searchParams.get("return_to")!;

    const landing = await session.navigate("/login", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: DEMO_USER.username,
        password: "password",
        return_to: returnTo,
      }).toString(),
    });
    assertEquals(landing.status, 200);
    assertStringIncludes(await landing.text(), "Profile");

    const me = await session.request("/api/me", {
      headers: { "x-csrf": "1" },
    });
    assertEquals(me.status, 200);
    assertEquals((await me.json()).sub, DEMO_USER.id);
  });

  it("re-renders the sign-in form with an error on bad credentials", async () => {
    const session = new Session();
    const res = await session.navigate("/login", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: DEMO_USER.username,
        password: "wrong",
        return_to: "/",
      }).toString(),
    });
    assertEquals(res.status, 200);
    assertStringIncludes(await res.text(), "Invalid username or password.");
  });

  it("spends the same password work on an unknown username as on a wrong password", async () => {
    async function derivations(
      username: string,
      password: string,
    ): Promise<number> {
      using hash = spy(passwords, "hash");
      using verify = spy(passwords, "verify");
      const res = await server.request(`${ORIGIN}/login`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ username, password, return_to: "/" }),
      });
      assertEquals(res.status, 200);
      await res.body?.cancel();
      return hash.calls.length + verify.calls.length;
    }

    const unknown = await derivations("no-such-user", "correct-horse-battery");
    const wrongPassword = await derivations(DEMO_USER.username, "wrong");
    assert(unknown > 0, "an unknown username must still cost a derivation");
    assertEquals(
      unknown,
      wrongPassword,
      "unknown-username and wrong-password sign-ins must cost the same work",
    );
  });

  it("rejects a duplicate username at sign-up", async () => {
    const session = new Session();
    const res = await session.navigate("/signup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: DEMO_USER.username,
        name: "Impostor",
        password: "correct-horse-battery",
        return_to: "/",
      }).toString(),
    });
    assertEquals(res.status, 200);
    assertStringIncludes(await res.text(), "already taken");
  });

  it("refuses an open-redirect return_to (same-origin only)", async () => {
    const res = await server.request(`${ORIGIN}/login`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: DEMO_USER.username,
        password: "password",
        return_to: "https://evil.example/phish",
      }),
    });
    assertEquals(res.status, 302);
    const location = res.headers.get("location") ?? "";
    assert(!location.includes("evil.example"), "must not leave the origin");
    assertStringIncludes(location, "/auth/login");
    await res.body?.cancel();
  });

  it("rejects a cross-site credential post (login/sign-up CSRF)", async () => {
    for (const path of ["/login", "/signup"]) {
      const res = await server.request(`${ORIGIN}${path}`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          origin: "https://evil.example",
        },
        body: new URLSearchParams({
          username: DEMO_USER.username,
          name: "Impostor",
          password: "correct-horse-battery",
          return_to: "/",
        }),
      });
      assertEquals(res.status, 403);
      assert(
        res.headers.getSetCookie().every((c) => !c.startsWith("idp_session=")),
        "must not open a session on a cross-site post",
      );
      await res.body?.cancel();
    }
  });

  it("rejects a cross-site forced logout and keeps the session", async () => {
    const session = new Session();
    await (await session.navigate("/signup", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "grace",
        name: "Grace Hopper",
        password: "correct-horse-battery",
        return_to: "/",
      }).toString(),
    })).body?.cancel();

    const forced = await session.request("/logout", {
      headers: { origin: "https://evil.example" },
    });
    assertEquals(forced.status, 403);
    await forced.body?.cancel();

    const start = await session.request("/auth/login?return_to=%2Fprofile");
    const authorize = await session.request(start.headers.get("location")!);
    assertEquals(authorize.status, 302);
    assertStringIncludes(
      authorize.headers.get("location")!,
      "/auth/callback",
    );
    await start.body?.cancel();
    await authorize.body?.cancel();
  });
});
