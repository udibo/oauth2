/**
 * Hermetic server tests. Everything runs in-process via `app.request(...)` —
 * no sockets, no build, no external services. The helpers walk the same
 * redirect chain the browser follows: identity form post → issuer session →
 * authorize → BFF callback → session cookie, carrying the login-state cookie
 * `/auth/login` sets so the callback recognizes the `state` as this browser's.
 *
 * @module
 */

import { assertEquals, assertStringIncludes } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { stub } from "@std/testing/mock";

import type { DeliveryMessage } from "@udibo/oauth2/identity";

import app from "./main.ts";
import { delivery } from "./oauth2/identity.ts";
import { bff, DEMO_PASSWORD, DEMO_USER, userService } from "./oauth2/server.ts";

function setCookieValue(res: Response, name: string): string | undefined {
  for (const value of res.headers.getSetCookie()) {
    const match = new RegExp(`^${name}=([^;]+)`).exec(value);
    if (match) return match[1];
  }
  return undefined;
}

function toPath(url: string): string {
  const parsed = new URL(url, "http://localhost:8000");
  return parsed.pathname + parsed.search;
}

interface SessionCookies {
  idpSession: string;
  bffSession: string;
  landedOn: string;
}

/**
 * Follows the redirect chain from a successful `/identity/*` response through
 * the authorize flow to a BFF session cookie, mirroring what the browser's
 * `fetch` does when it follows the redirects.
 */
async function followToSession(identityRes: Response): Promise<SessionCookies> {
  assertEquals(identityRes.status, 302);
  const idpSession = setCookieValue(identityRes, "idp_session")!;
  assertEquals(typeof idpSession, "string");
  const cookie = `idp_session=${idpSession}`;

  let location = identityRes.headers.get("location")!;
  let loginState: string | undefined;
  if (toPath(location).startsWith("/auth/login")) {
    const res = await app.request(toPath(location), { headers: { cookie } });
    assertEquals(res.status, 302);
    location = res.headers.get("location")!;
    loginState = setCookieValue(res, bff.loginStateCookieName);
    assertEquals(typeof loginState, "string");
  }

  const authorizeRes = await app.request(toPath(location), {
    headers: { cookie },
  });
  assertEquals(authorizeRes.status, 302);
  const callbackUrl = authorizeRes.headers.get("location")!;
  assertStringIncludes(callbackUrl, "/auth/callback");
  assertStringIncludes(callbackUrl, "code=");

  const callbackRes = await app.request(toPath(callbackUrl), {
    headers: loginState
      ? { cookie: `${bff.loginStateCookieName}=${loginState}` }
      : {},
  });
  assertEquals(callbackRes.status, 302);
  const bffSession = setCookieValue(callbackRes, "oauth2_session")!;
  assertEquals(typeof bffSession, "string");
  return {
    idpSession,
    bffSession,
    landedOn: callbackRes.headers.get("location")!,
  };
}

async function signIn(
  options: { email: string; password: string; returnTo?: string },
): Promise<Response> {
  const query = options.returnTo
    ? `?return_to=${encodeURIComponent(options.returnTo)}`
    : "";
  return await app.request(`/identity/signin${query}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      identifier: options.email,
      password: options.password,
    }),
  });
}

async function signUp(
  options: { name: string; email: string; password: string },
): Promise<Response> {
  return await app.request("/identity/signup", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(options),
  });
}

describe("SPA shell", () => {
  it("serves the shell at /", async () => {
    const res = await app.request("/");
    assertEquals(res.status, 200);
    assertStringIncludes(res.headers.get("content-type") ?? "", "text/html");
    const html = await res.text();
    assertStringIncludes(html, `<div id="root"></div>`);
    assertStringIncludes(html, "/build/main.js");
  });

  it("serves the shell for client-routed paths like /dashboard", async () => {
    const res = await app.request("/dashboard");
    assertEquals(res.status, 200);
    assertStringIncludes(await res.text(), "/build/main.js");
  });

  it("serves the shell for the password-reset pages", async () => {
    for (const path of ["/forgot-password", "/reset-password?token=x"]) {
      const res = await app.request(path);
      assertEquals(res.status, 200);
      assertStringIncludes(await res.text(), "/build/main.js");
    }
  });

  it("404s a missing /build asset instead of the shell", async () => {
    const res = await app.request("/build/does-not-exist.js");
    assertEquals(res.status, 404);
    await res.body?.cancel();
  });

  it("injects the demo-account flag when the demo user is seeded", async () => {
    const res = await app.request("/");
    assertStringIncludes(await res.text(), "__DEMO_ACCOUNT__ = true");
  });
});

describe("sign-in", () => {
  it("signs the demo user in end to end and reports the session", async () => {
    const { bffSession, landedOn } = await followToSession(
      await signIn({
        email: DEMO_USER.email,
        password: DEMO_PASSWORD,
        returnTo: "/dashboard",
      }),
    );
    assertEquals(landedOn, "/dashboard");

    const probe = await app.request("/auth/session", {
      headers: { cookie: `oauth2_session=${bffSession}`, "x-csrf": "1" },
    });
    assertEquals(probe.status, 200);
    const session = await probe.json();
    assertEquals(session.isAuthenticated, true);
    assertEquals(session.user.sub, DEMO_USER.id);
    assertEquals(session.user.email, DEMO_USER.email);
  });

  it("matches the email case-insensitively", async () => {
    const res = await signIn({
      email: "Demo@Example.com",
      password: DEMO_PASSWORD,
    });
    assertEquals(res.status, 302);
    await res.body?.cancel();
  });

  it("rejects a wrong password with invalid_credentials", async () => {
    const res = await signIn({
      email: DEMO_USER.email,
      password: "wrong-password",
    });
    assertEquals(res.status, 401);
    assertEquals(await res.json(), { error: "invalid_credentials" });
  });

  it("refuses an off-site return_to (open-redirect guard)", async () => {
    const res = await signIn({
      email: DEMO_USER.email,
      password: DEMO_PASSWORD,
      returnTo: "https://evil.example/phish",
    });
    assertEquals(res.status, 302);
    const location = res.headers.get("location")!;
    assertEquals(location.includes("evil.example"), false);
    assertStringIncludes(location, "/auth/login");
    await res.body?.cancel();
  });

  it("resumes an in-flight authorize URL unchanged (mid-authorize login)", async () => {
    const authorizeUrl = "/oauth2/authorize?response_type=code&client_id=web";
    const res = await signIn({
      email: DEMO_USER.email,
      password: DEMO_PASSWORD,
      returnTo: authorizeUrl,
    });
    assertEquals(res.status, 302);
    assertEquals(res.headers.get("location"), authorizeUrl);
    await res.body?.cancel();
  });

  it("blocks a cross-site form post (CSRF)", async () => {
    const res = await app.request("/identity/signin", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        origin: "https://evil.example",
      },
      body: new URLSearchParams({
        identifier: DEMO_USER.email,
        password: DEMO_PASSWORD,
      }),
    });
    assertEquals(res.status, 403);
    await res.body?.cancel();
  });
});

describe("sign-up", () => {
  it("creates an account, sends a console verification link, and signs in", async () => {
    let verifyUrl = "";
    using _hook = stub(
      delivery,
      "sendEmailVerification",
      (...args: unknown[]) => {
        verifyUrl = (args[0] as DeliveryMessage).url!;
      },
    );

    const email = `new-${crypto.randomUUID().slice(0, 8)}@example.com`;
    const { bffSession } = await followToSession(
      await signUp({ name: "New User", email, password: "long-enough-1" }),
    );
    assertStringIncludes(verifyUrl, "/verify-email?token=");

    const probe = await app.request("/auth/session", {
      headers: { cookie: `oauth2_session=${bffSession}`, "x-csrf": "1" },
    });
    const session = await probe.json();
    assertEquals(session.isAuthenticated, true);
    assertEquals(session.user.email, email);
    assertEquals(session.user.emailVerified, false);
  });

  it("rejects a duplicate email with identifier_taken", async () => {
    const res = await signUp({
      name: "Dupe",
      email: DEMO_USER.email,
      password: "long-enough-1",
    });
    assertEquals(res.status, 409);
    assertEquals(await res.json(), { error: "identifier_taken" });
  });

  it("rejects a weak password with weak_password", async () => {
    const res = await signUp({
      name: "Weak",
      email: "weak@example.com",
      password: "short",
    });
    assertEquals(res.status, 422);
    assertEquals(await res.json(), { error: "weak_password" });
  });
});

describe("email verification", () => {
  it("verifies with a single-use token, then rejects reuse", async () => {
    let verifyUrl = "";
    using _hook = stub(
      delivery,
      "sendEmailVerification",
      (...args: unknown[]) => {
        verifyUrl = (args[0] as DeliveryMessage).url!;
      },
    );
    const email = `verify-${crypto.randomUUID().slice(0, 8)}@example.com`;
    const res = await signUp({
      name: "Verify Me",
      email,
      password: "long-enough-1",
    });
    assertEquals(res.status, 302);
    await res.body?.cancel();

    const token = new URL(verifyUrl).searchParams.get("token")!;
    const verify = await app.request("/identity/email/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    assertEquals(verify.status, 200);
    assertEquals((await verify.json()).ok, true);
    assertEquals(
      (await userService.findByUsername(email))?.emailVerified,
      true,
    );

    const reuse = await app.request("/identity/email/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    assertEquals(reuse.status, 400);
    await reuse.body?.cancel();
  });
});

describe("password reset", () => {
  it("logs a reset link and consumes it to set a new password", async () => {
    let resetUrl = "";
    using _hook = stub(
      delivery,
      "sendPasswordReset",
      (...args: unknown[]) => {
        resetUrl = (args[0] as DeliveryMessage).url!;
      },
    );
    const email = `reset-${crypto.randomUUID().slice(0, 8)}@example.com`;
    await (await signUp({ name: "Reset Me", email, password: "long-enough-1" }))
      .body?.cancel();

    const request = await app.request("/identity/password/reset-request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    assertEquals(request.status, 200);
    assertEquals((await request.json()).ok, true);
    assertStringIncludes(resetUrl, "/reset-password?token=");

    const token = new URL(resetUrl).searchParams.get("token")!;
    const reset = await app.request("/identity/password/reset", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, password: "brand-new-secret" }),
    });
    assertEquals(reset.status, 200);
    assertEquals((await reset.json()).ok, true);

    const withNew = await signIn({ email, password: "brand-new-secret" });
    assertEquals(withNew.status, 302);
    await withNew.body?.cancel();

    const withOld = await signIn({ email, password: "long-enough-1" });
    assertEquals(withOld.status, 401);
    await withOld.body?.cancel();
  });

  it("stays enumeration-safe for an unknown email", async () => {
    const res = await app.request("/identity/password/reset-request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "nobody@example.com" }),
    });
    assertEquals(res.status, 200);
    assertEquals((await res.json()).ok, true);
  });
});

describe("session + protected API", () => {
  it("reports an unauthenticated session without a cookie", async () => {
    const res = await app.request("/auth/session");
    assertEquals(res.status, 200);
    assertEquals(await res.json(), { isAuthenticated: false, user: null });
  });

  it("rejects /api/me without a session", async () => {
    const res = await app.request("/api/me");
    assertEquals(res.status, 401);
    await res.body?.cancel();
  });

  it("serves /api/me with a session", async () => {
    const { bffSession } = await followToSession(
      await signIn({ email: DEMO_USER.email, password: DEMO_PASSWORD }),
    );
    const res = await app.request("/api/me", {
      headers: { cookie: `oauth2_session=${bffSession}`, "x-csrf": "1" },
    });
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.sub, DEMO_USER.id);
    assertEquals(body.email, DEMO_USER.email);
  });
});

describe("sign-out", () => {
  it("clears both sessions on /auth/logout", async () => {
    const { idpSession, bffSession } = await followToSession(
      await signIn({ email: DEMO_USER.email, password: DEMO_PASSWORD }),
    );
    const cookie = `oauth2_session=${bffSession}; idp_session=${idpSession}`;

    const logout = await app.request("/auth/logout?return_to=/", {
      headers: { cookie, "sec-fetch-site": "same-origin" },
    });
    assertEquals(logout.status, 302);
    assertEquals(logout.headers.get("location"), "/");
    await logout.body?.cancel();

    const probe = await app.request("/auth/session", {
      headers: { cookie, "x-csrf": "1" },
    });
    assertEquals(await probe.json(), { isAuthenticated: false, user: null });

    const login = await app.request("/auth/login?return_to=/dashboard");
    assertEquals(login.status, 302);
    const authorize = await app.request(
      toPath(login.headers.get("location")!),
      { headers: { cookie } },
    );
    assertEquals(authorize.status, 302);
    assertStringIncludes(
      authorize.headers.get("location") ?? "",
      "/login?return_to=",
    );
    await authorize.body?.cancel();
  });

  it("refuses a cross-site logout and keeps the issuer session", async () => {
    const { idpSession, bffSession } = await followToSession(
      await signIn({ email: DEMO_USER.email, password: DEMO_PASSWORD }),
    );
    const cookie = `oauth2_session=${bffSession}; idp_session=${idpSession}`;

    const forced = await app.request("/auth/logout?return_to=/", {
      headers: { cookie, origin: "https://evil.example" },
    });
    assertEquals(forced.status, 403);
    await forced.body?.cancel();

    const login = await app.request("/auth/login?return_to=/dashboard");
    const authorize = await app.request(
      toPath(login.headers.get("location")!),
      { headers: { cookie } },
    );
    assertEquals(authorize.status, 302);
    assertStringIncludes(
      authorize.headers.get("location") ?? "",
      "/auth/callback",
    );
    await authorize.body?.cancel();
  });
});
