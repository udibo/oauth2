/**
 * Hermetic tests of the auth layer. Everything runs in-process via
 * `app.request(...)` — no sockets, no build, no React Router. The helpers walk the same
 * redirect chain the browser follows: identity form post → issuer session →
 * authorize → BFF callback → session cookie, carrying the login-state cookie
 * `/auth/login` sets so the callback recognizes the `state` as this browser's.
 *
 * @module
 */

import { describe, expect, it, vi } from "vitest";

import app from "./auth.ts";
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
  expect(identityRes.status).toBe(302);
  const idpSession = setCookieValue(identityRes, "idp_session")!;
  expect(typeof idpSession).toBe("string");
  const cookie = `idp_session=${idpSession}`;

  let location = identityRes.headers.get("location")!;
  let loginState: string | undefined;
  if (toPath(location).startsWith("/auth/login")) {
    const res = await app.request(toPath(location), { headers: { cookie } });
    expect(res.status).toBe(302);
    location = res.headers.get("location")!;
    loginState = setCookieValue(res, bff.loginStateCookieName);
    expect(typeof loginState).toBe("string");
  }

  const authorizeRes = await app.request(toPath(location), {
    headers: { cookie },
  });
  expect(authorizeRes.status).toBe(302);
  const callbackUrl = authorizeRes.headers.get("location")!;
  expect(callbackUrl).toContain("/auth/callback");
  expect(callbackUrl).toContain("code=");

  const callbackRes = await app.request(toPath(callbackUrl), {
    headers: loginState
      ? { cookie: `${bff.loginStateCookieName}=${loginState}` }
      : {},
  });
  expect(callbackRes.status).toBe(302);
  const bffSession = setCookieValue(callbackRes, "oauth2_session")!;
  expect(typeof bffSession).toBe("string");
  return {
    idpSession,
    bffSession,
    landedOn: callbackRes.headers.get("location")!,
  };
}

async function signIn(options: {
  email: string;
  password: string;
  returnTo?: string;
}): Promise<Response> {
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

async function signUp(options: {
  name: string;
  email: string;
  password: string;
}): Promise<Response> {
  return await app.request("/identity/signup", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(options),
  });
}

describe("sign-in", () => {
  it("signs the demo user in end to end and reports the session", async () => {
    const { bffSession, landedOn } = await followToSession(
      await signIn({
        email: DEMO_USER.email,
        password: DEMO_PASSWORD,
        returnTo: "/dashboard",
      }),
    );
    expect(landedOn).toBe("/dashboard");

    const probe = await app.request("/auth/session", {
      headers: { cookie: `oauth2_session=${bffSession}`, "x-csrf": "1" },
    });
    expect(probe.status).toBe(200);
    const session = await probe.json();
    expect(session.isAuthenticated).toBe(true);
    expect(session.user.sub).toStrictEqual(DEMO_USER.id);
    expect(session.user.email).toStrictEqual(DEMO_USER.email);
  });

  it("matches the email case-insensitively", async () => {
    const res = await signIn({
      email: "Demo@Example.com",
      password: DEMO_PASSWORD,
    });
    expect(res.status).toBe(302);
    await res.body?.cancel();
  });

  it("rejects a wrong password with invalid_credentials", async () => {
    const res = await signIn({
      email: DEMO_USER.email,
      password: "wrong-password",
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toStrictEqual({ error: "invalid_credentials" });
  });

  it("refuses an off-site return_to (open-redirect guard)", async () => {
    const res = await signIn({
      email: DEMO_USER.email,
      password: DEMO_PASSWORD,
      returnTo: "https://evil.example/phish",
    });
    expect(res.status).toBe(302);
    const location = res.headers.get("location")!;
    expect(location).not.toContain("evil.example");
    expect(location).toContain("/auth/login");
    await res.body?.cancel();
  });

  it("resumes an in-flight authorize URL unchanged (mid-authorize login)", async () => {
    const authorizeUrl = "/oauth2/authorize?response_type=code&client_id=web";
    const res = await signIn({
      email: DEMO_USER.email,
      password: DEMO_PASSWORD,
      returnTo: authorizeUrl,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toStrictEqual(authorizeUrl);
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
    expect(res.status).toBe(403);
    await res.body?.cancel();
  });
});

describe("sign-up", () => {
  it("creates an account, sends a console verification link, and signs in", async () => {
    let verifyUrl = "";
    using _hook = vi
      .spyOn(delivery, "sendEmailVerification")
      .mockImplementation((message) => {
        verifyUrl = message.url!;
      });

    const email = `new-${crypto.randomUUID().slice(0, 8)}@example.com`;
    const { bffSession } = await followToSession(
      await signUp({ name: "New User", email, password: "long-enough-1" }),
    );
    expect(verifyUrl).toContain("/verify-email?token=");

    const probe = await app.request("/auth/session", {
      headers: { cookie: `oauth2_session=${bffSession}`, "x-csrf": "1" },
    });
    const session = await probe.json();
    expect(session.isAuthenticated).toBe(true);
    expect(session.user.email).toStrictEqual(email);
    expect(session.user.emailVerified).toBe(false);
  });

  it("rejects a duplicate email with identifier_taken", async () => {
    const res = await signUp({
      name: "Dupe",
      email: DEMO_USER.email,
      password: "long-enough-1",
    });
    expect(res.status).toBe(409);
    expect(await res.json()).toStrictEqual({ error: "identifier_taken" });
  });

  it("rejects a weak password with weak_password", async () => {
    const res = await signUp({
      name: "Weak",
      email: "weak@example.com",
      password: "short",
    });
    expect(res.status).toBe(422);
    expect(await res.json()).toStrictEqual({ error: "weak_password" });
  });
});

describe("email verification", () => {
  it("verifies with a single-use token, then rejects reuse", async () => {
    let verifyUrl = "";
    using _hook = vi
      .spyOn(delivery, "sendEmailVerification")
      .mockImplementation((message) => {
        verifyUrl = message.url!;
      });
    const email = `verify-${crypto.randomUUID().slice(0, 8)}@example.com`;
    const res = await signUp({
      name: "Verify Me",
      email,
      password: "long-enough-1",
    });
    expect(res.status).toBe(302);
    await res.body?.cancel();

    const token = new URL(verifyUrl).searchParams.get("token")!;
    const verify = await app.request("/identity/email/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    expect(verify.status).toBe(200);
    expect((await verify.json()).ok).toBe(true);
    expect((await userService.findByUsername(email))?.emailVerified).toBe(true);

    const reuse = await app.request("/identity/email/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    expect(reuse.status).toBe(400);
    await reuse.body?.cancel();
  });
});

describe("password reset", () => {
  it("logs a reset link and consumes it to set a new password", async () => {
    let resetUrl = "";
    using _hook = vi
      .spyOn(delivery, "sendPasswordReset")
      .mockImplementation((message) => {
        resetUrl = message.url!;
      });
    const email = `reset-${crypto.randomUUID().slice(0, 8)}@example.com`;
    await (
      await signUp({ name: "Reset Me", email, password: "long-enough-1" })
    ).body?.cancel();

    const request = await app.request("/identity/password/reset-request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    expect(request.status).toBe(200);
    expect((await request.json()).ok).toBe(true);
    expect(resetUrl).toContain("/reset-password?token=");

    const token = new URL(resetUrl).searchParams.get("token")!;
    const reset = await app.request("/identity/password/reset", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, password: "brand-new-secret" }),
    });
    expect(reset.status).toBe(200);
    expect((await reset.json()).ok).toBe(true);

    const withNew = await signIn({ email, password: "brand-new-secret" });
    expect(withNew.status).toBe(302);
    await withNew.body?.cancel();

    const withOld = await signIn({ email, password: "long-enough-1" });
    expect(withOld.status).toBe(401);
    await withOld.body?.cancel();
  });

  it("stays enumeration-safe for an unknown email", async () => {
    const res = await app.request("/identity/password/reset-request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "nobody@example.com" }),
    });
    expect(res.status).toBe(200);
    expect((await res.json()).ok).toBe(true);
  });
});

describe("session + protected API", () => {
  it("reports an unauthenticated session without a cookie", async () => {
    const res = await app.request("/auth/session");
    expect(res.status).toBe(200);
    expect(await res.json()).toStrictEqual({
      isAuthenticated: false,
      user: null,
    });
  });

  it("rejects /api/me without a session", async () => {
    const res = await app.request("/api/me");
    expect(res.status).toBe(401);
    await res.body?.cancel();
  });

  it("serves /api/me with a session", async () => {
    const { bffSession } = await followToSession(
      await signIn({ email: DEMO_USER.email, password: DEMO_PASSWORD }),
    );
    const res = await app.request("/api/me", {
      headers: { cookie: `oauth2_session=${bffSession}`, "x-csrf": "1" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.sub).toStrictEqual(DEMO_USER.id);
    expect(body.email).toStrictEqual(DEMO_USER.email);
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
    expect(logout.status).toBe(302);
    expect(logout.headers.get("location")).toBe("/");
    await logout.body?.cancel();

    const probe = await app.request("/auth/session", {
      headers: { cookie, "x-csrf": "1" },
    });
    expect(await probe.json()).toStrictEqual({
      isAuthenticated: false,
      user: null,
    });

    const login = await app.request("/auth/login?return_to=/dashboard");
    expect(login.status).toBe(302);
    const authorize = await app.request(
      toPath(login.headers.get("location")!),
      { headers: { cookie } },
    );
    expect(authorize.status).toBe(302);
    expect(authorize.headers.get("location") ?? "").toContain(
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
    expect(forced.status).toBe(403);
    await forced.body?.cancel();

    const login = await app.request("/auth/login?return_to=/dashboard");
    const authorize = await app.request(
      toPath(login.headers.get("location")!),
      { headers: { cookie } },
    );
    expect(authorize.status).toBe(302);
    expect(authorize.headers.get("location") ?? "").toContain("/auth/callback");
    await authorize.body?.cancel();
  });
});
