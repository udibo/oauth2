import { describe, expect, it, vi } from "vitest";

import app from "./main.ts";
import { delivery } from "./oauth2/identity.ts";
import { bff, userService } from "./oauth2/server.ts";

function setCookieValue(res: Response, name: string): string | undefined {
  const setCookie = res.headers.get("set-cookie");
  if (!setCookie) return undefined;
  const match = new RegExp(`${name}=([^;]+)`).exec(setCookie);
  return match?.[1];
}

/**
 * Drives the OAuth2 dance up to the point where the SPA holds a BFF
 * session cookie. Mirrors what the SPA's "Sign in" button kicks off:
 *
 *   1. `POST /auth/login` builds an authorize URL, binds the `state` to
 *      this browser with the login-state cookie, and redirects.
 *   2. `GET /oauth2/authorize` → no IDP session → redirects to `/login`.
 *   3. `POST /login` with credentials opens an IDP session and
 *      redirects back to the authorize URL.
 *   4. `GET /oauth2/authorize` (with IDP session) → renders the consent
 *      page (200).
 *   5. `POST /consent` records the decision server-side (one-time,
 *      bound to user/client/scope), sets the `consent_id` cookie, and
 *      redirects back to the authorize endpoint.
 *   6. `GET /oauth2/authorize` (with the consent cookie) consumes the
 *      decision → redirects to `/auth/callback` with a code.
 *   7. `GET /auth/callback` — carrying the login-state cookie from step 1,
 *      without which it refuses a `state` this browser never started —
 *      exchanges the code, sets the BFF session cookie, redirects to
 *      `return_to`.
 */
async function signInThroughLoginForm(opts: {
  username: string;
  returnTo?: string;
  consent?: "approve" | "deny";
}): Promise<{ session: string; returnTo: string; idpSession: string }> {
  const returnTo = opts.returnTo ?? "/welcome";
  const consent = opts.consent ?? "approve";
  const loginRes = await app.request(
    `/auth/login?return_to=${encodeURIComponent(returnTo)}`,
    { method: "POST" },
  );
  expect(loginRes.status).toBe(302);
  const authorizeUrl = loginRes.headers.get("Location")!;
  const loginState = setCookieValue(loginRes, bff.loginStateCookieName)!;
  expect(typeof loginState).toBe("string");

  const authorizePath =
    new URL(authorizeUrl).pathname + new URL(authorizeUrl).search;
  const loginRedirectRes = await app.request(authorizePath);
  expect(loginRedirectRes.status).toBe(302);
  const loginUrl = loginRedirectRes.headers.get("Location")!;
  expect(loginUrl).toMatch(/^\/login\?return_to=/);

  const loginParam = new URL(loginUrl, "http://localhost").searchParams.get(
    "return_to",
  )!;
  const submitRes = await app.request("/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      username: opts.username,
      password: "password",
      return_to: loginParam,
    }),
  });
  expect(submitRes.status).toBe(302);
  const idpSession = setCookieValue(submitRes, "idp_session")!;
  expect(typeof idpSession).toBe("string");
  const resumedAuthorize = submitRes.headers.get("Location")!;
  const resumedPath =
    new URL(resumedAuthorize, "http://localhost").pathname +
    new URL(resumedAuthorize, "http://localhost").search;

  const consentPageRes = await app.request(resumedPath, {
    headers: { cookie: `idp_session=${idpSession}` },
  });
  expect(consentPageRes.status).toBe(200);
  const consentHtml = await consentPageRes.text();
  const queryMatch = consentHtml.match(
    /name="authorize_query" value="([^"]*)"/,
  );
  if (!queryMatch) {
    throw new Error("consent page is missing the authorize_query hidden input");
  }
  const authorizeQuery = queryMatch[1].replaceAll("&amp;", "&");

  const consentRes = await app.request("/consent", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      cookie: `idp_session=${idpSession}`,
    },
    body: new URLSearchParams({
      decision: consent,
      authorize_query: authorizeQuery,
    }),
  });
  expect(consentRes.status).toBe(302);
  const consentId = setCookieValue(consentRes, "consent_id")!;
  expect(typeof consentId).toBe("string");
  const postConsentAuthorize = consentRes.headers.get("Location")!;
  const postConsentPath =
    new URL(postConsentAuthorize, "http://localhost").pathname +
    new URL(postConsentAuthorize, "http://localhost").search;

  const authorizeRes = await app.request(postConsentPath, {
    headers: { cookie: `idp_session=${idpSession}; consent_id=${consentId}` },
  });
  expect(authorizeRes.status).toBe(302);
  const callbackUrl = authorizeRes.headers.get("Location")!;
  expect(callbackUrl).toContain("/auth/callback");
  expect(callbackUrl).toContain("code=");

  const callbackPath =
    new URL(callbackUrl).pathname + new URL(callbackUrl).search;
  const callbackRes = await app.request(callbackPath, {
    headers: { cookie: `${bff.loginStateCookieName}=${loginState}` },
  });
  expect(callbackRes.status).toBe(302);
  const session = setCookieValue(callbackRes, "oauth2_session")!;
  expect(typeof session).toBe("string");
  return {
    session,
    idpSession,
    returnTo: callbackRes.headers.get("Location")!,
  };
}

/** Resolve a path+search from a possibly-absolute URL. */
function toPath(u: string): string {
  const url = new URL(u, "http://localhost");
  return url.pathname + url.search;
}

/**
 * Completes an authorize flow that already has an IDP session — the post
 * sign-up / "start-fresh" path. Starting from either a `/auth/login` URL or an
 * authorize URL, drives the consent approval through to a BFF session cookie,
 * carrying the login-state cookie `/auth/login` set so `/auth/callback`
 * recognizes the `state` as one this browser started.
 */
async function approveConsentToSession(
  startUrl: string,
  idpSession: string,
): Promise<string> {
  const cookie = `idp_session=${idpSession}`;
  let authorizeUrl = startUrl;
  let loginState: string | undefined;

  if (toPath(authorizeUrl).startsWith("/auth/login")) {
    const res = await app.request(toPath(authorizeUrl), {
      headers: { cookie },
    });
    expect(res.status).toBe(302);
    authorizeUrl = res.headers.get("Location")!;
    loginState = setCookieValue(res, bff.loginStateCookieName);
    expect(typeof loginState).toBe("string");
  }

  const consentPageRes = await app.request(toPath(authorizeUrl), {
    headers: { cookie },
  });
  expect(consentPageRes.status).toBe(200);
  const authorizeQuery = (await consentPageRes.text())
    .match(/name="authorize_query" value="([^"]*)"/)![1]
    .replaceAll("&amp;", "&");

  const consentRes = await app.request("/consent", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", cookie },
    body: new URLSearchParams({
      decision: "approve",
      authorize_query: authorizeQuery,
    }),
  });
  expect(consentRes.status).toBe(302);
  const consentId = setCookieValue(consentRes, "consent_id")!;

  const authorizeRes = await app.request(
    toPath(consentRes.headers.get("Location")!),
    { headers: { cookie: `${cookie}; consent_id=${consentId}` } },
  );
  expect(authorizeRes.status).toBe(302);
  const callbackUrl = authorizeRes.headers.get("Location")!;
  expect(callbackUrl).toContain("/auth/callback");

  const callbackRes = await app.request(toPath(callbackUrl), {
    headers: loginState
      ? { cookie: `${bff.loginStateCookieName}=${loginState}` }
      : {},
  });
  expect(callbackRes.status).toBe(302);
  const session = setCookieValue(callbackRes, "oauth2_session")!;
  expect(typeof session).toBe("string");
  return session;
}

describe("app-with-own-auth example", () => {
  it("GET / returns the SPA index page", async () => {
    const res = await app.request("/");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("App with own auth");
    expect(body).toContain(`action="/auth/login"`);
    expect(body).toContain(">Sign in<");
  });

  it("GET / lists the seeded user credentials", async () => {
    const res = await app.request("/");
    const body = await res.text();
    expect(body).toContain("<code>admin</code>");
    expect(body).toContain("<code>user</code>");
    expect(body).toContain("<code>password</code>");
  });

  it("GET / links to create-account", async () => {
    const body = await (await app.request("/")).text();
    expect(body).toContain(`href="/create-account"`);
  });

  it("login form links to create-account (with return_to) and forgot-password", async () => {
    const res = await app.request(
      `/login?return_to=${encodeURIComponent(
        "/oauth2/authorize?client_id=spa",
      )}`,
    );
    const html = await res.text();
    expect(html).toContain("/create-account?return_to=");
    expect(html).toContain(`href="/forgot-password"`);
  });

  it("GET /create-account renders the sign-up form", async () => {
    const res = await app.request("/create-account");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Create your account");
    expect(html).toContain('name="username"');
    expect(html).toContain('name="password"');
  });

  it("create-account (from scratch) starts a fresh login and lands authenticated", async () => {
    const createRes = await app.request("/create-account", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "newbie",
        name: "New Bie",
        password: "hunter2hunter2",
      }),
    });
    expect(createRes.status).toBe(302);
    const idpSession = setCookieValue(createRes, "idp_session")!;
    expect(typeof idpSession).toBe("string");
    const location = createRes.headers.get("Location")!;
    expect(location).toMatch(/^\/auth\/login\?return_to=/);

    const session = await approveConsentToSession(location, idpSession);
    const probe = await app.request("/auth/session", {
      headers: { cookie: `oauth2_session=${session}` },
    });
    const body = await probe.json();
    expect(body.isAuthenticated).toBe(true);
    expect(body.user?.username).toBe("newbie");
  });

  it("create-account (mid-authorize) resumes the in-flight authorize URL", async () => {
    const authorizeUrl =
      "/oauth2/authorize?response_type=code&client_id=spa&state=abc";
    const res = await app.request("/create-account", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "midflow",
        password: "hunter2hunter2",
        return_to: authorizeUrl,
      }),
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe(authorizeUrl);
    await res.body?.cancel();
  });

  it("create-account rejects a duplicate username", async () => {
    const res = await app.request("/create-account", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username: "admin", password: "whatever12" }),
    });
    expect(res.status).toBe(409);
    expect(await res.text()).toContain("taken");
  });

  it("create-account rejects a too-short password", async () => {
    const res = await app.request("/create-account", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "weak-pw-user",
        password: "short",
      }),
    });
    expect(res.status).toBe(422);
    expect(await res.text()).toContain("at least 8 characters");
  });

  it("create-account refuses an off-site return_to (open-redirect guard)", async () => {
    const res = await app.request("/create-account", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "offsite",
        password: "hunter2hunter2",
        return_to: "https://evil.example/phish",
      }),
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/auth/login?return_to=%2F");
    await res.body?.cancel();
  });

  it("GET /forgot-password renders the request form", async () => {
    const res = await app.request("/forgot-password");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Reset your password");
    expect(html).toContain('name="email"');
  });

  it("POST /forgot-password is enumeration-safe (identical response for any email)", async () => {
    const known = await app.request("/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ email: "admin@example.test" }),
    });
    const unknown = await app.request("/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ email: "nobody@example.test" }),
    });
    expect(known.status).toBe(200);
    expect(unknown.status).toBe(200);
    const knownBody = await known.text();
    const unknownBody = await unknown.text();
    expect(knownBody).toStrictEqual(unknownBody);
    expect(knownBody).toContain("If an account exists");
  });

  it("GET /auth/session returns isAuthenticated=false without a cookie", async () => {
    const res = await app.request("/auth/session");
    expect(res.status).toBe(200);
    expect(await res.json()).toStrictEqual({
      isAuthenticated: false,
      user: null,
    });
  });

  it("GET /api/me returns 401 without a session cookie", async () => {
    const res = await app.request("/api/me");
    expect(res.status).toBe(401);
  });

  it("GET /api/admin returns 401 without a session cookie", async () => {
    const res = await app.request("/api/admin");
    expect(res.status).toBe(401);
  });

  it("GET /oauth2/authorize redirects to /login when no IDP session exists", async () => {
    const url = new URL("http://localhost/oauth2/authorize");
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", "spa");
    url.searchParams.set("state", "xyz");
    url.searchParams.set("redirect_uri", "http://localhost:8001/auth/callback");
    const res = await app.request(url.pathname + url.search);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toMatch(/^\/login\?return_to=/);
  });

  it("POST /login with bad credentials returns 401 and re-renders the form", async () => {
    const res = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "user",
        password: "wrong",
      }),
    });
    expect(res.status).toBe(401);
    const html = await res.text();
    expect(html).toContain("Invalid username or password");
  });

  it("POST /login refuses an off-site return_to (open-redirect guard)", async () => {
    for (const evil of ["https://evil.example/phish", "//evil.example"]) {
      const res = await app.request("/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          username: "admin",
          password: "password",
          return_to: evil,
        }),
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/");
      await res.body?.cancel();
    }

    const ok = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "admin",
        password: "password",
        return_to: "/oauth2/authorize?response_type=code",
      }),
    });
    expect(ok.status).toBe(302);
    expect(ok.headers.get("Location")).toBe(
      "/oauth2/authorize?response_type=code",
    );
    await ok.body?.cancel();
  });

  it("end-to-end: login form → api → logout clears both sessions", async () => {
    const { session, idpSession } = await signInThroughLoginForm({
      username: "user",
    });

    const probeRes = await app.request("/auth/session", {
      headers: { cookie: `oauth2_session=${session}` },
    });
    const probeBody = await probeRes.json();
    expect(probeBody.isAuthenticated).toBe(true);
    expect(probeBody.user?.sub).toBe("user-1");
    expect(probeBody.user?.username).toBe("user");

    const apiRes = await app.request("/api/me", {
      headers: { cookie: `oauth2_session=${session}` },
    });
    expect(apiRes.status).toBe(200);
    const apiBody = await apiRes.json();
    expect(apiBody.sub).toBe("user-1");
    expect(apiBody.client).toBe("spa");

    const adminRes = await app.request("/api/admin", {
      headers: { cookie: `oauth2_session=${session}` },
    });
    expect(adminRes.status).toBe(403);
    expect(adminRes.headers.get("WWW-Authenticate")).toContain(
      "insufficient_scope",
    );

    const writeRes = await app.request("/api/write", {
      headers: { cookie: `oauth2_session=${session}` },
    });
    expect(writeRes.status).toBe(200);

    const logoutRes = await app.request("/auth/logout", {
      method: "POST",
      headers: { cookie: `oauth2_session=${session}` },
    });
    expect(logoutRes.status).toBe(302);

    const postLogoutProbe = await app.request("/auth/session", {
      headers: { cookie: `oauth2_session=${session}` },
    });
    const postLogoutBody = await postLogoutProbe.json();
    expect(postLogoutBody.isAuthenticated).toBe(false);

    const idpLogoutRes = await app.request("/logout", {
      method: "POST",
      headers: { cookie: `idp_session=${idpSession}` },
    });
    expect(idpLogoutRes.status).toBe(204);
  });

  it("POST /logout honors return_to (consent 'switch user'), else 204", async () => {
    const submitRes = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "user",
        password: "password",
        return_to: "/",
      }),
    });
    const idpSession = setCookieValue(submitRes, "idp_session")!;

    const switchRes = await app.request("/logout", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie: `idp_session=${idpSession}`,
      },
      body: new URLSearchParams({
        return_to: "/oauth2/authorize?client_id=spa",
      }),
    });
    expect(switchRes.status).toBe(302);
    expect(switchRes.headers.get("Location")).toBe(
      "/oauth2/authorize?client_id=spa",
    );

    const plainRes = await app.request("/logout", { method: "POST" });
    expect(plainRes.status).toBe(204);

    const evilRes = await app.request("/logout", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ return_to: "https://evil.example/" }),
    });
    expect(evilRes.status).toBe(204);
  });

  it("end-to-end: admin user gets the admin scope and /api/admin succeeds", async () => {
    const { session } = await signInThroughLoginForm({ username: "admin" });
    const adminRes = await app.request("/api/admin", {
      headers: { cookie: `oauth2_session=${session}` },
    });
    expect(adminRes.status).toBe(200);
    const body = await adminRes.json();
    expect(body.sub).toBe("user-admin");
    expect(body.scope).toContain("admin");
  });

  it("consent page narrows the displayed scope to what the user can grant", async () => {
    const loginRes = await app.request("/auth/login?return_to=/welcome", {
      method: "POST",
    });
    const authorizeUrl = loginRes.headers.get("Location")!;
    const authorizePath =
      new URL(authorizeUrl).pathname + new URL(authorizeUrl).search;
    const loginRedirectRes = await app.request(authorizePath);
    const loginUrl = loginRedirectRes.headers.get("Location")!;
    const loginParam = new URL(loginUrl, "http://localhost").searchParams.get(
      "return_to",
    )!;
    const submitRes = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "user",
        password: "password",
        return_to: loginParam,
      }),
    });
    const idpSession = setCookieValue(submitRes, "idp_session")!;
    const resumed = submitRes.headers.get("Location")!;
    const resumedPath =
      new URL(resumed, "http://localhost").pathname +
      new URL(resumed, "http://localhost").search;
    const consentPage = await app.request(resumedPath, {
      headers: { cookie: `idp_session=${idpSession}` },
    });
    const html = await consentPage.text();
    expect(html).toContain("<code>read</code>");
    expect(html).toContain("<code>write</code>");
    expect(html).not.toContain("<code>admin</code>");
  });

  it("denying consent redirects the client with error=access_denied", async () => {
    const loginRes = await app.request("/auth/login?return_to=/welcome", {
      method: "POST",
    });
    const authorizePath =
      new URL(loginRes.headers.get("Location")!).pathname +
      new URL(loginRes.headers.get("Location")!).search;
    const loginRedirectRes = await app.request(authorizePath);
    const loginParam = new URL(
      loginRedirectRes.headers.get("Location")!,
      "http://localhost",
    ).searchParams.get("return_to")!;
    const submitRes = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "user",
        password: "password",
        return_to: loginParam,
      }),
    });
    const idpSession = setCookieValue(submitRes, "idp_session")!;
    const resumedPath =
      new URL(submitRes.headers.get("Location")!, "http://localhost").pathname +
      new URL(submitRes.headers.get("Location")!, "http://localhost").search;
    const consentPage = await app.request(resumedPath, {
      headers: { cookie: `idp_session=${idpSession}` },
    });
    const html = await consentPage.text();
    const queryMatch = html.match(/name="authorize_query" value="([^"]*)"/)!;
    const authorizeQuery = queryMatch[1].replaceAll("&amp;", "&");

    const denyRes = await app.request("/consent", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie: `idp_session=${idpSession}`,
      },
      body: new URLSearchParams({
        decision: "deny",
        authorize_query: authorizeQuery,
      }),
    });
    expect(denyRes.status).toBe(302);
    const back = denyRes.headers.get("Location")!;
    expect(back).not.toContain("consent=");
    const denyConsentId = setCookieValue(denyRes, "consent_id")!;

    const backPath =
      new URL(back, "http://localhost").pathname +
      new URL(back, "http://localhost").search;
    const followRes = await app.request(backPath, {
      headers: {
        cookie: `idp_session=${idpSession}; consent_id=${denyConsentId}`,
      },
    });
    expect(followRes.status).toBe(302);
    const errorLocation = followRes.headers.get("Location")!;
    expect(errorLocation).toContain("error=access_denied");
  });

  it("a forged ?consent=approve on the authorize URL cannot skip the prompt", async () => {
    const submitRes = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "user",
        password: "password",
        return_to: "/",
      }),
    });
    const idpSession = setCookieValue(submitRes, "idp_session")!;

    const loginRes = await app.request("/auth/login?return_to=/welcome", {
      method: "POST",
    });
    const forged = new URL(loginRes.headers.get("Location")!);
    forged.searchParams.set("consent", "approve");
    const res = await app.request(forged.pathname + forged.search, {
      headers: { cookie: `idp_session=${idpSession}` },
    });

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('action="/consent"');
  });

  it("POST /consent without an IDP session is rejected (cross-site POST can't mint a decision)", async () => {
    const res = await app.request("/consent", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        decision: "approve",
        authorize_query: "?client_id=spa",
      }),
    });
    expect(res.status).toBe(403);
    await res.body?.cancel();
  });

  it("GET /device redirects to /login when no IDP session is set", async () => {
    const res = await app.request("/device?user_code=ABCD-EFGH");
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toMatch(/^\/login\?return_to=/);
    expect(loc).toContain(encodeURIComponent("/device?user_code="));
  });

  it("GET /device renders the code-entry form when signed in", async () => {
    const submitRes = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "admin",
        password: "password",
        return_to: "/",
      }),
    });
    const idpSession = setCookieValue(submitRes, "idp_session")!;
    const res = await app.request("/device", {
      headers: { cookie: `idp_session=${idpSession}` },
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Authorize a device");
    expect(html).toContain('name="user_code"');
  });

  it("device flow: request → enter code → approve issues a token", async () => {
    const deviceRes = await app.request("/oauth2/device_authorization", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "spa",
        client_secret: "spa-secret",
        scope: "read write",
      }),
    });
    expect(deviceRes.status).toBe(200);
    const codes = (await deviceRes.json()) as {
      device_code: string;
      user_code: string;
      verification_uri: string;
    };
    expect(typeof codes.device_code).toBe("string");
    expect(typeof codes.user_code).toBe("string");

    const submitRes = await app.request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        username: "admin",
        password: "password",
        return_to: "/",
      }),
    });
    const idpSession = setCookieValue(submitRes, "idp_session")!;

    const approvalPageRes = await app.request("/device", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie: `idp_session=${idpSession}`,
      },
      body: new URLSearchParams({ user_code: codes.user_code }),
    });
    expect(approvalPageRes.status).toBe(200);
    const approvalHtml = await approvalPageRes.text();
    expect(approvalHtml).toContain("Authorize <em>spa</em>");

    const approveRes = await app.request("/device", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie: `idp_session=${idpSession}`,
      },
      body: new URLSearchParams({
        user_code: codes.user_code,
        decision: "approve",
      }),
    });
    expect(approveRes.status).toBe(200);
    expect(await approveRes.text()).toContain("Device approved");

    const tokenRes = await app.request("/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: codes.device_code,
        client_id: "spa",
        client_secret: "spa-secret",
      }),
    });
    expect(tokenRes.status).toBe(200);
    const tokens = await tokenRes.json();
    expect(typeof tokens.access_token).toBe("string");
  });
});

describe("password reset flow", () => {
  async function createAccount(options: {
    username: string;
    email?: string;
    password?: string;
  }): Promise<void> {
    const res = await app.request("/create-account", {
      method: "POST",
      body: new URLSearchParams({
        username: options.username,
        name: options.username,
        email: options.email ?? "",
        password: options.password ?? "original-password-1",
        return_to: "/",
      }),
    });
    expect(res.status).toBe(302);
  }

  it("resets a password end to end with a single-use emailed link", async () => {
    const username = `reset-${crypto.randomUUID().slice(0, 8)}`;
    const email = `${username}@example.com`;
    await createAccount({ username, email });

    let resetUrl = "";
    using _hook = vi
      .spyOn(delivery, "sendPasswordReset")
      .mockImplementation((message) => {
        resetUrl = message.url!;
      });

    const requestRes = await app.request("/forgot-password", {
      method: "POST",
      body: new URLSearchParams({ email }),
    });
    expect(requestRes.status).toBe(200);
    expect(resetUrl).toContain("/reset-password?token=");

    const token = new URL(resetUrl).searchParams.get("token")!;
    const formRes = await app.request(`/reset-password?token=${token}`);
    expect(formRes.status).toBe(200);

    const resetRes = await app.request("/reset-password", {
      method: "POST",
      body: new URLSearchParams({ token, password: "new-password-12" }),
    });
    expect(resetRes.status).toBe(200);
    expect(await resetRes.text()).toContain("Password reset");

    const oldLogin = await app.request("/login", {
      method: "POST",
      body: new URLSearchParams({
        username,
        password: "original-password-1",
        return_to: "/",
      }),
    });
    expect(oldLogin.status).toBe(401);

    const newLogin = await app.request("/login", {
      method: "POST",
      body: new URLSearchParams({
        username,
        password: "new-password-12",
        return_to: "/",
      }),
    });
    expect(newLogin.status).toBe(302);

    const reuseRes = await app.request("/reset-password", {
      method: "POST",
      body: new URLSearchParams({ token, password: "again-password-1" }),
    });
    expect(reuseRes.status).toBe(400);
  });

  it("rejects a too-short new password without burning the token", async () => {
    const username = `weak-${crypto.randomUUID().slice(0, 8)}`;
    const email = `${username}@example.com`;
    await createAccount({ username, email });

    let resetUrl = "";
    using _hook = vi
      .spyOn(delivery, "sendPasswordReset")
      .mockImplementation((message) => {
        resetUrl = message.url!;
      });
    await app.request("/forgot-password", {
      method: "POST",
      body: new URLSearchParams({ email }),
    });
    const token = new URL(resetUrl).searchParams.get("token")!;

    const weakRes = await app.request("/reset-password", {
      method: "POST",
      body: new URLSearchParams({ token, password: "short" }),
    });
    expect(weakRes.status).toBe(422);
    expect(await weakRes.text()).toContain("at least 8 characters");

    const retryRes = await app.request("/reset-password", {
      method: "POST",
      body: new URLSearchParams({ token, password: "long-enough-12" }),
    });
    expect(retryRes.status).toBe(200);
  });

  it("matches reset emails case-insensitively", async () => {
    let sent = false;
    using _hook = vi
      .spyOn(delivery, "sendPasswordReset")
      .mockImplementation(() => {
        sent = true;
      });
    const res = await app.request("/forgot-password", {
      method: "POST",
      body: new URLSearchParams({ email: "ADMIN@Example.com" }),
    });
    expect(res.status).toBe(200);
    expect(sent).toBe(true);
  });

  it("responds identically for unknown and known emails", async () => {
    using _hook = vi
      .spyOn(delivery, "sendPasswordReset")
      .mockImplementation(() => {});
    const known = await app.request("/forgot-password", {
      method: "POST",
      body: new URLSearchParams({ email: "admin@example.com" }),
    });
    const unknown = await app.request("/forgot-password", {
      method: "POST",
      body: new URLSearchParams({ email: "nobody@example.com" }),
    });
    expect(known.status).toBe(unknown.status);
    expect(await known.text()).toStrictEqual(await unknown.text());
  });

  it("rejects an invalid reset link", async () => {
    const res = await app.request("/reset-password?token=garbage");
    expect(res.status).toBe(400);
  });
});

describe("email verification flow", () => {
  it("verifies a new account's email with a single-use link", async () => {
    const username = `verify-${crypto.randomUUID().slice(0, 8)}`;
    const email = `${username}@example.com`;

    let verifyUrl = "";
    using _hook = vi
      .spyOn(delivery, "sendEmailVerification")
      .mockImplementation((message) => {
        verifyUrl = message.url!;
      });

    const createRes = await app.request("/create-account", {
      method: "POST",
      body: new URLSearchParams({
        username,
        name: username,
        email,
        password: "signup-password-1",
        return_to: "/",
      }),
    });
    expect(createRes.status).toBe(302);
    expect(verifyUrl).toContain("/verify-email?token=");

    const user = await userService.findByUsername(username);
    expect(user?.emailVerified).toBe(false);

    const token = new URL(verifyUrl).searchParams.get("token")!;
    const verifyRes = await app.request(`/verify-email?token=${token}`);
    expect(verifyRes.status).toBe(200);
    expect(await verifyRes.text()).toContain("Email verified");
    expect((await userService.findByUsername(username))?.emailVerified).toBe(
      true,
    );

    const reuse = await app.request(`/verify-email?token=${token}`);
    expect(reuse.status).toBe(400);
  });

  it("rejects a missing or garbage token", async () => {
    const missing = await app.request("/verify-email");
    expect(missing.status).toBe(400);
    const garbage = await app.request("/verify-email?token=garbage");
    expect(garbage.status).toBe(400);
  });
});
