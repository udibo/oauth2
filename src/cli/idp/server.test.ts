import {
  assert,
  assertEquals,
  assertExists,
  assertMatch,
  assertRejects,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  exportSigningKeyJwk,
  generateSigningKey,
  importSigningKeyJwk,
  type SigningKey,
  verifyJwt,
} from "../../server/signing-keys.ts";
import {
  generateCodeChallenge,
  generateCodeVerifier,
} from "../../utils/pkce.ts";

import { defaultDevIdpConfig, type DevIdpConfig } from "./config.ts";
import {
  ADMIN_TOKEN_HEADER,
  type DevIdentityProvider,
  isLoopbackHostname,
  startDevIdentityProvider,
} from "./server.ts";

const REDIRECT_URI = "http://localhost:3000/callback";
const USERNAME = "alice@example.com";
const PASSWORD = "password";

function testConfig(overrides: Partial<DevIdpConfig> = {}): DevIdpConfig {
  return {
    ...defaultDevIdpConfig(),
    hostname: "127.0.0.1",
    port: 0,
    ...overrides,
  };
}

async function withIdp(
  options: { config?: Partial<DevIdpConfig>; signingKey?: SigningKey },
  fn: (idp: DevIdentityProvider) => Promise<void>,
): Promise<void> {
  const idp = await startDevIdentityProvider({
    config: testConfig(options.config),
    signingKey: options.signingKey ?? await generateSigningKey(),
  });
  try {
    await fn(idp);
  } finally {
    await idp.shutdown();
    await idp.finished;
  }
}

function adminInit(
  idp: DevIdentityProvider,
  body?: unknown,
): RequestInit {
  const headers: Record<string, string> = {
    [ADMIN_TOKEN_HEADER]: idp.adminToken,
  };
  if (body === undefined) return { headers };
  return {
    method: "POST",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}

class Browser {
  #cookies = new Map<string, string>();

  async fetch(url: string | URL, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    const cookie = [...this.#cookies].map(([name, value]) => `${name}=${value}`)
      .join("; ");
    if (cookie) headers.set("cookie", cookie);
    const response = await fetch(url, {
      ...init,
      headers,
      redirect: "manual",
    });
    for (const entry of response.headers.getSetCookie()) {
      const [pair] = entry.split(";");
      const separator = pair.indexOf("=");
      const name = pair.slice(0, separator).trim();
      const value = pair.slice(separator + 1).trim();
      if (value === "") this.#cookies.delete(name);
      else this.#cookies.set(name, value);
    }
    return response;
  }
}

function authorizeUrl(
  idp: DevIdentityProvider,
  challenge: string,
  overrides: Record<string, string> = {},
): string {
  const url = new URL("/authorize", idp.url);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: "dev-client",
    redirect_uri: REDIRECT_URI,
    scope: "openid profile email",
    state: "test-state",
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...overrides,
  }).toString();
  return url.toString();
}

function pathOf(url: string): string {
  const { pathname, search } = new URL(url);
  return `${pathname}${search}`;
}

async function signIn(
  browser: Browser,
  idp: DevIdentityProvider,
  returnTo: string,
  credentials: Record<string, string> = {
    username: USERNAME,
    password: PASSWORD,
  },
): Promise<Response> {
  return await browser.fetch(`${idp.url}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      return_to: returnTo.startsWith("/") ? returnTo : pathOf(returnTo),
      ...credentials,
    }),
  });
}

async function exchangeCode(
  idp: DevIdentityProvider,
  code: string,
  verifier: string,
): Promise<Record<string, string>> {
  const response = await fetch(`${idp.url}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: "dev-client",
      client_secret: "dev-secret",
      code_verifier: verifier,
    }),
  });
  assertEquals(response.status, 200);
  return await response.json();
}

async function firstJwk(
  idp: DevIdentityProvider,
): Promise<JsonWebKey & { kid?: string }> {
  const response = await fetch(`${idp.url}/jwks`);
  assertEquals(response.status, 200);
  const { keys } = await response.json();
  return keys[0];
}

describe("dev identity provider", () => {
  it("completes the authorization code flow with PKCE over a socket", async () => {
    await withIdp({}, async (idp) => {
      const browser = new Browser();
      const verifier = generateCodeVerifier();
      const begin = authorizeUrl(idp, await generateCodeChallenge(verifier));

      const loginPage = await browser.fetch(begin);
      assertEquals(loginPage.status, 200);
      assertMatch(loginPage.headers.get("content-type")!, /text\/html/);
      const html = await loginPage.text();
      assert(html.includes('id="sign-in-form"'));

      const signedIn = await signIn(browser, idp, begin);
      assertEquals(signedIn.status, 303);
      await signedIn.body?.cancel();

      const authorized = await browser.fetch(
        new URL(signedIn.headers.get("location")!, idp.url),
      );
      assertEquals(authorized.status, 302);
      await authorized.body?.cancel();

      const redirect = new URL(authorized.headers.get("location")!);
      assertEquals(redirect.origin + redirect.pathname, REDIRECT_URI);
      assertEquals(redirect.searchParams.get("state"), "test-state");
      const code = redirect.searchParams.get("code");
      assertExists(code);

      const tokens = await exchangeCode(idp, code, verifier);
      assertExists(tokens.access_token);
      assertExists(tokens.refresh_token);
      assertExists(tokens.id_token);

      const claims = await verifyJwt(tokens.id_token, await firstJwk(idp));
      assertEquals(claims?.sub, "user-alice");
      assertEquals(claims?.iss, idp.url);
      assertEquals(claims?.aud, "dev-client");
      assertEquals(claims?.email, USERNAME);

      const userinfo = await fetch(`${idp.url}/userinfo`, {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      assertEquals(userinfo.status, 200);
      assertEquals((await userinfo.json()).preferred_username, USERNAME);
    });
  });

  it("signs in from the seeded-user button without a password", async () => {
    await withIdp({}, async (idp) => {
      const browser = new Browser();
      const verifier = generateCodeVerifier();
      const begin = authorizeUrl(idp, await generateCodeChallenge(verifier));

      const signedIn = await signIn(browser, idp, begin, { as: USERNAME });
      assertEquals(signedIn.status, 303);
      await signedIn.body?.cancel();

      const authorized = await browser.fetch(
        new URL(signedIn.headers.get("location")!, idp.url),
      );
      assertEquals(authorized.status, 302);
      await authorized.body?.cancel();
      assertExists(
        new URL(authorized.headers.get("location")!).searchParams.get("code"),
      );
    });
  });

  it("re-renders the sign-in page with an error on a bad password", async () => {
    await withIdp({}, async (idp) => {
      const browser = new Browser();
      const response = await signIn(browser, idp, "/", {
        username: USERNAME,
        password: "wrong",
      });

      assertEquals(response.status, 401);
      const html = await response.text();
      assert(html.includes('id="sign-in-error"'));
      assertMatch(html, /Unknown username or password/);
    });
  });

  it("drops the session on logout", async () => {
    await withIdp({}, async (idp) => {
      const browser = new Browser();
      const signedIn = await signIn(browser, idp, "/");
      await signedIn.body?.cancel();

      const loggedOut = await browser.fetch(`${idp.url}/logout`);
      assertEquals(loggedOut.status, 200);
      await loggedOut.text();

      const verifier = generateCodeVerifier();
      const retry = await browser.fetch(
        authorizeUrl(idp, await generateCodeChallenge(verifier)),
      );
      assertEquals(retry.status, 200);
      assert((await retry.text()).includes('id="sign-in-form"'));
    });
  });

  it("serves discovery and JWKS for the origin the request arrived on", async () => {
    await withIdp({}, async (idp) => {
      const response = await fetch(
        `${idp.url}/.well-known/openid-configuration`,
      );
      assertEquals(response.status, 200);
      const metadata = await response.json();

      assertEquals(metadata.issuer, idp.url);
      assertEquals(metadata.authorization_endpoint, `${idp.url}/authorize`);
      assertEquals(metadata.token_endpoint, `${idp.url}/token`);
      assertEquals(metadata.jwks_uri, `${idp.url}/jwks`);
      assertEquals(metadata.userinfo_endpoint, `${idp.url}/userinfo`);
      assertEquals(metadata.id_token_signing_alg_values_supported, ["ES256"]);

      const jwk = await firstJwk(idp);
      assertEquals(jwk.alg, "ES256");
      assertEquals(jwk.use, "sig");
      assertEquals("d" in jwk, false);
    });
  });

  it("ignores a forged Host header when stamping the issuer", async () => {
    await withIdp({}, async (idp) => {
      const connection = await Deno.connect({
        hostname: idp.hostname,
        port: idp.port,
      });
      await connection.write(
        new TextEncoder().encode(
          "GET /.well-known/openid-configuration HTTP/1.1\r\n" +
            "Host: evil.example\r\nConnection: close\r\n\r\n",
        ),
      );
      const raw = await new Response(connection.readable).text();

      assert(raw.includes(`"issuer":"${idp.issuer}"`));
      assertEquals(raw.includes("evil.example"), false);
    });
  });

  it("pins the issuer when the config sets one", async () => {
    await withIdp({ config: { issuer: "https://idp.test" } }, async (idp) => {
      const metadata = await (await fetch(
        `${idp.url}/.well-known/openid-configuration`,
      )).json();

      assertEquals(metadata.issuer, "https://idp.test");
      assertEquals(metadata.token_endpoint, "https://idp.test/token");
    });
  });

  it("keeps the published JWKS stable across restarts with a pinned key", async () => {
    const key = await generateSigningKey();
    const jwk = await exportSigningKeyJwk(key);
    let first: (JsonWebKey & { kid?: string }) | undefined;
    let idToken: string | undefined;

    await withIdp(
      { signingKey: await importSigningKeyJwk(jwk) },
      async (idp) => {
        first = await firstJwk(idp);
        const tokens = await mintTokens(idp, { clientId: "dev-client" });
        idToken = tokens.id_token;
      },
    );

    await withIdp(
      { signingKey: await importSigningKeyJwk(jwk) },
      async (idp) => {
        const second = await firstJwk(idp);
        assertEquals(second.kid, first!.kid);
        assertEquals(second.x, first!.x);
        assertEquals(second.y, first!.y);

        const claims = await verifyJwt(idToken!, second);
        assertEquals(claims?.sub, "user-alice");
      },
    );
  });
});

async function mintTokens(
  idp: DevIdentityProvider,
  body: Record<string, unknown>,
): Promise<Record<string, string>> {
  const response = await fetch(
    `${idp.url}/__admin/tokens`,
    adminInit(idp, { username: USERNAME, ...body }),
  );
  assertEquals(response.status, 200);
  return await response.json();
}

describe("dev identity provider admin surface", () => {
  it("mints tokens that validate without touching the sign-in page", async () => {
    await withIdp({}, async (idp) => {
      const tokens = await mintTokens(idp, { clientId: "dev-client" });

      assertExists(tokens.access_token);
      assertExists(tokens.id_token);
      const claims = await verifyJwt(tokens.id_token, await firstJwk(idp));
      assertEquals(claims?.sub, "user-alice");
      assertEquals(claims?.iss, idp.url);

      const userinfo = await fetch(`${idp.url}/userinfo`, {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      assertEquals(userinfo.status, 200);
      assertEquals((await userinfo.json()).sub, "user-alice");
    });
  });

  it("mints tokens for a public client with no secret", async () => {
    await withIdp({}, async (idp) => {
      const tokens = await mintTokens(idp, { clientId: "dev-public-client" });
      assertExists(tokens.access_token);
    });
  });

  it("reports the seeded users and clients", async () => {
    await withIdp({}, async (idp) => {
      const state = await (await fetch(
        `${idp.url}/__admin/state`,
        adminInit(idp),
      )).json();

      assertEquals(state.users, [{ id: "user-alice", username: USERNAME }]);
      assertEquals(state.clients[0].id, "dev-client");
      assertEquals(state.clients[0].confidential, true);
      assertEquals(state.clients[1].confidential, false);
      assertEquals(state.sessions, 0);
    });
  });

  it("signs a user in so the authorize leg skips the form", async () => {
    await withIdp({}, async (idp) => {
      const browser = new Browser();
      const created = await browser.fetch(
        `${idp.url}/__admin/session`,
        adminInit(idp, { username: USERNAME }),
      );
      assertEquals(created.status, 200);
      assertEquals((await created.json()).user.id, "user-alice");

      const verifier = generateCodeVerifier();
      const authorized = await browser.fetch(
        authorizeUrl(idp, await generateCodeChallenge(verifier)),
      );
      assertEquals(authorized.status, 302);
      await authorized.body?.cancel();
      assertExists(
        new URL(authorized.headers.get("location")!).searchParams.get("code"),
      );
    });
  });

  it("rejects a session request for an unknown user", async () => {
    await withIdp({}, async (idp) => {
      const response = await fetch(
        `${idp.url}/__admin/session`,
        adminInit(idp, { username: "nobody@example.com" }),
      );

      assertEquals(response.status, 400);
      assertMatch((await response.json()).error, /no seeded user/);
    });
  });

  it("resets every session and token", async () => {
    await withIdp({}, async (idp) => {
      const browser = new Browser();
      const tokens = await mintTokens(idp, { clientId: "dev-client" });
      await (await browser.fetch(
        `${idp.url}/__admin/session`,
        adminInit(idp, { username: USERNAME }),
      )).json();

      const before = await fetch(`${idp.url}/userinfo`, {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      assertEquals(before.status, 200);
      await before.json();

      const reset = await fetch(
        `${idp.url}/__admin/reset`,
        adminInit(idp, {}),
      );
      assertEquals(reset.status, 200);
      assertEquals((await reset.json()).reset, true);

      const after = await fetch(`${idp.url}/userinfo`, {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      assertEquals(after.status, 401);
      await after.body?.cancel();

      const state = await (await fetch(
        `${idp.url}/__admin/state`,
        adminInit(idp),
      )).json();
      assertEquals(state.sessions, 0);

      const verifier = generateCodeVerifier();
      const authorize = await browser.fetch(
        authorizeUrl(idp, await generateCodeChallenge(verifier)),
      );
      assertEquals(authorize.status, 200);
      assert((await authorize.text()).includes('id="sign-in-form"'));
    });
  });
});

describe("dev identity provider admin authentication", () => {
  it("refuses every admin route without the token header", async () => {
    await withIdp({}, async (idp) => {
      for (
        const [path, init] of [
          ["/__admin/state", {}],
          ["/__admin/reset", {
            method: "POST",
            headers: { "content-type": "application/json" },
          }],
          ["/__admin/session", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ username: USERNAME }),
          }],
          ["/__admin/tokens", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              username: USERNAME,
              clientId: "dev-client",
            }),
          }],
        ] as const
      ) {
        const response = await fetch(`${idp.url}${path}`, init);
        assertEquals(response.status, 401, `${path} should require the token`);
        assertMatch((await response.json()).error, /x-admin-token/);
      }
    });
  });

  it("refuses a wrong token", async () => {
    await withIdp({}, async (idp) => {
      const response = await fetch(`${idp.url}/__admin/state`, {
        headers: { [ADMIN_TOKEN_HEADER]: crypto.randomUUID() },
      });

      assertEquals(response.status, 401);
      await response.body?.cancel();
    });
  });

  it("leaves state untouched when an unauthenticated reset is attempted", async () => {
    await withIdp({}, async (idp) => {
      const tokens = await mintTokens(idp, { clientId: "dev-client" });

      const reset = await fetch(`${idp.url}/__admin/reset`, {
        method: "POST",
        headers: { "content-type": "application/json" },
      });
      assertEquals(reset.status, 401);
      await reset.body?.cancel();

      const userinfo = await fetch(`${idp.url}/userinfo`, {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      assertEquals(userinfo.status, 200);
      await userinfo.json();
    });
  });

  it("rejects the CORS-simple content types a drive-by page could send", async () => {
    await withIdp({}, async (idp) => {
      for (
        const contentType of [
          "text/plain;charset=UTF-8",
          "application/x-www-form-urlencoded",
          "multipart/form-data",
        ]
      ) {
        const response = await fetch(`${idp.url}/__admin/tokens`, {
          method: "POST",
          headers: {
            [ADMIN_TOKEN_HEADER]: idp.adminToken,
            "content-type": contentType,
          },
          body: JSON.stringify({
            username: USERNAME,
            clientId: "dev-client",
          }),
        });

        assertEquals(response.status, 415, contentType);
        assertMatch((await response.json()).error, /application\/json/);
      }
    });
  });

  it("rejects an admin request carrying a browser Origin", async () => {
    await withIdp({}, async (idp) => {
      const response = await fetch(`${idp.url}/__admin/tokens`, {
        method: "POST",
        headers: {
          [ADMIN_TOKEN_HEADER]: idp.adminToken,
          "content-type": "application/json",
          origin: "http://evil.example",
        },
        body: JSON.stringify({ username: USERNAME, clientId: "dev-client" }),
      });

      assertEquals(response.status, 403);
      assertMatch((await response.json()).error, /cross-origin/);
    });
  });

  it("accepts a caller-supplied admin token so CI can hold it up front", async () => {
    const adminToken = "ci-token-value";
    const idp = await startDevIdentityProvider({
      config: testConfig(),
      signingKey: await generateSigningKey(),
      adminToken,
    });
    try {
      assertEquals(idp.adminToken, adminToken);
      const response = await fetch(`${idp.url}/__admin/state`, {
        headers: { [ADMIN_TOKEN_HEADER]: adminToken },
      });
      assertEquals(response.status, 200);
      await response.json();
    } finally {
      await idp.shutdown();
      await idp.finished;
    }
  });
});

describe("dev identity provider bind address", () => {
  it("refuses a non-loopback bind without the explicit opt-in", async () => {
    const signingKey = await generateSigningKey();
    await assertRejects(
      () =>
        startDevIdentityProvider({
          config: testConfig({ hostname: "0.0.0.0" }),
          signingKey,
        }),
      Error,
      "refusing to bind 0.0.0.0",
    );
  });

  it("binds a non-loopback address when the opt-in is given", async () => {
    const idp = await startDevIdentityProvider({
      config: testConfig({ hostname: "0.0.0.0" }),
      signingKey: await generateSigningKey(),
      allowRemoteAccess: true,
    });
    try {
      assertEquals(isLoopbackHostname(idp.hostname), false);
      assertEquals(idp.issuer, `http://localhost:${idp.port}`);
    } finally {
      await idp.shutdown();
      await idp.finished;
    }
  });

  it("recognizes loopback bind addresses", () => {
    assertEquals(isLoopbackHostname("127.0.0.1"), true);
    assertEquals(isLoopbackHostname("localhost"), true);
    assertEquals(isLoopbackHostname("::1"), true);
    assertEquals(isLoopbackHostname("0.0.0.0"), false);
    assertEquals(isLoopbackHostname("192.168.1.10"), false);
  });
});

describe("dev identity provider logout", () => {
  it("redirects only to a registered redirect URI", async () => {
    await withIdp({}, async (idp) => {
      const browser = new Browser();
      const signedIn = await signIn(browser, idp, "/");
      await signedIn.body?.cancel();

      const response = await browser.fetch(
        `${idp.url}/logout?post_logout_redirect_uri=${
          encodeURIComponent(REDIRECT_URI)
        }`,
      );

      assertEquals(response.status, 303);
      assertEquals(response.headers.get("location"), REDIRECT_URI);
      await response.body?.cancel();
    });
  });

  it("refuses an unregistered post_logout_redirect_uri", async () => {
    await withIdp({}, async (idp) => {
      const response = await fetch(
        `${idp.url}/logout?post_logout_redirect_uri=${
          encodeURIComponent("https://evil.example/steal")
        }`,
        { redirect: "manual" },
      );

      assertEquals(response.status, 400);
      assertEquals(response.headers.get("location"), null);
      assertMatch(await response.text(), /must exactly match a redirect URI/);
    });
  });
});

describe("dev identity provider consent prompt", () => {
  it("issues a code once the user approves", async () => {
    await withIdp({ config: { consent: "prompt" } }, async (idp) => {
      const browser = new Browser();
      const verifier = generateCodeVerifier();
      const begin = authorizeUrl(idp, await generateCodeChallenge(verifier));

      const signedIn = await signIn(browser, idp, begin);
      await signedIn.body?.cancel();
      const consent = await browser.fetch(
        new URL(signedIn.headers.get("location")!, idp.url),
      );
      assertEquals(consent.status, 200);
      const html = await consent.text();
      assert(html.includes('id="consent-form"'));
      assertMatch(html, /openid profile email/);

      const decision = await browser.fetch(`${idp.url}/consent`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          return_to: pathOf(begin),
          decision: "approve",
        }),
      });
      assertEquals(decision.status, 303);
      await decision.body?.cancel();

      const authorized = await browser.fetch(
        new URL(decision.headers.get("location")!, idp.url),
      );
      assertEquals(authorized.status, 302);
      await authorized.body?.cancel();
      const code = new URL(authorized.headers.get("location")!).searchParams
        .get("code");
      assertExists(code);
      assertExists((await exchangeCode(idp, code, verifier)).id_token);
    });
  });

  it("redirects with access_denied when the user denies", async () => {
    await withIdp({ config: { consent: "prompt" } }, async (idp) => {
      const browser = new Browser();
      const verifier = generateCodeVerifier();
      const begin = authorizeUrl(idp, await generateCodeChallenge(verifier));

      const signedIn = await signIn(browser, idp, begin);
      await signedIn.body?.cancel();
      await (await browser.fetch(
        new URL(signedIn.headers.get("location")!, idp.url),
      )).text();

      const decision = await browser.fetch(`${idp.url}/consent`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          return_to: pathOf(begin),
          decision: "deny",
        }),
      });
      await decision.body?.cancel();

      const denied = await browser.fetch(
        new URL(decision.headers.get("location")!, idp.url),
      );
      assertEquals(denied.status, 302);
      await denied.body?.cancel();
      assertEquals(
        new URL(denied.headers.get("location")!).searchParams.get("error"),
        "access_denied",
      );
    });
  });
});
