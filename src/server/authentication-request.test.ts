import { Hono } from "hono";
import { assert, describe, expect, it, vi } from "vitest";
import { HonoAuthorizationServer } from "../adapters/hono/authorization-server.ts";
import type {
  AuthenticationContext,
  AuthenticationRequest,
} from "../models/authentication.ts";
import { BasicScope } from "../models/scope.ts";
import {
  basicAuthHeader,
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
  tokenRequest,
} from "../testing/_test_fixtures.ts";
import { satisfiesAuthenticationRequest } from "./authentication-request.ts";
import {
  type AuthenticateUserFn,
  AuthorizationServer,
  type AuthorizationServerOptions,
  type HandleConsentFn,
} from "./authorization-server.ts";
import { AuthorizationCodeGrant } from "./grants/authorization-code.ts";
import {
  generateSigningKey,
  StaticSigningKeyProvider,
  verifyJwt,
} from "./signing-keys.ts";

const ISSUER = "https://auth.example";
const CALLBACK = "https://app.example/callback";
const user: TestUser = { id: "user-1", username: "person" };
const client: TestClient = {
  id: "app",
  confidential: true,
  grants: ["authorization_code"],
  redirectUris: [CALLBACK],
};

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

async function createServer(
  options: Partial<
    AuthorizationServerOptions<TestClient, TestUser, BasicScope>
  > = {},
) {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  const authorizationCodeService = new MemoryAuthorizationCodeService({
    clientService,
    userService,
  });
  await userService.add(user, "password");
  await clientService.add(client, "secret", user.id);
  const services = {
    userService,
    clientService,
    tokenService,
    authorizationCodeService,
  };
  const key = await generateSigningKey();
  const serverOptions: AuthorizationServerOptions<
    TestClient,
    TestUser,
    BasicScope
  > = {
    resolve: () => ({ services, issuer: ISSUER }),
    grants: {
      authorization_code: new AuthorizationCodeGrant<TestClient, TestUser>({
        resolve: () => services,
        requirePKCE: false,
      }),
    },
    signingKeys: new StaticSigningKeyProvider(key),
    ...options,
  };
  return {
    server: new AuthorizationServer(serverOptions),
    hono: new HonoAuthorizationServer(serverOptions),
    key,
  };
}

function authorizeRequest(extra: Record<string, string> = {}): Request {
  const url = new URL(`${ISSUER}/authorize`);
  url.search = new URLSearchParams({
    client_id: client.id,
    response_type: "code",
    redirect_uri: CALLBACK,
    scope: "openid",
    state: "xyz",
    ...extra,
  }).toString();
  return new Request(url);
}

function signedIn(
  authenticationContext?: AuthenticationContext,
  extra: { reauthenticated?: boolean } = {},
): AuthenticateUserFn<TestUser> & ReturnType<typeof vi.fn> {
  return vi.fn(() =>
    Promise.resolve({
      user,
      authorizedScope: new BasicScope("openid"),
      authenticationContext,
      ...extra,
    }),
  );
}

function loginPage(): Response {
  return new Response("<form>sign in</form>", {
    headers: { "content-type": "text/html" },
  });
}

function redirectParams(response: Response): URLSearchParams {
  expect(response.status).toBe(302);
  const location = response.headers.get("location");
  assert.exists(location);
  const target = new URL(location);
  expect(`${target.origin}${target.pathname}`).toBe(CALLBACK);
  return target.searchParams;
}

function expectError(response: Response, error: string): URLSearchParams {
  const params = redirectParams(response);
  expect(params.get("error")).toBe(error);
  expect(params.get("state")).toBe("xyz");
  expect(params.getAll("iss")).toStrictEqual([ISSUER]);
  expect(params.has("code")).toBe(false);
  return params;
}

async function idTokenClaims(
  server: AuthorizationServer<TestClient, TestUser, BasicScope>,
  key: Awaited<ReturnType<typeof generateSigningKey>>,
  response: Response,
): Promise<Record<string, unknown>> {
  const code = redirectParams(response).get("code");
  assert.exists(code);
  const exchange = await server.handleTokenRequest(
    tokenRequest(
      { grant_type: "authorization_code", code, redirect_uri: CALLBACK },
      basicAuthHeader(client.id, "secret"),
    ),
  );
  expect(exchange.status).toBe(200);
  const { id_token } = await exchange.json();
  const claims = await verifyJwt(id_token, key.publicJwk);
  assert.exists(claims);
  return claims;
}

describe("prompt=none", () => {
  it("answers login_required instead of the login page authenticateUser returns", async () => {
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "none" }),
      () => Promise.resolve(loginPage()),
    );
    expect(response.headers.get("content-type")).toBe(null);
    expectError(response, "login_required");
  });

  it("answers consent_required instead of the consent page handleConsent returns", async () => {
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "none", scope: "openid profile" }),
      signedIn(),
      () => Promise.resolve(loginPage()),
    );
    expectError(response, "consent_required");
  });

  it("answers login_required when the session is older than max_age", async () => {
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "none", max_age: "60" }),
      signedIn({ auth_time: nowSeconds() - 3600 }),
    );
    expectError(response, "login_required");
  });

  it("issues a code silently for a signed-in user who already consented", async () => {
    const { server } = await createServer();
    const authenticateUser = signedIn();
    const handleConsent = vi.fn<HandleConsentFn<TestClient, BasicScope>>();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "none" }),
      authenticateUser,
      handleConsent,
    );
    expect(redirectParams(response).has("code")).toBe(true);
    expect(handleConsent).not.toHaveBeenCalled();
    expect(authenticateUser.mock.calls[0]?.[1]).toStrictEqual({
      prompt: ["none"],
      acrValues: [],
    });
  });

  for (const other of ["login", "consent"]) {
    it(`refuses none combined with ${other} before authenticating anyone`, async () => {
      const { server } = await createServer();
      const authenticateUser = signedIn();
      const response = await server.handleAuthorizeRequest(
        authorizeRequest({ prompt: `none ${other}` }),
        authenticateUser,
      );
      expectError(response, "invalid_request");
      expect(authenticateUser).not.toHaveBeenCalled();
    });
  }

  it("lets the application answer interaction_required from authenticateUser", async () => {
    const { InteractionRequiredError } = await import("../errors.ts");
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "none" }),
      () => Promise.reject(new InteractionRequiredError("accept the terms")),
    );
    expect(
      expectError(response, "interaction_required").get("error_description"),
    ).toBe("accept the terms");
  });
});

describe("RFC 9207 iss on authentication-control errors", () => {
  const cases: {
    name: string;
    extra: Record<string, string>;
    error: string;
    authenticateUser: AuthenticateUserFn<TestUser>;
    handleConsent?: HandleConsentFn<TestClient, BasicScope>;
  }[] = [
    {
      name: "prompt=none with a login page",
      extra: { prompt: "none" },
      error: "login_required",
      authenticateUser: () => Promise.resolve(loginPage()),
    },
    {
      name: "prompt=none with a consent page",
      extra: { prompt: "none", scope: "openid profile" },
      error: "consent_required",
      authenticateUser: signedIn(),
      handleConsent: () => Promise.resolve(loginPage()),
    },
    {
      name: "prompt=login without a re-authentication",
      extra: { prompt: "login" },
      error: "login_required",
      authenticateUser: signedIn({ auth_time: nowSeconds() }),
    },
    {
      name: "a session older than max_age",
      extra: { max_age: "60" },
      error: "login_required",
      authenticateUser: signedIn({ auth_time: nowSeconds() - 3600 }),
    },
    {
      name: "prompt=consent without a handler",
      extra: { prompt: "consent" },
      error: "consent_required",
      authenticateUser: signedIn(),
    },
    {
      name: "prompt=none combined with login",
      extra: { prompt: "none login" },
      error: "invalid_request",
      authenticateUser: signedIn(),
    },
    {
      name: "a malformed max_age",
      extra: { max_age: "soon" },
      error: "invalid_request",
      authenticateUser: signedIn(),
    },
  ];
  for (const testCase of cases) {
    it(`names the issuer on the ${testCase.error} redirect for ${testCase.name}`, async () => {
      const { server } = await createServer();
      const response = await server.handleAuthorizeRequest(
        authorizeRequest(testCase.extra),
        testCase.authenticateUser,
        testCase.handleConsent,
      );
      const params = expectError(response, testCase.error);
      expect(params.getAll("iss")).toStrictEqual([ISSUER]);
    });
  }

  it("names the issuer on the silent code a prompt=none request receives", async () => {
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "none" }),
      signedIn(),
    );
    const params = redirectParams(response);
    expect(params.has("code")).toBe(true);
    expect(params.getAll("iss")).toStrictEqual([ISSUER]);
  });
});

describe("prompt=login", () => {
  it("answers login_required rather than a code for a session that did not re-authenticate", async () => {
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "login" }),
      signedIn({ auth_time: nowSeconds() }),
    );
    expectError(response, "login_required");
  });

  it("issues a code once authenticateUser reports the user re-authenticated", async () => {
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "login" }),
      signedIn({ auth_time: nowSeconds() }, { reauthenticated: true }),
    );
    expect(redirectParams(response).has("code")).toBe(true);
  });

  it("returns the login page authenticateUser sends for a re-authentication", async () => {
    const { server } = await createServer();
    const page = loginPage();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "login" }),
      (_request, authentication) =>
        Promise.resolve(
          authentication?.prompt.includes("login")
            ? page
            : { user, authenticationContext: { auth_time: nowSeconds() } },
        ),
    );
    expect(response).toBe(page);
  });
});

describe("max_age", () => {
  it("sends a stale session through the application's login rather than issuing a silent code", async () => {
    const { server } = await createServer();
    const session = { user, authenticationContext: { auth_time: 1000 } };
    const page = loginPage();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ max_age: "300" }),
      (_request, authentication) =>
        Promise.resolve(
          authentication &&
            !satisfiesAuthenticationRequest(authentication, session)
            ? page
            : session,
        ),
    );
    expect(response).toBe(page);
  });

  it("refuses a stale session an application returns anyway with login_required", async () => {
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ max_age: "300" }),
      signedIn({ auth_time: nowSeconds() - 301 }),
    );
    expect(
      expectError(response, "login_required").get("error_description"),
    ).toBe("the user's last authentication is older than max_age");
  });

  it("refuses an hour-old session whose auth_time was recorded in milliseconds", async () => {
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ max_age: "300" }),
      signedIn({ auth_time: Date.now() - 3_600_000 }),
    );
    expect(
      expectError(response, "login_required").get("error_description"),
    ).toBe("the user's authentication time is in the future");
  });

  it("accepts an auth_time up to a minute ahead of the server's clock", () => {
    const now = 1_700_000_000_000;
    const at = (auth_time: number) => ({
      authenticationContext: { auth_time },
    });
    const request = { prompt: [], maxAge: 300, acrValues: [] };
    expect(
      satisfiesAuthenticationRequest(request, at(now / 1000 + 60), now),
    ).toBe(true);
    expect(
      satisfiesAuthenticationRequest(request, at(now / 1000 + 61), now),
    ).toBe(false);
  });

  it("issues a code for an authentication within max_age and puts its auth_time in the ID token", async () => {
    const { server, key } = await createServer();
    const authTime = nowSeconds() - 120;
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ max_age: "300" }),
      signedIn({ auth_time: authTime }),
    );
    const claims = await idTokenClaims(server, key, response);
    expect(claims.auth_time).toBe(authTime);
  });

  it("refuses when the authentication time is unknown, even after a re-authentication", async () => {
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ max_age: "300" }),
      signedIn({ acr: "urn:example:pwd" }, { reauthenticated: true }),
    );
    expect(
      expectError(response, "login_required").get("error_description"),
    ).toBe("max_age requires the time the user authenticated");
  });

  it("treats max_age=0 like prompt=login, even for an authentication this second", async () => {
    const { server } = await createServer();
    const authTime = nowSeconds() + 1;
    const stale = await server.handleAuthorizeRequest(
      authorizeRequest({ max_age: "0" }),
      signedIn({ auth_time: authTime }),
    );
    expectError(stale, "login_required");
    const fresh = await server.handleAuthorizeRequest(
      authorizeRequest({ max_age: "0" }),
      signedIn({ auth_time: authTime }, { reauthenticated: true }),
    );
    expect(redirectParams(fresh).has("code")).toBe(true);
  });

  it("refuses a re-authentication whose recorded auth_time is older than max_age", async () => {
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ max_age: "60" }),
      signedIn({ auth_time: nowSeconds() - 3600 }, { reauthenticated: true }),
    );
    expect(
      expectError(response, "login_required").get("error_description"),
    ).toBe("the user's last authentication is older than max_age");
  });

  for (const value of ["-1", "1.5", "abc", "1e3", " 60", "9007199254740993"]) {
    it(`refuses max_age=${JSON.stringify(value)} with invalid_request`, async () => {
      const { server } = await createServer();
      const authenticateUser = signedIn({ auth_time: nowSeconds() });
      const response = await server.handleAuthorizeRequest(
        authorizeRequest({ max_age: value }),
        authenticateUser,
      );
      expectError(response, "invalid_request");
      expect(authenticateUser).not.toHaveBeenCalled();
    });
  }

  it("passes max_age to authenticateUser as a number", async () => {
    const { server } = await createServer();
    const authenticateUser = signedIn({ auth_time: nowSeconds() });
    await server.handleAuthorizeRequest(
      authorizeRequest({ max_age: "0600" }),
      authenticateUser,
    );
    expect(authenticateUser.mock.calls[0]?.[1]).toStrictEqual({
      prompt: [],
      maxAge: 600,
      acrValues: [],
    });
  });
});

describe("prompt=consent", () => {
  it("asks for consent again even when the scope is already authorized", async () => {
    const { server } = await createServer();
    const handleConsent = vi.fn<HandleConsentFn<TestClient, BasicScope>>(() =>
      Promise.resolve(loginPage()),
    );
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "consent" }),
      signedIn(),
      handleConsent,
    );
    expect(await response.text()).toBe("<form>sign in</form>");
    expect(handleConsent.mock.calls[0]?.[3]?.prompt).toStrictEqual(["consent"]);
  });

  it("asks for consent even when no scope was requested", async () => {
    const { server } = await createServer();
    const handleConsent = vi.fn<HandleConsentFn<TestClient, BasicScope>>(() =>
      Promise.resolve({ approved: true }),
    );
    const url = new URL(authorizeRequest({ prompt: "consent" }).url);
    url.searchParams.delete("scope");
    const response = await server.handleAuthorizeRequest(
      new Request(url),
      signedIn(),
      handleConsent,
    );
    expect(redirectParams(response).has("code")).toBe(true);
    expect(handleConsent).toHaveBeenCalledOnce();
  });

  it("answers consent_required on a server with no consent handler", async () => {
    const { server } = await createServer();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "consent" }),
      signedIn(),
    );
    expectError(response, "consent_required");
  });
});

describe("prompt values", () => {
  for (const prompt of ["select_account", "create", "Login"]) {
    it(`refuses prompt=${prompt}, which the server does not support by default`, async () => {
      const { server } = await createServer();
      const authenticateUser = signedIn();
      const response = await server.handleAuthorizeRequest(
        authorizeRequest({ prompt }),
        authenticateUser,
      );
      expectError(response, "invalid_request");
      expect(authenticateUser).not.toHaveBeenCalled();
    });
  }

  it("passes a value listed in promptValuesSupported through to authenticateUser", async () => {
    const { server } = await createServer({
      promptValuesSupported: ["none", "login", "consent", "select_account"],
    });
    const authenticateUser = signedIn();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "select_account" }),
      authenticateUser,
    );
    expect(redirectParams(response).has("code")).toBe(true);
    expect(authenticateUser.mock.calls[0]?.[1]?.prompt).toStrictEqual([
      "select_account",
    ]);
  });

  it("still refuses select_account combined with none when it is supported", async () => {
    const { server } = await createServer({
      promptValuesSupported: ["none", "select_account"],
    });
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "select_account none" }),
      signedIn(),
    );
    expectError(response, "invalid_request");
  });

  for (const name of ["prompt", "max_age", "acr_values"]) {
    it(`refuses a repeated ${name}`, async () => {
      const { server } = await createServer();
      const request = authorizeRequest();
      const url = new URL(request.url);
      const value =
        name === "max_age" ? "60" : name === "prompt" ? "login" : "a";
      url.searchParams.append(name, value);
      url.searchParams.append(name, name === "prompt" ? "none" : value);
      const authenticateUser = signedIn();
      const response = await server.handleAuthorizeRequest(
        new Request(url),
        authenticateUser,
      );
      expectError(response, "invalid_request");
      expect(authenticateUser).not.toHaveBeenCalled();
    });
  }

  it("treats parameters sent without a value as omitted", async () => {
    const { server } = await createServer();
    const authenticateUser = signedIn();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ prompt: "", max_age: "", acr_values: "" }),
      authenticateUser,
    );
    expect(redirectParams(response).has("code")).toBe(true);
    expect(authenticateUser.mock.calls[0]?.[1]).toStrictEqual({
      prompt: [],
      acrValues: [],
    });
  });

  for (const entry of ["", "select account", "café"]) {
    it(`refuses ${JSON.stringify(entry)} in promptValuesSupported and acrValuesSupported`, async () => {
      for (const option of ["promptValuesSupported", "acrValuesSupported"]) {
        await expect(createServer({ [option]: [entry] })).rejects.toThrow(
          TypeError,
        );
      }
    });
  }
});

describe("acr_values and acr", () => {
  it("passes acr_values to authenticateUser in preference order", async () => {
    const { server } = await createServer();
    const authenticateUser = signedIn();
    await server.handleAuthorizeRequest(
      authorizeRequest({ acr_values: "urn:example:mfa urn:example:pwd" }),
      authenticateUser,
    );
    expect(authenticateUser.mock.calls[0]?.[1]?.acrValues).toStrictEqual([
      "urn:example:mfa",
      "urn:example:pwd",
    ]);
  });

  it("puts the acr the login achieved in the ID token, not the requested one", async () => {
    const { server, key } = await createServer({
      userClaims: () => ({ acr: "urn:example:mfa", auth_time: 1 }),
    });
    const authTime = nowSeconds();
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ acr_values: "urn:example:mfa" }),
      signedIn({ auth_time: authTime, acr: "urn:example:pwd" }),
    );
    const claims = await idTokenClaims(server, key, response);
    expect(claims.acr).toBe("urn:example:pwd");
    expect(claims.auth_time).toBe(authTime);
  });

  it("leaves acr and auth_time out of the ID token when the login reported neither", async () => {
    const { server, key } = await createServer({
      userClaims: () => ({ acr: "urn:example:mfa", auth_time: 1 }),
    });
    const response = await server.handleAuthorizeRequest(
      authorizeRequest({ acr_values: "urn:example:mfa" }),
      signedIn(),
    );
    const claims = await idTokenClaims(server, key, response);
    expect(Object.hasOwn(claims, "acr")).toBe(false);
    expect(Object.hasOwn(claims, "auth_time")).toBe(false);
  });
});

describe("discovery", () => {
  async function metadata(
    server: AuthorizationServer<TestClient, TestUser, BasicScope>,
    path = "/.well-known/openid-configuration",
  ): Promise<Record<string, unknown>> {
    const response =
      path === "/.well-known/openid-configuration"
        ? await server.handleOidcMetadataRequest(
            new Request(`${ISSUER}${path}`),
          )
        : await server.handleMetadataRequest(new Request(`${ISSUER}${path}`));
    expect(response.status).toBe(200);
    return await response.json();
  }

  it("advertises the prompt values the server enforces and no acr values by default", async () => {
    const { server } = await createServer();
    for (const path of [
      "/.well-known/openid-configuration",
      "/.well-known/oauth-authorization-server",
    ]) {
      const document = await metadata(server, path);
      expect(document.prompt_values_supported).toStrictEqual([
        "none",
        "login",
        "consent",
      ]);
      expect(Object.hasOwn(document, "acr_values_supported")).toBe(false);
      expect(document.authorization_response_iss_parameter_supported).toBe(
        true,
      );
    }
  });

  it("advertises configured prompt and acr values", async () => {
    const { server } = await createServer({
      promptValuesSupported: ["none", "login", "consent", "create"],
      acrValuesSupported: ["urn:example:pwd", "urn:example:mfa"],
    });
    const document = await metadata(server);
    expect(document.prompt_values_supported).toStrictEqual([
      "none",
      "login",
      "consent",
      "create",
    ]);
    expect(document.acr_values_supported).toStrictEqual([
      "urn:example:pwd",
      "urn:example:mfa",
    ]);
  });

  it("advertises no prompt values without an authorization endpoint", async () => {
    const { server } = await createServer({
      grants: {},
      acrValuesSupported: ["urn:example:pwd"],
    });
    const document = await metadata(server);
    expect(Object.hasOwn(document, "prompt_values_supported")).toBe(false);
    expect(Object.hasOwn(document, "acr_values_supported")).toBe(false);
  });
});

describe("Hono authorize handler", () => {
  it("passes the authentication request to both callbacks and enforces prompt=none", async () => {
    const { hono } = await createServer();
    const seen: (AuthenticationRequest | undefined)[] = [];
    const app = new Hono();
    app.get(
      "/authorize",
      hono.authorizeHandler({
        authenticateUser: (c, authentication) => {
          seen.push(authentication);
          return Promise.resolve(
            c.req.query("signed_in")
              ? { user, authorizedScope: new BasicScope("openid") }
              : c.html("<form>sign in</form>"),
          );
        },
        handleConsent: (c, _client, _scope, _user, authentication) => {
          seen.push(authentication);
          return Promise.resolve(c.html("<form>consent</form>"));
        },
      }),
    );
    const silent = await app.request(authorizeRequest({ prompt: "none" }));
    expectError(silent, "login_required");
    const consent = await app.request(
      authorizeRequest({ prompt: "consent", signed_in: "1" }),
    );
    expect(await consent.text()).toBe("<form>consent</form>");
    expect(seen.map((request) => request?.prompt)).toStrictEqual([
      ["none"],
      ["consent"],
      ["consent"],
    ]);
  });
});

describe("satisfiesAuthenticationRequest", () => {
  const now = 1_700_000_000_000;
  const at = (secondsAgo: number) => ({
    authenticationContext: { auth_time: now / 1000 - secondsAgo },
  });
  const request = (
    init: Partial<AuthenticationRequest> = {},
  ): AuthenticationRequest => ({ prompt: [], acrValues: [], ...init });

  it("accepts any authentication when no control is requested", () => {
    expect(satisfiesAuthenticationRequest(request(), {}, now)).toBe(true);
  });

  it("ignores acr_values, which are preferences", () => {
    expect(
      satisfiesAuthenticationRequest(
        request({ acrValues: ["urn:example:mfa"] }),
        { authenticationContext: { acr: "urn:example:pwd" } },
        now,
      ),
    ).toBe(true);
  });

  it("accepts an auth_time exactly max_age old and refuses one a second older", () => {
    expect(
      satisfiesAuthenticationRequest(request({ maxAge: 60 }), at(60), now),
    ).toBe(true);
    expect(
      satisfiesAuthenticationRequest(request({ maxAge: 60 }), at(61), now),
    ).toBe(false);
  });

  it("refuses a non-numeric auth_time under max_age", () => {
    expect(
      satisfiesAuthenticationRequest(
        request({ maxAge: 60 }),
        {
          authenticationContext: {
            auth_time: Number.NaN,
          },
          reauthenticated: true,
        },
        now,
      ),
    ).toBe(false);
  });

  it("requires reauthenticated to be exactly true for prompt=login", () => {
    expect(
      satisfiesAuthenticationRequest(
        request({ prompt: ["login"] }),
        { ...at(0), reauthenticated: "yes" as unknown as boolean },
        now,
      ),
    ).toBe(false);
  });

  it("defaults the clock to now", () => {
    expect(
      satisfiesAuthenticationRequest(request({ maxAge: 5 }), {
        authenticationContext: { auth_time: nowSeconds() },
      }),
    ).toBe(true);
  });

  it("refuses max_age without any authentication context", () => {
    expect(
      satisfiesAuthenticationRequest(request({ maxAge: 5 }), {}, now),
    ).toBe(false);
  });
});
