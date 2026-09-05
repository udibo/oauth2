import {
  assert,
  assertEquals,
  assertExists,
  assertFalse,
  assertStringIncludes,
  assertThrows,
} from "@std/assert";
import { decodeBase64Url } from "@std/encoding/base64url";
import { describe, it } from "@std/testing/bdd";

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
import {
  AuthorizationServer,
  type AuthorizationServerOptions,
  type EndSessionContext,
  type EndSessionFn,
} from "./authorization-server.ts";
import { AuthorizationCodeGrant } from "./grants/authorization-code.ts";
import { ClientCredentialsGrant } from "./grants/client-credentials.ts";
import {
  createJwtAccessTokenGenerator,
  generateSigningKey,
  type SigningKey,
  type SigningKeyProvider,
  signJwt,
  StaticSigningKeyProvider,
  verifyJwt,
} from "./signing-keys.ts";

const testUser: TestUser = { id: "user-1", username: "testuser" };
const testClient: TestClient = {
  id: "client-1",
  confidential: true,
  grants: ["authorization_code", "refresh_token"],
  redirectUris: ["https://example.com/callback"],
};

async function createOidcServer(
  key?: SigningKey,
  userClaims: (user: TestUser) => Record<string, unknown> = (user) => ({
    preferred_username: user.username,
  }),
) {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  const authorizationCodeService = new MemoryAuthorizationCodeService({
    clientService,
    userService,
  });
  await userService.add(testUser, "password");
  await clientService.add(testClient, "secret", testUser.id);

  const signingKey = key ?? await generateSigningKey();
  const grant = new AuthorizationCodeGrant<TestClient, TestUser, BasicScope>({
    resolve: () => ({
      clientService,
      tokenService,
      authorizationCodeService,
    }),
    allowRefreshToken: true,
    requirePKCE: false,
  });
  const server = new AuthorizationServer<TestClient, TestUser, BasicScope>({
    resolve: () => ({
      services: { clientService, tokenService },
      issuer: "https://auth.example.com",
    }),
    grants: { authorization_code: grant },
    scopesSupported: ["openid", "profile", "read"],
    signingKeys: new StaticSigningKeyProvider(signingKey),
    userClaims,
  });
  return { server, grant, tokenService, signingKey };
}

function createServer(
  options: Partial<
    AuthorizationServerOptions<TestClient, TestUser, BasicScope>
  > = {},
) {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  return new AuthorizationServer<TestClient, TestUser, BasicScope>({
    resolve: () => ({
      services: { clientService, tokenService },
      issuer: "https://auth.example.com",
    }),
    grants: {},
    ...options,
  });
}

async function exchangeCodeWithNonce(
  server: AuthorizationServer<TestClient, TestUser, BasicScope>,
  grant: AuthorizationCodeGrant<TestClient, TestUser, BasicScope>,
  scope: string,
  nonce?: string,
) {
  const code = await grant.generateAuthorizationCode({
    client: testClient,
    user: testUser,
    scope: new BasicScope(scope),
    redirectUri: "https://example.com/callback",
    nonce: nonce ?? null,
  }, new Request("http://localhost/authorize"));

  const response = await server.handleTokenRequest(
    tokenRequest({
      grant_type: "authorization_code",
      code: code.code,
      redirect_uri: "https://example.com/callback",
    }, basicAuthHeader("client-1", "secret")),
  );
  assertEquals(response.status, 200);
  return await response.json();
}

describe("OIDC issuance", () => {
  it("mints a verifiable id_token with nonce for openid-scoped user grants", async () => {
    const { server, grant, signingKey } = await createOidcServer();
    const body = await exchangeCodeWithNonce(
      server,
      grant,
      "openid profile",
      "nonce-123",
    );

    assertExists(body.id_token);
    const claims = await verifyJwt(body.id_token, signingKey.publicJwk);
    assertExists(claims);
    assertEquals(claims!.iss, "https://auth.example.com");
    assertEquals(claims!.sub, "user-1");
    assertEquals(claims!.aud, "client-1");
    assertEquals(claims!.nonce, "nonce-123");
    assertEquals(claims!.preferred_username, "testuser");
    assert(typeof claims!.exp === "number" && typeof claims!.iat === "number");
  });

  it("omits the id_token without the openid scope", async () => {
    const { server, grant } = await createOidcServer();
    const body = await exchangeCodeWithNonce(server, grant, "read");
    assertEquals(body.id_token, undefined);
  });

  it("advertises the OIDC surface in metadata at both well-known names", async () => {
    const { server } = await createOidcServer();
    const response = await server.handleMetadataRequest(
      new Request(
        "https://auth.example.com/.well-known/openid-configuration",
      ),
    );
    const metadata = await response.json();
    assertEquals(metadata.issuer, "https://auth.example.com");
    assertEquals(metadata.jwks_uri, "https://auth.example.com/jwks");
    assertEquals(
      metadata.userinfo_endpoint,
      "https://auth.example.com/userinfo",
    );
    assertEquals(metadata.id_token_signing_alg_values_supported, ["ES256"]);
    assertEquals(metadata.subject_types_supported, ["public"]);
  });

  it("serves only public key material from the JWKS endpoint", async () => {
    const { server, signingKey } = await createOidcServer();
    const response = await server.handleJwksRequest(
      new Request("https://auth.example.com/jwks"),
    );
    assertEquals(response.status, 200);
    const jwks = await response.json();
    assertEquals(jwks.keys.length, 1);
    assertEquals(jwks.keys[0].kid, signingKey.kid);
    assertEquals(jwks.keys[0].d, undefined);
  });

  it("maps a getPublicJwks outage on /jwks to a clean error response", async () => {
    const userService = new MemoryUserService();
    const clientService = new MemoryClientService(userService);
    const tokenService = new MemoryTokenService({ clientService, userService });
    const failingKeys: SigningKeyProvider = {
      getSigningKey: () => Promise.reject(new Error("kms unavailable")),
      getPublicJwks: () => Promise.reject(new Error("kms unavailable")),
    };
    const server = new AuthorizationServer<TestClient, TestUser, BasicScope>({
      resolve: () => ({
        services: { clientService, tokenService },
        issuer: "https://auth.example.com",
      }),
      grants: {},
      signingKeys: failingKeys,
    });

    const response = await server.handleJwksRequest(
      new Request("https://auth.example.com/jwks"),
    );
    assertEquals(response.status, 500);
    assertEquals((await response.json()).error, "server_error");
  });

  it("maps a resolve outage on the metadata endpoint to a clean error response", async () => {
    const server = new AuthorizationServer<TestClient, TestUser, BasicScope>({
      resolve: () => {
        throw new Error("service registry unavailable");
      },
      grants: {},
    });

    const response = await server.handleMetadataRequest(
      new Request(
        "https://auth.example.com/.well-known/oauth-authorization-server",
      ),
    );
    assertEquals(response.status, 500);
    assertEquals((await response.json()).error, "server_error");
  });

  it("userinfo returns sub + claims for an openid-scoped token", async () => {
    const { server, grant } = await createOidcServer();
    const openidBody = await exchangeCodeWithNonce(server, grant, "openid");
    const userinfo = await server.handleUserInfoRequest(
      new Request("https://auth.example.com/userinfo", {
        headers: { authorization: `Bearer ${openidBody.access_token}` },
      }),
    );
    assertEquals(userinfo.status, 200);
    const claims = await userinfo.json();
    assertEquals(claims.sub, "user-1");
    assertEquals(claims.preferred_username, "testuser");
  });

  it('userinfo answers 403 insufficient_scope, challenging for scope="openid", when a valid token lacks it', async () => {
    const { server, grant } = await createOidcServer();
    const plainBody = await exchangeCodeWithNonce(server, grant, "read");

    const denied = await server.handleUserInfoRequest(
      new Request("https://auth.example.com/userinfo", {
        headers: { authorization: `Bearer ${plainBody.access_token}` },
      }),
    );

    assertEquals(denied.status, 403);
    assertEquals((await denied.json()).error, "insufficient_scope");
    const challenge = denied.headers.get("www-authenticate");
    assertExists(challenge);
    assertStringIncludes(challenge, 'error="insufficient_scope"');
    assertStringIncludes(challenge, 'scope="openid"');
  });

  it("userinfo answers 401 invalid_token for a bearer token the server does not know", async () => {
    const { server } = await createOidcServer();

    const denied = await server.handleUserInfoRequest(
      new Request("https://auth.example.com/userinfo", {
        headers: { authorization: "Bearer not-a-token" },
      }),
    );

    assertEquals(denied.status, 401);
    assertEquals((await denied.json()).error, "invalid_token");
    const challenge = denied.headers.get("www-authenticate");
    assertExists(challenge);
    assertStringIncludes(challenge, 'error="invalid_token"');
  });

  it("protocol claims win over userClaims collisions", async () => {
    const { server, grant, signingKey } = await createOidcServer(
      undefined,
      () => ({ sub: "spoofed", exp: 1, locale: "en" }),
    );
    const body = await exchangeCodeWithNonce(server, grant, "openid");
    const claims = await verifyJwt(body.id_token, signingKey.publicJwk);
    assertExists(claims);
    assertEquals(claims!.sub, "user-1");
    assert(typeof claims!.exp === "number" && claims!.exp * 1000 > Date.now());
    assertEquals(claims!.locale, "en");

    const userinfo = await server.handleUserInfoRequest(
      new Request("https://auth.example.com/userinfo", {
        headers: { authorization: `Bearer ${body.access_token}` },
      }),
    );
    assertEquals((await userinfo.json()).sub, "user-1");
  });

  it("does not mint an id_token for client_credentials even with openid", async () => {
    const userService = new MemoryUserService();
    const clientService = new MemoryClientService(userService);
    const tokenService = new MemoryTokenService({ clientService, userService });
    await userService.add(testUser, "password");
    const machineClient: TestClient = {
      id: "client-cc",
      confidential: true,
      grants: ["client_credentials"],
      redirectUris: [],
    };
    await clientService.add(machineClient, "secret", testUser.id);
    const server = new AuthorizationServer<TestClient, TestUser, BasicScope>({
      resolve: () => ({
        services: { clientService, tokenService },
        issuer: "https://auth.example.com",
      }),
      grants: {
        client_credentials: new ClientCredentialsGrant<
          TestClient,
          TestUser,
          BasicScope
        >({ resolve: () => ({ clientService, tokenService }) }),
      },
      signingKeys: new StaticSigningKeyProvider(await generateSigningKey()),
    });

    const response = await server.handleTokenRequest(
      tokenRequest({
        grant_type: "client_credentials",
        scope: "openid",
      }, basicAuthHeader("client-cc", "secret")),
    );
    assertEquals(response.status, 200);
    const body = await response.json();
    assertExists(body.access_token);
    assertEquals(body.id_token, undefined);
  });

  it("404s OIDC discovery when issuance is off", async () => {
    const server = createServer();
    const denied = await server.handleOidcMetadataRequest(
      new Request("https://auth.example.com/.well-known/openid-configuration"),
    );
    assertEquals(denied.status, 404);
    const metadata = await server.handleMetadataRequest(
      new Request(
        "https://auth.example.com/.well-known/oauth-authorization-server",
      ),
    );
    assertEquals(metadata.status, 200);
  });

  it("issues verifiable JWT access tokens via the generator", async () => {
    const signingKey = await generateSigningKey();
    const generate = createJwtAccessTokenGenerator({
      signingKeys: new StaticSigningKeyProvider(signingKey),
      issuer: "https://auth.example.com",
    });
    const jwt = await generate(testClient, testUser, new BasicScope("read"));
    const claims = await verifyJwt(jwt, signingKey.publicJwk);
    assertExists(claims);
    assertEquals(claims!.sub, "user-1");
    assertEquals(claims!.client_id, "client-1");
    assertEquals(claims!.scope, "read");
    const header = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(jwt.split(".")[0])),
    );
    assertEquals(header.typ, "at+jwt");
  });
});

describe("RP-Initiated Logout", () => {
  const POST_LOGOUT = "https://example.com/signed-out";

  async function createLogoutServer(
    options: {
      registered?: string[];
      endSession?: EndSessionFn<TestClient>;
    } = {},
  ) {
    const calls: EndSessionContext<TestClient>[] = [];
    const userService = new MemoryUserService();
    const clientService = new MemoryClientService(userService);
    const tokenService = new MemoryTokenService({ clientService, userService });
    await userService.add(testUser, "password");
    await clientService.add(
      {
        ...testClient,
        postLogoutRedirectUris: options.registered ?? [POST_LOGOUT],
      },
      "secret",
      testUser.id,
    );

    const signingKey = await generateSigningKey();
    const endSession: EndSessionFn<TestClient> | undefined =
      options.endSession === undefined
        ? (context) => {
          calls.push(context);
          return { headers: { "Set-Cookie": "session=; Max-Age=0" } };
        }
        : options.endSession;
    const server = new AuthorizationServer<TestClient, TestUser, BasicScope>({
      resolve: () => ({
        services: { clientService, tokenService },
        issuer: "https://auth.example.com",
      }),
      grants: {},
      signingKeys: new StaticSigningKeyProvider(signingKey),
      endSession,
    });
    return { server, calls, signingKey };
  }

  function logout(params: Record<string, string>, method = "GET"): Request {
    const url = new URL("https://auth.example.com/end_session");
    if (method === "GET") {
      for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
      }
      return new Request(url, { method });
    }
    return new Request(url, {
      method,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params),
    });
  }

  it("ends the session and redirects to a registered post_logout_redirect_uri", async () => {
    const { server, calls } = await createLogoutServer();
    const response = await server.handleEndSessionRequest(
      logout({
        client_id: "client-1",
        post_logout_redirect_uri: POST_LOGOUT,
        state: "xyz",
      }),
    );

    assertEquals(response.status, 302);
    assertEquals(
      response.headers.get("location"),
      `${POST_LOGOUT}?state=xyz`,
      "state rides along to an authorized URI",
    );
    assertEquals(
      response.headers.get("set-cookie"),
      "session=; Max-Age=0",
      "the app's session-clearing header survives onto the redirect",
    );
    assertEquals(calls.length, 1);
    assertEquals(calls[0].client?.id, "client-1");
  });

  it("accepts the same request over POST", async () => {
    const { server, calls } = await createLogoutServer();
    const response = await server.handleEndSessionRequest(
      logout(
        { client_id: "client-1", post_logout_redirect_uri: POST_LOGOUT },
        "POST",
      ),
    );
    assertEquals(response.status, 302);
    assertEquals(response.headers.get("location"), POST_LOGOUT);
    assertEquals(calls.length, 1);
  });

  it("still ends the session when the redirect is unauthorized, and refuses to send the browser there", async () => {
    const unauthorized: Record<string, string>[] = [
      {
        client_id: "client-1",
        post_logout_redirect_uri: "https://evil.example/steal",
      },
      { post_logout_redirect_uri: POST_LOGOUT },
      { client_id: "nobody", post_logout_redirect_uri: POST_LOGOUT },
    ];
    for (const params of unauthorized) {
      const { server, calls } = await createLogoutServer();
      const response = await server.handleEndSessionRequest(logout(params));
      assertEquals(
        response.status,
        204,
        `unauthorized redirect must not become a 302: ${
          JSON.stringify(params)
        }`,
      );
      assertFalse(response.headers.get("location"));
      assertEquals(
        calls.length,
        1,
        "a logout whose redirect is refused still logs the person out",
      );
    }
  });

  it("prefers the app's fallback when the request named no authorized redirect", async () => {
    const { server } = await createLogoutServer({
      endSession: () => ({ fallback: "/signed-out" }),
    });
    const response = await server.handleEndSessionRequest(
      logout({
        client_id: "client-1",
        post_logout_redirect_uri: "https://evil.example/x",
      }),
    );
    assertEquals(response.status, 302);
    assertEquals(response.headers.get("location"), "/signed-out");
  });

  it("reads the subject and the client from an expired id_token_hint", async () => {
    const { server, calls, signingKey } = await createLogoutServer();
    const expired = await signJwt(signingKey, {
      iss: "https://auth.example.com",
      sub: testUser.id,
      aud: "client-1",
      exp: Math.floor(Date.now() / 1000) - 3600,
    });

    const response = await server.handleEndSessionRequest(
      logout({ id_token_hint: expired, post_logout_redirect_uri: POST_LOGOUT }),
    );
    assertEquals(
      response.status,
      302,
      "an id_token that has expired is still a valid hint — logout happens after the token dies",
    );
    assertEquals(calls[0].subject, testUser.id);
    assertEquals(calls[0].client?.id, "client-1");
  });

  it("ignores an id_token_hint it cannot verify", async () => {
    const { server, calls } = await createLogoutServer();
    const forged = await signJwt(await generateSigningKey(), {
      iss: "https://auth.example.com",
      sub: "someone-else",
      aud: "client-1",
    });

    const response = await server.handleEndSessionRequest(
      logout({ id_token_hint: forged, post_logout_redirect_uri: POST_LOGOUT }),
    );
    assertEquals(
      response.status,
      204,
      "a forged hint names no client, so no redirect is authorized",
    );
    assertEquals(calls[0].subject, null, "and it contributes no subject");
  });

  it("is 404 and unadvertised until the app wires endSession", async () => {
    const { server } = await createLogoutServer({ endSession: undefined });
    const withoutSeam = new AuthorizationServer<
      TestClient,
      TestUser,
      BasicScope
    >({
      resolve: () => ({
        services: {
          clientService: new MemoryClientService(new MemoryUserService()),
          tokenService: new MemoryTokenService({
            clientService: new MemoryClientService(new MemoryUserService()),
            userService: new MemoryUserService(),
          }),
        },
        issuer: "https://auth.example.com",
      }),
      grants: {},
      signingKeys: new StaticSigningKeyProvider(await generateSigningKey()),
    });

    const response = await withoutSeam.handleEndSessionRequest(
      logout({ client_id: "client-1" }),
    );
    assertEquals(response.status, 404);

    const unwired = await (await withoutSeam.handleOidcMetadataRequest(
      new Request("https://auth.example.com/.well-known/openid-configuration"),
    )).json();
    assertFalse(
      "end_session_endpoint" in unwired,
      "metadata must not advertise a logout the server cannot perform",
    );

    const wired = await (await server.handleOidcMetadataRequest(
      new Request("https://auth.example.com/.well-known/openid-configuration"),
    )).json();
    assertEquals(
      wired.end_session_endpoint,
      "https://auth.example.com/end_session",
    );
  });
});

describe("OIDC configuration assertions", () => {
  it("reports oidcEnabled false on a server without signing keys", () => {
    assertFalse(createServer().oidcEnabled);
  });

  it("reports oidcEnabled true on a server with signing keys", async () => {
    const server = createServer({
      signingKeys: new StaticSigningKeyProvider(await generateSigningKey()),
    });
    assert(server.oidcEnabled);
  });

  it("follows a signingKeys assignment made after construction", async () => {
    const server = createServer();
    server.signingKeys = new StaticSigningKeyProvider(
      await generateSigningKey(),
    );
    assert(server.oidcEnabled);
  });

  it("refuses to construct with requireOidc and no signing keys", () => {
    const error = assertThrows(
      () => createServer({ requireOidc: true }),
      Error,
      "requireOidc",
    );
    assertStringIncludes(error.message, "signingKeys");
    assertStringIncludes(error.message, "id_token");
    assertStringIncludes(error.message, "/jwks");
  });

  it("constructs with requireOidc when signing keys are configured", async () => {
    const server = createServer({
      requireOidc: true,
      signingKeys: new StaticSigningKeyProvider(await generateSigningKey()),
    });
    assert(server.oidcEnabled);
  });
});
