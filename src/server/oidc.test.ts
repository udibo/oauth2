import { assert, describe, expect, it } from "vitest";
import { thrown } from "../_test_assert.ts";
import { decodeBase64Url } from "../utils/_encoding.ts";
import { BasicScope } from "../models/scope.ts";
import type { RefreshToken } from "../models/token.ts";
import {
  basicAuthHeader,
  exchangeToken,
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
import { RefreshTokenGrant } from "./grants/refresh-token.ts";
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

  const signingKey = key ?? (await generateSigningKey());
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
  const code = await grant.generateAuthorizationCode(
    {
      client: testClient,
      user: testUser,
      scope: new BasicScope(scope),
      redirectUri: "https://example.com/callback",
      nonce: nonce ?? null,
    },
    new Request("http://localhost/authorize"),
  );

  const response = await server.handleTokenRequest(
    tokenRequest(
      {
        grant_type: "authorization_code",
        code: code.code,
        redirect_uri: "https://example.com/callback",
      },
      basicAuthHeader("client-1", "secret"),
    ),
  );
  expect(response.status).toStrictEqual(200);
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

    assert.exists(body.id_token);
    const claims = await verifyJwt(body.id_token, signingKey.publicJwk);
    assert.exists(claims);
    expect(claims!.iss).toStrictEqual("https://auth.example.com");
    expect(claims!.sub).toStrictEqual("user-1");
    expect(claims!.aud).toStrictEqual("client-1");
    expect(claims!.nonce).toStrictEqual("nonce-123");
    expect(claims!.preferred_username).toStrictEqual("testuser");
    assert(typeof claims!.exp === "number" && typeof claims!.iat === "number");
  });

  it("keeps nonce absent when the request sent none, whatever userClaims returns", async () => {
    const { server, grant, signingKey } = await createOidcServer(
      undefined,
      () => ({ nonce: "injected-by-hook" }),
    );
    const body = await exchangeCodeWithNonce(server, grant, "openid");

    const claims = await verifyJwt(body.id_token, signingKey.publicJwk);
    assert.exists(claims);
    expect(
      claims!.nonce,
      "the protocol nonce is authoritative: a request without one yields an id_token without one",
    ).toStrictEqual(undefined);
  });

  it("stamps the request's nonce over one userClaims returns", async () => {
    const { server, grant, signingKey } = await createOidcServer(
      undefined,
      () => ({ nonce: "injected-by-hook" }),
    );
    const body = await exchangeCodeWithNonce(
      server,
      grant,
      "openid",
      "nonce-123",
    );

    const claims = await verifyJwt(body.id_token, signingKey.publicJwk);
    expect(claims!.nonce).toStrictEqual("nonce-123");
  });

  it("userinfo honors clockSkewSeconds on the bearer token's expiry", async () => {
    const userService = new MemoryUserService();
    const clientService = new MemoryClientService(userService);
    const tokenService = new MemoryTokenService({ clientService, userService });
    await userService.add(testUser, "password");
    await clientService.add(testClient, "secret", testUser.id);
    const server = new AuthorizationServer<TestClient, TestUser, BasicScope>({
      resolve: () => ({
        services: { clientService, tokenService },
        issuer: "https://auth.example.com",
      }),
      grants: {},
      signingKeys: new StaticSigningKeyProvider(await generateSigningKey()),
      clockSkewSeconds: 30,
    });
    await tokenService.save({
      accessToken: "drifted-token",
      accessTokenExpiresAt: new Date(Date.now() - 10_000),
      client: testClient,
      user: testUser,
      scope: new BasicScope("openid"),
    });

    const userinfo = await server.handleUserInfoRequest(
      new Request("https://auth.example.com/userinfo", {
        headers: { authorization: "Bearer drifted-token" },
      }),
    );

    expect(
      userinfo.status,
      "a token expired within the configured skew is still accepted",
    ).toStrictEqual(200);
    expect((await userinfo.json()).sub).toStrictEqual("user-1");
  });

  it("omits the id_token without the openid scope", async () => {
    const { server, grant } = await createOidcServer();
    const body = await exchangeCodeWithNonce(server, grant, "read");
    expect(body.id_token).toStrictEqual(undefined);
  });

  it("advertises the OIDC surface in metadata at both well-known names", async () => {
    const { server } = await createOidcServer();
    const response = await server.handleMetadataRequest(
      new Request("https://auth.example.com/.well-known/openid-configuration"),
    );
    const metadata = await response.json();
    expect(metadata.issuer).toStrictEqual("https://auth.example.com");
    expect(metadata.jwks_uri).toStrictEqual("https://auth.example.com/jwks");
    expect(metadata.userinfo_endpoint).toStrictEqual(
      "https://auth.example.com/userinfo",
    );
    expect(metadata.id_token_signing_alg_values_supported).toStrictEqual([
      "ES256",
    ]);
    expect(metadata.subject_types_supported).toStrictEqual(["public"]);
  });

  it("serves only public key material from the JWKS endpoint", async () => {
    const { server, signingKey } = await createOidcServer();
    const response = await server.handleJwksRequest(
      new Request("https://auth.example.com/jwks"),
    );
    expect(response.status).toStrictEqual(200);
    const jwks = await response.json();
    expect(jwks.keys.length).toStrictEqual(1);
    expect(jwks.keys[0].kid).toStrictEqual(signingKey.kid);
    expect(jwks.keys[0].d).toStrictEqual(undefined);
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
    expect(response.status).toStrictEqual(500);
    expect((await response.json()).error).toStrictEqual("server_error");
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
    expect(response.status).toStrictEqual(500);
    expect((await response.json()).error).toStrictEqual("server_error");
  });

  it("userinfo returns sub + claims for an openid-scoped token", async () => {
    const { server, grant } = await createOidcServer();
    const openidBody = await exchangeCodeWithNonce(server, grant, "openid");
    const userinfo = await server.handleUserInfoRequest(
      new Request("https://auth.example.com/userinfo", {
        headers: { authorization: `Bearer ${openidBody.access_token}` },
      }),
    );
    expect(userinfo.status).toStrictEqual(200);
    const claims = await userinfo.json();
    expect(claims.sub).toStrictEqual("user-1");
    expect(claims.preferred_username).toStrictEqual("testuser");
  });

  it('userinfo answers 403 insufficient_scope, challenging for scope="openid", when a valid token lacks it', async () => {
    const { server, grant } = await createOidcServer();
    const plainBody = await exchangeCodeWithNonce(server, grant, "read");

    const denied = await server.handleUserInfoRequest(
      new Request("https://auth.example.com/userinfo", {
        headers: { authorization: `Bearer ${plainBody.access_token}` },
      }),
    );

    expect(denied.status).toStrictEqual(403);
    expect((await denied.json()).error).toStrictEqual("insufficient_scope");
    const challenge = denied.headers.get("www-authenticate");
    assert.exists(challenge);
    expect(challenge).toContain('error="insufficient_scope"');
    expect(challenge).toContain('scope="openid"');
  });

  it("userinfo answers 401 invalid_token for a bearer token the server does not know", async () => {
    const { server } = await createOidcServer();

    const denied = await server.handleUserInfoRequest(
      new Request("https://auth.example.com/userinfo", {
        headers: { authorization: "Bearer not-a-token" },
      }),
    );

    expect(denied.status).toStrictEqual(401);
    expect((await denied.json()).error).toStrictEqual("invalid_token");
    const challenge = denied.headers.get("www-authenticate");
    assert.exists(challenge);
    expect(challenge).toContain('error="invalid_token"');
  });

  it("protocol claims win over userClaims collisions", async () => {
    const { server, grant, signingKey } = await createOidcServer(
      undefined,
      () => ({ sub: "spoofed", exp: 1, locale: "en" }),
    );
    const body = await exchangeCodeWithNonce(server, grant, "openid");
    const claims = await verifyJwt(body.id_token, signingKey.publicJwk);
    assert.exists(claims);
    expect(claims!.sub).toStrictEqual("user-1");
    assert(typeof claims!.exp === "number" && claims!.exp * 1000 > Date.now());
    expect(claims!.locale).toStrictEqual("en");

    const userinfo = await server.handleUserInfoRequest(
      new Request("https://auth.example.com/userinfo", {
        headers: { authorization: `Bearer ${body.access_token}` },
      }),
    );
    expect((await userinfo.json()).sub).toStrictEqual("user-1");
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
      tokenRequest(
        {
          grant_type: "client_credentials",
          scope: "openid",
        },
        basicAuthHeader("client-cc", "secret"),
      ),
    );
    expect(response.status).toStrictEqual(200);
    const body = await response.json();
    assert.exists(body.access_token);
    expect(body.id_token).toStrictEqual(undefined);
  });

  it("404s OIDC discovery when issuance is off", async () => {
    const server = createServer();
    const denied = await server.handleOidcMetadataRequest(
      new Request("https://auth.example.com/.well-known/openid-configuration"),
    );
    expect(denied.status).toStrictEqual(404);
    const metadata = await server.handleMetadataRequest(
      new Request(
        "https://auth.example.com/.well-known/oauth-authorization-server",
      ),
    );
    expect(metadata.status).toStrictEqual(200);
  });

  it("issues verifiable JWT access tokens via the generator", async () => {
    const signingKey = await generateSigningKey();
    const generate = createJwtAccessTokenGenerator({
      signingKeys: new StaticSigningKeyProvider(signingKey),
      issuer: "https://auth.example.com",
    });
    const jwt = await generate(testClient, testUser, new BasicScope("read"));
    const claims = await verifyJwt(jwt, signingKey.publicJwk);
    assert.exists(claims);
    expect(claims!.sub).toStrictEqual("user-1");
    expect(claims!.client_id).toStrictEqual("client-1");
    expect(claims!.scope).toStrictEqual("read");
    const header = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(jwt.split(".")[0])),
    );
    expect(header.typ).toStrictEqual("at+jwt");
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

    expect(response.status).toStrictEqual(302);
    expect(
      response.headers.get("location"),
      "state rides along to an authorized URI",
    ).toStrictEqual(`${POST_LOGOUT}?state=xyz`);
    expect(
      response.headers.get("set-cookie"),
      "the app's session-clearing header survives onto the redirect",
    ).toStrictEqual("session=; Max-Age=0");
    expect(calls.length).toStrictEqual(1);
    expect(calls[0].client?.id).toStrictEqual("client-1");
  });

  it("accepts the same request over POST", async () => {
    const { server, calls } = await createLogoutServer();
    const response = await server.handleEndSessionRequest(
      logout(
        { client_id: "client-1", post_logout_redirect_uri: POST_LOGOUT },
        "POST",
      ),
    );
    expect(response.status).toStrictEqual(302);
    expect(response.headers.get("location")).toStrictEqual(POST_LOGOUT);
    expect(calls.length).toStrictEqual(1);
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
      expect(
        response.status,
        `unauthorized redirect must not become a 302: ${JSON.stringify(
          params,
        )}`,
      ).toStrictEqual(204);
      expect(response.headers.get("location")).toBeFalsy();
      expect(
        calls.length,
        "a logout whose redirect is refused still logs the person out",
      ).toStrictEqual(1);
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
    expect(response.status).toStrictEqual(302);
    expect(response.headers.get("location")).toStrictEqual("/signed-out");
  });

  it("uses the app fallback without clearing a session when logout is refused", async () => {
    const { server } = await createLogoutServer({
      endSession: () => ({
        refused: true,
        fallback: "/sign-in",
        headers: { "Set-Cookie": "session=; Max-Age=0" },
      }),
    });
    const response = await server.handleEndSessionRequest(
      logout({
        client_id: "client-1",
        post_logout_redirect_uri: POST_LOGOUT,
        state: "rp-state",
      }),
    );

    expect(response.status).toStrictEqual(302);
    expect(response.headers.get("location")).toStrictEqual("/sign-in");
    expect(response.headers.has("set-cookie")).toBeFalsy();
  });

  it("answers 204 without session headers when a refused logout has no fallback", async () => {
    const { server } = await createLogoutServer({
      endSession: () => ({
        refused: true,
        headers: { "Set-Cookie": "session=; Max-Age=0" },
      }),
    });
    const response = await server.handleEndSessionRequest(
      logout({ client_id: "client-1", post_logout_redirect_uri: POST_LOGOUT }),
    );

    expect(response.status).toStrictEqual(204);
    expect(response.headers.has("location")).toBeFalsy();
    expect(response.headers.has("set-cookie")).toBeFalsy();
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
    expect(
      response.status,
      "an id_token that has expired is still a valid hint — logout happens after the token dies",
    ).toStrictEqual(302);
    expect(calls[0].subject).toStrictEqual(testUser.id);
    expect(calls[0].client?.id).toStrictEqual("client-1");
  });

  it("refuses a logout whose client_id disagrees with the id_token_hint's audience", async () => {
    const { server, calls, signingKey } = await createLogoutServer();
    const otherClientsToken = await signJwt(signingKey, {
      iss: "https://auth.example.com",
      sub: testUser.id,
      aud: "client-2",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    const response = await server.handleEndSessionRequest(
      logout({
        client_id: "client-1",
        id_token_hint: otherClientsToken,
        post_logout_redirect_uri: POST_LOGOUT,
      }),
    );

    expect(
      response.status,
      "RP-Initiated Logout requires client_id to match the id_token's audience",
    ).toStrictEqual(400);
    expect((await response.json()).error).toStrictEqual("invalid_request");
    expect(response.headers.get("location")).toBeFalsy();
    expect(
      calls.length,
      "an inconsistent request ends no session for anyone",
    ).toStrictEqual(0);
  });

  it("accepts a client_id that matches the id_token_hint's audience", async () => {
    const { server, calls, signingKey } = await createLogoutServer();
    const hint = await signJwt(signingKey, {
      iss: "https://auth.example.com",
      sub: testUser.id,
      aud: ["client-1", "client-2"],
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    const response = await server.handleEndSessionRequest(
      logout({
        client_id: "client-1",
        id_token_hint: hint,
        post_logout_redirect_uri: POST_LOGOUT,
      }),
    );

    expect(response.status).toStrictEqual(302);
    expect(calls[0].client?.id).toStrictEqual("client-1");
    expect(calls[0].subject).toStrictEqual(testUser.id);
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
    expect(
      response.status,
      "a forged hint names no client, so no redirect is authorized",
    ).toStrictEqual(204);
    expect(calls[0].subject, "and it contributes no subject").toStrictEqual(
      null,
    );
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
    expect(response.status).toStrictEqual(404);

    const unwired = await (
      await withoutSeam.handleOidcMetadataRequest(
        new Request(
          "https://auth.example.com/.well-known/openid-configuration",
        ),
      )
    ).json();
    expect(
      "end_session_endpoint" in unwired,
      "metadata must not advertise a logout the server cannot perform",
    ).toBeFalsy();

    const wired = await (
      await server.handleOidcMetadataRequest(
        new Request(
          "https://auth.example.com/.well-known/openid-configuration",
        ),
      )
    ).json();
    expect(wired.end_session_endpoint).toStrictEqual(
      "https://auth.example.com/end_session",
    );
  });
});

describe("JWT access token expiry", () => {
  class JwtTokenService extends MemoryTokenService<
    TestClient,
    TestUser,
    BasicScope
  > {
    override generateAccessToken: MemoryTokenService<
      TestClient,
      TestUser,
      BasicScope
    >["generateAccessToken"];
    constructor(
      options: ConstructorParameters<
        typeof MemoryTokenService<TestClient, TestUser, BasicScope>
      >[0],
      signingKey: SigningKey,
    ) {
      super(options);
      this.generateAccessToken = createJwtAccessTokenGenerator({
        signingKeys: new StaticSigningKeyProvider(signingKey),
        issuer: "https://auth.example.com",
        lifetimeSeconds: 3600,
      });
    }
  }

  async function createJwtServices(options: {
    accessTokenLifetime?: number;
    refreshTokenLifetime?: number;
    refreshTokenMaxLifetime?: number;
  }) {
    const signingKey = await generateSigningKey();
    const userService = new MemoryUserService();
    const clientService = new MemoryClientService(userService);
    const tokenService = new JwtTokenService(
      { clientService, userService, ...options },
      signingKey,
    );
    await userService.add(testUser, "password");
    await clientService.add(testClient, "secret", testUser.id);
    return { signingKey, clientService, tokenService };
  }

  async function expOf(jwt: string, key: SigningKey): Promise<number> {
    const claims = await verifyJwt(jwt, key.publicJwk);
    assert.exists(claims);
    assert(typeof claims!.exp === "number");
    return claims!.exp as number;
  }

  function seconds(date: Date | undefined): number {
    assert.exists(date);
    return Math.ceil(date!.getTime() / 1000);
  }

  it("never outlives the stored access token expiry", async () => {
    const { signingKey, clientService, tokenService } = await createJwtServices(
      { accessTokenLifetime: 60 },
    );
    const grant = new ClientCredentialsGrant<TestClient, TestUser, BasicScope>({
      resolve: () => ({ clientService, tokenService }),
    });

    const token = await grant.generateToken(
      testClient,
      testUser,
      new BasicScope("read"),
      tokenService,
    );

    const exp = await expOf(token.accessToken, signingKey);
    assert(
      exp <= seconds(token.accessTokenExpiresAt),
      `JWT exp ${exp} must not exceed the stored expiry ${seconds(
        token.accessTokenExpiresAt,
      )}`,
    );
  });

  it("never outlives a new refresh family's cap", async () => {
    const { signingKey, clientService, tokenService } = await createJwtServices(
      {
        accessTokenLifetime: 600,
        refreshTokenLifetime: 30,
        refreshTokenMaxLifetime: 30,
      },
    );
    const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
      resolve: () => ({ clientService, tokenService }),
    });

    const token = await grant.generateToken(
      testClient,
      testUser,
      new BasicScope("read"),
      tokenService,
    );

    const exp = await expOf(token.accessToken, signingKey);
    assert(
      exp <= seconds(token.accessTokenExpiresAt),
      `JWT exp ${exp} must not exceed the family-capped expiry ${seconds(
        token.accessTokenExpiresAt,
      )}`,
    );
    assert(exp <= Math.ceil(Date.now() / 1000) + 30);
  });

  it("never outlives the family cap on a rotation", async () => {
    const { signingKey, clientService, tokenService } = await createJwtServices(
      {
        accessTokenLifetime: 600,
        refreshTokenLifetime: 30,
        refreshTokenMaxLifetime: 30,
      },
    );
    const grant = new RefreshTokenGrant<TestClient, TestUser, BasicScope>({
      resolve: () => ({ clientService, tokenService }),
    });
    const familyCreatedAt = new Date(Date.now() - 20_000);
    const original: RefreshToken<TestClient, TestUser, BasicScope> = {
      accessToken: crypto.randomUUID(),
      accessTokenExpiresAt: new Date(Date.now() + 600_000),
      refreshToken: crypto.randomUUID(),
      refreshTokenExpiresAt: new Date(Date.now() + 30_000),
      client: testClient,
      user: testUser,
      scope: new BasicScope("read"),
      familyId: crypto.randomUUID(),
      familyCreatedAt,
    };
    await tokenService.save(original);

    const rotated = await exchangeToken(
      grant,
      tokenRequest(
        { grant_type: "refresh_token", refresh_token: original.refreshToken },
        basicAuthHeader("client-1", "secret"),
      ),
      testClient,
    );

    const exp = await expOf(rotated.accessToken, signingKey);
    assert(
      exp <= seconds(rotated.accessTokenExpiresAt),
      `JWT exp ${exp} must not exceed the rotation's capped expiry ${seconds(
        rotated.accessTokenExpiresAt,
      )}`,
    );
    assert(exp <= seconds(familyCreatedAt) + 30);
  });
});

describe("OIDC configuration assertions", () => {
  it("reports oidcEnabled false on a server without signing keys", () => {
    expect(createServer().oidcEnabled).toBeFalsy();
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
    const error = thrown(
      () => createServer({ requireOidc: true }),
      Error,
      "requireOidc",
    );
    expect(error.message).toContain("signingKeys");
    expect(error.message).toContain("id_token");
    expect(error.message).toContain("/jwks");
  });

  it("constructs with requireOidc when signing keys are configured", async () => {
    const server = createServer({
      requireOidc: true,
      signingKeys: new StaticSigningKeyProvider(await generateSigningKey()),
    });
    assert(server.oidcEnabled);
  });
});
