import { assertEquals, assertExists } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import type { AuthenticationContext } from "../models/authentication.ts";
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
import { AuthorizationServer } from "./authorization-server.ts";
import { AuthorizationCodeGrant } from "./grants/authorization-code.ts";
import { RefreshTokenGrant } from "./grants/refresh-token.ts";
import {
  createJwtAccessTokenGenerator,
  generateSigningKey,
  StaticSigningKeyProvider,
  verifyJwt,
} from "./signing-keys.ts";

describe("authentication event propagation", () => {
  for (const recorded of ["verified", "unknown", "legacy"]) {
    it(`keeps ${recorded} context on code, token views and refresh descendants`, async () => {
      const user: TestUser = { id: "context-user", username: "person" };
      const client: TestClient = {
        id: "context-client",
        confidential: true,
        grants: ["authorization_code", "refresh_token"],
        redirectUris: ["https://app.example/callback"],
      };
      const userService = new MemoryUserService();
      const clientService = new MemoryClientService(userService);
      const key = await generateSigningKey();
      class JwtTokens extends MemoryTokenService<TestClient, TestUser> {
        override generateAccessToken = createJwtAccessTokenGenerator({
          signingKeys: new StaticSigningKeyProvider(key),
          issuer: "https://auth.example",
          userClaims: (_user, _scope, _client, event) => ({ ...event }),
        });
      }
      const tokenService = new JwtTokens({ clientService, userService });
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
      const claims = (
        _user: TestUser,
        _scope?: BasicScope | null,
        event?: AuthenticationContext,
      ): Record<string, unknown> => ({ ...event });
      const server = new AuthorizationServer<TestClient, TestUser, BasicScope>({
        resolve: () => ({ services, issuer: "https://auth.example" }),
        grants: {
          authorization_code: new AuthorizationCodeGrant<TestClient, TestUser>({
            resolve: () => services,
            requirePKCE: false,
          }),
          refresh_token: new RefreshTokenGrant<TestClient, TestUser>({
            resolve: () => services,
          }),
        },
        signingKeys: new StaticSigningKeyProvider(key),
        userClaims: claims,
        introspectionClaims: (token) => ({ ...token.authenticationContext }),
      });
      const event:
        | { auth_time?: number; acr?: string; amr?: string[] }
        | undefined = recorded === "verified"
          ? { auth_time: 1000, acr: "single", amr: ["pwd"] }
          : recorded === "unknown"
          ? {}
          : undefined;
      const expected = structuredClone(event);
      const expectedClaims = {
        auth_time: expected?.auth_time,
        acr: expected?.acr,
        amr: expected?.amr,
      };
      const authorize = await server.handleAuthorizeRequest(
        new Request(
          "https://auth.example/authorize?client_id=context-client&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=state",
        ),
        () => Promise.resolve({ user, authenticationContext: event }),
      );
      assertEquals(authorize.status, 302);
      const code = new URL(authorize.headers.get("location")!).searchParams.get(
        "code",
      );
      assertExists(code);
      if (event) {
        event.auth_time = 2000;
        event.acr = "mfa";
        if (event.amr) event.amr.push("otp", "mfa");
        else event.amr = ["pwd", "otp", "mfa"];
      }
      const exchange = await server.handleTokenRequest(tokenRequest({
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://app.example/callback",
      }, basicAuthHeader(client.id, "secret")));
      assertEquals(exchange.status, 200);
      let credential = await exchange.json();
      for (let generation = 0; generation < 3; generation++) {
        const id = await verifyJwt(credential.id_token, key.publicJwk);
        assertExists(id);
        assertEquals(
          { auth_time: id.auth_time, acr: id.acr, amr: id.amr },
          expectedClaims,
        );
        const access = await verifyJwt(credential.access_token, key.publicJwk);
        assertExists(access);
        assertEquals(
          { auth_time: access.auth_time, acr: access.acr, amr: access.amr },
          expectedClaims,
        );
        const info = await server.handleUserInfoRequest(
          new Request("https://auth.example/userinfo", {
            headers: { authorization: `Bearer ${credential.access_token}` },
          }),
        );
        assertEquals(info.status, 200);
        assertEquals(await info.json(), { sub: user.id, ...expected });
        const introspection = await server.handleIntrospectionRequest(
          tokenRequest(
            { token: credential.access_token },
            basicAuthHeader(client.id, "secret"),
          ),
        );
        const inspected = await introspection.json();
        assertEquals({
          auth_time: inspected.auth_time,
          acr: inspected.acr,
          amr: inspected.amr,
        }, expectedClaims);
        const stored = await tokenService.getToken(credential.access_token);
        assertEquals(stored?.authenticationContext, expected);
        const refresh = await server.handleTokenRequest(
          tokenRequest({
            grant_type: "refresh_token",
            refresh_token: credential.refresh_token,
          }, basicAuthHeader(client.id, "secret")),
        );
        assertEquals(refresh.status, 200);
        credential = await refresh.json();
      }
    });
  }

  it("does not attach a user event to a token without a user", async () => {
    const userService = new MemoryUserService();
    const clientService = new MemoryClientService(userService);
    const key = await generateSigningKey();
    let userClaimsCalled = false;
    class JwtTokens extends MemoryTokenService<TestClient, TestUser> {
      override generateAccessToken = createJwtAccessTokenGenerator({
        signingKeys: new StaticSigningKeyProvider(key),
        issuer: "https://auth.example",
        userClaims: (_user, _scope, _client, event) => {
          userClaimsCalled = true;
          return { ...event };
        },
      });
    }
    const tokenService = new JwtTokens({ clientService, userService });
    const grant = new RefreshTokenGrant<TestClient, TestUser>({
      resolve: () => ({ clientService, tokenService }),
    });
    const token = await grant.generateToken(
      { id: "machine" },
      undefined,
      new BasicScope("read"),
      tokenService,
      { auth_time: 1000, acr: "mfa", amr: ["pwd", "otp", "mfa"] },
    );
    assertEquals(token.authenticationContext, undefined);
    const claims = await verifyJwt(token.accessToken, key.publicJwk);
    assertExists(claims);
    assertEquals(claims.sub, "machine");
    for (const name of ["auth_time", "acr", "amr"]) {
      assertEquals(Object.hasOwn(claims, name), false);
    }
    assertEquals(userClaimsCalled, false);
  });

  it("exposes raw authentication controls to application policy without converting malformed values", () => {
    const userService = new MemoryUserService();
    const clientService = new MemoryClientService(userService);
    const tokenService = new MemoryTokenService({ clientService, userService });
    const server = new AuthorizationServer<TestClient, TestUser, BasicScope>({
      resolve: () => ({ services: { clientService, tokenService } }),
      grants: {},
    });
    const parsed = server.parseAuthorizeParameters(
      new Request(
        "https://auth.example/authorize?acr_values=single+mfa&max_age=0&prompt=login",
      ),
    );
    assertEquals(parsed.acrValues, "single mfa");
    assertEquals(parsed.maxAge, "0");
    assertEquals(parsed.prompt, "login");
    assertEquals(
      server.parseAuthorizeParameters(
        new Request("https://auth.example/authorize?max_age=garbage"),
      ).maxAge,
      "garbage",
    );
  });
});
