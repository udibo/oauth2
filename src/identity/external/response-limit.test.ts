import { describe, expect, it } from "vitest";
import { rejection } from "../../_test_assert.ts";
import {
  jsonOfSize,
  type Reply,
  type ReplyServer,
  serveReplies,
} from "../../_test_response-server.ts";
import { encodeBase64 } from "../../utils/_encoding.ts";
import { base64urlEncode } from "../../utils/crypto.ts";
import { appleProvider } from "./apple.ts";
import { ExternalAuthError } from "./errors.ts";
import { githubProvider } from "./github.ts";
import { oauth2Provider } from "./oauth2.ts";
import { oidcProvider } from "./oidc.ts";

const LIMIT = 64 * 1024;
const redirectUri = "https://app.example/cb";
const TOKEN_RESPONSE: Reply = {
  body: JSON.stringify({ access_token: "at", token_type: "Bearer" }),
  transfer: "length",
};

function serveRoutes(routes: Record<string, Reply>): Promise<ReplyServer> {
  return serveReplies(
    (pathname) =>
      routes[pathname] ?? { status: 404, body: "{}", transfer: "length" },
  );
}

function sameHostFetch(server: ReplyServer): typeof fetch {
  return (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input);
    return fetch(`${server.origin}${url.pathname}`, init);
  };
}

function genericProvider(server: ReplyServer) {
  return oauth2Provider({
    id: "acme",
    displayName: "Acme",
    authorizationEndpoint: `${server.origin}/authorize`,
    tokenEndpoint: `${server.origin}/token`,
    userInfoEndpoint: `${server.origin}/userinfo`,
    clientId: "client",
    clientSecret: "secret",
    defaultScopes: ["identify"],
    mapProfile: ({ profile }) => ({ subject: String(profile.id) }),
  });
}

describe("external provider response size limit", () => {
  it("reads a profile response of exactly 64 KiB", async () => {
    await using server = await serveRoutes({
      "/token": TOKEN_RESPONSE,
      "/userinfo": { body: jsonOfSize(LIMIT, { id: 7 }), transfer: "chunked" },
    });

    const profile = await genericProvider(server).fetchProfile({
      code: "code",
      redirectUri,
    });

    expect(profile.subject).toBe("7");
  });

  for (const transfer of ["length", "chunked"] as const) {
    it(`refuses a profile response one byte over 64 KiB (${transfer})`, async () => {
      await using server = await serveRoutes({
        "/token": TOKEN_RESPONSE,
        "/userinfo": { body: jsonOfSize(LIMIT + 1, { id: 7 }), transfer },
      });

      const error = await rejection(
        () =>
          genericProvider(server).fetchProfile({ code: "code", redirectUri }),
        ExternalAuthError,
        `Acme profile endpoint response exceeded ${LIMIT} bytes`,
      );
      expect(error.code).toBe("provider_error");
    });
  }

  it("stops reading an endless profile response at the cap and cancels it", async () => {
    await using server = await serveRoutes({
      "/token": TOKEN_RESPONSE,
      "/userinfo": { body: '{"id":7', transfer: "endless" },
    });

    await rejection(
      () => genericProvider(server).fetchProfile({ code: "code", redirectUri }),
      ExternalAuthError,
      `Acme profile endpoint response exceeded ${LIMIT} bytes`,
    );
    await server.abandoned;
  });

  it("quotes no more than the cap of an endless error body and cancels it", async () => {
    await using server = await serveRoutes({
      "/token": TOKEN_RESPONSE,
      "/userinfo": {
        status: 401,
        contentType: "text/plain",
        body: "denied",
        transfer: "endless",
      },
    });

    await rejection(
      () => genericProvider(server).fetchProfile({ code: "code", redirectUri }),
      ExternalAuthError,
      "profile endpoint responded with HTTP 401",
    );
    await server.abandoned;
  });

  it("refuses a GitHub user response over 64 KiB", async () => {
    await using server = await serveRoutes({
      "/login/oauth/access_token": TOKEN_RESPONSE,
      "/user": { body: jsonOfSize(LIMIT + 1, { id: 7 }), transfer: "chunked" },
      "/user/emails": { body: "[]", transfer: "length" },
    });
    const provider = githubProvider({
      clientId: "client",
      clientSecret: "secret",
      fetch: sameHostFetch(server),
    });

    await rejection(
      () => provider.fetchProfile({ code: "code", redirectUri }),
      ExternalAuthError,
      `https://api.github.com/user response exceeded ${LIMIT} bytes`,
    );
  });

  it("discards an OIDC UserInfo response over 64 KiB and keeps the id_token claims", async () => {
    const issuer = "https://sso.example";
    const segment = (value: unknown) =>
      base64urlEncode(new TextEncoder().encode(JSON.stringify(value)));
    const idToken = `${segment({ alg: "ES256" })}.${segment({
      iss: issuer,
      aud: "client",
      sub: "sso-1",
      email: "id-token@example.com",
      exp: Math.floor(Date.now() / 1000) + 3600,
    })}.sig`;
    await using server = await serveRoutes({
      "/.well-known/openid-configuration": {
        body: JSON.stringify({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          userinfo_endpoint: `${issuer}/userinfo`,
        }),
        transfer: "length",
      },
      "/token": {
        body: JSON.stringify({
          access_token: "at",
          token_type: "Bearer",
          id_token: idToken,
        }),
        transfer: "length",
      },
      "/userinfo": {
        body: jsonOfSize(LIMIT + 1, {
          sub: "sso-1",
          email: "userinfo@example.com",
        }),
        transfer: "chunked",
      },
    });
    const provider = oidcProvider({
      issuer,
      clientId: "client",
      clientSecret: "secret",
      fetch: sameHostFetch(server),
    });

    const profile = await provider.fetchProfile({ code: "code", redirectUri });

    expect(profile.email).toBe("id-token@example.com");
  });

  it("refuses an Apple JWKS over 64 KiB", async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
    const privateKey = `-----BEGIN PRIVATE KEY-----\n${encodeBase64(
      new Uint8Array(pkcs8),
    )}\n-----END PRIVATE KEY-----`;
    const segment = (value: unknown) =>
      base64urlEncode(new TextEncoder().encode(JSON.stringify(value)));
    await using server = await serveRoutes({
      "/auth/token": {
        body: JSON.stringify({
          id_token: `${segment({ alg: "RS256", kid: "k" })}.${segment({})}.sig`,
        }),
        transfer: "length",
      },
      "/auth/keys": {
        body: jsonOfSize(LIMIT + 1, { keys: [] }),
        transfer: "chunked",
      },
    });
    const provider = appleProvider({
      clientId: "com.example.web",
      teamId: "ABCDE12345",
      keyId: "KEY1234567",
      privateKey,
      fetch: sameHostFetch(server),
    });

    await rejection(
      () => provider.fetchProfile({ code: "code", redirectUri }),
      ExternalAuthError,
      `Apple's JWKS endpoint response exceeded ${LIMIT} bytes`,
    );
  });
});
