import { assert, describe, expect, it } from "vitest";
import { rejection } from "../../_test_assert.ts";
import type { BasicScope } from "../../models/scope.ts";
import {
  AuthorizationServer,
  localAuthServerFetch,
} from "../../server/authorization-server.ts";
import { AuthorizationCodeGrant } from "../../server/grants/authorization-code.ts";
import {
  generateSigningKey,
  StaticSigningKeyProvider,
} from "../../server/signing-keys.ts";
import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../../testing/_test_fixtures.ts";
import { ExternalAuthError } from "./errors.ts";
import { DEFAULT_MAX_TRANSIENT_AGE_MS, ExternalAuthFlow } from "./flow.ts";
import { oidcProvider } from "./oidc.ts";

const issuer = "https://idp.example";
const redirectUri = "https://app.example/cb";
const user: TestUser = { id: "user-1", username: "ada" };
const webClient: TestClient = {
  id: "web-app",
  grants: ["authorization_code"],
  redirectUris: [redirectUri],
};
const userClaims = {
  email: "ada@idp.example",
  email_verified: true,
  name: "Ada Lovelace",
  given_name: "Ada",
  family_name: "Lovelace",
  picture: "https://img.example/ada.png",
};

async function createHarness(options: { maxTransientAgeMs?: number } = {}) {
  const userService = new MemoryUserService<TestUser>();
  const clientService = new MemoryClientService<TestClient, TestUser>(
    userService,
  );
  const tokenService = new MemoryTokenService<TestClient, TestUser, BasicScope>(
    { clientService, userService },
  );
  const authorizationCodeService = new MemoryAuthorizationCodeService<
    TestClient,
    TestUser,
    BasicScope
  >({ clientService, userService });
  await userService.add(user, "password");
  await clientService.add(webClient, "web-secret");
  const server = new AuthorizationServer<TestClient, TestUser, BasicScope>({
    resolve: () => ({ services: { clientService, tokenService }, issuer }),
    grants: {
      authorization_code: new AuthorizationCodeGrant<
        TestClient,
        TestUser,
        BasicScope
      >({
        resolve: () => ({
          clientService,
          tokenService,
          authorizationCodeService,
        }),
      }),
    },
    scopesSupported: ["openid", "email", "profile"],
    signingKeys: new StaticSigningKeyProvider(await generateSigningKey()),
    userClaims: () => userClaims,
  });
  const provider = oidcProvider({
    id: "test-idp",
    displayName: "Test IdP",
    issuer,
    clientId: webClient.id,
    clientSecret: "web-secret",
    fetch: localAuthServerFetch(server),
  });
  const flow = new ExternalAuthFlow({
    provider,
    maxTransientAgeMs: options.maxTransientAgeMs,
  });
  const authorize = async (url: string): Promise<URL> => {
    const response = await server.handleAuthorizeRequest(new Request(url), () =>
      Promise.resolve({ user }),
    );
    expect(response.status).toStrictEqual(302);
    return new URL(response.headers.get("location")!);
  };
  return { flow, authorize };
}

describe("ExternalAuthFlow with the embedded OIDC provider", () => {
  it("completes start → authorize → finish with a normalized profile and nonce round-trip", async () => {
    const { flow, authorize } = await createHarness();

    const { url, transient } = await flow.start({ redirectUri });
    const authorizeUrl = new URL(url);
    expect(authorizeUrl.origin + authorizeUrl.pathname).toStrictEqual(
      `${issuer}/authorize`,
    );
    expect(authorizeUrl.searchParams.get("state")).toStrictEqual(
      transient.state,
    );
    expect(authorizeUrl.searchParams.get("nonce")).toStrictEqual(
      transient.nonce,
    );
    expect(authorizeUrl.searchParams.get("scope")).toStrictEqual(
      "openid email profile",
    );
    expect(
      authorizeUrl.searchParams.get("code_challenge_method"),
    ).toStrictEqual("S256");
    assert(authorizeUrl.searchParams.get("code_challenge"));
    expect(transient.provider).toStrictEqual("test-idp");
    expect(transient.redirectUri).toStrictEqual(redirectUri);
    assert(transient.codeVerifier);
    assert(transient.nonce);

    const callback = await authorize(url);
    const profile = await flow.finish({ params: callback, transient });

    expect(profile.provider).toStrictEqual("test-idp");
    expect(profile.subject).toStrictEqual(user.id);
    expect(profile.email).toStrictEqual(userClaims.email);
    expect(profile.emailVerified).toStrictEqual(true);
    expect(profile.name).toStrictEqual(userClaims.name);
    expect(profile.givenName).toStrictEqual(userClaims.given_name);
    expect(profile.familyName).toStrictEqual(userClaims.family_name);
    expect(profile.picture).toStrictEqual(userClaims.picture);
    expect(profile.raw.nonce).toStrictEqual(transient.nonce);
    expect(profile.raw.aud).toStrictEqual(webClient.id);
  });

  it("rejects a callback whose state does not match, timing-safely", async () => {
    const { flow, authorize } = await createHarness();
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    callback.searchParams.set("state", "tampered-state");

    const error = await rejection(
      () => flow.finish({ params: callback, transient }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("state_mismatch");
    expect(error.message).toContain("[test-idp]");
  });

  it("rejects a transient older than the default 10 minute window", async () => {
    const { flow, authorize } = await createHarness();
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    transient.createdAt = Date.now() - DEFAULT_MAX_TRANSIENT_AGE_MS - 1;

    const error = await rejection(
      () => flow.finish({ params: callback, transient }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("transient_expired");
    expect(error.message).toContain(String(DEFAULT_MAX_TRANSIENT_AGE_MS));
  });

  it("honors a configured maxTransientAgeMs", async () => {
    const { flow, authorize } = await createHarness({
      maxTransientAgeMs: 1000,
    });
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    transient.createdAt = Date.now() - 2000;

    const error = await rejection(
      () => flow.finish({ params: callback, transient }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("transient_expired");
  });

  it("surfaces a provider error callback diagnosably", async () => {
    const { flow } = await createHarness();
    const { transient } = await flow.start({ redirectUri });
    const params = new URLSearchParams({
      error: "access_denied",
      error_description: "User cancelled the request",
      state: transient.state,
    });

    const error = await rejection(
      () => flow.finish({ params, transient }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[test-idp]");
    expect(error.message).toContain("access_denied");
    expect(error.message).toContain("User cancelled the request");
  });

  it("rejects an id_token whose nonce does not match the transient", async () => {
    const { flow, authorize } = await createHarness();
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    transient.nonce = "a-different-nonce";

    const error = await rejection(
      () => flow.finish({ params: callback, transient }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("nonce_mismatch");
  });

  it("reports state_mismatch, not provider_error, for a forged error callback with a bad state", async () => {
    const { flow } = await createHarness();
    const { transient } = await flow.start({ redirectUri });
    const params = new URLSearchParams({
      error: "access_denied",
      error_description: "attacker-controlled text",
      state: "not-the-real-state",
    });

    const error = await rejection(
      () => flow.finish({ params, transient }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("state_mismatch");
  });

  it("parses a path-relative callback URL string", async () => {
    const { flow, authorize } = await createHarness();
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    const relative = `${callback.pathname}${callback.search}`;
    assert(relative.startsWith("/"));

    const profile = await flow.finish({ params: relative, transient });
    expect(profile.subject).toStrictEqual(user.id);
  });

  it("rejects a callback missing the code parameter", async () => {
    const { flow } = await createHarness();
    const { transient } = await flow.start({ redirectUri });
    const params = new URLSearchParams({ state: transient.state });

    const error = await rejection(
      () => flow.finish({ params, transient }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("invalid_callback");
    expect(error.message).toContain("code");
  });

  it("rejects a transient started for a different provider", async () => {
    const { flow, authorize } = await createHarness();
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    transient.provider = "github";

    const error = await rejection(
      () => flow.finish({ params: callback, transient }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("configuration");
    expect(error.message).toContain("github");
  });

  it("names the issuer and the well-known URL when discovery fails", async () => {
    const provider = oidcProvider({
      id: "broken",
      issuer: "https://missing.example",
      clientId: "web-app",
      clientSecret: "secret",
      fetch: () => Promise.resolve(new Response("Not Found", { status: 404 })),
    });
    const flow = new ExternalAuthFlow({ provider });

    const error = await rejection(
      () => flow.start({ redirectUri }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("configuration");
    expect(error.message).toContain("https://missing.example");
    expect(error.message).toContain(
      "https://missing.example/.well-known/openid-configuration",
    );
  });
});
