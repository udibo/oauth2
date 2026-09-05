import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";

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
    const response = await server.handleAuthorizeRequest(
      new Request(url),
      () => Promise.resolve({ user }),
    );
    assertEquals(response.status, 302);
    return new URL(response.headers.get("location")!);
  };
  return { flow, authorize };
}

describe("ExternalAuthFlow with the embedded OIDC provider", () => {
  it("completes start → authorize → finish with a normalized profile and nonce round-trip", async () => {
    const { flow, authorize } = await createHarness();

    const { url, transient } = await flow.start({ redirectUri });
    const authorizeUrl = new URL(url);
    assertEquals(
      authorizeUrl.origin + authorizeUrl.pathname,
      `${issuer}/authorize`,
    );
    assertEquals(authorizeUrl.searchParams.get("state"), transient.state);
    assertEquals(authorizeUrl.searchParams.get("nonce"), transient.nonce);
    assertEquals(
      authorizeUrl.searchParams.get("scope"),
      "openid email profile",
    );
    assertEquals(
      authorizeUrl.searchParams.get("code_challenge_method"),
      "S256",
    );
    assert(authorizeUrl.searchParams.get("code_challenge"));
    assertEquals(transient.provider, "test-idp");
    assertEquals(transient.redirectUri, redirectUri);
    assert(transient.codeVerifier);
    assert(transient.nonce);

    const callback = await authorize(url);
    const profile = await flow.finish({ params: callback, transient });

    assertEquals(profile.provider, "test-idp");
    assertEquals(profile.subject, user.id);
    assertEquals(profile.email, userClaims.email);
    assertEquals(profile.emailVerified, true);
    assertEquals(profile.name, userClaims.name);
    assertEquals(profile.givenName, userClaims.given_name);
    assertEquals(profile.familyName, userClaims.family_name);
    assertEquals(profile.picture, userClaims.picture);
    assertEquals(profile.raw.nonce, transient.nonce);
    assertEquals(profile.raw.aud, webClient.id);
  });

  it("rejects a callback whose state does not match, timing-safely", async () => {
    const { flow, authorize } = await createHarness();
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    callback.searchParams.set("state", "tampered-state");

    const error = await assertRejects(
      () => flow.finish({ params: callback, transient }),
      ExternalAuthError,
    );
    assertEquals(error.code, "state_mismatch");
    assertStringIncludes(error.message, "[test-idp]");
  });

  it("rejects a transient older than the default 10 minute window", async () => {
    const { flow, authorize } = await createHarness();
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    transient.createdAt = Date.now() - DEFAULT_MAX_TRANSIENT_AGE_MS - 1;

    const error = await assertRejects(
      () => flow.finish({ params: callback, transient }),
      ExternalAuthError,
    );
    assertEquals(error.code, "transient_expired");
    assertStringIncludes(error.message, String(DEFAULT_MAX_TRANSIENT_AGE_MS));
  });

  it("honors a configured maxTransientAgeMs", async () => {
    const { flow, authorize } = await createHarness({
      maxTransientAgeMs: 1000,
    });
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    transient.createdAt = Date.now() - 2000;

    const error = await assertRejects(
      () => flow.finish({ params: callback, transient }),
      ExternalAuthError,
    );
    assertEquals(error.code, "transient_expired");
  });

  it("surfaces a provider error callback diagnosably", async () => {
    const { flow } = await createHarness();
    const { transient } = await flow.start({ redirectUri });
    const params = new URLSearchParams({
      error: "access_denied",
      error_description: "User cancelled the request",
      state: transient.state,
    });

    const error = await assertRejects(
      () => flow.finish({ params, transient }),
      ExternalAuthError,
    );
    assertEquals(error.code, "provider_error");
    assertStringIncludes(error.message, "[test-idp]");
    assertStringIncludes(error.message, "access_denied");
    assertStringIncludes(error.message, "User cancelled the request");
  });

  it("rejects an id_token whose nonce does not match the transient", async () => {
    const { flow, authorize } = await createHarness();
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    transient.nonce = "a-different-nonce";

    const error = await assertRejects(
      () => flow.finish({ params: callback, transient }),
      ExternalAuthError,
    );
    assertEquals(error.code, "nonce_mismatch");
  });

  it("reports state_mismatch, not provider_error, for a forged error callback with a bad state", async () => {
    const { flow } = await createHarness();
    const { transient } = await flow.start({ redirectUri });
    const params = new URLSearchParams({
      error: "access_denied",
      error_description: "attacker-controlled text",
      state: "not-the-real-state",
    });

    const error = await assertRejects(
      () => flow.finish({ params, transient }),
      ExternalAuthError,
    );
    assertEquals(error.code, "state_mismatch");
  });

  it("parses a path-relative callback URL string", async () => {
    const { flow, authorize } = await createHarness();
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    const relative = `${callback.pathname}${callback.search}`;
    assert(relative.startsWith("/"));

    const profile = await flow.finish({ params: relative, transient });
    assertEquals(profile.subject, user.id);
  });

  it("rejects a callback missing the code parameter", async () => {
    const { flow } = await createHarness();
    const { transient } = await flow.start({ redirectUri });
    const params = new URLSearchParams({ state: transient.state });

    const error = await assertRejects(
      () => flow.finish({ params, transient }),
      ExternalAuthError,
    );
    assertEquals(error.code, "invalid_callback");
    assertStringIncludes(error.message, "code");
  });

  it("rejects a transient started for a different provider", async () => {
    const { flow, authorize } = await createHarness();
    const { url, transient } = await flow.start({ redirectUri });
    const callback = await authorize(url);
    transient.provider = "github";

    const error = await assertRejects(
      () => flow.finish({ params: callback, transient }),
      ExternalAuthError,
    );
    assertEquals(error.code, "configuration");
    assertStringIncludes(error.message, "github");
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

    const error = await assertRejects(
      () => flow.start({ redirectUri }),
      ExternalAuthError,
    );
    assertEquals(error.code, "configuration");
    assertStringIncludes(error.message, "https://missing.example");
    assertStringIncludes(
      error.message,
      "https://missing.example/.well-known/openid-configuration",
    );
  });
});
