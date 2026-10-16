import { describe, expect, it } from "vitest";
import { rejection, thrown } from "../../_test_assert.ts";
import { generateCodeChallenge } from "../../utils/pkce.ts";
import { ExternalAuthError } from "./errors.ts";
import { ExternalAuthFlow } from "./flow.ts";
import { oauth2Provider, type OAuth2ProviderOptions } from "./oauth2.ts";

const redirectUri = "https://app.example/auth/social/acme/callback";

function acmeProvider(authorizationParams: Record<string, string>) {
  return oauth2Provider({
    id: "acme",
    displayName: "Acme",
    authorizationEndpoint: "https://acme.example/oauth/authorize",
    tokenEndpoint: "https://acme.example/oauth/token",
    clientId: "acme-client-id",
    clientSecret: "acme-client-secret",
    defaultScopes: ["profile"],
    usesPkce: true,
    mapProfile: ({ profile }) => ({ subject: String(profile.id) }),
    authorizationParams,
  });
}

describe("oauth2Provider authorize URL", () => {
  it("keeps the protocol params over same-named authorizationParams", async () => {
    const provider = acmeProvider({
      state: "attacker-state",
      code_challenge: "attacker-challenge",
      code_challenge_method: "plain",
      redirect_uri: "https://attacker.example/callback",
      client_id: "attacker-client",
      response_type: "token",
      scope: "admin",
      audience: "https://api.acme.example",
    });
    const codeVerifier = "verifier-verifier-verifier-verifier-verifier";
    const url = new URL(
      await provider.buildAuthorizationUrl({
        redirectUri,
        scopes: ["profile"],
        state: "flow-state",
        codeVerifier,
      }),
    );

    expect(url.searchParams.get("state")).toStrictEqual("flow-state");
    expect(url.searchParams.get("code_challenge")).toStrictEqual(
      await generateCodeChallenge(codeVerifier),
    );
    expect(url.searchParams.get("code_challenge_method")).toStrictEqual("S256");
    expect(url.searchParams.get("redirect_uri")).toStrictEqual(redirectUri);
    expect(url.searchParams.get("client_id")).toStrictEqual("acme-client-id");
    expect(url.searchParams.get("response_type")).toStrictEqual("code");
    expect(url.searchParams.get("scope")).toStrictEqual("profile");
    expect(url.searchParams.get("audience")).toStrictEqual(
      "https://api.acme.example",
    );
    expect(url.searchParams.getAll("state").length).toStrictEqual(1);
  });
});

describe("oauth2Provider authorization response issuer (RFC 9207)", () => {
  const issuer = "https://acme.example";

  function issuerHarness(
    config: Pick<
      OAuth2ProviderOptions,
      "issuer" | "authorizationResponseIssParameterSupported"
    >,
  ) {
    const context = { tokenCalls: 0 };
    const flow = new ExternalAuthFlow({
      provider: oauth2Provider({
        id: "acme",
        displayName: "Acme",
        authorizationEndpoint: `${issuer}/oauth/authorize`,
        tokenEndpoint: `${issuer}/oauth/token`,
        clientId: "acme-client-id",
        clientSecret: "acme-client-secret",
        defaultScopes: ["profile"],
        mapProfile: ({ profile }) => ({ subject: String(profile.user_id) }),
        fetch: (input) => {
          const url = input instanceof Request ? input.url : String(input);
          if (url !== `${issuer}/oauth/token`) {
            throw new Error(`unexpected fetch: ${url}`);
          }
          context.tokenCalls++;
          return Promise.resolve(
            Response.json({ access_token: "acme-token", user_id: "acme-1" }),
          );
        },
        ...config,
      }),
    });
    const finish = async (iss?: string) => {
      const { transient } = await flow.start({ redirectUri });
      const params = new URLSearchParams({
        code: "acme-code",
        state: transient.state,
      });
      if (iss !== undefined) params.set("iss", iss);
      return await flow.finish({ params, transient });
    };
    return { context, finish };
  }

  it("refuses an iss other than the configured issuer before redeeming the code", async () => {
    const { context, finish } = issuerHarness({ issuer });
    const error = await rejection(
      () => finish("https://evil.example"),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("invalid_callback");
    expect(error.message).toContain("[acme]");
    expect(context.tokenCalls).toStrictEqual(0);
  });

  it("accepts an iss equal to the configured issuer", async () => {
    const { context, finish } = issuerHarness({ issuer });
    const profile = await finish(issuer);
    expect(profile.subject).toStrictEqual("acme-1");
    expect(context.tokenCalls).toStrictEqual(1);
  });

  it("accepts a missing iss unless the provider is configured as sending it", async () => {
    const { finish } = issuerHarness({ issuer });
    const profile = await finish();
    expect(profile.subject).toStrictEqual("acme-1");
  });

  it("refuses a missing iss when configured with authorizationResponseIssParameterSupported", async () => {
    const { context, finish } = issuerHarness({
      issuer,
      authorizationResponseIssParameterSupported: true,
    });
    const error = await rejection(() => finish(), ExternalAuthError);
    expect(error.code).toStrictEqual("invalid_callback");
    expect(error.message).toContain("missing `iss`");
    expect(context.tokenCalls).toStrictEqual(0);
  });

  it("keeps ignoring iss when no issuer is configured", async () => {
    const { finish } = issuerHarness({});
    const profile = await finish("https://anything.example");
    expect(profile.subject).toStrictEqual("acme-1");
  });

  it("rejects authorizationResponseIssParameterSupported without an issuer at construction", () => {
    const error = thrown(
      () =>
        oauth2Provider({
          id: "acme",
          displayName: "Acme",
          authorizationEndpoint: `${issuer}/oauth/authorize`,
          tokenEndpoint: `${issuer}/oauth/token`,
          clientId: "acme-client-id",
          clientSecret: "acme-client-secret",
          defaultScopes: ["profile"],
          mapProfile: ({ profile }) => ({ subject: String(profile.user_id) }),
          authorizationResponseIssParameterSupported: true,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("configuration");
    expect(error.message).toContain("issuer");
  });
});
