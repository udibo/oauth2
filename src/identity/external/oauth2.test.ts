import { describe, expect, it } from "vitest";
import { generateCodeChallenge } from "../../utils/pkce.ts";
import { oauth2Provider } from "./oauth2.ts";

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
