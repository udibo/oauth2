import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

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

    assertEquals(url.searchParams.get("state"), "flow-state");
    assertEquals(
      url.searchParams.get("code_challenge"),
      await generateCodeChallenge(codeVerifier),
    );
    assertEquals(url.searchParams.get("code_challenge_method"), "S256");
    assertEquals(url.searchParams.get("redirect_uri"), redirectUri);
    assertEquals(url.searchParams.get("client_id"), "acme-client-id");
    assertEquals(url.searchParams.get("response_type"), "code");
    assertEquals(url.searchParams.get("scope"), "profile");
    assertEquals(url.searchParams.get("audience"), "https://api.acme.example");
    assertEquals(url.searchParams.getAll("state").length, 1);
  });

  it("lets the flow's prompt override a configured one", async () => {
    const provider = acmeProvider({ prompt: "none" });
    const url = new URL(
      await provider.buildAuthorizationUrl({
        redirectUri,
        scopes: ["profile"],
        state: "flow-state",
        prompt: "consent",
      }),
    );
    assertEquals(url.searchParams.get("prompt"), "consent");
  });
});
