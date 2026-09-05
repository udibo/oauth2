import {
  assertEquals,
  assertFalse,
  assertRejects,
  assertStringIncludes,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { ExternalAuthError } from "./errors.ts";
import { ExternalAuthFlow } from "./flow.ts";
import { discordProvider } from "./discord.ts";

const clientId = "discord-client-id";
const clientSecret = "discord-client-secret";
const redirectUri = "https://app.example/auth/social/discord/callback";

const discordUser = {
  id: "80351110224678912",
  username: "nelly",
  global_name: "Nelly",
  avatar: "8342729096ea3675442027381ff50dfe",
  email: "nelly@example.com",
  verified: true,
};

function createDiscordStub(options: {
  tokenResponse?: Record<string, unknown>;
  tokenStatus?: number;
  user?: Record<string, unknown>;
  userStatus?: number;
} = {}) {
  const context = {
    tokenRequest: undefined as URLSearchParams | undefined,
    userAuthorization: undefined as string | null | undefined,
  };
  const fetchStub: typeof fetch = async (input, init) => {
    const request = input instanceof Request
      ? new Request(input, init)
      : new Request(String(input), init);
    if (request.url === "https://discord.com/api/oauth2/token") {
      context.tokenRequest = new URLSearchParams(await request.text());
      if (options.tokenStatus) {
        return new Response("bad", { status: options.tokenStatus });
      }
      return Response.json(
        options.tokenResponse ??
          { access_token: "discord-token", token_type: "Bearer" },
      );
    }
    if (request.url === "https://discord.com/api/users/@me") {
      context.userAuthorization = request.headers.get("authorization");
      if (options.userStatus) {
        return new Response("nope", { status: options.userStatus });
      }
      return Response.json(options.user ?? discordUser);
    }
    throw new Error(`unexpected fetch: ${request.method} ${request.url}`);
  };
  return { fetch: fetchStub, context };
}

async function signIn(stub: ReturnType<typeof createDiscordStub>) {
  const flow = new ExternalAuthFlow({
    provider: discordProvider({ clientId, clientSecret, fetch: stub.fetch }),
  });
  const { url, transient } = await flow.start({ redirectUri });
  const authorizeUrl = new URL(url);
  assertEquals(
    authorizeUrl.origin + authorizeUrl.pathname,
    "https://discord.com/oauth2/authorize",
  );
  assertEquals(authorizeUrl.searchParams.get("response_type"), "code");
  assertEquals(authorizeUrl.searchParams.get("client_id"), clientId);
  assertEquals(authorizeUrl.searchParams.get("redirect_uri"), redirectUri);
  assertEquals(authorizeUrl.searchParams.get("scope"), "identify email");
  assertEquals(authorizeUrl.searchParams.get("state"), transient.state);
  assertFalse(authorizeUrl.searchParams.has("code_challenge"));
  assertEquals(transient.codeVerifier, undefined);
  assertEquals(transient.nonce, undefined);
  const profile = await flow.finish({
    params: new URLSearchParams({
      code: "discord-code",
      state: transient.state,
    }),
    transient,
  });
  return profile;
}

describe("discordProvider", () => {
  it("builds the profile from /users/@me and exchanges via client_secret_post", async () => {
    const stub = createDiscordStub();
    const profile = await signIn(stub);

    assertEquals(profile.provider, "discord");
    assertEquals(profile.subject, "80351110224678912");
    assertEquals(profile.email, "nelly@example.com");
    assertEquals(profile.emailVerified, true);
    assertEquals(profile.name, "Nelly");
    assertEquals(
      profile.picture,
      "https://cdn.discordapp.com/avatars/80351110224678912/" +
        "8342729096ea3675442027381ff50dfe.png",
    );
    assertEquals(profile.raw.username, "nelly");

    const token = stub.context.tokenRequest!;
    assertEquals(token.get("grant_type"), "authorization_code");
    assertEquals(token.get("client_id"), clientId);
    assertEquals(token.get("client_secret"), clientSecret);
    assertEquals(token.get("code"), "discord-code");
    assertEquals(token.get("redirect_uri"), redirectUri);
    assertEquals(
      stub.context.userAuthorization,
      "Bearer discord-token",
    );
  });

  it("falls back to the username when global_name is absent", async () => {
    const stub = createDiscordStub({
      user: { ...discordUser, global_name: undefined },
    });
    const profile = await signIn(stub);
    assertEquals(profile.name, "nelly");
  });

  it("reports emailVerified false when Discord has not verified the email", async () => {
    const stub = createDiscordStub({
      user: { ...discordUser, verified: false },
    });
    const profile = await signIn(stub);
    assertEquals(profile.email, "nelly@example.com");
    assertEquals(profile.emailVerified, false);
  });

  it("uses an animated avatar's gif extension", async () => {
    const stub = createDiscordStub({
      user: { ...discordUser, avatar: "a_1234567890" },
    });
    const profile = await signIn(stub);
    assertStringIncludes(profile.picture!, ".gif");
  });

  it("surfaces a token endpoint failure diagnosably", async () => {
    const stub = createDiscordStub({ tokenStatus: 401 });
    const error = await assertRejects(() => signIn(stub), ExternalAuthError);
    assertEquals(error.code, "provider_error");
    assertStringIncludes(error.message, "[discord]");
    assertStringIncludes(error.message, "401");
  });

  it("surfaces a missing access token diagnosably", async () => {
    const stub = createDiscordStub({
      tokenResponse: { error: "invalid_grant" },
    });
    const error = await assertRejects(() => signIn(stub), ExternalAuthError);
    assertEquals(error.code, "provider_error");
    assertStringIncludes(error.message, "invalid_grant");
  });

  it("surfaces a profile endpoint failure diagnosably", async () => {
    const stub = createDiscordStub({ userStatus: 403 });
    const error = await assertRejects(() => signIn(stub), ExternalAuthError);
    assertEquals(error.code, "provider_error");
    assertStringIncludes(error.message, "[discord]");
  });

  it("wraps a network failure instead of leaking it", async () => {
    const flow = new ExternalAuthFlow({
      provider: discordProvider({
        clientId,
        clientSecret,
        fetch: () => Promise.reject(new TypeError("network down")),
      }),
    });
    const { transient } = await flow.start({ redirectUri });
    const error = await assertRejects(
      () =>
        flow.finish({
          params: new URLSearchParams({
            code: "discord-code",
            state: transient.state,
          }),
          transient,
        }),
      ExternalAuthError,
    );
    assertEquals(error.code, "provider_error");
    assertStringIncludes(error.message, "[discord]");
  });
});
