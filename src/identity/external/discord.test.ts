import { describe, expect, it } from "vitest";
import { rejection } from "../../_test_assert.ts";
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

function createDiscordStub(
  options: {
    tokenResponse?: Record<string, unknown>;
    tokenStatus?: number;
    user?: Record<string, unknown>;
    userStatus?: number;
  } = {},
) {
  const context = {
    tokenRequest: undefined as URLSearchParams | undefined,
    userAuthorization: undefined as string | null | undefined,
  };
  const fetchStub: typeof fetch = async (input, init) => {
    const request =
      input instanceof Request
        ? new Request(input, init)
        : new Request(String(input), init);
    if (request.url === "https://discord.com/api/oauth2/token") {
      context.tokenRequest = new URLSearchParams(await request.text());
      if (options.tokenStatus) {
        return new Response("bad", { status: options.tokenStatus });
      }
      return Response.json(
        options.tokenResponse ?? {
          access_token: "discord-token",
          token_type: "Bearer",
        },
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
  expect(authorizeUrl.origin + authorizeUrl.pathname).toStrictEqual(
    "https://discord.com/oauth2/authorize",
  );
  expect(authorizeUrl.searchParams.get("response_type")).toStrictEqual("code");
  expect(authorizeUrl.searchParams.get("client_id")).toStrictEqual(clientId);
  expect(authorizeUrl.searchParams.get("redirect_uri")).toStrictEqual(
    redirectUri,
  );
  expect(authorizeUrl.searchParams.get("scope")).toStrictEqual(
    "identify email",
  );
  expect(authorizeUrl.searchParams.get("state")).toStrictEqual(transient.state);
  expect(authorizeUrl.searchParams.has("code_challenge")).toBeFalsy();
  expect(transient.codeVerifier).toStrictEqual(undefined);
  expect(transient.nonce).toStrictEqual(undefined);
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

    expect(profile.provider).toStrictEqual("discord");
    expect(profile.subject).toStrictEqual("80351110224678912");
    expect(profile.email).toStrictEqual("nelly@example.com");
    expect(profile.emailVerified).toStrictEqual(true);
    expect(profile.name).toStrictEqual("Nelly");
    expect(profile.picture).toStrictEqual(
      "https://cdn.discordapp.com/avatars/80351110224678912/" +
        "8342729096ea3675442027381ff50dfe.png",
    );
    expect(profile.raw.username).toStrictEqual("nelly");

    const token = stub.context.tokenRequest!;
    expect(token.get("grant_type")).toStrictEqual("authorization_code");
    expect(token.get("client_id")).toStrictEqual(clientId);
    expect(token.get("client_secret")).toStrictEqual(clientSecret);
    expect(token.get("code")).toStrictEqual("discord-code");
    expect(token.get("redirect_uri")).toStrictEqual(redirectUri);
    expect(stub.context.userAuthorization).toStrictEqual(
      "Bearer discord-token",
    );
  });

  it("falls back to the username when global_name is absent", async () => {
    const stub = createDiscordStub({
      user: { ...discordUser, global_name: undefined },
    });
    const profile = await signIn(stub);
    expect(profile.name).toStrictEqual("nelly");
  });

  it("reports emailVerified false when Discord has not verified the email", async () => {
    const stub = createDiscordStub({
      user: { ...discordUser, verified: false },
    });
    const profile = await signIn(stub);
    expect(profile.email).toStrictEqual("nelly@example.com");
    expect(profile.emailVerified).toStrictEqual(false);
  });

  it("uses an animated avatar's gif extension", async () => {
    const stub = createDiscordStub({
      user: { ...discordUser, avatar: "a_1234567890" },
    });
    const profile = await signIn(stub);
    expect(profile.picture!).toContain(".gif");
  });

  it("surfaces a token endpoint failure diagnosably", async () => {
    const stub = createDiscordStub({ tokenStatus: 401 });
    const error = await rejection(() => signIn(stub), ExternalAuthError);
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[discord]");
    expect(error.message).toContain("401");
  });

  it("surfaces a missing access token diagnosably", async () => {
    const stub = createDiscordStub({
      tokenResponse: { error: "invalid_grant" },
    });
    const error = await rejection(() => signIn(stub), ExternalAuthError);
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("invalid_grant");
  });

  it("surfaces a profile endpoint failure diagnosably", async () => {
    const stub = createDiscordStub({ userStatus: 403 });
    const error = await rejection(() => signIn(stub), ExternalAuthError);
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[discord]");
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
    const error = await rejection(
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
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[discord]");
  });
});
