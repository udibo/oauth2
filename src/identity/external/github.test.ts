import { assert, describe, expect, it } from "vitest";
import { rejection } from "../../_test_assert.ts";
import { ExternalAuthError } from "./errors.ts";
import { ExternalAuthFlow } from "./flow.ts";
import { githubProvider } from "./github.ts";

const clientId = "github-client-id";
const clientSecret = "github-client-secret";
const redirectUri = "https://app.example/auth/social/github/callback";

const octocat = {
  id: 583231,
  login: "octocat",
  name: "The Octocat",
  avatar_url: "https://avatars.example/octocat.png",
  email: null as string | null,
};

function createGithubStub(options: {
  tokenResponse?: Record<string, unknown>;
  tokenStatus?: number;
  tokenBody?: string;
  user?: Record<string, unknown>;
  emails?: unknown;
  emailsStatus?: number;
}) {
  const context = {
    tokenRequest: undefined as
      | { headers: Headers; body: URLSearchParams }
      | undefined,
  };
  const fetchStub: typeof fetch = async (input, init) => {
    const request =
      input instanceof Request
        ? new Request(input, init)
        : new Request(String(input), init);
    switch (request.url) {
      case "https://github.com/login/oauth/access_token":
        context.tokenRequest = {
          headers: request.headers,
          body: new URLSearchParams(await request.text()),
        };
        if (options.tokenStatus) {
          return new Response(options.tokenBody ?? "", {
            status: options.tokenStatus,
          });
        }
        return Response.json(
          options.tokenResponse ?? {
            access_token: "gh-token",
            token_type: "bearer",
          },
        );
      case "https://api.github.com/user":
        return Response.json(options.user ?? octocat);
      case "https://api.github.com/user/emails":
        if (options.emailsStatus) {
          return new Response("Forbidden", { status: options.emailsStatus });
        }
        return Response.json(options.emails ?? []);
      default:
        throw new Error(`unexpected fetch: ${request.method} ${request.url}`);
    }
  };
  return { fetch: fetchStub, context };
}

async function signIn(stub: ReturnType<typeof createGithubStub>) {
  const flow = new ExternalAuthFlow({
    provider: githubProvider({ clientId, clientSecret, fetch: stub.fetch }),
  });
  const { url, transient } = await flow.start({ redirectUri });
  const authorizeUrl = new URL(url);
  expect(authorizeUrl.origin + authorizeUrl.pathname).toStrictEqual(
    "https://github.com/login/oauth/authorize",
  );
  expect(authorizeUrl.searchParams.get("scope")).toStrictEqual(
    "read:user user:email",
  );
  expect(authorizeUrl.searchParams.has("code_challenge")).toBeFalsy();
  expect(transient.codeVerifier).toStrictEqual(undefined);
  expect(transient.nonce).toStrictEqual(undefined);
  const profile = await flow.finish({
    params: new URLSearchParams({ code: "gh-code", state: transient.state }),
    transient,
  });
  return profile;
}

describe("githubProvider", () => {
  it("selects the verified primary email from /user/emails", async () => {
    const stub = createGithubStub({
      emails: [
        {
          email: "octocat@users.noreply.github.com",
          primary: false,
          verified: true,
        },
        { email: "octocat@example.com", primary: true, verified: true },
      ],
    });
    const profile = await signIn(stub);

    expect(profile.provider).toStrictEqual("github");
    expect(profile.subject).toStrictEqual("583231");
    expect(profile.email).toStrictEqual("octocat@example.com");
    expect(profile.emailVerified).toStrictEqual(true);
    expect(profile.name).toStrictEqual("The Octocat");
    expect(profile.picture).toStrictEqual(
      "https://avatars.example/octocat.png",
    );
    expect(profile.raw.login).toStrictEqual("octocat");
    assert(Array.isArray(profile.raw.emails));

    const tokenRequest = stub.context.tokenRequest!;
    expect(tokenRequest.headers.get("accept")).toStrictEqual(
      "application/json",
    );
    expect(tokenRequest.body.get("client_id")).toStrictEqual(clientId);
    expect(tokenRequest.body.get("client_secret")).toStrictEqual(clientSecret);
    expect(tokenRequest.body.get("code")).toStrictEqual("gh-code");
    expect(tokenRequest.body.get("redirect_uri")).toStrictEqual(redirectUri);
  });

  it("reports emailVerified false when the primary email is unverified", async () => {
    const stub = createGithubStub({
      emails: [
        { email: "octocat@example.com", primary: true, verified: false },
      ],
    });
    const profile = await signIn(stub);
    expect(profile.email).toStrictEqual("octocat@example.com");
    expect(profile.emailVerified).toStrictEqual(false);
  });

  it("falls back to the public profile email, unverified, when /user/emails is unavailable", async () => {
    const stub = createGithubStub({
      user: { ...octocat, email: "octocat@public.example" },
      emailsStatus: 403,
    });
    const profile = await signIn(stub);
    expect(profile.email).toStrictEqual("octocat@public.example");
    expect(profile.emailVerified).toStrictEqual(false);
  });

  it("ignores /user/emails entries that carry no string email", async () => {
    const stub = createGithubStub({
      emails: [
        null,
        "octocat@example.com",
        { primary: true, verified: true },
        { email: "octocat@example.com", primary: true, verified: true },
      ],
    });
    const profile = await signIn(stub);
    expect(profile.email).toStrictEqual("octocat@example.com");
    expect(profile.emailVerified).toStrictEqual(true);
  });

  it("falls back to the public email when every /user/emails entry is malformed", async () => {
    const stub = createGithubStub({
      user: { ...octocat, email: "octocat@public.example" },
      emails: [null, { verified: true }],
    });
    const profile = await signIn(stub);
    expect(profile.email).toStrictEqual("octocat@public.example");
    expect(profile.emailVerified).toStrictEqual(false);
  });

  it("falls back to the public email when /user/emails returns a non-array body", async () => {
    const stub = createGithubStub({
      user: { ...octocat, email: "octocat@public.example" },
      emails: { message: "Not Found" },
    });
    const profile = await signIn(stub);
    expect(profile.email).toStrictEqual("octocat@public.example");
    expect(profile.emailVerified).toStrictEqual(false);
  });

  it("wraps a network failure as an ExternalAuthError instead of leaking it", async () => {
    const flow = new ExternalAuthFlow({
      provider: githubProvider({
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
            code: "gh-code",
            state: transient.state,
          }),
          transient,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[github]");
  });

  it("keeps the upstream body when the token endpoint fails with an HTTP error", async () => {
    const stub = createGithubStub({
      tokenStatus: 502,
      tokenBody: "upstream unavailable",
    });

    const error = await rejection(() => signIn(stub), ExternalAuthError);
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("HTTP 502");
    expect(error.message).toContain("upstream unavailable");
  });

  it("surfaces a token endpoint error body diagnosably", async () => {
    const stub = createGithubStub({
      tokenResponse: {
        error: "bad_verification_code",
        error_description: "The code passed is incorrect or expired.",
      },
    });

    const error = await rejection(() => signIn(stub), ExternalAuthError);
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[github]");
    expect(error.message).toContain("bad_verification_code");
    expect(error.message).toContain("The code passed is incorrect or expired.");
    expect(error.message).toContain("start");
  });
});
