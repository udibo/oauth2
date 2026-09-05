import {
  assert,
  assertEquals,
  assertFalse,
  assertRejects,
  assertStringIncludes,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";

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
    const request = input instanceof Request
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
          options.tokenResponse ??
            { access_token: "gh-token", token_type: "bearer" },
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
  assertEquals(
    authorizeUrl.origin + authorizeUrl.pathname,
    "https://github.com/login/oauth/authorize",
  );
  assertEquals(authorizeUrl.searchParams.get("scope"), "read:user user:email");
  assertFalse(authorizeUrl.searchParams.has("code_challenge"));
  assertEquals(transient.codeVerifier, undefined);
  assertEquals(transient.nonce, undefined);
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

    assertEquals(profile.provider, "github");
    assertEquals(profile.subject, "583231");
    assertEquals(profile.email, "octocat@example.com");
    assertEquals(profile.emailVerified, true);
    assertEquals(profile.name, "The Octocat");
    assertEquals(profile.picture, "https://avatars.example/octocat.png");
    assertEquals(profile.raw.login, "octocat");
    assert(Array.isArray(profile.raw.emails));

    const tokenRequest = stub.context.tokenRequest!;
    assertEquals(tokenRequest.headers.get("accept"), "application/json");
    assertEquals(tokenRequest.body.get("client_id"), clientId);
    assertEquals(tokenRequest.body.get("client_secret"), clientSecret);
    assertEquals(tokenRequest.body.get("code"), "gh-code");
    assertEquals(tokenRequest.body.get("redirect_uri"), redirectUri);
  });

  it("reports emailVerified false when the primary email is unverified", async () => {
    const stub = createGithubStub({
      emails: [
        { email: "octocat@example.com", primary: true, verified: false },
      ],
    });
    const profile = await signIn(stub);
    assertEquals(profile.email, "octocat@example.com");
    assertEquals(profile.emailVerified, false);
  });

  it("falls back to the public profile email, unverified, when /user/emails is unavailable", async () => {
    const stub = createGithubStub({
      user: { ...octocat, email: "octocat@public.example" },
      emailsStatus: 403,
    });
    const profile = await signIn(stub);
    assertEquals(profile.email, "octocat@public.example");
    assertEquals(profile.emailVerified, false);
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
    assertEquals(profile.email, "octocat@example.com");
    assertEquals(profile.emailVerified, true);
  });

  it("falls back to the public email when every /user/emails entry is malformed", async () => {
    const stub = createGithubStub({
      user: { ...octocat, email: "octocat@public.example" },
      emails: [null, { verified: true }],
    });
    const profile = await signIn(stub);
    assertEquals(profile.email, "octocat@public.example");
    assertEquals(profile.emailVerified, false);
  });

  it("falls back to the public email when /user/emails returns a non-array body", async () => {
    const stub = createGithubStub({
      user: { ...octocat, email: "octocat@public.example" },
      emails: { message: "Not Found" },
    });
    const profile = await signIn(stub);
    assertEquals(profile.email, "octocat@public.example");
    assertEquals(profile.emailVerified, false);
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

    const error = await assertRejects(
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
    assertEquals(error.code, "provider_error");
    assertStringIncludes(error.message, "[github]");
  });

  it("keeps the upstream body when the token endpoint fails with an HTTP error", async () => {
    const stub = createGithubStub({
      tokenStatus: 502,
      tokenBody: "upstream unavailable",
    });

    const error = await assertRejects(() => signIn(stub), ExternalAuthError);
    assertEquals(error.code, "provider_error");
    assertStringIncludes(error.message, "HTTP 502");
    assertStringIncludes(error.message, "upstream unavailable");
  });

  it("surfaces a token endpoint error body diagnosably", async () => {
    const stub = createGithubStub({
      tokenResponse: {
        error: "bad_verification_code",
        error_description: "The code passed is incorrect or expired.",
      },
    });

    const error = await assertRejects(() => signIn(stub), ExternalAuthError);
    assertEquals(error.code, "provider_error");
    assertStringIncludes(error.message, "[github]");
    assertStringIncludes(error.message, "bad_verification_code");
    assertStringIncludes(
      error.message,
      "The code passed is incorrect or expired.",
    );
    assertStringIncludes(error.message, "start");
  });
});
