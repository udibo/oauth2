import { assert, describe, expect, it } from "vitest";
import { rejection } from "../../_test_assert.ts";
import { encodeBase64Url } from "../../utils/_encoding.ts";
import { ExternalAuthError } from "./errors.ts";
import { ExternalAuthFlow } from "./flow.ts";
import { googleProvider, type GoogleProviderOptions } from "./google.ts";

const clientId = "google-client-id";
const clientSecret = "google-client-secret";
const redirectUri = "https://app.example/auth/social/google/callback";

function segment(value: unknown): string {
  return encodeBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

function unsignedIdToken(claims: Record<string, unknown>): string {
  return `${segment({ alg: "ES256", typ: "JWT" })}.${segment(claims)}.sig`;
}

function createGoogleStub(options: {
  claims: Record<string, unknown>;
  userinfo?: Record<string, unknown>;
}) {
  const context = {
    nonce: undefined as string | undefined,
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
      case "https://accounts.google.com/.well-known/oauth-authorization-server":
        return new Response("Not Found", { status: 404 });
      case "https://accounts.google.com/.well-known/openid-configuration":
        return Response.json({
          issuer: "https://accounts.google.com",
          authorization_endpoint:
            "https://accounts.google.com/o/oauth2/v2/auth",
          token_endpoint: "https://oauth2.googleapis.com/token",
          ...(options.userinfo
            ? {
                userinfo_endpoint:
                  "https://openidconnect.googleapis.com/v1/userinfo",
              }
            : {}),
        });
      case "https://oauth2.googleapis.com/token":
        context.tokenRequest = {
          headers: request.headers,
          body: new URLSearchParams(await request.text()),
        };
        return Response.json({
          token_type: "Bearer",
          access_token: "google-access-token",
          expires_in: 3600,
          id_token: unsignedIdToken({
            iss: "https://accounts.google.com",
            aud: clientId,
            exp: Math.floor(Date.now() / 1000) + 3600,
            nonce: context.nonce,
            ...options.claims,
          }),
        });
      case "https://openidconnect.googleapis.com/v1/userinfo":
        return Response.json(options.userinfo);
      default:
        throw new Error(`unexpected fetch: ${request.method} ${request.url}`);
    }
  };
  return { fetch: fetchStub, context };
}

async function signIn(
  stub: ReturnType<typeof createGoogleStub>,
  config?: Pick<GoogleProviderOptions, "azp">,
): Promise<Awaited<ReturnType<ExternalAuthFlow["finish"]>>> {
  const flow = new ExternalAuthFlow({
    provider: googleProvider({
      clientId,
      clientSecret,
      fetch: stub.fetch,
      ...config,
    }),
  });
  const { url, transient } = await flow.start({ redirectUri });
  expect(url).toContain("https://accounts.google.com/o/oauth2/v2/auth");
  stub.context.nonce = transient.nonce;
  return await flow.finish({
    params: new URLSearchParams({
      code: "google-code",
      state: transient.state,
    }),
    transient,
  });
}

describe("googleProvider", () => {
  it("maps Google claims and keeps hd in raw when email_verified is true", async () => {
    const stub = createGoogleStub({
      claims: {
        sub: "g-123",
        email: "ada@example.com",
        email_verified: true,
        name: "Ada Lovelace",
        given_name: "Ada",
        family_name: "Lovelace",
        picture: "https://img.example/ada.png",
        hd: "example.com",
      },
    });
    const profile = await signIn(stub);

    expect(profile.provider).toStrictEqual("google");
    expect(profile.subject).toStrictEqual("g-123");
    expect(profile.email).toStrictEqual("ada@example.com");
    expect(profile.emailVerified).toStrictEqual(true);
    expect(profile.name).toStrictEqual("Ada Lovelace");
    expect(profile.givenName).toStrictEqual("Ada");
    expect(profile.familyName).toStrictEqual("Lovelace");
    expect(profile.picture).toStrictEqual("https://img.example/ada.png");
    expect(profile.raw.hd).toStrictEqual("example.com");

    const tokenRequest = stub.context.tokenRequest!;
    assert(tokenRequest.headers.get("authorization")?.startsWith("Basic "));
    expect(tokenRequest.body.get("code")).toStrictEqual("google-code");
    expect(tokenRequest.body.get("redirect_uri")).toStrictEqual(redirectUri);
    assert(tokenRequest.body.get("code_verifier"));
  });

  it("maps email_verified false to emailVerified false", async () => {
    const stub = createGoogleStub({
      claims: {
        sub: "g-456",
        email: "grace@example.com",
        email_verified: false,
      },
    });
    const profile = await signIn(stub);
    expect(profile.email).toStrictEqual("grace@example.com");
    expect(profile.emailVerified).toStrictEqual(false);
  });

  it("defaults emailVerified to false when the claim is absent", async () => {
    const stub = createGoogleStub({
      claims: { sub: "g-789", email: "joan@example.com" },
    });
    const profile = await signIn(stub);
    expect(profile.emailVerified).toStrictEqual(false);
  });

  it("rejects an expired id_token", async () => {
    const stub = createGoogleStub({
      claims: {
        sub: "g-exp",
        email: "old@example.com",
        exp: Math.floor(Date.now() / 1000) - 3600,
      },
    });
    const error = await rejection(() => signIn(stub), ExternalAuthError);
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("expired");
  });

  it("rejects an id_token with multiple audiences and a foreign azp", async () => {
    const stub = createGoogleStub({
      claims: {
        sub: "g-azp",
        email: "azp@example.com",
        aud: [clientId, "another-client"],
        azp: "another-client",
      },
    });
    const error = await rejection(() => signIn(stub), ExternalAuthError);
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("azp");
  });

  it("accepts a cross-client azp when the config opts out of the check", async () => {
    const stub = createGoogleStub({
      claims: {
        sub: "g-cross-client",
        email: "cross@example.com",
        azp: "another-client-of-the-same-project",
      },
    });
    const profile = await signIn(stub, { azp: "ignore" });
    expect(profile.subject).toStrictEqual("g-cross-client");
  });

  it("accepts a single-element aud array with no azp claim", async () => {
    const stub = createGoogleStub({
      claims: {
        sub: "g-single-aud",
        email: "single@example.com",
        email_verified: true,
        aud: [clientId],
      },
    });
    const profile = await signIn(stub);
    expect(profile.subject).toStrictEqual("g-single-aud");
    expect(profile.email).toStrictEqual("single@example.com");
  });

  it("merges userinfo claims over id_token claims when the sub matches", async () => {
    const stub = createGoogleStub({
      claims: {
        sub: "g-123",
        email: "ada@example.com",
        email_verified: true,
        picture: "https://img.example/stale.png",
      },
      userinfo: {
        sub: "g-123",
        picture: "https://img.example/fresh.png",
        locale: "en-GB",
      },
    });
    const profile = await signIn(stub);
    expect(profile.picture).toStrictEqual("https://img.example/fresh.png");
    expect(profile.raw.locale).toStrictEqual("en-GB");
    expect(profile.email).toStrictEqual("ada@example.com");
  });

  it("ignores a userinfo response whose sub does not match the id_token", async () => {
    const stub = createGoogleStub({
      claims: { sub: "g-123", email: "ada@example.com", email_verified: true },
      userinfo: { sub: "g-999", email: "attacker@example.com" },
    });
    const profile = await signIn(stub);
    expect(profile.email).toStrictEqual("ada@example.com");
    expect(profile.subject).toStrictEqual("g-123");
  });
});
