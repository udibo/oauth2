import { assert, describe, expect, it } from "vitest";
import { rejection } from "../../_test_assert.ts";
import { encodeBase64 } from "../../utils/_encoding.ts";
import { base64urlEncode } from "../../utils/crypto.ts";
import { ExternalAuthError } from "./errors.ts";
import { ExternalAuthFlow } from "./flow.ts";
import { appleProvider } from "./apple.ts";

const clientId = "com.example.web";
const redirectUri = "https://app.example/auth/social/apple/callback";
const APPLE_ISSUER = "https://appleid.apple.com";

const encoder = new TextEncoder();
const RSA_ALG = {
  name: "RSASSA-PKCS1-v1_5",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
} as const;

function segment(value: unknown): string {
  return base64urlEncode(encoder.encode(JSON.stringify(value)));
}

interface Signer {
  kid: string;
  publicJwk: JsonWebKey & { kid: string };
  sign(claims: Record<string, unknown>, alg?: string): Promise<string>;
}

async function createSigner(kid: string): Promise<Signer> {
  const pair = await crypto.subtle.generateKey(RSA_ALG, true, [
    "sign",
    "verify",
  ]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    kid,
    publicJwk: { ...jwk, kid, alg: "RS256", use: "sig" },
    async sign(claims, alg = "RS256"): Promise<string> {
      const signingInput = `${segment({ alg, kid })}.${segment(claims)}`;
      const signature = await crypto.subtle.sign(
        RSA_ALG.name,
        pair.privateKey,
        encoder.encode(signingInput),
      );
      return `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
    },
  };
}

async function generateP8(): Promise<string> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  const body = encodeBase64(new Uint8Array(pkcs8)).replace(/(.{64})/g, "$1\n");
  return `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`;
}

function baseClaims(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: APPLE_ISSUER,
    aud: clientId,
    sub: "001999.apple-subject.0001",
    email: "user@example.com",
    email_verified: true,
    exp: now + 600,
    iat: now,
    ...overrides,
  };
}

async function harness(
  options: {
    signer: Signer;
    jwksKeys?: JsonWebKey[];
    clientSecret?: () => Promise<string>;
  } & Partial<{ privateKey: string }>,
) {
  const privateKey = options.privateKey ?? (await generateP8());
  const holder = {
    idToken: "" as string,
    tokenStatus: 200 as number,
    tokenBody: undefined as Record<string, unknown> | undefined,
    tokenRequest: undefined as URLSearchParams | undefined,
  };
  const fetchStub: typeof fetch = async (input, init) => {
    const request =
      input instanceof Request
        ? new Request(input, init)
        : new Request(String(input), init);
    if (request.url === "https://appleid.apple.com/auth/token") {
      holder.tokenRequest = new URLSearchParams(await request.text());
      if (holder.tokenStatus !== 200) {
        return new Response("bad", { status: holder.tokenStatus });
      }
      return Response.json(holder.tokenBody ?? { id_token: holder.idToken });
    }
    if (request.url === "https://appleid.apple.com/auth/keys") {
      return Response.json({
        keys: options.jwksKeys ?? [options.signer.publicJwk],
      });
    }
    throw new Error(`unexpected fetch: ${request.method} ${request.url}`);
  };
  const flow = new ExternalAuthFlow({
    provider: appleProvider({
      clientId,
      teamId: "ABCDE12345",
      keyId: "KEY1234567",
      privateKey,
      clientSecret: options.clientSecret,
      fetch: fetchStub,
    }),
  });
  return { flow, holder };
}

describe("appleProvider", () => {
  it("requests form_post with the name/email scopes and a nonce", async () => {
    const signer = await createSigner("apple-key-1");
    const { flow } = await harness({ signer });
    const { url, transient } = await flow.start({ redirectUri });
    const authorize = new URL(url);
    expect(authorize.origin + authorize.pathname).toStrictEqual(
      "https://appleid.apple.com/auth/authorize",
    );
    expect(authorize.searchParams.get("response_type")).toStrictEqual("code");
    expect(authorize.searchParams.get("response_mode")).toStrictEqual(
      "form_post",
    );
    expect(authorize.searchParams.get("scope")).toStrictEqual("name email");
    expect(authorize.searchParams.get("client_id")).toStrictEqual(clientId);
    expect(authorize.searchParams.get("nonce")).toStrictEqual(transient.nonce);
    expect(authorize.searchParams.get("state")).toStrictEqual(transient.state);
  });

  it("exchanges the code and returns a JWKS-verified profile", async () => {
    const signer = await createSigner("apple-key-1");
    const { flow, holder } = await harness({ signer });
    const { transient } = await flow.start({ redirectUri });
    holder.idToken = await signer.sign(baseClaims({ nonce: transient.nonce }));

    const profile = await flow.finish({
      params: new URLSearchParams({
        code: "apple-code",
        state: transient.state,
      }),
      transient,
    });

    expect(profile.provider).toStrictEqual("apple");
    expect(profile.subject).toStrictEqual("001999.apple-subject.0001");
    expect(profile.email).toStrictEqual("user@example.com");
    expect(profile.emailVerified).toStrictEqual(true);
    expect(holder.tokenRequest!.get("grant_type")).toStrictEqual(
      "authorization_code",
    );
    expect(holder.tokenRequest!.get("client_id")).toStrictEqual(clientId);
    assert(
      (holder.tokenRequest!.get("client_secret") ?? "").split(".").length === 3,
      "client_secret is a signed JWT",
    );
  });

  it('accepts email_verified as the string "true" and keeps a private-relay email', async () => {
    const signer = await createSigner("apple-key-1");
    const { flow, holder } = await harness({ signer });
    const { transient } = await flow.start({ redirectUri });
    holder.idToken = await signer.sign(
      baseClaims({
        nonce: transient.nonce,
        email: "abc123@privaterelay.appleid.com",
        email_verified: "true",
        is_private_email: "true",
      }),
    );

    const profile = await flow.finish({
      params: new URLSearchParams({ code: "c", state: transient.state }),
      transient,
    });
    expect(profile.email).toStrictEqual("abc123@privaterelay.appleid.com");
    expect(profile.emailVerified).toStrictEqual(true);
    expect(profile.raw.is_private_email).toStrictEqual("true");
  });

  it("rejects an id_token whose signature does not verify against the JWKS", async () => {
    const signer = await createSigner("apple-key-1");
    const attacker = await createSigner("apple-key-1");
    const { flow, holder } = await harness({ signer });
    const { transient } = await flow.start({ redirectUri });
    holder.idToken = await attacker.sign(
      baseClaims({ nonce: transient.nonce }),
    );

    const error = await rejection(
      () =>
        flow.finish({
          params: new URLSearchParams({ code: "c", state: transient.state }),
          transient,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("signature");
  });

  it("maps an undecodable signature segment to the same provider error", async () => {
    const signer = await createSigner("apple-key-1");
    const { flow, holder } = await harness({ signer });
    const { transient } = await flow.start({ redirectUri });
    const signed = await signer.sign(baseClaims({ nonce: transient.nonce }));
    const [header, payload] = signed.split(".");
    holder.idToken = `${header}.${payload}.abc+def`;

    const error = await rejection(
      () =>
        flow.finish({
          params: new URLSearchParams({ code: "c", state: transient.state }),
          transient,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("signature");
  });

  it("rejects an id_token for a different audience", async () => {
    const signer = await createSigner("apple-key-1");
    const { flow, holder } = await harness({ signer });
    const { transient } = await flow.start({ redirectUri });
    holder.idToken = await signer.sign(
      baseClaims({ nonce: transient.nonce, aud: "com.someone.else" }),
    );

    const error = await rejection(
      () =>
        flow.finish({
          params: new URLSearchParams({ code: "c", state: transient.state }),
          transient,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("aud");
  });

  it("rejects an id_token whose azp names a different client", async () => {
    const signer = await createSigner("apple-key-1");
    const { flow, holder } = await harness({ signer });
    const { transient } = await flow.start({ redirectUri });
    holder.idToken = await signer.sign(
      baseClaims({ nonce: transient.nonce, azp: "com.someone.else" }),
    );

    const error = await rejection(
      () =>
        flow.finish({
          params: new URLSearchParams({ code: "c", state: transient.state }),
          transient,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("azp");
  });

  it("rejects an expired id_token", async () => {
    const signer = await createSigner("apple-key-1");
    const { flow, holder } = await harness({ signer });
    const { transient } = await flow.start({ redirectUri });
    const now = Math.floor(Date.now() / 1000);
    holder.idToken = await signer.sign(
      baseClaims({ nonce: transient.nonce, exp: now - 3600 }),
    );

    const error = await rejection(
      () =>
        flow.finish({
          params: new URLSearchParams({ code: "c", state: transient.state }),
          transient,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("expired");
  });

  it("rejects a replayed id_token with a mismatched nonce", async () => {
    const signer = await createSigner("apple-key-1");
    const { flow, holder } = await harness({ signer });
    const { transient } = await flow.start({ redirectUri });
    holder.idToken = await signer.sign(
      baseClaims({ nonce: "some-other-nonce" }),
    );

    const error = await rejection(
      () =>
        flow.finish({
          params: new URLSearchParams({ code: "c", state: transient.state }),
          transient,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("nonce_mismatch");
  });

  it("rejects an id_token that claims an unexpected algorithm", async () => {
    const signer = await createSigner("apple-key-1");
    const { flow, holder } = await harness({ signer });
    const { transient } = await flow.start({ redirectUri });
    holder.idToken = await signer.sign(
      baseClaims({ nonce: transient.nonce }),
      "HS256",
    );

    const error = await rejection(
      () =>
        flow.finish({
          params: new URLSearchParams({ code: "c", state: transient.state }),
          transient,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("RS256");
  });

  it("rejects an id_token whose header omits kid rather than guessing a key", async () => {
    const signer = await createSigner("apple-key-1");
    const { flow, holder } = await harness({ signer });
    const { transient } = await flow.start({ redirectUri });
    const claims = baseClaims({ nonce: transient.nonce });
    holder.idToken = `${segment({ alg: "RS256" })}.${segment(claims)}.${base64urlEncode(
      encoder.encode("not-a-real-signature"),
    )}`;

    const error = await rejection(
      () =>
        flow.finish({
          params: new URLSearchParams({ code: "c", state: transient.state }),
          transient,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("kid");
  });

  it("surfaces an invalid_client token error diagnosably", async () => {
    const signer = await createSigner("apple-key-1");
    const { flow, holder } = await harness({ signer });
    const { transient } = await flow.start({ redirectUri });
    holder.tokenStatus = 400;

    const error = await rejection(
      () =>
        flow.finish({
          params: new URLSearchParams({ code: "c", state: transient.state }),
          transient,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[apple]");
    expect(error.message).toContain("invalid_client");
  });

  it("accepts an injected client-secret factory for tests", async () => {
    const signer = await createSigner("apple-key-1");
    let called = 0;
    const { flow, holder } = await harness({
      signer,
      clientSecret: () => {
        called++;
        return Promise.resolve("stub.secret.jwt");
      },
    });
    const { transient } = await flow.start({ redirectUri });
    holder.idToken = await signer.sign(baseClaims({ nonce: transient.nonce }));
    await flow.finish({
      params: new URLSearchParams({ code: "c", state: transient.state }),
      transient,
    });
    expect(called).toStrictEqual(1);
    expect(holder.tokenRequest!.get("client_secret")).toStrictEqual(
      "stub.secret.jwt",
    );
  });
});
