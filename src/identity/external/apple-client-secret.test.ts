import { assert, describe, expect, it } from "vitest";
import { FakeTime } from "../../_test_fake-time.ts";
import { rejection } from "../../_test_assert.ts";
import { encodeBase64 } from "../../utils/_encoding.ts";
import { toArrayBuffer } from "../../utils/_buffer.ts";
import { base64urlDecode } from "../../utils/crypto.ts";
import { ExternalAuthError } from "./errors.ts";
import {
  APPLE_AUDIENCE,
  APPLE_CLIENT_SECRET_MAX_TTL_SECONDS,
  createAppleClientSecretFactory,
  generateAppleClientSecret,
} from "./apple-client-secret.ts";

async function generateP8(
  namedCurve: "P-256" | "P-384" = "P-256",
): Promise<{ pem: string; publicKey: CryptoKey }> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve },
    true,
    ["sign", "verify"],
  );
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  const body = encodeBase64(new Uint8Array(pkcs8)).replace(/(.{64})/g, "$1\n");
  const pem = `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`;
  return { pem, publicKey: pair.publicKey };
}

function decodeSegment(segment: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64urlDecode(segment)));
}

const config = {
  teamId: "ABCDE12345",
  keyId: "KEY1234567",
  clientId: "com.example.web",
};

describe("generateAppleClientSecret", () => {
  it("signs an ES256 JWT with the correct header and claims, verifiable by the public key", async () => {
    const { pem, publicKey } = await generateP8();
    const before = Math.floor(Date.now() / 1000);
    const jwt = await generateAppleClientSecret({ ...config, privateKey: pem });

    const [headerPart, payloadPart, signaturePart] = jwt.split(".");
    const header = decodeSegment(headerPart);
    expect(header.alg).toStrictEqual("ES256");
    expect(header.kid).toStrictEqual(config.keyId);

    const payload = decodeSegment(payloadPart);
    expect(payload.iss).toStrictEqual(config.teamId);
    expect(payload.sub).toStrictEqual(config.clientId);
    expect(payload.aud).toStrictEqual(APPLE_AUDIENCE);
    expect(payload.exp as number).toBeGreaterThan(payload.iat as number);
    expect(payload.iat as number).toBeGreaterThan(before - 5);
    expect(
      (payload.exp as number) - (payload.iat as number),
    ).toBeLessThanOrEqual(APPLE_CLIENT_SECRET_MAX_TTL_SECONDS);

    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      toArrayBuffer(base64urlDecode(signaturePart)),
      new TextEncoder().encode(`${headerPart}.${payloadPart}`),
    );
    assert(valid, "signature must verify against the exported public key");
  });

  it("rejects a TTL over Apple's six-month cap with a configuration error", async () => {
    const { pem } = await generateP8();
    const error = await rejection(
      () =>
        generateAppleClientSecret({
          ...config,
          privateKey: pem,
          expiresInSeconds: APPLE_CLIENT_SECRET_MAX_TTL_SECONDS + 1,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("configuration");
    expect(error.provider).toStrictEqual("apple");
    expect(error.message).toContain("6 months");
  });

  it("rejects a NaN TTL with a configuration error instead of signing an unusable exp", async () => {
    const { pem } = await generateP8();
    const error = await rejection(
      () =>
        generateAppleClientSecret({
          ...config,
          privateKey: pem,
          expiresInSeconds: Number.NaN,
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("configuration");
    expect(error.message).toContain("TTL");
  });

  it("names an empty team id in a configuration error", async () => {
    const { pem } = await generateP8();
    const error = await rejection(
      () =>
        generateAppleClientSecret({ ...config, teamId: "  ", privateKey: pem }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("configuration");
    expect(error.message).toContain("team id");
  });

  it("names an empty Services ID in a configuration error", async () => {
    const { pem } = await generateP8();
    const error = await rejection(
      () =>
        generateAppleClientSecret({ ...config, clientId: "", privateKey: pem }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("configuration");
    expect(error.message).toContain("Services ID");
  });

  it("rejects a malformed private key with a configuration error", async () => {
    const error = await rejection(
      () =>
        generateAppleClientSecret({
          ...config,
          privateKey:
            "-----BEGIN PRIVATE KEY-----\n@@@not base64@@@\n" +
            "-----END PRIVATE KEY-----",
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("configuration");
    expect(error.message).toContain(".p8");
  });

  it("rejects a wrong-curve (P-384) key with a configuration error", async () => {
    const { pem } = await generateP8("P-384");
    const error = await rejection(
      () => generateAppleClientSecret({ ...config, privateKey: pem }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("configuration");
    expect(error.message).toContain("P-256");
  });
});

describe("createAppleClientSecretFactory", () => {
  it("caches the secret and re-signs only after it nears expiry", async () => {
    using time = new FakeTime(1_700_000_000_000);
    const { pem } = await generateP8();
    const factory = createAppleClientSecretFactory({
      ...config,
      privateKey: pem,
      expiresInSeconds: 3600,
      renewBeforeSeconds: 600,
    });
    const first = await factory();
    expect(await factory(), "within TTL the cached secret is reused").toBe(
      first,
    );

    await time.tickAsync(2_999_000);
    expect(
      await factory(),
      "just before the renew window it is still reused",
    ).toBe(first);

    await time.tickAsync(1_000);
    expect(await factory(), "inside the renew window it is re-signed").not.toBe(
      first,
    );
  });

  it("re-signs on every call when the renew window covers the whole TTL", async () => {
    using time = new FakeTime(1_700_000_000_000);
    const { pem } = await generateP8();
    const eager = createAppleClientSecretFactory({
      ...config,
      privateKey: pem,
      expiresInSeconds: 3600,
      renewBeforeSeconds: 3600 + 10,
    });
    const a = await eager();
    await time.tickAsync(1100);
    const b = await eager();
    assert(a !== b, "a secret already inside the renew window is re-signed");
  });

  it("surfaces bad key material as a configuration error", async () => {
    const factory = createAppleClientSecretFactory({
      ...config,
      privateKey: "not a key",
    });
    const error = await rejection(() => factory(), ExternalAuthError);
    expect(error.code).toStrictEqual("configuration");
  });
});
