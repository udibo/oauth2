import {
  assert,
  assertEquals,
  assertGreater,
  assertLessOrEqual,
  assertRejects,
  assertStringIncludes,
} from "@std/assert";
import { encodeBase64 } from "@std/encoding/base64";
import { describe, it } from "@std/testing/bdd";
import { FakeTime } from "@std/testing/time";

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
    assertEquals(header.alg, "ES256");
    assertEquals(header.kid, config.keyId);

    const payload = decodeSegment(payloadPart);
    assertEquals(payload.iss, config.teamId);
    assertEquals(payload.sub, config.clientId);
    assertEquals(payload.aud, APPLE_AUDIENCE);
    assertGreater(payload.exp as number, payload.iat as number);
    assertGreater(payload.iat as number, before - 5);
    assertLessOrEqual(
      (payload.exp as number) - (payload.iat as number),
      APPLE_CLIENT_SECRET_MAX_TTL_SECONDS,
    );

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
    const error = await assertRejects(
      () =>
        generateAppleClientSecret({
          ...config,
          privateKey: pem,
          expiresInSeconds: APPLE_CLIENT_SECRET_MAX_TTL_SECONDS + 1,
        }),
      ExternalAuthError,
    );
    assertEquals(error.code, "configuration");
    assertEquals(error.provider, "apple");
    assertStringIncludes(error.message, "6 months");
  });

  it("names an empty team id in a configuration error", async () => {
    const { pem } = await generateP8();
    const error = await assertRejects(
      () =>
        generateAppleClientSecret({ ...config, teamId: "  ", privateKey: pem }),
      ExternalAuthError,
    );
    assertEquals(error.code, "configuration");
    assertStringIncludes(error.message, "team id");
  });

  it("names an empty Services ID in a configuration error", async () => {
    const { pem } = await generateP8();
    const error = await assertRejects(
      () =>
        generateAppleClientSecret({ ...config, clientId: "", privateKey: pem }),
      ExternalAuthError,
    );
    assertEquals(error.code, "configuration");
    assertStringIncludes(error.message, "Services ID");
  });

  it("rejects a malformed private key with a configuration error", async () => {
    const error = await assertRejects(
      () =>
        generateAppleClientSecret({
          ...config,
          privateKey: "-----BEGIN PRIVATE KEY-----\n@@@not base64@@@\n" +
            "-----END PRIVATE KEY-----",
        }),
      ExternalAuthError,
    );
    assertEquals(error.code, "configuration");
    assertStringIncludes(error.message, ".p8");
  });

  it("rejects a wrong-curve (P-384) key with a configuration error", async () => {
    const { pem } = await generateP8("P-384");
    const error = await assertRejects(
      () => generateAppleClientSecret({ ...config, privateKey: pem }),
      ExternalAuthError,
    );
    assertEquals(error.code, "configuration");
    assertStringIncludes(error.message, "P-256");
  });
});

describe("createAppleClientSecretFactory", () => {
  it("caches the secret and re-signs only after it nears expiry", async () => {
    using time = new FakeTime();
    const { pem } = await generateP8();
    const factory = createAppleClientSecretFactory({
      ...config,
      privateKey: pem,
      expiresInSeconds: 3600,
      renewBeforeSeconds: 3600,
    });
    const first = await factory();
    const second = await factory();
    assertEquals(first, second, "within TTL the cached secret is reused");

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
    const error = await assertRejects(() => factory(), ExternalAuthError);
    assertEquals(error.code, "configuration");
  });
});
