import { assert, describe, expect, it } from "vitest";
import { decodeBase64Url } from "../utils/_encoding.ts";
import { BasicScope } from "../models/scope.ts";
import {
  createJwtAccessTokenGenerator,
  exportSigningKeyJwk,
  generateSigningKey,
  importSigningKeyJwk,
  RotatingSigningKeyProvider,
  type SigningKey,
  signJwt,
  StaticSigningKeyProvider,
  verifyJwt,
} from "./signing-keys.ts";

function kidHeaderOf(jwt: string): string {
  return JSON.parse(
    new TextDecoder().decode(decodeBase64Url(jwt.split(".")[0])),
  ).kid;
}

function jwkByKid(
  jwks: { keys: JsonWebKey[] },
  kid: string,
): JsonWebKey | undefined {
  return jwks.keys.find((jwk) => (jwk as { kid?: string }).kid === kid);
}

describe("signing keys", () => {
  it("signs a JWT that verifies against the published public JWK", async () => {
    const key = await generateSigningKey();
    const jwt = await signJwt(key, { sub: "user-1", iss: "https://issuer" });

    const payload = await verifyJwt(jwt, key.publicJwk);
    expect(payload?.sub).toStrictEqual("user-1");
    expect(payload?.iss).toStrictEqual("https://issuer");

    const header = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(jwt.split(".")[0])),
    );
    expect(header.alg).toStrictEqual("ES256");
    expect(header.kid).toStrictEqual(key.kid);
  });

  it("rejects a tampered token and a wrong key", async () => {
    const key = await generateSigningKey();
    const other = await generateSigningKey();
    const jwt = await signJwt(key, { sub: "user-1" });

    expect(await verifyJwt(jwt, other.publicJwk)).toStrictEqual(undefined);
    const [h, p, s] = jwt.split(".");
    const tamperedPayload = p.slice(0, -2) + (p.endsWith("aa") ? "bb" : "aa");
    expect(
      await verifyJwt(`${h}.${tamperedPayload}.${s}`, key.publicJwk),
    ).toStrictEqual(undefined);
    expect(await verifyJwt("garbage", key.publicJwk)).toStrictEqual(undefined);
  });

  it("round-trips non-ASCII claim values", async () => {
    const key = await generateSigningKey();
    const jwt = await signJwt(key, { name: "José García" });
    const payload = await verifyJwt(jwt, key.publicJwk);
    expect(payload?.name).toStrictEqual("José García");
  });

  it("rejects a token whose exp is in the past", async () => {
    const key = await generateSigningKey();
    const jwt = await signJwt(key, {
      sub: "user-1",
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    expect(await verifyJwt(jwt, key.publicJwk)).toStrictEqual(undefined);
  });

  it("round-trips a key through export/import", async () => {
    const key = await generateSigningKey();
    const exported = await exportSigningKeyJwk(key);
    assert.exists(exported.d, "exported key must include private material");

    const imported = await importSigningKeyJwk(exported);
    expect(imported.kid).toStrictEqual(key.kid);
    const jwt = await signJwt(imported, { sub: "user-2" });
    expect((await verifyJwt(jwt, key.publicJwk))?.sub).toStrictEqual("user-2");
  });

  it("publishes only public material in the JWKS", async () => {
    const key = await generateSigningKey();
    const provider = new StaticSigningKeyProvider(key);
    const jwks = await provider.getPublicJwks();
    expect(jwks.keys.length).toStrictEqual(1);
    const jwk = jwks.keys[0] as Record<string, unknown>;
    expect(jwk.d).toStrictEqual(undefined);
    expect(jwk.kid).toStrictEqual(key.kid);
    assert(jwk.x && jwk.y);
  });
});

describe("RotatingSigningKeyProvider", () => {
  it("signs with the current key only", async () => {
    const current = await generateSigningKey();
    const previous = await generateSigningKey();
    const provider = new RotatingSigningKeyProvider({
      current,
      previous: [previous],
    });

    const signing = await provider.getSigningKey();
    expect(signing.kid).toStrictEqual(current.kid);
    const jwt = await signJwt(signing, { sub: "user-1" });
    expect(kidHeaderOf(jwt)).toStrictEqual(current.kid);
  });

  it("publishes current + previous during the grace window", async () => {
    const current = await generateSigningKey();
    const previous = await generateSigningKey();
    const provider = new RotatingSigningKeyProvider({
      current,
      previous: [previous],
    });

    const jwks = await provider.getPublicJwks();
    expect(jwks.keys.length).toStrictEqual(2);
    expect(
      (jwks.keys[0] as { kid?: string }).kid,
      "current key is published first",
    ).toStrictEqual(current.kid);
    assert.exists(jwkByKid(jwks, current.kid));
    assert.exists(jwkByKid(jwks, previous.kid));
    for (const jwk of jwks.keys) {
      expect((jwk as Record<string, unknown>).d).toStrictEqual(undefined);
    }
  });

  it("keeps a token signed by the previous key verifying while it is published", async () => {
    const previous = await generateSigningKey();
    const current = await generateSigningKey();
    const oldToken = await signJwt(previous, { sub: "grace" });

    const provider = new RotatingSigningKeyProvider({
      current,
      previous: [previous],
    });
    const jwks = await provider.getPublicJwks();

    const publishedForKid = jwkByKid(jwks, kidHeaderOf(oldToken));
    assert.exists(publishedForKid, "the old kid must still be published");
    expect((await verifyJwt(oldToken, publishedForKid))?.sub).toStrictEqual(
      "grace",
    );
  });

  it("stops verifying an old token once the previous key is retired", async () => {
    const previous = await generateSigningKey();
    const current = await generateSigningKey();
    const oldToken = await signJwt(previous, { sub: "grace" });

    const retired = new RotatingSigningKeyProvider({ current });
    const jwks = await retired.getPublicJwks();

    expect(jwks.keys.length).toStrictEqual(1);
    expect(jwkByKid(jwks, kidHeaderOf(oldToken))).toStrictEqual(undefined);
    for (const jwk of jwks.keys) {
      expect(await verifyJwt(oldToken, jwk)).toStrictEqual(undefined);
    }
  });

  it("matches the single-key StaticSigningKeyProvider when previous is empty", async () => {
    const key = await generateSigningKey();
    const rotating = new RotatingSigningKeyProvider({ current: key });
    const staticProvider = new StaticSigningKeyProvider(key);

    expect((await rotating.getSigningKey()).kid).toStrictEqual(
      (await staticProvider.getSigningKey()).kid,
    );
    expect(await rotating.getPublicJwks()).toStrictEqual(
      await staticProvider.getPublicJwks(),
    );
  });

  it("de-duplicates a previous key that shares the current kid", async () => {
    const current = await generateSigningKey();
    const alias: SigningKey = { ...current };
    const provider = new RotatingSigningKeyProvider({
      current,
      previous: [alias],
    });

    const jwks = await provider.getPublicJwks();
    expect(jwks.keys.length).toStrictEqual(1);
    expect((jwks.keys[0] as { kid?: string }).kid).toStrictEqual(current.kid);
  });
});

describe("createJwtAccessTokenGenerator userClaims", () => {
  const client = { id: "client-1" };
  const user = { id: "user-1" };

  async function generateAndVerify(
    options: Omit<
      Parameters<typeof createJwtAccessTokenGenerator>[0],
      "signingKeys" | "issuer"
    >,
    subject: unknown,
    scope?: BasicScope | null,
  ): Promise<Record<string, unknown>> {
    const key = await generateSigningKey();
    const generate = createJwtAccessTokenGenerator({
      signingKeys: new StaticSigningKeyProvider(key),
      issuer: "https://auth.example.com",
      ...options,
    });
    const jwt = await generate(client, subject, scope);
    const claims = await verifyJwt(jwt, key.publicJwk);
    assert.exists(claims);
    return claims!;
  }

  it("merges userClaims into the resource owner's access token", async () => {
    const seen: unknown[] = [];
    const claims = await generateAndVerify(
      {
        userClaims: (forUser, forScope, forClient) => {
          seen.push(forUser, forScope?.toString(), forClient?.id);
          return {
            permissions: ["posts:write"],
            org_id: "org-1",
            org_roles: ["admin"],
          };
        },
      },
      user,
      new BasicScope("openid posts:read"),
    );

    expect(claims.permissions).toStrictEqual(["posts:write"]);
    expect(claims.org_id).toStrictEqual("org-1");
    expect(claims.org_roles).toStrictEqual(["admin"]);
    expect(claims.scope).toStrictEqual("openid posts:read");
    expect(seen).toStrictEqual([user, "openid posts:read", "client-1"]);
  });

  it("never lets userClaims shadow a protocol claim", async () => {
    const claims = await generateAndVerify(
      {
        userClaims: () => ({
          iss: "https://evil.example.com",
          sub: "someone-else",
          aud: "another-api",
          client_id: "another-client",
          iat: 1,
          exp: 9999999999999,
          jti: "forged",
          scope: "identity:users:write",
        }),
      },
      user,
    );

    expect(claims.iss).toStrictEqual("https://auth.example.com");
    expect(claims.sub).toStrictEqual("user-1");
    expect(claims.aud).toStrictEqual("client-1");
    expect(claims.client_id).toStrictEqual("client-1");
    assert(typeof claims.iat === "number" && claims.iat > 1);
    assert(typeof claims.exp === "number" && claims.exp < 9999999999999);
    assert(claims.jti !== "forged");
    expect(claims.scope).toStrictEqual(undefined);
  });

  it("never invokes userClaims for a machine token", async () => {
    let invoked = false;
    const claims = await generateAndVerify(
      {
        userClaims: () => {
          invoked = true;
          return { permissions: ["posts:write"] };
        },
      },
      null,
      new BasicScope("identity:users:read"),
    );

    expect(invoked).toStrictEqual(false);
    expect(claims.permissions).toStrictEqual(undefined);
    expect(claims.sub).toStrictEqual("client-1");
    expect(claims.scope).toStrictEqual("identity:users:read");
  });

  it("awaits an async userClaims hook", async () => {
    const claims = await generateAndVerify(
      {
        userClaims: () => Promise.resolve({ roles: ["editor"] }),
      },
      user,
    );
    expect(claims.roles).toStrictEqual(["editor"]);
  });
});
