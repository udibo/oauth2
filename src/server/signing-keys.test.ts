import { assert, assertEquals, assertExists } from "@std/assert";
import { decodeBase64Url } from "@std/encoding/base64url";
import { describe, it } from "@std/testing/bdd";

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
    assertEquals(payload?.sub, "user-1");
    assertEquals(payload?.iss, "https://issuer");

    const header = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(jwt.split(".")[0])),
    );
    assertEquals(header.alg, "ES256");
    assertEquals(header.kid, key.kid);
  });

  it("rejects a tampered token and a wrong key", async () => {
    const key = await generateSigningKey();
    const other = await generateSigningKey();
    const jwt = await signJwt(key, { sub: "user-1" });

    assertEquals(await verifyJwt(jwt, other.publicJwk), undefined);
    const [h, p, s] = jwt.split(".");
    const tamperedPayload = p.slice(0, -2) + (p.endsWith("aa") ? "bb" : "aa");
    assertEquals(
      await verifyJwt(`${h}.${tamperedPayload}.${s}`, key.publicJwk),
      undefined,
    );
    assertEquals(await verifyJwt("garbage", key.publicJwk), undefined);
  });

  it("round-trips non-ASCII claim values", async () => {
    const key = await generateSigningKey();
    const jwt = await signJwt(key, { name: "José García" });
    const payload = await verifyJwt(jwt, key.publicJwk);
    assertEquals(payload?.name, "José García");
  });

  it("rejects a token whose exp is in the past", async () => {
    const key = await generateSigningKey();
    const jwt = await signJwt(key, {
      sub: "user-1",
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    assertEquals(await verifyJwt(jwt, key.publicJwk), undefined);
  });

  it("round-trips a key through export/import", async () => {
    const key = await generateSigningKey();
    const exported = await exportSigningKeyJwk(key);
    assertExists(exported.d, "exported key must include private material");

    const imported = await importSigningKeyJwk(exported);
    assertEquals(imported.kid, key.kid);
    const jwt = await signJwt(imported, { sub: "user-2" });
    assertEquals((await verifyJwt(jwt, key.publicJwk))?.sub, "user-2");
  });

  it("publishes only public material in the JWKS", async () => {
    const key = await generateSigningKey();
    const provider = new StaticSigningKeyProvider(key);
    const jwks = await provider.getPublicJwks();
    assertEquals(jwks.keys.length, 1);
    const jwk = jwks.keys[0] as Record<string, unknown>;
    assertEquals(jwk.d, undefined);
    assertEquals(jwk.kid, key.kid);
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
    assertEquals(signing.kid, current.kid);
    const jwt = await signJwt(signing, { sub: "user-1" });
    assertEquals(kidHeaderOf(jwt), current.kid);
  });

  it("publishes current + previous during the grace window", async () => {
    const current = await generateSigningKey();
    const previous = await generateSigningKey();
    const provider = new RotatingSigningKeyProvider({
      current,
      previous: [previous],
    });

    const jwks = await provider.getPublicJwks();
    assertEquals(jwks.keys.length, 2);
    assertEquals(
      (jwks.keys[0] as { kid?: string }).kid,
      current.kid,
      "current key is published first",
    );
    assertExists(jwkByKid(jwks, current.kid));
    assertExists(jwkByKid(jwks, previous.kid));
    for (const jwk of jwks.keys) {
      assertEquals((jwk as Record<string, unknown>).d, undefined);
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
    assertExists(publishedForKid, "the old kid must still be published");
    assertEquals(
      (await verifyJwt(oldToken, publishedForKid))?.sub,
      "grace",
    );
  });

  it("stops verifying an old token once the previous key is retired", async () => {
    const previous = await generateSigningKey();
    const current = await generateSigningKey();
    const oldToken = await signJwt(previous, { sub: "grace" });

    const retired = new RotatingSigningKeyProvider({ current });
    const jwks = await retired.getPublicJwks();

    assertEquals(jwks.keys.length, 1);
    assertEquals(jwkByKid(jwks, kidHeaderOf(oldToken)), undefined);
    for (const jwk of jwks.keys) {
      assertEquals(await verifyJwt(oldToken, jwk), undefined);
    }
  });

  it("matches the single-key StaticSigningKeyProvider when previous is empty", async () => {
    const key = await generateSigningKey();
    const rotating = new RotatingSigningKeyProvider({ current: key });
    const staticProvider = new StaticSigningKeyProvider(key);

    assertEquals(
      (await rotating.getSigningKey()).kid,
      (await staticProvider.getSigningKey()).kid,
    );
    assertEquals(
      await rotating.getPublicJwks(),
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
    assertEquals(jwks.keys.length, 1);
    assertEquals((jwks.keys[0] as { kid?: string }).kid, current.kid);
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
    assertExists(claims);
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

    assertEquals(claims.permissions, ["posts:write"]);
    assertEquals(claims.org_id, "org-1");
    assertEquals(claims.org_roles, ["admin"]);
    assertEquals(claims.scope, "openid posts:read");
    assertEquals(seen, [user, "openid posts:read", "client-1"]);
  });

  it("never lets userClaims shadow a protocol claim", async () => {
    const claims = await generateAndVerify({
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
    }, user);

    assertEquals(claims.iss, "https://auth.example.com");
    assertEquals(claims.sub, "user-1");
    assertEquals(claims.aud, "client-1");
    assertEquals(claims.client_id, "client-1");
    assert(typeof claims.iat === "number" && claims.iat > 1);
    assert(typeof claims.exp === "number" && claims.exp < 9999999999999);
    assert(claims.jti !== "forged");
    assertEquals(claims.scope, undefined);
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

    assertEquals(invoked, false);
    assertEquals(claims.permissions, undefined);
    assertEquals(claims.sub, "client-1");
    assertEquals(claims.scope, "identity:users:read");
  });

  it("awaits an async userClaims hook", async () => {
    const claims = await generateAndVerify({
      userClaims: () => Promise.resolve({ roles: ["editor"] }),
    }, user);
    assertEquals(claims.roles, ["editor"]);
  });
});
