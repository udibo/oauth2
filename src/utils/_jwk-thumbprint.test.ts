import { describe, expect, it } from "vitest";
import { jwkThumbprint } from "./_jwk-thumbprint.ts";

const RFC_7638_EXAMPLE_JWK: JsonWebKey & { kid: string } = {
  kty: "RSA",
  n:
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFF" +
    "xuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt" +
    "7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6q" +
    "MQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHa" +
    "Q-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  e: "AQAB",
  alg: "RS256",
  kid: "2011-04-29",
};

describe("jwkThumbprint", () => {
  it("matches the RFC 7638 section 3.1 example thumbprint", async () => {
    expect(await jwkThumbprint(RFC_7638_EXAMPLE_JWK)).toBe(
      "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
    );
  });

  it("matches the RFC 8037 appendix A.3 Ed25519 thumbprint", async () => {
    expect(
      await jwkThumbprint({
        kty: "OKP",
        crv: "Ed25519",
        x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      }),
    ).toBe("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  });

  it("hashes an EC key's crv, kty, x and y in lexicographic order", async () => {
    expect(
      await jwkThumbprint({
        y: "izbPvtQ_Nce_nKR9TBVR3mwsXonGCL8HG8qiGa4SYGM",
        x: "lW_EzJXSl3ZeT1-06WE7iBU3Vlm9ZKzsofnuaIQZ6qU",
        kty: "EC",
        crv: "P-256",
      }),
    ).toBe("hG0RV2LvokByO5hVjjpjEYhRsf303brZjUenGeiUJC4");
  });

  it("hashes only the required members, so a private JWK and its public JWK agree", async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);

    expect(
      await jwkThumbprint({ ...privateJwk, alg: "ES256", use: "sig" }),
    ).toBe(await jwkThumbprint(publicJwk));
  });

  it("rejects a key type it has no required members for", async () => {
    await expect(jwkThumbprint({ kty: "oct", k: "AA" })).rejects.toThrow(
      TypeError,
    );
  });

  it("rejects a key missing a required member", async () => {
    await expect(
      jwkThumbprint({ kty: "EC", crv: "P-256", x: "AA" }),
    ).rejects.toThrow(/"y"/);
  });
});
