import { assert, describe, expect, it } from "vitest";
import {
  findLegacyVerifier,
  type LegacyPasswordVerifier,
  parsePhc,
  pbkdf2Verifier,
  verifyLegacyPassword,
} from "./migration.ts";

const DJANGO_PASSWORD = "correct horse battery staple";
const DJANGO_HASH =
  "pbkdf2_sha256$100000$saltysaltZ12$EQSwFOiYCoPexswCmQxKexbKLdLHxTCke89Wx+gNvTs=";
const PHC_HASH =
  "$pbkdf2-sha256$i=100000$AQIDBAUGBwgJCgsMDQ4PEA$ftOFRW9rEf44G4LTTpOER237yEdk9NMG/2LcdIRmFaQ";

describe("pbkdf2Verifier", () => {
  const verifier = pbkdf2Verifier();

  it("has a default id", () => {
    expect(verifier.id).toStrictEqual("pbkdf2");
    expect(pbkdf2Verifier({ id: "django" }).id).toStrictEqual("django");
  });

  it("verifies a correct Django-format password", async () => {
    assert(verifier.canVerify(DJANGO_HASH));
    assert(await verifier.verify(DJANGO_PASSWORD, DJANGO_HASH));
  });

  it("rejects a wrong password against a Django hash", async () => {
    expect(await verifier.verify("wrong password", DJANGO_HASH)).toBeFalsy();
  });

  it("verifies a correct PHC-format password", async () => {
    assert(verifier.canVerify(PHC_HASH));
    assert(await verifier.verify(DJANGO_PASSWORD, PHC_HASH));
    expect(await verifier.verify("nope", PHC_HASH)).toBeFalsy();
  });

  it("canVerify is false for malformed or foreign hashes", () => {
    expect(verifier.canVerify("$2b$12$abcdefghijklmnopqrstuv")).toBeFalsy();
    expect(
      verifier.canVerify("pbkdf2_sha256$notanumber$salt$aGFzaA=="),
    ).toBeFalsy();
    expect(verifier.canVerify("pbkdf2_sha256$100000$salt")).toBeFalsy();
    expect(verifier.canVerify("pbkdf2_md5$1000$salt$aGFzaA==")).toBeFalsy();
    expect(verifier.canVerify("plaintext")).toBeFalsy();
    expect(verifier.canVerify("")).toBeFalsy();
  });

  it("verify returns false (never throws) for a hash it can't parse", async () => {
    expect(await verifier.verify(DJANGO_PASSWORD, "garbage")).toBeFalsy();
  });

  it("rejects a hash with an empty/short checksum (no universal password)", async () => {
    const empty = "pbkdf2_sha256$100000$saltysaltZ12$";
    expect(
      verifier.canVerify(empty),
      "an empty checksum must not parse",
    ).toBeFalsy();
    expect(
      await verifier.verify("anything", empty),
      "an empty stored hash must never authenticate any password",
    ).toBeFalsy();
    // A short but non-empty checksum (8 bytes) is below the floor.
    const short = "pbkdf2_sha256$100000$saltysaltZ12$aGFzaGhhc2g=";
    expect(verifier.canVerify(short)).toBeFalsy();
  });

  it("rejects an implausibly high iteration count (DoS guard)", () => {
    const huge =
      "pbkdf2_sha256$99999999999$saltysaltZ12$" +
      "EQSwFOiYCoPexswCmQxKexbKLdLHxTCke89Wx+gNvTs=";
    expect(
      verifier.canVerify(huge),
      "an unbounded iteration count must be rejected before deriveBits",
    ).toBeFalsy();
  });
});

describe("parsePhc", () => {
  it("parses an argon2id string with version, params, salt, and hash", () => {
    const parsed = parsePhc(
      "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$c29tZWhhc2g",
    );
    assert(parsed);
    expect(parsed.id).toStrictEqual("argon2id");
    expect(parsed.version).toStrictEqual(19);
    expect(parsed.params).toStrictEqual({ m: "65536", t: "3", p: "4" });
    expect(new TextDecoder().decode(parsed.salt)).toStrictEqual("somesalt");
    expect(new TextDecoder().decode(parsed.hash)).toStrictEqual("somehash");
  });

  it("parses a params-less string", () => {
    const parsed = parsePhc("$scrypt$c29tZXNhbHQ$c29tZWhhc2g");
    assert(parsed);
    expect(parsed.id).toStrictEqual("scrypt");
    expect(parsed.version).toStrictEqual(undefined);
    expect(parsed.params).toStrictEqual({});
    assert(parsed.salt);
    assert(parsed.hash);
  });

  it("returns null for non-PHC input", () => {
    expect(parsePhc("not-a-phc-string")).toStrictEqual(null);
    expect(parsePhc("")).toStrictEqual(null);
    expect(parsePhc("$")).toStrictEqual(null);
  });
});

describe("findLegacyVerifier / verifyLegacyPassword", () => {
  const bcryptish: LegacyPasswordVerifier = {
    id: "bcrypt",
    canVerify: (phc) => phc.startsWith("$2"),
    verify: (password) => Promise.resolve(password === "secret"),
  };
  const throwing: LegacyPasswordVerifier = {
    id: "boom",
    canVerify: () => {
      throw new Error("bad connector");
    },
    verify: () => Promise.resolve(true),
  };
  const verifiers = [pbkdf2Verifier(), bcryptish];

  it("selects the verifier whose canVerify matches", () => {
    expect(findLegacyVerifier(verifiers, DJANGO_HASH)?.id).toStrictEqual(
      "pbkdf2",
    );
    expect(findLegacyVerifier(verifiers, "$2b$12$xyz")?.id).toStrictEqual(
      "bcrypt",
    );
    expect(findLegacyVerifier(verifiers, "$argon2id$x")).toStrictEqual(
      undefined,
    );
  });

  it("skips a verifier that throws from canVerify", () => {
    expect(
      findLegacyVerifier([throwing, bcryptish], "$2b$x")?.id,
    ).toStrictEqual("bcrypt");
  });

  it("verifyLegacyPassword routes to the matching verifier", async () => {
    assert(await verifyLegacyPassword(verifiers, DJANGO_PASSWORD, DJANGO_HASH));
    assert(await verifyLegacyPassword(verifiers, "secret", "$2b$12$x"));
    expect(
      await verifyLegacyPassword(verifiers, "nope", "$2b$12$x"),
    ).toBeFalsy();
  });

  it("returns false when no verifier claims the hash — scrypt is BYO, not built-in", async () => {
    expect(
      findLegacyVerifier([pbkdf2Verifier()], "$scrypt$ln=16$c2FsdA$aGFzaA"),
    ).toStrictEqual(undefined);
    expect(
      await verifyLegacyPassword(
        [pbkdf2Verifier()],
        "any",
        "$scrypt$ln=16$c2FsdA$aGFzaA",
      ),
    ).toBeFalsy();
  });
});
