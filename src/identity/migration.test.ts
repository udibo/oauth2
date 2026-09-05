import { assert, assertEquals, assertFalse } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

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
    assertEquals(verifier.id, "pbkdf2");
    assertEquals(pbkdf2Verifier({ id: "django" }).id, "django");
  });

  it("verifies a correct Django-format password", async () => {
    assert(verifier.canVerify(DJANGO_HASH));
    assert(await verifier.verify(DJANGO_PASSWORD, DJANGO_HASH));
  });

  it("rejects a wrong password against a Django hash", async () => {
    assertFalse(await verifier.verify("wrong password", DJANGO_HASH));
  });

  it("verifies a correct PHC-format password", async () => {
    assert(verifier.canVerify(PHC_HASH));
    assert(await verifier.verify(DJANGO_PASSWORD, PHC_HASH));
    assertFalse(await verifier.verify("nope", PHC_HASH));
  });

  it("canVerify is false for malformed or foreign hashes", () => {
    assertFalse(verifier.canVerify("$2b$12$abcdefghijklmnopqrstuv"));
    assertFalse(verifier.canVerify("pbkdf2_sha256$notanumber$salt$aGFzaA=="));
    assertFalse(verifier.canVerify("pbkdf2_sha256$100000$salt"));
    assertFalse(verifier.canVerify("pbkdf2_md5$1000$salt$aGFzaA=="));
    assertFalse(verifier.canVerify("plaintext"));
    assertFalse(verifier.canVerify(""));
  });

  it("verify returns false (never throws) for a hash it can't parse", async () => {
    assertFalse(await verifier.verify(DJANGO_PASSWORD, "garbage"));
  });

  it("rejects a hash with an empty/short checksum (no universal password)", async () => {
    const empty = "pbkdf2_sha256$100000$saltysaltZ12$";
    assertFalse(verifier.canVerify(empty), "an empty checksum must not parse");
    assertFalse(
      await verifier.verify("anything", empty),
      "an empty stored hash must never authenticate any password",
    );
    // A short but non-empty checksum (8 bytes) is below the floor.
    const short = "pbkdf2_sha256$100000$saltysaltZ12$aGFzaGhhc2g=";
    assertFalse(verifier.canVerify(short));
  });

  it("rejects an implausibly high iteration count (DoS guard)", () => {
    const huge = "pbkdf2_sha256$99999999999$saltysaltZ12$" +
      "EQSwFOiYCoPexswCmQxKexbKLdLHxTCke89Wx+gNvTs=";
    assertFalse(
      verifier.canVerify(huge),
      "an unbounded iteration count must be rejected before deriveBits",
    );
  });
});

describe("parsePhc", () => {
  it("parses an argon2id string with version, params, salt, and hash", () => {
    const parsed = parsePhc(
      "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$c29tZWhhc2g",
    );
    assert(parsed);
    assertEquals(parsed.id, "argon2id");
    assertEquals(parsed.version, 19);
    assertEquals(parsed.params, { m: "65536", t: "3", p: "4" });
    assertEquals(new TextDecoder().decode(parsed.salt), "somesalt");
    assertEquals(new TextDecoder().decode(parsed.hash), "somehash");
  });

  it("parses a params-less string", () => {
    const parsed = parsePhc("$scrypt$c29tZXNhbHQ$c29tZWhhc2g");
    assert(parsed);
    assertEquals(parsed.id, "scrypt");
    assertEquals(parsed.version, undefined);
    assertEquals(parsed.params, {});
    assert(parsed.salt);
    assert(parsed.hash);
  });

  it("returns null for non-PHC input", () => {
    assertEquals(parsePhc("not-a-phc-string"), null);
    assertEquals(parsePhc(""), null);
    assertEquals(parsePhc("$"), null);
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
    assertEquals(findLegacyVerifier(verifiers, DJANGO_HASH)?.id, "pbkdf2");
    assertEquals(findLegacyVerifier(verifiers, "$2b$12$xyz")?.id, "bcrypt");
    assertEquals(findLegacyVerifier(verifiers, "$argon2id$x"), undefined);
  });

  it("skips a verifier that throws from canVerify", () => {
    assertEquals(
      findLegacyVerifier([throwing, bcryptish], "$2b$x")?.id,
      "bcrypt",
    );
  });

  it("verifyLegacyPassword routes to the matching verifier", async () => {
    assert(await verifyLegacyPassword(verifiers, DJANGO_PASSWORD, DJANGO_HASH));
    assert(await verifyLegacyPassword(verifiers, "secret", "$2b$12$x"));
    assertFalse(await verifyLegacyPassword(verifiers, "nope", "$2b$12$x"));
  });

  it("returns false when no verifier claims the hash — scrypt is BYO, not built-in", async () => {
    assertEquals(
      findLegacyVerifier([pbkdf2Verifier()], "$scrypt$ln=16$c2FsdA$aGFzaA"),
      undefined,
    );
    assertFalse(
      await verifyLegacyPassword(
        [pbkdf2Verifier()],
        "any",
        "$scrypt$ln=16$c2FsdA$aGFzaA",
      ),
    );
  });
});
