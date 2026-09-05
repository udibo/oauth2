import { assertEquals, assertStrictEquals } from "@std/assert";
import { decodeBase64Url } from "@std/encoding/base64url";
import { describe, it } from "@std/testing/bdd";
import type { ChallengeMethod, ChallengeMethods } from "./pkce.ts";
import {
  challengeMethods,
  CODE_VERIFIER_MAX_LENGTH,
  CODE_VERIFIER_MIN_LENGTH,
  CODE_VERIFIER_PATTERN,
  generateCodeChallenge,
  generateCodeVerifier,
  getChallengeMethod,
  validateCodeChallenge,
  validateCodeVerifier,
  verifyCodeChallenge,
} from "./pkce.ts";

const INHERITED_MEMBER_NAMES = [
  "toString",
  "valueOf",
  "constructor",
  "hasOwnProperty",
  "isPrototypeOf",
  "__proto__",
];

describe("PKCE", () => {
  describe("generateCodeVerifier", () => {
    it("should generate a 43 character string", () => {
      const verifier = generateCodeVerifier();
      assertStrictEquals(verifier.length, 43);
    });

    it("should generate base64url-encoded data", () => {
      const verifier = generateCodeVerifier();
      const decoded = decodeBase64Url(verifier);
      assertEquals(decoded.length, 32);
    });

    it("should generate unique verifiers", () => {
      const verifier1 = generateCodeVerifier();
      const verifier2 = generateCodeVerifier();
      assertStrictEquals(verifier1 !== verifier2, true);
    });
  });

  describe("challengeMethods", () => {
    describe("S256", () => {
      it("should match RFC 7636 Appendix B test vector", async () => {
        // Test vector from https://datatracker.ietf.org/doc/html/rfc7636#appendix-B
        const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        const challenge = await challengeMethods.S256(verifier);
        assertEquals(challenge, expectedChallenge);
      });

      it("should generate different challenges for different verifiers", async () => {
        const challenge1 = await challengeMethods.S256("verifier1");
        const challenge2 = await challengeMethods.S256("verifier2");
        assertStrictEquals(challenge1 !== challenge2, true);
      });
    });
  });

  describe("generateCodeChallenge", () => {
    it("should generate challenge using S256", async () => {
      const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      const challenge = await generateCodeChallenge(verifier);
      const expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
      assertEquals(challenge, expectedChallenge);
    });

    it("should match challengeMethods.S256 output", async () => {
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const expected = await challengeMethods.S256(verifier);
      assertEquals(challenge, expected);
    });
  });

  describe("verifyCodeChallenge", () => {
    it("should return true for matching verifier and challenge", async () => {
      const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
      const result = await verifyCodeChallenge(verifier, challenge);
      assertStrictEquals(result, true);
    });

    it("should return false for non-matching verifier and challenge", async () => {
      const verifier = "wrong-verifier";
      const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
      const result = await verifyCodeChallenge(verifier, challenge);
      assertStrictEquals(result, false);
    });

    it("should use specified challenge method", async () => {
      const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
      const result = await verifyCodeChallenge(verifier, challenge, "S256");
      assertStrictEquals(result, true);
    });

    it("rejects every challenge method name inherited from Object.prototype", async () => {
      const verifier = generateCodeVerifier();
      for (const method of INHERITED_MEMBER_NAMES) {
        assertStrictEquals(
          await verifyCodeChallenge(verifier, "[object Undefined]", method),
          false,
          method,
        );
      }
    });

    it("rejects the constant Object.prototype.toString returns as a challenge", async () => {
      const result = await verifyCodeChallenge(
        "a".repeat(43),
        "[object Undefined]",
        "toString",
      );
      assertStrictEquals(result, false);
    });

    it("returns false rather than throwing for an unknown challenge method", async () => {
      const verifier = generateCodeVerifier();
      assertStrictEquals(
        await verifyCodeChallenge(verifier, "challenge", "plain"),
        false,
      );
    });
  });

  describe("getChallengeMethod", () => {
    it("resolves an own callable method by name", () => {
      assertStrictEquals(
        getChallengeMethod(challengeMethods, "S256"),
        challengeMethods.S256,
      );
    });

    it("defaults to S256 when no method is named", () => {
      assertStrictEquals(
        getChallengeMethod(challengeMethods),
        challengeMethods.S256,
      );
      assertStrictEquals(
        getChallengeMethod(challengeMethods, null),
        challengeMethods.S256,
      );
    });

    it("resolves a method a consumer added to their own map", () => {
      const custom: ChallengeMethod = (verifier) => Promise.resolve(verifier);
      const methods: ChallengeMethods = { custom };
      assertStrictEquals(getChallengeMethod(methods, "custom"), custom);
    });

    it("resolves nothing for a name inherited from Object.prototype", () => {
      const methods: ChallengeMethods = { S256: challengeMethods.S256 };
      for (const name of INHERITED_MEMBER_NAMES) {
        assertStrictEquals(
          getChallengeMethod(challengeMethods, name),
          undefined,
          name,
        );
        assertStrictEquals(getChallengeMethod(methods, name), undefined, name);
      }
    });

    it("resolves nothing for a name the map does not hold", () => {
      assertStrictEquals(
        getChallengeMethod(challengeMethods, "plain"),
        undefined,
      );
    });
  });

  describe("CODE_VERIFIER constants", () => {
    it("should have correct minimum length per RFC 7636", () => {
      assertStrictEquals(CODE_VERIFIER_MIN_LENGTH, 43);
    });

    it("should have correct maximum length per RFC 7636", () => {
      assertStrictEquals(CODE_VERIFIER_MAX_LENGTH, 128);
    });

    it("should have correct pattern per RFC 7636", () => {
      assertStrictEquals(CODE_VERIFIER_PATTERN.test("abcABC123-._~"), true);
      assertStrictEquals(CODE_VERIFIER_PATTERN.test("invalid chars!"), false);
      assertStrictEquals(CODE_VERIFIER_PATTERN.test("has space"), false);
    });
  });

  describe("validateCodeChallenge", () => {
    it("accepts an S256 challenge, which is 43 base64url characters", async () => {
      const challenge = await generateCodeChallenge(generateCodeVerifier());
      assertStrictEquals(validateCodeChallenge(challenge, "S256"), true);
    });

    it("rejects an S256 challenge shorter than 43 characters", () => {
      assertStrictEquals(validateCodeChallenge("a".repeat(42), "S256"), false);
    });

    it("rejects an S256 challenge longer than 128 characters", () => {
      assertStrictEquals(validateCodeChallenge("a".repeat(129), "S256"), false);
    });

    it("rejects an S256 challenge holding a character outside the unreserved set", () => {
      assertStrictEquals(
        validateCodeChallenge("a".repeat(42) + "!", "S256"),
        false,
      );
    });

    it("holds a plain challenge to the same shape as the verifier it repeats", () => {
      assertStrictEquals(validateCodeChallenge("a".repeat(43), "plain"), true);
      assertStrictEquals(validateCodeChallenge("short", "plain"), false);
    });

    it("validates against S256 when no method is named", () => {
      assertStrictEquals(validateCodeChallenge("a".repeat(43)), true);
      assertStrictEquals(validateCodeChallenge("short"), false);
      assertStrictEquals(validateCodeChallenge("short", null), false);
    });

    it("leaves the shape to the server for a method RFC 7636 does not define", () => {
      assertStrictEquals(validateCodeChallenge("short", "first-8"), true);
      assertStrictEquals(validateCodeChallenge("", "first-8"), true);
    });
  });

  describe("validateCodeVerifier", () => {
    it("should accept minimum length verifier (43 chars)", () => {
      const verifier = "a".repeat(43);
      assertStrictEquals(validateCodeVerifier(verifier), true);
    });

    it("should accept maximum length verifier (128 chars)", () => {
      const verifier = "a".repeat(128);
      assertStrictEquals(validateCodeVerifier(verifier), true);
    });

    it("should reject verifier shorter than 43 chars", () => {
      const verifier = "a".repeat(42);
      assertStrictEquals(validateCodeVerifier(verifier), false);
    });

    it("should reject verifier longer than 128 chars", () => {
      const verifier = "a".repeat(129);
      assertStrictEquals(validateCodeVerifier(verifier), false);
    });

    it("should accept valid unreserved characters per RFC 7636", () => {
      const verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk0123456";
      assertStrictEquals(validateCodeVerifier(verifier), true);
    });

    it("should accept verifier with hyphen", () => {
      const verifier = "a-b-c-d-e-f-g-h-i-j-k-l-m-n-o-p-q-r-s-t-u-v";
      assertStrictEquals(validateCodeVerifier(verifier), true);
    });

    it("should accept verifier with period", () => {
      const verifier = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v";
      assertStrictEquals(validateCodeVerifier(verifier), true);
    });

    it("should accept verifier with underscore", () => {
      const verifier = "a_b_c_d_e_f_g_h_i_j_k_l_m_n_o_p_q_r_s_t_u_v";
      assertStrictEquals(validateCodeVerifier(verifier), true);
    });

    it("should accept verifier with tilde", () => {
      const verifier = "a~b~c~d~e~f~g~h~i~j~k~l~m~n~o~p~q~r~s~t~u~v";
      assertStrictEquals(validateCodeVerifier(verifier), true);
    });

    it("should reject verifier with invalid characters", () => {
      const verifier = "a".repeat(42) + "!";
      assertStrictEquals(validateCodeVerifier(verifier), false);
    });

    it("should reject verifier with space", () => {
      const verifier = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn op";
      assertStrictEquals(validateCodeVerifier(verifier), false);
    });

    it("should reject verifier with plus sign (not in allowed set)", () => {
      const verifier = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn+p";
      assertStrictEquals(validateCodeVerifier(verifier), false);
    });

    it("should accept RFC 7636 Appendix B test vector", () => {
      const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      assertStrictEquals(validateCodeVerifier(verifier), true);
    });

    it("should accept generated code verifier", () => {
      const verifier = generateCodeVerifier();
      assertStrictEquals(validateCodeVerifier(verifier), true);
    });

    it("should reject empty string", () => {
      assertStrictEquals(validateCodeVerifier(""), false);
    });
  });
});
