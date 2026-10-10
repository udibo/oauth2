import { describe, expect, it } from "vitest";
import { decodeBase64Url } from "./_encoding.ts";
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
      expect(verifier.length).toBe(43);
    });

    it("should generate base64url-encoded data", () => {
      const verifier = generateCodeVerifier();
      const decoded = decodeBase64Url(verifier);
      expect(decoded.length).toStrictEqual(32);
    });

    it("should generate unique verifiers", () => {
      const verifier1 = generateCodeVerifier();
      const verifier2 = generateCodeVerifier();
      expect(verifier1 !== verifier2).toBe(true);
    });
  });

  describe("challengeMethods", () => {
    describe("S256", () => {
      it("should match RFC 7636 Appendix B test vector", async () => {
        // Test vector from https://datatracker.ietf.org/doc/html/rfc7636#appendix-B
        const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        const challenge = await challengeMethods.S256(verifier);
        expect(challenge).toStrictEqual(expectedChallenge);
      });

      it("should generate different challenges for different verifiers", async () => {
        const challenge1 = await challengeMethods.S256("verifier1");
        const challenge2 = await challengeMethods.S256("verifier2");
        expect(challenge1 !== challenge2).toBe(true);
      });
    });
  });

  describe("generateCodeChallenge", () => {
    it("should generate challenge using S256", async () => {
      const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      const challenge = await generateCodeChallenge(verifier);
      const expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
      expect(challenge).toStrictEqual(expectedChallenge);
    });

    it("should match challengeMethods.S256 output", async () => {
      const verifier = generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const expected = await challengeMethods.S256(verifier);
      expect(challenge).toStrictEqual(expected);
    });
  });

  describe("verifyCodeChallenge", () => {
    it("should return true for matching verifier and challenge", async () => {
      const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
      const result = await verifyCodeChallenge(verifier, challenge);
      expect(result).toBe(true);
    });

    it("should return false for non-matching verifier and challenge", async () => {
      const verifier = "wrong-verifier";
      const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
      const result = await verifyCodeChallenge(verifier, challenge);
      expect(result).toBe(false);
    });

    it("should use specified challenge method", async () => {
      const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
      const result = await verifyCodeChallenge(verifier, challenge, "S256");
      expect(result).toBe(true);
    });

    it("rejects every challenge method name inherited from Object.prototype", async () => {
      const verifier = generateCodeVerifier();
      for (const method of INHERITED_MEMBER_NAMES) {
        expect(
          await verifyCodeChallenge(verifier, "[object Undefined]", method),
          method,
        ).toBe(false);
      }
    });

    it("rejects the constant Object.prototype.toString returns as a challenge", async () => {
      const result = await verifyCodeChallenge(
        "a".repeat(43),
        "[object Undefined]",
        "toString",
      );
      expect(result).toBe(false);
    });

    it("returns false rather than throwing for an unknown challenge method", async () => {
      const verifier = generateCodeVerifier();
      expect(await verifyCodeChallenge(verifier, "challenge", "plain")).toBe(
        false,
      );
    });
  });

  describe("getChallengeMethod", () => {
    it("resolves an own callable method by name", () => {
      expect(getChallengeMethod(challengeMethods, "S256")).toBe(
        challengeMethods.S256,
      );
    });

    it("defaults to S256 when no method is named", () => {
      expect(getChallengeMethod(challengeMethods)).toBe(challengeMethods.S256);
      expect(getChallengeMethod(challengeMethods, null)).toBe(
        challengeMethods.S256,
      );
    });

    it("resolves a method a consumer added to their own map", () => {
      const custom: ChallengeMethod = (verifier) => Promise.resolve(verifier);
      const methods: ChallengeMethods = { custom };
      expect(getChallengeMethod(methods, "custom")).toBe(custom);
    });

    it("resolves nothing for a name inherited from Object.prototype", () => {
      const methods: ChallengeMethods = { S256: challengeMethods.S256 };
      for (const name of INHERITED_MEMBER_NAMES) {
        expect(getChallengeMethod(challengeMethods, name), name).toBe(
          undefined,
        );
        expect(getChallengeMethod(methods, name), name).toBe(undefined);
      }
    });

    it("resolves nothing for a name the map does not hold", () => {
      expect(getChallengeMethod(challengeMethods, "plain")).toBe(undefined);
    });
  });

  describe("CODE_VERIFIER constants", () => {
    it("should have correct minimum length per RFC 7636", () => {
      expect(CODE_VERIFIER_MIN_LENGTH).toBe(43);
    });

    it("should have correct maximum length per RFC 7636", () => {
      expect(CODE_VERIFIER_MAX_LENGTH).toBe(128);
    });

    it("should have correct pattern per RFC 7636", () => {
      expect(CODE_VERIFIER_PATTERN.test("abcABC123-._~")).toBe(true);
      expect(CODE_VERIFIER_PATTERN.test("invalid chars!")).toBe(false);
      expect(CODE_VERIFIER_PATTERN.test("has space")).toBe(false);
    });
  });

  describe("validateCodeChallenge", () => {
    it("accepts an S256 challenge, which is 43 base64url characters", async () => {
      const challenge = await generateCodeChallenge(generateCodeVerifier());
      expect(validateCodeChallenge(challenge, "S256")).toBe(true);
    });

    it("rejects an S256 challenge shorter than 43 characters", () => {
      expect(validateCodeChallenge("a".repeat(42), "S256")).toBe(false);
    });

    it("rejects an S256 challenge longer than 128 characters", () => {
      expect(validateCodeChallenge("a".repeat(129), "S256")).toBe(false);
    });

    it("rejects an S256 challenge holding a character outside the unreserved set", () => {
      expect(validateCodeChallenge("a".repeat(42) + "!", "S256")).toBe(false);
    });

    it("holds a plain challenge to the same shape as the verifier it repeats", () => {
      expect(validateCodeChallenge("a".repeat(43), "plain")).toBe(true);
      expect(validateCodeChallenge("short", "plain")).toBe(false);
    });

    it("validates against S256 when no method is named", () => {
      expect(validateCodeChallenge("a".repeat(43))).toBe(true);
      expect(validateCodeChallenge("short")).toBe(false);
      expect(validateCodeChallenge("short", null)).toBe(false);
    });

    it("leaves the shape to the server for a method RFC 7636 does not define", () => {
      expect(validateCodeChallenge("short", "first-8")).toBe(true);
      expect(validateCodeChallenge("", "first-8")).toBe(true);
    });
  });

  describe("validateCodeVerifier", () => {
    it("should accept minimum length verifier (43 chars)", () => {
      const verifier = "a".repeat(43);
      expect(validateCodeVerifier(verifier)).toBe(true);
    });

    it("should accept maximum length verifier (128 chars)", () => {
      const verifier = "a".repeat(128);
      expect(validateCodeVerifier(verifier)).toBe(true);
    });

    it("should reject verifier shorter than 43 chars", () => {
      const verifier = "a".repeat(42);
      expect(validateCodeVerifier(verifier)).toBe(false);
    });

    it("should reject verifier longer than 128 chars", () => {
      const verifier = "a".repeat(129);
      expect(validateCodeVerifier(verifier)).toBe(false);
    });

    it("should accept valid unreserved characters per RFC 7636", () => {
      const verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk0123456";
      expect(validateCodeVerifier(verifier)).toBe(true);
    });

    it("should accept verifier with hyphen", () => {
      const verifier = "a-b-c-d-e-f-g-h-i-j-k-l-m-n-o-p-q-r-s-t-u-v";
      expect(validateCodeVerifier(verifier)).toBe(true);
    });

    it("should accept verifier with period", () => {
      const verifier = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v";
      expect(validateCodeVerifier(verifier)).toBe(true);
    });

    it("should accept verifier with underscore", () => {
      const verifier = "a_b_c_d_e_f_g_h_i_j_k_l_m_n_o_p_q_r_s_t_u_v";
      expect(validateCodeVerifier(verifier)).toBe(true);
    });

    it("should accept verifier with tilde", () => {
      const verifier = "a~b~c~d~e~f~g~h~i~j~k~l~m~n~o~p~q~r~s~t~u~v";
      expect(validateCodeVerifier(verifier)).toBe(true);
    });

    it("should reject verifier with invalid characters", () => {
      const verifier = "a".repeat(42) + "!";
      expect(validateCodeVerifier(verifier)).toBe(false);
    });

    it("should reject verifier with space", () => {
      const verifier = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn op";
      expect(validateCodeVerifier(verifier)).toBe(false);
    });

    it("should reject verifier with plus sign (not in allowed set)", () => {
      const verifier = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn+p";
      expect(validateCodeVerifier(verifier)).toBe(false);
    });

    it("should accept RFC 7636 Appendix B test vector", () => {
      const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      expect(validateCodeVerifier(verifier)).toBe(true);
    });

    it("should accept generated code verifier", () => {
      const verifier = generateCodeVerifier();
      expect(validateCodeVerifier(verifier)).toBe(true);
    });

    it("should reject empty string", () => {
      expect(validateCodeVerifier("")).toBe(false);
    });
  });
});
