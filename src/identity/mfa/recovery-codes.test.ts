import { assert, describe, expect, it } from "vitest";
import {
  generateRecoveryCodes,
  hashRecoveryCode,
  normalizeRecoveryCode,
  RECOVERY_CODE_LENGTH,
  verifyRecoveryCode,
} from "./recovery-codes.ts";

describe("generateRecoveryCodes", () => {
  it("generates 10 unique XXXXXXXX-XXXXXXXX codes from the unambiguous alphabet by default", async () => {
    const { codes, hashes } = await generateRecoveryCodes();
    expect(codes.length).toStrictEqual(10);
    expect(hashes.length).toStrictEqual(10);
    expect(new Set(codes).size).toStrictEqual(10);
    for (const code of codes) {
      assert(/^[0-9A-HJKMNP-TV-Z]{8}-[0-9A-HJKMNP-TV-Z]{8}$/.test(code), code);
    }
  });

  it("aligns each hash with its code", async () => {
    const { codes, hashes } = await generateRecoveryCodes({ count: 3 });
    for (let i = 0; i < codes.length; i++) {
      expect(hashes[i]).toStrictEqual(await hashRecoveryCode(codes[i]));
    }
  });

  it("honors a custom count", async () => {
    const { codes } = await generateRecoveryCodes({ count: 4 });
    expect(codes.length).toStrictEqual(4);
  });

  it("normalizes every code to exactly RECOVERY_CODE_LENGTH characters", async () => {
    const { codes } = await generateRecoveryCodes();
    for (const code of codes) {
      expect(normalizeRecoveryCode(code).length).toStrictEqual(
        RECOVERY_CODE_LENGTH,
      );
    }
  });
});

describe("normalizeRecoveryCode", () => {
  it("uppercases and strips separators and whitespace", () => {
    expect(normalizeRecoveryCode("ab2de-fg7jk")).toStrictEqual("AB2DEFG7JK");
    expect(normalizeRecoveryCode(" AB2DE FG7JK ")).toStrictEqual("AB2DEFG7JK");
    expect(normalizeRecoveryCode("ab2de_fg7.jk")).toStrictEqual("AB2DEFG7JK");
  });
});

describe("hashRecoveryCode", () => {
  it("hashes to hex SHA-256 of the normalized code", async () => {
    const hash = await hashRecoveryCode("AB2DE-FG7JK");
    assert(/^[0-9a-f]{64}$/.test(hash));
  });

  it("produces the same hash regardless of case and separators", async () => {
    const canonical = await hashRecoveryCode("AB2DE-FG7JK");
    expect(await hashRecoveryCode("ab2defg7jk")).toStrictEqual(canonical);
    expect(await hashRecoveryCode("Ab2De fG7Jk")).toStrictEqual(canonical);
  });

  it("produces different hashes for different codes", async () => {
    assert(
      (await hashRecoveryCode("AB2DE-FG7JK")) !==
        (await hashRecoveryCode("AB2DE-FG7JM")),
    );
  });
});

describe("verifyRecoveryCode", () => {
  it("matches a stored hash and reports its index for burning", async () => {
    const { codes, hashes } = await generateRecoveryCodes({ count: 5 });
    expect(await verifyRecoveryCode({ code: codes[3], hashes })).toStrictEqual({
      valid: true,
      index: 3,
    });
  });

  it("accepts any case with or without separators", async () => {
    const { codes, hashes } = await generateRecoveryCodes({ count: 2 });
    const submitted = codes[1].toLowerCase().replaceAll("-", "");
    expect(await verifyRecoveryCode({ code: submitted, hashes })).toStrictEqual(
      { valid: true, index: 1 },
    );
  });

  it("rejects unknown codes and an empty hash set", async () => {
    const { codes, hashes } = await generateRecoveryCodes({ count: 2 });
    expect(
      await verifyRecoveryCode({ code: "AAAAAAAA-AAAAAAAA", hashes }),
    ).toStrictEqual({ valid: false });
    expect(
      await verifyRecoveryCode({ code: codes[0], hashes: [] }),
    ).toStrictEqual({ valid: false });
  });
});
