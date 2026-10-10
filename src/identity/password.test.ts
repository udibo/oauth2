import { describe, expect, it } from "vitest";
import {
  DEFAULT_PBKDF2_ITERATIONS,
  generateSalt,
  hashPassword,
  LEGACY_PBKDF2_ITERATIONS,
  PasswordIdentityService,
  PBKDF2_SHA256,
  verifyPassword,
} from "./password.ts";

describe("PasswordIdentityService", () => {
  const passwords = new PasswordIdentityService();

  it("hashes to a hex digest + salt", async () => {
    const cred = await passwords.hash("hunter2hunter2");
    expect(/^[0-9a-f]{64}$/.test(cred.hash)).toStrictEqual(true);
    expect(/^[0-9a-f]{32}$/.test(cred.salt)).toStrictEqual(true);
  });

  it("verifies the correct password and rejects a wrong one", async () => {
    const cred = await passwords.hash("correct horse");
    expect(await passwords.verify("correct horse", cred)).toStrictEqual(true);
    expect(await passwords.verify("Correct Horse", cred)).toStrictEqual(false);
    expect(await passwords.verify("", cred)).toStrictEqual(false);
  });

  it("uses a fresh salt per hash (no deterministic output)", async () => {
    const a = await passwords.hash("same-password");
    const b = await passwords.hash("same-password");
    expect(a.salt).not.toStrictEqual(b.salt);
    expect(a.hash).not.toStrictEqual(b.hash);
    expect(await passwords.verify("same-password", a)).toStrictEqual(true);
    expect(await passwords.verify("same-password", b)).toStrictEqual(true);
  });

  it("records the algorithm and iteration count it minted a credential with", async () => {
    const cred = await passwords.hash("hunter2hunter2");
    expect(cred.params).toStrictEqual({
      algorithm: PBKDF2_SHA256,
      iterations: DEFAULT_PBKDF2_ITERATIONS,
    });
  });

  it("mints at 600000 iterations by default", () => {
    expect(DEFAULT_PBKDF2_ITERATIONS).toStrictEqual(600_000);
    expect(new PasswordIdentityService().iterations).toStrictEqual(600_000);
  });

  it("mints at a configured iteration count when one is supplied", async () => {
    const custom = new PasswordIdentityService({ iterations: 120_000 });
    const cred = await custom.hash("hunter2hunter2");
    expect(cred.params?.iterations).toStrictEqual(120_000);
    expect(await custom.verify("hunter2hunter2", cred)).toStrictEqual(true);
    expect(await custom.verify("wrong-password", cred)).toStrictEqual(false);
  });

  it("verifies a credential stored without params as the original 100000-iteration PBKDF2", async () => {
    const salt = generateSalt();
    const legacy = {
      salt,
      hash: await hashPassword("hunter2hunter2", salt, 100_000),
    };
    expect(await passwords.verify("hunter2hunter2", legacy)).toStrictEqual(
      true,
    );
    expect(await passwords.verify("wrong-password", legacy)).toStrictEqual(
      false,
    );
  });

  it("reports a params-less credential as needing a rehash, and a freshly minted one as not", async () => {
    const salt = generateSalt();
    expect(
      passwords.needsRehash({
        salt,
        hash: await hashPassword("hunter2hunter2", salt, 100_000),
      }),
    ).toStrictEqual(true);
    expect(
      passwords.needsRehash(await passwords.hash("hunter2hunter2")),
    ).toBeFalsy();
  });

  it("reports a credential minted at a lower work factor as needing a rehash", async () => {
    const weak = new PasswordIdentityService({ iterations: 120_000 });
    expect(
      passwords.needsRehash(await weak.hash("hunter2hunter2")),
    ).toStrictEqual(true);
    expect(
      weak.needsRehash(await passwords.hash("hunter2hunter2")),
    ).toBeFalsy();
  });

  it("refuses a credential recorded under an algorithm it does not implement", async () => {
    const cred = await passwords.hash("hunter2hunter2");
    expect(
      await passwords.verify("hunter2hunter2", {
        ...cred,
        params: { algorithm: "argon2id", iterations: 3 },
      }),
    ).toStrictEqual(false);
  });

  it("keeps hashPassword and verifyPassword agreeing on the same default", async () => {
    const salt = generateSalt();
    const hash = await hashPassword("hunter2hunter2", salt);
    expect(await verifyPassword("hunter2hunter2", salt, hash)).toStrictEqual(
      true,
    );
    expect(
      await verifyPassword(
        "hunter2hunter2",
        salt,
        hash,
        LEGACY_PBKDF2_ITERATIONS,
      ),
    ).toStrictEqual(false);
  });
});
