import { describe, expect, it } from "vitest";
import { generateSalt, hashPassword, verifyPassword } from "./user.ts";
import * as identity from "../../identity/password.ts";

describe("generateSalt", () => {
  it("should generate hex string of correct length", () => {
    const salt = generateSalt();
    expect(salt.length).toBe(32);
  });

  it("should generate hex string with specified length", () => {
    const salt = generateSalt(32);
    expect(salt.length).toBe(64);
  });

  it("should generate unique salts", () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    expect(salt1).not.toBe(salt2);
  });

  it("should only contain hex characters", () => {
    const salt = generateSalt();
    expect(/^[0-9a-f]+$/.test(salt)).toBe(true);
  });
});

describe("hashPassword", () => {
  it("should generate consistent hash for same password and salt", async () => {
    const password = "mysecretpassword";
    const salt = "0123456789abcdef";

    const hash1 = await hashPassword(password, salt);
    const hash2 = await hashPassword(password, salt);

    expect(hash1).toBe(hash2);
  });

  it("should generate different hashes for different passwords", async () => {
    const salt = "0123456789abcdef";

    const hash1 = await hashPassword("password1", salt);
    const hash2 = await hashPassword("password2", salt);

    expect(hash1).not.toBe(hash2);
  });

  it("should generate different hashes for different salts", async () => {
    const password = "mysecretpassword";

    const hash1 = await hashPassword(password, "salt1");
    const hash2 = await hashPassword(password, "salt2");

    expect(hash1).not.toBe(hash2);
  });

  it("should generate 64 character hex string (256 bits)", async () => {
    const hash = await hashPassword("password", "salt");
    expect(hash.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(hash)).toBe(true);
  });
});

describe("verifyPassword", () => {
  it("should return true for correct password", async () => {
    const password = "mysecretpassword";
    const salt = generateSalt();
    const hash = await hashPassword(password, salt);

    const result = await verifyPassword(password, salt, hash);
    expect(result).toBe(true);
  });

  it("should return false for incorrect password", async () => {
    const salt = generateSalt();
    const hash = await hashPassword("correctpassword", salt);

    const result = await verifyPassword("wrongpassword", salt, hash);
    expect(result).toBe(false);
  });

  it("should return false for incorrect salt", async () => {
    const password = "mysecretpassword";
    const originalSalt = generateSalt();
    const hash = await hashPassword(password, originalSalt);
    const differentSalt = generateSalt();

    const result = await verifyPassword(password, differentSalt, hash);
    expect(result).toBe(false);
  });

  it("should work with empty password", async () => {
    const password = "";
    const salt = generateSalt();
    const hash = await hashPassword(password, salt);

    const result = await verifyPassword(password, salt, hash);
    expect(result).toBe(true);
  });

  it("should work with unicode characters", async () => {
    const password = "pässwörd🔐";
    const salt = generateSalt();
    const hash = await hashPassword(password, salt);

    const result = await verifyPassword(password, salt, hash);
    expect(result).toBe(true);
  });
});

describe("password hashing entrypoints", () => {
  it("shares one implementation with the identity layer, so a credential minted at one entrypoint verifies at the other", async () => {
    expect(hashPassword).toBe(identity.hashPassword);
    expect(verifyPassword).toBe(identity.verifyPassword);
    expect(generateSalt).toBe(identity.generateSalt);

    const credential = await new identity.PasswordIdentityService().hash(
      "mysecretpassword",
    );
    expect(
      await verifyPassword(
        "mysecretpassword",
        credential.salt,
        credential.hash,
        credential.params?.iterations,
      ),
    ).toBe(true);
  });
});
