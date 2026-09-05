import { assertNotStrictEquals, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { generateSalt, hashPassword, verifyPassword } from "./user.ts";
import * as identity from "../../identity/password.ts";

describe("generateSalt", () => {
  it("should generate hex string of correct length", () => {
    const salt = generateSalt();
    assertStrictEquals(salt.length, 32);
  });

  it("should generate hex string with specified length", () => {
    const salt = generateSalt(32);
    assertStrictEquals(salt.length, 64);
  });

  it("should generate unique salts", () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    assertNotStrictEquals(salt1, salt2);
  });

  it("should only contain hex characters", () => {
    const salt = generateSalt();
    assertStrictEquals(/^[0-9a-f]+$/.test(salt), true);
  });
});

describe("hashPassword", () => {
  it("should generate consistent hash for same password and salt", async () => {
    const password = "mysecretpassword";
    const salt = "0123456789abcdef";

    const hash1 = await hashPassword(password, salt);
    const hash2 = await hashPassword(password, salt);

    assertStrictEquals(hash1, hash2);
  });

  it("should generate different hashes for different passwords", async () => {
    const salt = "0123456789abcdef";

    const hash1 = await hashPassword("password1", salt);
    const hash2 = await hashPassword("password2", salt);

    assertNotStrictEquals(hash1, hash2);
  });

  it("should generate different hashes for different salts", async () => {
    const password = "mysecretpassword";

    const hash1 = await hashPassword(password, "salt1");
    const hash2 = await hashPassword(password, "salt2");

    assertNotStrictEquals(hash1, hash2);
  });

  it("should generate 64 character hex string (256 bits)", async () => {
    const hash = await hashPassword("password", "salt");
    assertStrictEquals(hash.length, 64);
    assertStrictEquals(/^[0-9a-f]+$/.test(hash), true);
  });
});

describe("verifyPassword", () => {
  it("should return true for correct password", async () => {
    const password = "mysecretpassword";
    const salt = generateSalt();
    const hash = await hashPassword(password, salt);

    const result = await verifyPassword(password, salt, hash);
    assertStrictEquals(result, true);
  });

  it("should return false for incorrect password", async () => {
    const salt = generateSalt();
    const hash = await hashPassword("correctpassword", salt);

    const result = await verifyPassword("wrongpassword", salt, hash);
    assertStrictEquals(result, false);
  });

  it("should return false for incorrect salt", async () => {
    const password = "mysecretpassword";
    const originalSalt = generateSalt();
    const hash = await hashPassword(password, originalSalt);
    const differentSalt = generateSalt();

    const result = await verifyPassword(password, differentSalt, hash);
    assertStrictEquals(result, false);
  });

  it("should work with empty password", async () => {
    const password = "";
    const salt = generateSalt();
    const hash = await hashPassword(password, salt);

    const result = await verifyPassword(password, salt, hash);
    assertStrictEquals(result, true);
  });

  it("should work with unicode characters", async () => {
    const password = "pässwörd🔐";
    const salt = generateSalt();
    const hash = await hashPassword(password, salt);

    const result = await verifyPassword(password, salt, hash);
    assertStrictEquals(result, true);
  });
});

describe("password hashing entrypoints", () => {
  it("shares one implementation with the identity layer, so a credential minted at one entrypoint verifies at the other", async () => {
    assertStrictEquals(hashPassword, identity.hashPassword);
    assertStrictEquals(verifyPassword, identity.verifyPassword);
    assertStrictEquals(generateSalt, identity.generateSalt);

    const credential = await new identity.PasswordIdentityService().hash(
      "mysecretpassword",
    );
    assertStrictEquals(
      await verifyPassword(
        "mysecretpassword",
        credential.salt,
        credential.hash,
        credential.params?.iterations,
      ),
      true,
    );
  });
});
