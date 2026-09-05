import { assertEquals, assertFalse, assertNotEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

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
    assertEquals(/^[0-9a-f]{64}$/.test(cred.hash), true);
    assertEquals(/^[0-9a-f]{32}$/.test(cred.salt), true);
  });

  it("verifies the correct password and rejects a wrong one", async () => {
    const cred = await passwords.hash("correct horse");
    assertEquals(await passwords.verify("correct horse", cred), true);
    assertEquals(await passwords.verify("Correct Horse", cred), false);
    assertEquals(await passwords.verify("", cred), false);
  });

  it("uses a fresh salt per hash (no deterministic output)", async () => {
    const a = await passwords.hash("same-password");
    const b = await passwords.hash("same-password");
    assertNotEquals(a.salt, b.salt);
    assertNotEquals(a.hash, b.hash);
    assertEquals(await passwords.verify("same-password", a), true);
    assertEquals(await passwords.verify("same-password", b), true);
  });

  it("records the algorithm and iteration count it minted a credential with", async () => {
    const cred = await passwords.hash("hunter2hunter2");
    assertEquals(cred.params, {
      algorithm: PBKDF2_SHA256,
      iterations: DEFAULT_PBKDF2_ITERATIONS,
    });
  });

  it("mints at 600000 iterations by default", () => {
    assertEquals(DEFAULT_PBKDF2_ITERATIONS, 600_000);
    assertEquals(new PasswordIdentityService().iterations, 600_000);
  });

  it("mints at a configured iteration count when one is supplied", async () => {
    const custom = new PasswordIdentityService({ iterations: 120_000 });
    const cred = await custom.hash("hunter2hunter2");
    assertEquals(cred.params?.iterations, 120_000);
    assertEquals(await custom.verify("hunter2hunter2", cred), true);
    assertEquals(await custom.verify("wrong-password", cred), false);
  });

  it("verifies a credential stored without params as the original 100000-iteration PBKDF2", async () => {
    const salt = generateSalt();
    const legacy = {
      salt,
      hash: await hashPassword("hunter2hunter2", salt, 100_000),
    };
    assertEquals(await passwords.verify("hunter2hunter2", legacy), true);
    assertEquals(await passwords.verify("wrong-password", legacy), false);
  });

  it("reports a params-less credential as needing a rehash, and a freshly minted one as not", async () => {
    const salt = generateSalt();
    assertEquals(
      passwords.needsRehash({
        salt,
        hash: await hashPassword("hunter2hunter2", salt, 100_000),
      }),
      true,
    );
    assertFalse(passwords.needsRehash(await passwords.hash("hunter2hunter2")));
  });

  it("reports a credential minted at a lower work factor as needing a rehash", async () => {
    const weak = new PasswordIdentityService({ iterations: 120_000 });
    assertEquals(
      passwords.needsRehash(await weak.hash("hunter2hunter2")),
      true,
    );
    assertFalse(weak.needsRehash(await passwords.hash("hunter2hunter2")));
  });

  it("refuses a credential recorded under an algorithm it does not implement", async () => {
    const cred = await passwords.hash("hunter2hunter2");
    assertEquals(
      await passwords.verify("hunter2hunter2", {
        ...cred,
        params: { algorithm: "argon2id", iterations: 3 },
      }),
      false,
    );
  });

  it("keeps hashPassword and verifyPassword agreeing on the same default", async () => {
    const salt = generateSalt();
    const hash = await hashPassword("hunter2hunter2", salt);
    assertEquals(await verifyPassword("hunter2hunter2", salt, hash), true);
    assertEquals(
      await verifyPassword(
        "hunter2hunter2",
        salt,
        hash,
        LEGACY_PBKDF2_ITERATIONS,
      ),
      false,
    );
  });
});
