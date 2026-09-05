import { assertEquals, assertExists, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { PasswordIdentityService } from "../identity/password.ts";
import { MemoryUserService } from "./services.ts";

describe("MemoryUserService credential accessors", () => {
  const user = { id: "u1", username: "alice" };

  it("findByUsername resolves the user without a password check", async () => {
    const service = new MemoryUserService();
    await service.add(user, "hunter2hunter2");

    assertEquals((await service.findByUsername("alice"))?.id, "u1");
    assertEquals(await service.findByUsername("ghost"), undefined);
  });

  it("getCredential returns a credential verifiable by the identity hasher", async () => {
    const service = new MemoryUserService();
    await service.add(user, "hunter2hunter2");

    const credential = await service.getCredential("u1");
    assertExists(credential);
    const passwords = new PasswordIdentityService();
    assertEquals(await passwords.verify("hunter2hunter2", credential), true);
    assertEquals(await service.getCredential("ghost"), undefined);
  });

  it("setCredential replaces the stored credential", async () => {
    const service = new MemoryUserService();
    await service.add(user, "old-password-1");

    const passwords = new PasswordIdentityService();
    await service.setCredential("u1", await passwords.hash("new-password-1"));

    assertEquals(
      await service.getAuthenticated("alice", "old-password-1"),
      undefined,
    );
    assertEquals(
      (await service.getAuthenticated("alice", "new-password-1"))?.id,
      "u1",
    );
  });

  it("setCredential throws for an unknown user", async () => {
    const service = new MemoryUserService();
    const passwords = new PasswordIdentityService();
    await assertRejects(
      async () => service.setCredential("ghost", await passwords.hash("x")),
      Error,
      "does not exist",
    );
  });
});
