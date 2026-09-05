import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { classifyIdentifier, createIdentifierResolver } from "./identifier.ts";

describe("classifyIdentifier", () => {
  it("classifies emails", () => {
    assertEquals(classifyIdentifier("alice@example.com"), "email");
    assertEquals(classifyIdentifier("  a@b.co  "), "email");
  });

  it("classifies phone numbers", () => {
    assertEquals(classifyIdentifier("+1 (555) 123-4567"), "phone");
    assertEquals(classifyIdentifier("5551234567"), "phone");
  });

  it("classifies everything else as a username", () => {
    assertEquals(classifyIdentifier("alice"), "username");
    assertEquals(classifyIdentifier("  bob_99 "), "username");
    assertEquals(classifyIdentifier("12345"), "username");
  });
});

describe("createIdentifierResolver", () => {
  const users = {
    email: { "alice@example.com": { id: "u-email" } },
    username: { "alice": { id: "u-name" } },
    phone: { "5551234567": { id: "u-phone" } },
  } as const;

  const resolve = createIdentifierResolver<{ id: string }>({
    email: (e) => Promise.resolve(users.email[e as "alice@example.com"]),
    username: (u) => Promise.resolve(users.username[u as "alice"]),
    phone: (p) => Promise.resolve(users.phone[p as "5551234567"]),
  });

  it("dispatches to the matching lookup", async () => {
    assertEquals((await resolve("alice@example.com"))?.id, "u-email");
    assertEquals((await resolve("alice"))?.id, "u-name");
    assertEquals((await resolve("5551234567"))?.id, "u-phone");
  });

  it("trims before dispatching", async () => {
    assertEquals((await resolve("  alice@example.com "))?.id, "u-email");
  });

  it("returns undefined when the kind has no configured lookup", async () => {
    const emailOnly = createIdentifierResolver<{ id: string }>({
      email: () => Promise.resolve({ id: "x" }),
    });
    assertEquals(await emailOnly("alice"), undefined);
  });

  it("returns undefined when the user is not found", async () => {
    assertEquals(await resolve("nobody@example.com"), undefined);
  });
});
