import { describe, expect, it } from "vitest";
import { classifyIdentifier, createIdentifierResolver } from "./identifier.ts";

describe("classifyIdentifier", () => {
  it("classifies emails", () => {
    expect(classifyIdentifier("alice@example.com")).toStrictEqual("email");
    expect(classifyIdentifier("  a@b.co  ")).toStrictEqual("email");
  });

  it("classifies phone numbers", () => {
    expect(classifyIdentifier("+1 (555) 123-4567")).toStrictEqual("phone");
    expect(classifyIdentifier("5551234567")).toStrictEqual("phone");
  });

  it("classifies everything else as a username", () => {
    expect(classifyIdentifier("alice")).toStrictEqual("username");
    expect(classifyIdentifier("  bob_99 ")).toStrictEqual("username");
    expect(classifyIdentifier("12345")).toStrictEqual("username");
  });
});

describe("createIdentifierResolver", () => {
  const users = {
    email: { "alice@example.com": { id: "u-email" } },
    username: { alice: { id: "u-name" } },
    phone: { "5551234567": { id: "u-phone" } },
  } as const;

  const resolve = createIdentifierResolver<{ id: string }>({
    email: (e) => Promise.resolve(users.email[e as "alice@example.com"]),
    username: (u) => Promise.resolve(users.username[u as "alice"]),
    phone: (p) => Promise.resolve(users.phone[p as "5551234567"]),
  });

  it("dispatches to the matching lookup", async () => {
    expect((await resolve("alice@example.com"))?.id).toStrictEqual("u-email");
    expect((await resolve("alice"))?.id).toStrictEqual("u-name");
    expect((await resolve("5551234567"))?.id).toStrictEqual("u-phone");
  });

  it("trims before dispatching", async () => {
    expect((await resolve("  alice@example.com "))?.id).toStrictEqual(
      "u-email",
    );
  });

  it("returns undefined when the kind has no configured lookup", async () => {
    const emailOnly = createIdentifierResolver<{ id: string }>({
      email: () => Promise.resolve({ id: "x" }),
    });
    expect(await emailOnly("alice")).toStrictEqual(undefined);
  });

  it("returns undefined when the user is not found", async () => {
    expect(await resolve("nobody@example.com")).toStrictEqual(undefined);
  });
});
