import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { createSignInLinkBinding, verifySignInLinkBinding } from "./mod.ts";

describe("createSignInLinkBinding", () => {
  it("mints a 43-character base64url nonce and binds links to its SHA-256", () => {
    const { nonce, binding } = createSignInLinkBinding();

    expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(binding).toBe(
      createHash("sha256").update(nonce).digest("base64url"),
    );
  });

  it("gives each browser that holds no nonce a binding of its own", () => {
    const first = createSignInLinkBinding();
    const second = createSignInLinkBinding(null);

    expect(second.nonce).not.toBe(first.nonce);
    expect(second.binding).not.toBe(first.binding);
  });

  it("keeps the nonce a browser already holds, so its earlier links still work", () => {
    const first = createSignInLinkBinding();

    expect(createSignInLinkBinding(first.nonce)).toStrictEqual(first);
  });

  it.each([
    ["too short", "short"],
    ["too long", "a".repeat(44)],
    ["outside base64url", `${"a".repeat(42)}=`],
    ["empty", ""],
  ])(
    "replaces a held nonce that is %s instead of binding links to it",
    (_, held) => {
      const { nonce } = createSignInLinkBinding(held);

      expect(nonce).not.toBe(held);
      expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
    },
  );

  it("never puts the nonce in the binding", () => {
    const { nonce, binding } = createSignInLinkBinding();

    expect(binding).not.toContain(nonce);
  });
});

describe("verifySignInLinkBinding", () => {
  it("accepts the browser that asked for the link", () => {
    const { nonce, binding } = createSignInLinkBinding();

    expect(verifySignInLinkBinding(nonce, binding)).toBe(true);
  });

  it("refuses a browser that holds no nonce", () => {
    const { binding } = createSignInLinkBinding();

    expect(verifySignInLinkBinding(undefined, binding)).toBe(false);
    expect(verifySignInLinkBinding(null, binding)).toBe(false);
    expect(verifySignInLinkBinding("", binding)).toBe(false);
  });

  it("refuses a browser that asked for a different link", () => {
    const { binding } = createSignInLinkBinding();
    const other = createSignInLinkBinding();

    expect(verifySignInLinkBinding(other.nonce, binding)).toBe(false);
  });

  it.each([
    ["missing", undefined],
    ["null", null],
    ["empty", ""],
    ["truncated", "abc"],
  ])(
    "refuses the asking browser when the link's binding is %s",
    (_, binding) => {
      const { nonce } = createSignInLinkBinding();

      expect(verifySignInLinkBinding(nonce, binding)).toBe(false);
    },
  );

  it("refuses a link whose binding is the browser's own nonce rather than its hash", () => {
    const { nonce } = createSignInLinkBinding();

    expect(verifySignInLinkBinding(nonce, nonce)).toBe(false);
  });

  it("refuses a malformed nonce even when the link carries its hash", () => {
    const nonce = "short";
    const binding = createHash("sha256").update(nonce).digest("base64url");

    expect(verifySignInLinkBinding(nonce, binding)).toBe(false);
  });
});
