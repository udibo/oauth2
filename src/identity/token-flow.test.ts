import { assertEquals, assertNotEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  MemoryTokenFlowStore,
  TokenFlowService,
  type TokenFlowStore,
  TokenPurpose,
} from "./token-flow.ts";

const HOUR = 3_600_000;

function setup() {
  const store = new MemoryTokenFlowStore();
  return { store, tokens: new TokenFlowService(store) };
}

describe("TokenFlowService", () => {
  it("stores only the token hash, not the raw token", async () => {
    const { store, tokens } = setup();
    const { token } = await tokens.create({
      purpose: TokenPurpose.PasswordReset,
      subject: "u1",
      ttlMs: HOUR,
    });
    assertEquals(await store.get(token), null);
  });

  it("validates idempotently, then consumes once (single-use)", async () => {
    const { tokens } = setup();
    const { token } = await tokens.create({
      purpose: TokenPurpose.PasswordReset,
      subject: "u1",
      data: { email: "a@b.co" },
      ttlMs: HOUR,
    });
    assertEquals(
      (await tokens.validate(TokenPurpose.PasswordReset, token))?.subject,
      "u1",
    );
    assertEquals(
      (await tokens.validate(TokenPurpose.PasswordReset, token))?.subject,
      "u1",
    );
    const consumed = await tokens.consume(TokenPurpose.PasswordReset, token);
    assertEquals(consumed?.subject, "u1");
    assertEquals(consumed?.data?.email, "a@b.co");
    assertEquals(await tokens.consume(TokenPurpose.PasswordReset, token), null);
    assertEquals(
      await tokens.validate(TokenPurpose.PasswordReset, token),
      null,
    );
  });

  it("hands the token to exactly one of two racing consumers", async () => {
    const { tokens } = setup();
    const { token } = await tokens.create({
      purpose: TokenPurpose.PasswordReset,
      subject: "u1",
      ttlMs: HOUR,
    });

    const results = await Promise.all([
      tokens.consume(TokenPurpose.PasswordReset, token),
      tokens.consume(TokenPurpose.PasswordReset, token),
    ]);
    assertEquals(results.filter((result) => result !== null).length, 1);
  });

  it("only the claiming markConsumed call reports success", async () => {
    const store = new MemoryTokenFlowStore();
    const record = {
      tokenHash: "hash",
      purpose: TokenPurpose.PasswordReset,
      subject: "u1",
      expiresAt: Date.now() + HOUR,
      createdAt: Date.now(),
    };
    await store.save(record);

    assertEquals(await store.markConsumed("hash", Date.now()), true);
    assertEquals(await store.markConsumed("hash", Date.now()), false);
    assertEquals(await store.markConsumed("unknown", Date.now()), false);
  });

  it("rejects unknown, wrong-purpose, and expired tokens", async () => {
    const { tokens } = setup();
    assertEquals(
      await tokens.consume(TokenPurpose.PasswordReset, "nope"),
      null,
    );

    const { token } = await tokens.create({
      purpose: TokenPurpose.EmailVerification,
      subject: "u2",
      ttlMs: HOUR,
    });
    assertEquals(await tokens.consume(TokenPurpose.PasswordReset, token), null);
    assertEquals(
      (await tokens.validate(TokenPurpose.EmailVerification, token))?.subject,
      "u2",
    );

    const expired = await tokens.create({
      purpose: TokenPurpose.EmailVerification,
      subject: "u3",
      ttlMs: -1000,
    });
    assertEquals(
      await tokens.consume(TokenPurpose.EmailVerification, expired.token),
      null,
    );
  });

  it("inspect distinguishes valid / invalid / expired / consumed / wrong-purpose", async () => {
    const { tokens } = setup();
    const { token } = await tokens.create({
      purpose: TokenPurpose.EmailVerification,
      subject: "u1",
      data: { email: "a@b.co" },
      ttlMs: HOUR,
    });

    const valid = await tokens.inspect(TokenPurpose.EmailVerification, token);
    assertEquals(valid.status, "valid");
    assertEquals(valid.status === "valid" ? valid.subject : null, "u1");

    assertEquals(
      (await tokens.inspect(TokenPurpose.EmailVerification, "nope")).status,
      "invalid",
    );
    assertEquals(
      (await tokens.inspect(TokenPurpose.PasswordReset, token)).status,
      "invalid",
    );

    const expired = await tokens.create({
      purpose: TokenPurpose.EmailVerification,
      subject: "u2",
      ttlMs: -1000,
    });
    assertEquals(
      (await tokens.inspect(TokenPurpose.EmailVerification, expired.token))
        .status,
      "expired",
    );

    await tokens.consume(TokenPurpose.EmailVerification, token);
    assertEquals(
      (await tokens.inspect(TokenPurpose.EmailVerification, token)).status,
      "consumed",
    );
  });

  it("issues distinct tokens and can invalidate prior ones", async () => {
    const { tokens } = setup();
    const a = await tokens.create({
      purpose: TokenPurpose.PasswordReset,
      subject: "u1",
      ttlMs: HOUR,
    });
    const b = await tokens.create({
      purpose: TokenPurpose.PasswordReset,
      subject: "u1",
      ttlMs: HOUR,
      invalidateExisting: true,
    });
    assertNotEquals(a.token, b.token);
    assertEquals(
      await tokens.consume(TokenPurpose.PasswordReset, a.token),
      null,
    );
    assertEquals(
      (await tokens.consume(TokenPurpose.PasswordReset, b.token))?.subject,
      "u1",
    );
  });
  it("invalidate drops the subject's pending tokens for that purpose only", async () => {
    const { tokens } = setup();
    const reset = await tokens.create({
      purpose: TokenPurpose.PasswordReset,
      subject: "u1",
      ttlMs: HOUR,
    });
    const link = await tokens.create({
      purpose: TokenPurpose.SignIn,
      subject: "u1",
      ttlMs: HOUR,
    });
    const otherUser = await tokens.create({
      purpose: TokenPurpose.SignIn,
      subject: "u2",
      ttlMs: HOUR,
    });

    assertEquals(await tokens.invalidate(TokenPurpose.SignIn, "u1"), true);

    assertEquals(await tokens.consume(TokenPurpose.SignIn, link.token), null);
    assertEquals(
      (await tokens.consume(TokenPurpose.SignIn, otherUser.token))?.subject,
      "u2",
    );
    assertEquals(
      (await tokens.consume(TokenPurpose.PasswordReset, reset.token))?.subject,
      "u1",
    );
  });

  it("invalidate reports false, and leaves tokens live, on a store without deleteBySubject", async () => {
    const backing = new MemoryTokenFlowStore();
    const store: TokenFlowStore = {
      save: (record) => backing.save(record),
      get: (hash) => backing.get(hash),
      markConsumed: (hash, at) => backing.markConsumed(hash, at),
    };
    const tokens = new TokenFlowService(store);
    const link = await tokens.create({
      purpose: TokenPurpose.SignIn,
      subject: "u1",
      ttlMs: HOUR,
    });

    assertEquals(await tokens.invalidate(TokenPurpose.SignIn, "u1"), false);
    assertEquals(
      (await tokens.consume(TokenPurpose.SignIn, link.token))?.subject,
      "u1",
    );
  });
});
