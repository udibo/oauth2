import { describe, expect, it } from "vitest";
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
    expect(await store.get(token)).toStrictEqual(null);
  });

  it("validates idempotently, then consumes once (single-use)", async () => {
    const { tokens } = setup();
    const { token } = await tokens.create({
      purpose: TokenPurpose.PasswordReset,
      subject: "u1",
      data: { email: "a@b.co" },
      ttlMs: HOUR,
    });
    expect(
      (await tokens.validate(TokenPurpose.PasswordReset, token))?.subject,
    ).toStrictEqual("u1");
    expect(
      (await tokens.validate(TokenPurpose.PasswordReset, token))?.subject,
    ).toStrictEqual("u1");
    const consumed = await tokens.consume(TokenPurpose.PasswordReset, token);
    expect(consumed?.subject).toStrictEqual("u1");
    expect(consumed?.data?.email).toStrictEqual("a@b.co");
    expect(
      await tokens.consume(TokenPurpose.PasswordReset, token),
    ).toStrictEqual(null);
    expect(
      await tokens.validate(TokenPurpose.PasswordReset, token),
    ).toStrictEqual(null);
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
    expect(results.filter((result) => result !== null).length).toStrictEqual(1);
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

    expect(await store.markConsumed("hash", Date.now())).toStrictEqual(true);
    expect(await store.markConsumed("hash", Date.now())).toStrictEqual(false);
    expect(await store.markConsumed("unknown", Date.now())).toStrictEqual(
      false,
    );
  });

  it("rejects unknown, wrong-purpose, and expired tokens", async () => {
    const { tokens } = setup();
    expect(
      await tokens.consume(TokenPurpose.PasswordReset, "nope"),
    ).toStrictEqual(null);

    const { token } = await tokens.create({
      purpose: TokenPurpose.EmailVerification,
      subject: "u2",
      ttlMs: HOUR,
    });
    expect(
      await tokens.consume(TokenPurpose.PasswordReset, token),
    ).toStrictEqual(null);
    expect(
      (await tokens.validate(TokenPurpose.EmailVerification, token))?.subject,
    ).toStrictEqual("u2");

    const expired = await tokens.create({
      purpose: TokenPurpose.EmailVerification,
      subject: "u3",
      ttlMs: -1000,
    });
    expect(
      await tokens.consume(TokenPurpose.EmailVerification, expired.token),
    ).toStrictEqual(null);
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
    expect(valid.status).toStrictEqual("valid");
    expect(valid.status === "valid" ? valid.subject : null).toStrictEqual("u1");

    expect(
      (await tokens.inspect(TokenPurpose.EmailVerification, "nope")).status,
    ).toStrictEqual("invalid");
    expect(
      (await tokens.inspect(TokenPurpose.PasswordReset, token)).status,
    ).toStrictEqual("invalid");

    const expired = await tokens.create({
      purpose: TokenPurpose.EmailVerification,
      subject: "u2",
      ttlMs: -1000,
    });
    expect(
      (await tokens.inspect(TokenPurpose.EmailVerification, expired.token))
        .status,
    ).toStrictEqual("expired");

    await tokens.consume(TokenPurpose.EmailVerification, token);
    expect(
      (await tokens.inspect(TokenPurpose.EmailVerification, token)).status,
    ).toStrictEqual("consumed");
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
    expect(a.token).not.toStrictEqual(b.token);
    expect(
      await tokens.consume(TokenPurpose.PasswordReset, a.token),
    ).toStrictEqual(null);
    expect(
      (await tokens.consume(TokenPurpose.PasswordReset, b.token))?.subject,
    ).toStrictEqual("u1");
  });
  it("leaves one live link when creates that invalidate existing ones race", async () => {
    const { tokens } = setup();
    const created = await Promise.all(
      Array.from({ length: 4 }, () =>
        tokens.create({
          purpose: TokenPurpose.PasswordReset,
          subject: "u1",
          ttlMs: HOUR,
          invalidateExisting: true,
        }),
      ),
    );

    const live = [];
    for (const { token } of created) {
      if (await tokens.validate(TokenPurpose.PasswordReset, token)) {
        live.push(token);
      }
    }
    expect(
      live.length,
      "each create invalidates the others, so only one link may still work",
    ).toStrictEqual(1);
  });

  it("invalidates then saves on a store without replacePending", async () => {
    const backing = new MemoryTokenFlowStore();
    const store: TokenFlowStore = {
      save: (record) => backing.save(record),
      get: (hash) => backing.get(hash),
      markConsumed: (hash, at) => backing.markConsumed(hash, at),
      deleteBySubject: (purpose, subject) =>
        backing.deleteBySubject(purpose, subject),
    };
    const tokens = new TokenFlowService(store);
    const first = await tokens.create({
      purpose: TokenPurpose.SignIn,
      subject: "u1",
      ttlMs: HOUR,
    });
    const second = await tokens.create({
      purpose: TokenPurpose.SignIn,
      subject: "u1",
      ttlMs: HOUR,
      invalidateExisting: true,
    });

    expect(await tokens.validate(TokenPurpose.SignIn, first.token)).toBe(null);
    expect(
      (await tokens.validate(TokenPurpose.SignIn, second.token))?.subject,
    ).toStrictEqual("u1");
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

    expect(await tokens.invalidate(TokenPurpose.SignIn, "u1")).toStrictEqual(
      true,
    );

    expect(await tokens.consume(TokenPurpose.SignIn, link.token)).toStrictEqual(
      null,
    );
    expect(
      (await tokens.consume(TokenPurpose.SignIn, otherUser.token))?.subject,
    ).toStrictEqual("u2");
    expect(
      (await tokens.consume(TokenPurpose.PasswordReset, reset.token))?.subject,
    ).toStrictEqual("u1");
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

    expect(await tokens.invalidate(TokenPurpose.SignIn, "u1")).toStrictEqual(
      false,
    );
    expect(
      (await tokens.consume(TokenPurpose.SignIn, link.token))?.subject,
    ).toStrictEqual("u1");
  });
});
