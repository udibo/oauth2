import { assert, describe, expect, it, vi } from "vitest";
import { FakeTime } from "../../_test_fake-time.ts";
import { rejection, thrown } from "../../_test_assert.ts";
import { IdentityError } from "../errors.ts";
import type { IdentityEvent } from "../events.ts";
import { RateLimiter } from "../rate-limit.ts";
import { MemoryMfaStore, MfaService } from "./service.ts";
import { generateTotpCode } from "./totp.ts";

const START = 1_700_000_000_000;
const PERIOD_MS = 30_000;

function setup() {
  const store = new MemoryMfaStore();
  return { store, mfa: new MfaService({ store }) };
}

async function enroll(
  mfa: MfaService,
  userId: string,
): Promise<{ base32: string; recoveryCodes: string[] }> {
  const { base32 } = await mfa.startEnrollment(userId, {
    issuer: "Udibo",
    accountName: `${userId}@example.com`,
  });
  const confirmation = await mfa.confirmEnrollment(
    userId,
    await generateTotpCode({ secret: base32 }),
  );
  assert(confirmation.confirmed);
  return { base32, recoveryCodes: confirmation.recoveryCodes };
}

describe("MfaService", () => {
  it("runs the full lifecycle: enroll, verify, replay-reject, recover, regenerate, disable", async () => {
    using time = new FakeTime(START);
    const { mfa } = setup();

    const start = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    expect(start.otpauthUri).toContain(`secret=${start.base32}`);
    expect(await mfa.isEnrolled("u1")).toStrictEqual(false);

    const confirmation = await mfa.confirmEnrollment(
      "u1",
      await generateTotpCode({ secret: start.base32 }),
    );
    assert(confirmation.confirmed);
    expect(confirmation.recoveryCodes.length).toStrictEqual(10);
    expect(await mfa.isEnrolled("u1")).toStrictEqual(true);

    time.tick(PERIOD_MS);
    const code = await generateTotpCode({ secret: start.base32 });
    expect(await mfa.verify("u1", code)).toStrictEqual({
      valid: true,
      method: "totp",
    });
    expect(await mfa.verify("u1", code)).toStrictEqual({
      valid: false,
      reason: "replayed",
    });

    time.tick(PERIOD_MS);
    expect(
      (await mfa.verify("u1", await generateTotpCode({ secret: start.base32 })))
        .valid,
    ).toStrictEqual(true);

    const recoveryCode = confirmation.recoveryCodes[0];
    expect(await mfa.verify("u1", recoveryCode)).toStrictEqual({
      valid: true,
      method: "recovery",
      remainingRecoveryCodes: 9,
    });
    expect(await mfa.verify("u1", recoveryCode)).toStrictEqual({
      valid: false,
      reason: "invalid",
    });

    const regenerated = await mfa.regenerateRecoveryCodes("u1");
    expect(regenerated.length).toStrictEqual(10);
    expect(await mfa.verify("u1", confirmation.recoveryCodes[1])).toStrictEqual(
      { valid: false, reason: "invalid" },
    );
    expect(await mfa.verify("u1", regenerated[0])).toStrictEqual({
      valid: true,
      method: "recovery",
      remainingRecoveryCodes: 9,
    });

    await mfa.disable("u1");
    expect(await mfa.isEnrolled("u1")).toStrictEqual(false);
    time.tick(PERIOD_MS);
    expect(
      await mfa.verify("u1", await generateTotpCode({ secret: start.base32 })),
    ).toStrictEqual({ valid: false, reason: "invalid" });
    expect(await mfa.verify("u1", regenerated[1])).toStrictEqual({
      valid: false,
      reason: "invalid",
    });
  });

  it("accepts recovery codes in any case and without separators", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();
    const { recoveryCodes } = await enroll(mfa, "u1");
    const submitted = recoveryCodes[0].toLowerCase().replaceAll("-", "");
    expect(await mfa.verify("u1", submitted)).toStrictEqual({
      valid: true,
      method: "recovery",
      remainingRecoveryCodes: 9,
    });
  });

  it("ignores a pending secret in verify until enrollment is confirmed", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();
    const { base32 } = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    expect(
      await mfa.verify("u1", await generateTotpCode({ secret: base32 })),
    ).toStrictEqual({ valid: false, reason: "invalid" });
  });

  it("rejects a wrong confirmation code and stays unenrolled", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();
    await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    expect(await mfa.confirmEnrollment("u1", "000000")).toStrictEqual({
      confirmed: false,
    });
    expect(await mfa.isEnrolled("u1")).toStrictEqual(false);
  });

  it("rejects confirmation when no enrollment is pending", async () => {
    const { mfa } = setup();
    expect(await mfa.confirmEnrollment("u1", "123456")).toStrictEqual({
      confirmed: false,
    });
  });

  it("refuses enrollment while an active credential exists", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();
    await enroll(mfa, "u1");

    const startError = await rejection(
      () =>
        mfa.startEnrollment("u1", {
          issuer: "Udibo",
          accountName: "u1@example.com",
        }),
      IdentityError,
    );
    expect(startError.code).toStrictEqual("mfa_already_enrolled");

    const confirmError = await rejection(
      () => mfa.confirmEnrollment("u1", "000000"),
      IdentityError,
    );
    expect(confirmError.code).toStrictEqual("mfa_already_enrolled");
  });

  it("allows a fresh enrollment after disable", async () => {
    using time = new FakeTime(START);
    const { mfa } = setup();
    const { base32: oldSecret } = await enroll(mfa, "u1");
    await mfa.disable("u1");

    time.tick(PERIOD_MS);
    const { base32: newSecret } = await enroll(mfa, "u1");
    expect(newSecret).not.toStrictEqual(oldSecret);
    time.tick(PERIOD_MS);
    expect(
      await mfa.verify("u1", await generateTotpCode({ secret: newSecret })),
    ).toStrictEqual({ valid: true, method: "totp" });
    expect(
      await mfa.verify("u1", await generateTotpCode({ secret: oldSecret })),
    ).toStrictEqual({ valid: false, reason: "invalid" });
  });

  it("does not confirm with a code for a pending secret that was replaced", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();
    const { base32: first } = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    const firstCode = await generateTotpCode({ secret: first });
    await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    expect(await mfa.confirmEnrollment("u1", firstCode)).toStrictEqual({
      confirmed: false,
    });
    expect(await mfa.isEnrolled("u1")).toStrictEqual(false);
  });

  it("rejects the confirmation code if replayed as the first verification", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();
    const { base32 } = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    const code = await generateTotpCode({ secret: base32 });
    expect((await mfa.confirmEnrollment("u1", code)).confirmed).toStrictEqual(
      true,
    );
    expect(await mfa.verify("u1", code)).toStrictEqual({
      valid: false,
      reason: "replayed",
    });
  });

  it("scopes verification to the requested method", async () => {
    using time = new FakeTime(START);
    const { mfa } = setup();
    const { base32, recoveryCodes } = await enroll(mfa, "u1");

    expect(
      await mfa.verify("u1", recoveryCodes[0], { method: "totp" }),
    ).toStrictEqual({ valid: false, reason: "invalid" });
    expect(await mfa.verify("u1", recoveryCodes[0])).toStrictEqual({
      valid: true,
      method: "recovery",
      remainingRecoveryCodes: 9,
    });

    time.tick(PERIOD_MS);
    expect(
      await mfa.verify("u1", await generateTotpCode({ secret: base32 }), {
        method: "recovery",
      }),
    ).toStrictEqual({ valid: false, reason: "invalid" });
  });

  it("leaves the replay guard unspent when a TOTP code is submitted as a recovery code", async () => {
    using time = new FakeTime(START);
    const { mfa } = setup();
    const { base32 } = await enroll(mfa, "u1");

    time.tick(PERIOD_MS);
    const code = await generateTotpCode({ secret: base32 });
    expect(await mfa.verify("u1", code, { method: "recovery" })).toStrictEqual({
      valid: false,
      reason: "invalid",
    });
    expect(await mfa.verify("u1", code)).toStrictEqual({
      valid: true,
      method: "totp",
    });
  });

  it("does not consume a recovery code when the attempt is scoped to TOTP", async () => {
    using _time = new FakeTime(START);
    const store = new MemoryMfaStore();
    const mfa = new MfaService({ store });
    const { recoveryCodes } = await enroll(mfa, "u1");

    expect(
      await mfa.verify("u1", recoveryCodes[0], { method: "totp" }),
    ).toStrictEqual({
      valid: false,
      reason: "invalid",
    });
    expect((await store.getRecoveryHashes("u1")).length).toStrictEqual(10);
  });

  it("throws a typed error when regenerating recovery codes without an active enrollment", async () => {
    const { mfa } = setup();
    const error = await rejection(
      () => mfa.regenerateRecoveryCodes("u1"),
      IdentityError,
      "not enrolled",
    );
    expect(error.code).toStrictEqual("mfa_not_enrolled");
  });

  it("burns recovery codes before clearing TOTP so a failed disable fails closed", async () => {
    using time = new FakeTime(START);
    class FailingClearStore extends MemoryMfaStore {
      override clearTotp(_userId: string): Promise<void> {
        return Promise.reject(new Error("db down"));
      }
    }
    const store = new FailingClearStore();
    const mfa = new MfaService({ store });
    const { base32, recoveryCodes } = await enroll(mfa, "u1");

    await rejection(() => mfa.disable("u1"), Error, "db down");
    expect(await mfa.isEnrolled("u1")).toStrictEqual(true);
    expect(await mfa.verify("u1", recoveryCodes[0])).toStrictEqual({
      valid: false,
      reason: "invalid",
    });
    time.tick(PERIOD_MS);
    expect(
      await mfa.verify("u1", await generateTotpCode({ secret: base32 })),
    ).toStrictEqual({ valid: true, method: "totp" });
  });

  it("rate limits verify per user and throws rate_limited when enforcing", async () => {
    using _time = new FakeTime(START);
    const store = new MemoryMfaStore();
    const mfa = new MfaService({
      store,
      rateLimiter: new RateLimiter({ limit: 1, windowMs: 60_000 }),
    });
    const { base32 } = await enroll(mfa, "u1");

    expect((await mfa.verify("u1", "000000")).valid).toStrictEqual(false);
    const validCode = await generateTotpCode({ secret: base32 });
    const error = await rejection(
      () => mfa.verify("u1", validCode),
      IdentityError,
    );
    expect(error.code).toStrictEqual("rate_limited");
    assert(error.retryAfterMs !== undefined && error.retryAfterMs > 0);
  });

  it("lets attempts through in log-only protection mode", async () => {
    using time = new FakeTime(START);
    const events: IdentityEvent[] = [];
    const store = new MemoryMfaStore();
    const mfa = new MfaService({
      store,
      rateLimiter: new RateLimiter({ limit: 1, windowMs: 60_000 }),
      protectionMode: "log-only",
      onEvent: (event) => {
        events.push(event);
      },
    });
    const { base32 } = await enroll(mfa, "u1");

    expect((await mfa.verify("u1", "000000")).valid).toStrictEqual(false);
    time.tick(PERIOD_MS);
    expect(
      await mfa.verify("u1", await generateTotpCode({ secret: base32 })),
    ).toStrictEqual({ valid: true, method: "totp" });
    const limited = events.find((e) => e.type === "mfa.verify.rate_limited");
    assert(limited?.type === "mfa.verify.rate_limited");
    expect(limited.enforced).toStrictEqual(false);
  });

  it("emits mfa events for the significant outcomes", async () => {
    using time = new FakeTime(START);
    const events: IdentityEvent[] = [];
    const store = new MemoryMfaStore();
    const mfa = new MfaService({
      store,
      onEvent: (event) => {
        events.push(event);
      },
    });
    const { base32, recoveryCodes } = await enroll(mfa, "u1");

    time.tick(PERIOD_MS);
    await mfa.verify("u1", await generateTotpCode({ secret: base32 }));
    await mfa.verify("u1", "000000");
    await mfa.verify("u1", recoveryCodes[0]);
    await mfa.regenerateRecoveryCodes("u1");
    await mfa.disable("u1");

    expect(events.map((event) => event.type)).toStrictEqual([
      "mfa.enrollment.confirmed",
      "mfa.verify.succeeded",
      "mfa.verify.failed",
      "mfa.verify.succeeded",
      "mfa.recovery_codes.regenerated",
      "mfa.disabled",
    ]);
    const recovery = events[3];
    assert(recovery.type === "mfa.verify.succeeded");
    expect(recovery.method).toStrictEqual("recovery");
    expect(recovery.remainingRecoveryCodes).toStrictEqual(9);
  });

  it("applies constructor TOTP options to enrollment and verification", async () => {
    using time = new FakeTime(START);
    const store = new MemoryMfaStore();
    const mfa = new MfaService({
      store,
      totp: { digits: 8, periodSeconds: 60, algorithm: "SHA-256" },
      recoveryCodeCount: 4,
    });
    const start = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    expect(start.otpauthUri).toContain("algorithm=SHA256");
    expect(start.otpauthUri).toContain("digits=8");
    expect(start.otpauthUri).toContain("period=60");
    const confirmation = await mfa.confirmEnrollment(
      "u1",
      await generateTotpCode({
        secret: start.base32,
        digits: 8,
        periodSeconds: 60,
        algorithm: "SHA-256",
      }),
    );
    assert(confirmation.confirmed);
    expect(confirmation.recoveryCodes.length).toStrictEqual(4);

    time.tick(60_000);
    expect(
      await mfa.verify(
        "u1",
        await generateTotpCode({
          secret: start.base32,
          digits: 8,
          periodSeconds: 60,
          algorithm: "SHA-256",
        }),
      ),
    ).toStrictEqual({ valid: true, method: "totp" });
    expect(
      await mfa.verify("u1", await generateTotpCode({ secret: start.base32 })),
    ).toStrictEqual({ valid: false, reason: "invalid" });
  });

  it("scopes state per user", async () => {
    using time = new FakeTime(START);
    const { mfa } = setup();
    await enroll(mfa, "u1");
    time.tick(PERIOD_MS);
    const u2 = await enroll(mfa, "u2");

    time.tick(PERIOD_MS);
    expect(
      await mfa.verify("u2", await generateTotpCode({ secret: u2.base32 })),
    ).toStrictEqual({ valid: true, method: "totp" });
    expect(
      await mfa.verify("u1", await generateTotpCode({ secret: u2.base32 })),
    ).toStrictEqual({ valid: false, reason: "invalid" });
    expect(await mfa.verify("u1", u2.recoveryCodes[0])).toStrictEqual({
      valid: false,
      reason: "invalid",
    });
  });

  it("rejects unusable configuration at construction", () => {
    const store = new MemoryMfaStore();
    thrown(() => new MfaService({ store, totp: { digits: 6.5 } }), TypeError);
    thrown(
      () => new MfaService({ store, totp: { periodSeconds: 0 } }),
      TypeError,
    );
    thrown(() => new MfaService({ store, totp: { windows: -1 } }), TypeError);
    thrown(() => new MfaService({ store, recoveryCodeCount: 0 }), TypeError);
  });

  it("resets the rate-limit window on successful TOTP verification", async () => {
    using time = new FakeTime(START);
    const store = new MemoryMfaStore();
    const mfa = new MfaService({
      store,
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60 * 60_000 }),
    });
    const { base32 } = await enroll(mfa, "u1");

    for (let round = 0; round < 3; round++) {
      time.tick(PERIOD_MS);
      expect((await mfa.verify("u1", "000000")).valid).toStrictEqual(false);
      expect(
        (await mfa.verify("u1", await generateTotpCode({ secret: base32 })))
          .valid,
      ).toStrictEqual(true);
    }
  });

  it("resets the rate-limit window on successful recovery verification", async () => {
    using _time = new FakeTime(START);
    const store = new MemoryMfaStore();
    const mfa = new MfaService({
      store,
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60 * 60_000 }),
    });
    const { recoveryCodes } = await enroll(mfa, "u1");

    for (let round = 0; round < 3; round++) {
      expect((await mfa.verify("u1", "000000")).valid).toStrictEqual(false);
      expect(
        (await mfa.verify("u1", recoveryCodes[round])).valid,
      ).toStrictEqual(true);
    }
  });

  it("rejects recovery codes when no active credential exists, even with stale hashes", async () => {
    using _time = new FakeTime(START);
    const store = new MemoryMfaStore();
    const mfa = new MfaService({ store });
    const { recoveryCodes } = await enroll(mfa, "u1");
    await store.clearTotp("u1");

    expect(await mfa.verify("u1", recoveryCodes[0])).toStrictEqual({
      valid: false,
      reason: "invalid",
    });
    expect((await store.getRecoveryHashes("u1")).length).toStrictEqual(10);
  });

  it("skips the recovery-code lookup for codes that cannot be recovery codes", async () => {
    using _time = new FakeTime(START);
    class CountingStore extends MemoryMfaStore {
      consumeCalls = 0;
      override consumeRecoveryHash(
        userId: string,
        hash: string,
      ): Promise<boolean> {
        this.consumeCalls++;
        return super.consumeRecoveryHash(userId, hash);
      }
    }
    const store = new CountingStore();
    const mfa = new MfaService({ store });
    const { recoveryCodes } = await enroll(mfa, "u1");

    expect((await mfa.verify("u1", "000000")).valid).toStrictEqual(false);
    expect(store.consumeCalls).toStrictEqual(0);
    expect((await mfa.verify("u1", recoveryCodes[0])).valid).toStrictEqual(
      true,
    );
    expect(store.consumeCalls).toStrictEqual(1);
  });

  it("rate limits confirmEnrollment per user and throws rate_limited when enforcing", async () => {
    using _time = new FakeTime(START);
    const events: IdentityEvent[] = [];
    const mfa = new MfaService({
      store: new MemoryMfaStore(),
      rateLimiter: new RateLimiter({ limit: 1, windowMs: 60_000 }),
      onEvent: (event) => {
        events.push(event);
      },
    });
    const { base32 } = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });

    expect(await mfa.confirmEnrollment("u1", "000000")).toStrictEqual({
      confirmed: false,
    });
    const validCode = await generateTotpCode({ secret: base32 });
    const error = await rejection(
      () => mfa.confirmEnrollment("u1", validCode),
      IdentityError,
    );
    expect(error.code).toStrictEqual("rate_limited");
    expect(await mfa.isEnrolled("u1")).toStrictEqual(false);
    assert(events.some((e) => e.type === "mfa.verify.rate_limited"));
  });

  it("shares the verify window with confirmEnrollment and resets it on a confirmed enrollment", async () => {
    using _time = new FakeTime(START);
    const mfa = new MfaService({
      store: new MemoryMfaStore(),
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60_000 }),
    });
    const { base32 } = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    expect(await mfa.confirmEnrollment("u1", "000000")).toStrictEqual({
      confirmed: false,
    });
    const code = await generateTotpCode({ secret: base32 });
    assert((await mfa.confirmEnrollment("u1", code)).confirmed);

    expect((await mfa.verify("u1", "000000")).valid).toStrictEqual(false);
    expect((await mfa.verify("u1", "000001")).valid).toStrictEqual(false);
    const error = await rejection(
      () => mfa.verify("u1", "000002"),
      IdentityError,
    );
    expect(error.code).toStrictEqual("rate_limited");
  });

  for (const method of ["totp", "recovery"] as const) {
    it(`completes a ${method} verification when the limiter's reset throws, so the spent code still signs the user in`, async () => {
      using consoleError = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});
      using time = new FakeTime(START);
      const limiter = new RateLimiter({ limit: 5, windowMs: 60_000 });
      let resetBroken = false;
      const mfa = new MfaService({
        store: new MemoryMfaStore(),
        rateLimiter: {
          check: (key) => limiter.check(key),
          reset: (key) =>
            resetBroken
              ? Promise.reject(new Error("limiter down"))
              : limiter.reset(key),
        },
      });
      const { base32, recoveryCodes } = await enroll(mfa, "u1");
      time.tick(PERIOD_MS);
      resetBroken = true;
      const code =
        method === "totp"
          ? await generateTotpCode({ secret: base32 })
          : recoveryCodes[0];

      const outcome = await mfa
        .verify("u1", code, { method })
        .catch((error) => ({ threw: error.message }));

      expect(outcome).toStrictEqual(
        method === "totp"
          ? { valid: true, method: "totp" }
          : { valid: true, method: "recovery", remainingRecoveryCodes: 9 },
      );
      expect(consoleError.mock.calls.length).toStrictEqual(1);
    });
  }

  it("rolls back activation when storing recovery codes fails, so enrollment can be retried", async () => {
    using time = new FakeTime(START);
    class FailingRecoveryStore extends MemoryMfaStore {
      fail = true;
      override setRecoveryHashes(
        userId: string,
        hashes: string[],
      ): Promise<void> {
        if (this.fail) return Promise.reject(new Error("db down"));
        return super.setRecoveryHashes(userId, hashes);
      }
    }
    const store = new FailingRecoveryStore();
    const mfa = new MfaService({ store });
    const start = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    const code = await generateTotpCode({ secret: start.base32 });
    await rejection(() => mfa.confirmEnrollment("u1", code), Error, "db down");
    expect(await mfa.isEnrolled("u1")).toStrictEqual(false);

    store.fail = false;
    const retry = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    time.tick(PERIOD_MS);
    const confirmation = await mfa.confirmEnrollment(
      "u1",
      await generateTotpCode({ secret: retry.base32 }),
    );
    assert(confirmation.confirmed);
    expect(await mfa.isEnrolled("u1")).toStrictEqual(true);
  });

  it("labels failed verifications with a reason distinguishing replay from a wrong code", async () => {
    using time = new FakeTime(START);
    const events: IdentityEvent[] = [];
    const store = new MemoryMfaStore();
    const mfa = new MfaService({
      store,
      onEvent: (event) => {
        events.push(event);
      },
    });
    const { base32 } = await enroll(mfa, "u1");

    time.tick(PERIOD_MS);
    const code = await generateTotpCode({ secret: base32 });
    expect(await mfa.verify("u1", code)).toStrictEqual({
      valid: true,
      method: "totp",
    });
    const replayed = await mfa.verify("u1", code);
    expect(replayed).toStrictEqual({ valid: false, reason: "replayed" });
    const wrong = await mfa.verify("u1", "000000");
    expect(wrong).toStrictEqual({ valid: false, reason: "invalid" });

    const eventReasons = events.flatMap((event) =>
      event.type === "mfa.verify.failed" ? [event.reason] : [],
    );
    expect(eventReasons).toStrictEqual(["replayed", "invalid"]);
    assert(!replayed.valid && !wrong.valid);
    expect([replayed.reason, wrong.reason]).toStrictEqual(eventReasons);
  });

  it("reports a no-credential failure as invalid on both result and event", async () => {
    const events: IdentityEvent[] = [];
    const store = new MemoryMfaStore();
    const mfa = new MfaService({
      store,
      onEvent: (event) => {
        events.push(event);
      },
    });

    expect(await mfa.verify("u1", "000000")).toStrictEqual({
      valid: false,
      reason: "invalid",
    });
    const failed = events.filter((e) => e.type === "mfa.verify.failed");
    expect(failed.length).toStrictEqual(1);
    assert(failed[0].type === "mfa.verify.failed");
    expect(failed[0].reason).toStrictEqual("invalid");
  });

  it("reports enrollment status across none, pending, and active", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();

    expect(await mfa.enrollmentStatus("u1")).toStrictEqual("none");

    const start = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    expect(await mfa.enrollmentStatus("u1")).toStrictEqual("pending");
    expect(await mfa.isEnrolled("u1")).toStrictEqual(false);

    const confirmation = await mfa.confirmEnrollment(
      "u1",
      await generateTotpCode({ secret: start.base32 }),
    );
    assert(confirmation.confirmed);
    expect(await mfa.enrollmentStatus("u1")).toStrictEqual("active");

    await mfa.disable("u1");
    expect(await mfa.enrollmentStatus("u1")).toStrictEqual("none");
  });
});

describe("MemoryMfaStore", () => {
  it("activates only the still-pending secret", async () => {
    const store = new MemoryMfaStore();
    expect(await store.activateTotp("u1", "SECRET", 5)).toStrictEqual(false);

    await store.setPendingTotp("u1", "FIRST");
    await store.setPendingTotp("u1", "SECOND");
    expect(await store.activateTotp("u1", "FIRST", 5)).toStrictEqual(false);
    expect((await store.getTotp("u1"))?.secretBase32).toStrictEqual(undefined);
    expect(await store.activateTotp("u1", "SECOND", 5)).toStrictEqual(true);
    expect(await store.getTotp("u1")).toStrictEqual({
      secretBase32: "SECOND",
      lastStep: 5,
    });
  });

  it("advances the replay guard only forward", async () => {
    const store = new MemoryMfaStore();
    expect(await store.advanceLastStep("u1", 5)).toStrictEqual(false);

    await store.setPendingTotp("u1", "SECRET");
    await store.activateTotp("u1", "SECRET", 5);
    expect(await store.advanceLastStep("u1", 5)).toStrictEqual(false);
    expect(await store.advanceLastStep("u1", 4)).toStrictEqual(false);
    expect(await store.advanceLastStep("u1", 6)).toStrictEqual(true);
    expect((await store.getTotp("u1"))?.lastStep).toStrictEqual(6);
  });

  it("consumes a recovery hash exactly once", async () => {
    const store = new MemoryMfaStore();
    await store.setRecoveryHashes("u1", ["a", "b"]);
    expect(await store.consumeRecoveryHash("u1", "a")).toStrictEqual(true);
    expect(await store.consumeRecoveryHash("u1", "a")).toStrictEqual(false);
    expect(await store.getRecoveryHashes("u1")).toStrictEqual(["b"]);
    expect(await store.consumeRecoveryHash("u2", "b")).toStrictEqual(false);
  });

  it("returns copies so callers cannot mutate stored state", async () => {
    const store = new MemoryMfaStore();
    await store.setPendingTotp("u1", "SECRET");
    const record = await store.getTotp("u1");
    record!.pendingSecretBase32 = "TAMPERED";
    expect((await store.getTotp("u1"))?.pendingSecretBase32).toStrictEqual(
      "SECRET",
    );

    await store.setRecoveryHashes("u1", ["a", "b"]);
    const hashes = await store.getRecoveryHashes("u1");
    hashes.push("c");
    expect(await store.getRecoveryHashes("u1")).toStrictEqual(["a", "b"]);
  });
});
