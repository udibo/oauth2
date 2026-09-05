import {
  assert,
  assertEquals,
  assertNotEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { FakeTime } from "@std/testing/time";

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
    assertStringIncludes(start.otpauthUri, `secret=${start.base32}`);
    assertEquals(await mfa.isEnrolled("u1"), false);

    const confirmation = await mfa.confirmEnrollment(
      "u1",
      await generateTotpCode({ secret: start.base32 }),
    );
    assert(confirmation.confirmed);
    assertEquals(confirmation.recoveryCodes.length, 10);
    assertEquals(await mfa.isEnrolled("u1"), true);

    time.tick(PERIOD_MS);
    const code = await generateTotpCode({ secret: start.base32 });
    assertEquals(await mfa.verify("u1", code), {
      valid: true,
      method: "totp",
    });
    assertEquals(await mfa.verify("u1", code), {
      valid: false,
      reason: "replayed",
    });

    time.tick(PERIOD_MS);
    assertEquals(
      (await mfa.verify("u1", await generateTotpCode({ secret: start.base32 })))
        .valid,
      true,
    );

    const recoveryCode = confirmation.recoveryCodes[0];
    assertEquals(await mfa.verify("u1", recoveryCode), {
      valid: true,
      method: "recovery",
      remainingRecoveryCodes: 9,
    });
    assertEquals(await mfa.verify("u1", recoveryCode), {
      valid: false,
      reason: "invalid",
    });

    const regenerated = await mfa.regenerateRecoveryCodes("u1");
    assertEquals(regenerated.length, 10);
    assertEquals(
      await mfa.verify("u1", confirmation.recoveryCodes[1]),
      { valid: false, reason: "invalid" },
    );
    assertEquals(await mfa.verify("u1", regenerated[0]), {
      valid: true,
      method: "recovery",
      remainingRecoveryCodes: 9,
    });

    await mfa.disable("u1");
    assertEquals(await mfa.isEnrolled("u1"), false);
    time.tick(PERIOD_MS);
    assertEquals(
      await mfa.verify("u1", await generateTotpCode({ secret: start.base32 })),
      { valid: false, reason: "invalid" },
    );
    assertEquals(await mfa.verify("u1", regenerated[1]), {
      valid: false,
      reason: "invalid",
    });
  });

  it("accepts recovery codes in any case and without separators", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();
    const { recoveryCodes } = await enroll(mfa, "u1");
    const submitted = recoveryCodes[0].toLowerCase().replaceAll("-", "");
    assertEquals(await mfa.verify("u1", submitted), {
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
    assertEquals(
      await mfa.verify("u1", await generateTotpCode({ secret: base32 })),
      { valid: false, reason: "invalid" },
    );
  });

  it("rejects a wrong confirmation code and stays unenrolled", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();
    await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    assertEquals(await mfa.confirmEnrollment("u1", "000000"), {
      confirmed: false,
    });
    assertEquals(await mfa.isEnrolled("u1"), false);
  });

  it("rejects confirmation when no enrollment is pending", async () => {
    const { mfa } = setup();
    assertEquals(await mfa.confirmEnrollment("u1", "123456"), {
      confirmed: false,
    });
  });

  it("refuses enrollment while an active credential exists", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();
    await enroll(mfa, "u1");

    const startError = await assertRejects(
      () =>
        mfa.startEnrollment("u1", {
          issuer: "Udibo",
          accountName: "u1@example.com",
        }),
      IdentityError,
    );
    assertEquals(startError.code, "mfa_already_enrolled");

    const confirmError = await assertRejects(
      () => mfa.confirmEnrollment("u1", "000000"),
      IdentityError,
    );
    assertEquals(confirmError.code, "mfa_already_enrolled");
  });

  it("allows a fresh enrollment after disable", async () => {
    using time = new FakeTime(START);
    const { mfa } = setup();
    const { base32: oldSecret } = await enroll(mfa, "u1");
    await mfa.disable("u1");

    time.tick(PERIOD_MS);
    const { base32: newSecret } = await enroll(mfa, "u1");
    assertNotEquals(newSecret, oldSecret);
    time.tick(PERIOD_MS);
    assertEquals(
      await mfa.verify("u1", await generateTotpCode({ secret: newSecret })),
      { valid: true, method: "totp" },
    );
    assertEquals(
      await mfa.verify("u1", await generateTotpCode({ secret: oldSecret })),
      { valid: false, reason: "invalid" },
    );
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
    assertEquals(await mfa.confirmEnrollment("u1", firstCode), {
      confirmed: false,
    });
    assertEquals(await mfa.isEnrolled("u1"), false);
  });

  it("rejects the confirmation code if replayed as the first verification", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();
    const { base32 } = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    const code = await generateTotpCode({ secret: base32 });
    assertEquals((await mfa.confirmEnrollment("u1", code)).confirmed, true);
    assertEquals(await mfa.verify("u1", code), {
      valid: false,
      reason: "replayed",
    });
  });

  it("scopes verification to the requested method", async () => {
    using time = new FakeTime(START);
    const { mfa } = setup();
    const { base32, recoveryCodes } = await enroll(mfa, "u1");

    assertEquals(
      await mfa.verify("u1", recoveryCodes[0], { method: "totp" }),
      { valid: false, reason: "invalid" },
    );
    assertEquals(await mfa.verify("u1", recoveryCodes[0]), {
      valid: true,
      method: "recovery",
      remainingRecoveryCodes: 9,
    });

    time.tick(PERIOD_MS);
    assertEquals(
      await mfa.verify("u1", await generateTotpCode({ secret: base32 }), {
        method: "recovery",
      }),
      { valid: false, reason: "invalid" },
    );
  });

  it("leaves the replay guard unspent when a TOTP code is submitted as a recovery code", async () => {
    using time = new FakeTime(START);
    const { mfa } = setup();
    const { base32 } = await enroll(mfa, "u1");

    time.tick(PERIOD_MS);
    const code = await generateTotpCode({ secret: base32 });
    assertEquals(await mfa.verify("u1", code, { method: "recovery" }), {
      valid: false,
      reason: "invalid",
    });
    assertEquals(await mfa.verify("u1", code), { valid: true, method: "totp" });
  });

  it("does not consume a recovery code when the attempt is scoped to TOTP", async () => {
    using _time = new FakeTime(START);
    const store = new MemoryMfaStore();
    const mfa = new MfaService({ store });
    const { recoveryCodes } = await enroll(mfa, "u1");

    assertEquals(await mfa.verify("u1", recoveryCodes[0], { method: "totp" }), {
      valid: false,
      reason: "invalid",
    });
    assertEquals((await store.getRecoveryHashes("u1")).length, 10);
  });

  it("throws a typed error when regenerating recovery codes without an active enrollment", async () => {
    const { mfa } = setup();
    const error = await assertRejects(
      () => mfa.regenerateRecoveryCodes("u1"),
      IdentityError,
      "not enrolled",
    );
    assertEquals(error.code, "mfa_not_enrolled");
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

    await assertRejects(() => mfa.disable("u1"), Error, "db down");
    assertEquals(await mfa.isEnrolled("u1"), true);
    assertEquals(await mfa.verify("u1", recoveryCodes[0]), {
      valid: false,
      reason: "invalid",
    });
    time.tick(PERIOD_MS);
    assertEquals(
      await mfa.verify("u1", await generateTotpCode({ secret: base32 })),
      { valid: true, method: "totp" },
    );
  });

  it("rate limits verify per user and throws rate_limited when enforcing", async () => {
    using _time = new FakeTime(START);
    const store = new MemoryMfaStore();
    const mfa = new MfaService({
      store,
      rateLimiter: new RateLimiter({ limit: 1, windowMs: 60_000 }),
    });
    const { base32 } = await enroll(mfa, "u1");

    assertEquals((await mfa.verify("u1", "000000")).valid, false);
    const validCode = await generateTotpCode({ secret: base32 });
    const error = await assertRejects(
      () => mfa.verify("u1", validCode),
      IdentityError,
    );
    assertEquals(error.code, "rate_limited");
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

    assertEquals((await mfa.verify("u1", "000000")).valid, false);
    time.tick(PERIOD_MS);
    assertEquals(
      await mfa.verify("u1", await generateTotpCode({ secret: base32 })),
      { valid: true, method: "totp" },
    );
    const limited = events.find((e) => e.type === "mfa.verify.rate_limited");
    assert(limited?.type === "mfa.verify.rate_limited");
    assertEquals(limited.enforced, false);
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

    assertEquals(events.map((event) => event.type), [
      "mfa.enrollment.confirmed",
      "mfa.verify.succeeded",
      "mfa.verify.failed",
      "mfa.verify.succeeded",
      "mfa.recovery_codes.regenerated",
      "mfa.disabled",
    ]);
    const recovery = events[3];
    assert(recovery.type === "mfa.verify.succeeded");
    assertEquals(recovery.method, "recovery");
    assertEquals(recovery.remainingRecoveryCodes, 9);
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
    assertStringIncludes(start.otpauthUri, "algorithm=SHA256");
    assertStringIncludes(start.otpauthUri, "digits=8");
    assertStringIncludes(start.otpauthUri, "period=60");
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
    assertEquals(confirmation.recoveryCodes.length, 4);

    time.tick(60_000);
    assertEquals(
      await mfa.verify(
        "u1",
        await generateTotpCode({
          secret: start.base32,
          digits: 8,
          periodSeconds: 60,
          algorithm: "SHA-256",
        }),
      ),
      { valid: true, method: "totp" },
    );
    assertEquals(
      await mfa.verify(
        "u1",
        await generateTotpCode({ secret: start.base32 }),
      ),
      { valid: false, reason: "invalid" },
    );
  });

  it("scopes state per user", async () => {
    using time = new FakeTime(START);
    const { mfa } = setup();
    await enroll(mfa, "u1");
    time.tick(PERIOD_MS);
    const u2 = await enroll(mfa, "u2");

    time.tick(PERIOD_MS);
    assertEquals(
      await mfa.verify("u2", await generateTotpCode({ secret: u2.base32 })),
      { valid: true, method: "totp" },
    );
    assertEquals(
      await mfa.verify("u1", await generateTotpCode({ secret: u2.base32 })),
      { valid: false, reason: "invalid" },
    );
    assertEquals(await mfa.verify("u1", u2.recoveryCodes[0]), {
      valid: false,
      reason: "invalid",
    });
  });

  it("rejects unusable configuration at construction", () => {
    const store = new MemoryMfaStore();
    assertThrows(
      () => new MfaService({ store, totp: { digits: 6.5 } }),
      TypeError,
    );
    assertThrows(
      () => new MfaService({ store, totp: { periodSeconds: 0 } }),
      TypeError,
    );
    assertThrows(
      () => new MfaService({ store, totp: { windows: -1 } }),
      TypeError,
    );
    assertThrows(
      () => new MfaService({ store, recoveryCodeCount: 0 }),
      TypeError,
    );
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
      assertEquals((await mfa.verify("u1", "000000")).valid, false);
      assertEquals(
        (await mfa.verify("u1", await generateTotpCode({ secret: base32 })))
          .valid,
        true,
      );
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
      assertEquals((await mfa.verify("u1", "000000")).valid, false);
      assertEquals((await mfa.verify("u1", recoveryCodes[round])).valid, true);
    }
  });

  it("rejects recovery codes when no active credential exists, even with stale hashes", async () => {
    using _time = new FakeTime(START);
    const store = new MemoryMfaStore();
    const mfa = new MfaService({ store });
    const { recoveryCodes } = await enroll(mfa, "u1");
    await store.clearTotp("u1");

    assertEquals(await mfa.verify("u1", recoveryCodes[0]), {
      valid: false,
      reason: "invalid",
    });
    assertEquals((await store.getRecoveryHashes("u1")).length, 10);
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

    assertEquals((await mfa.verify("u1", "000000")).valid, false);
    assertEquals(store.consumeCalls, 0);
    assertEquals((await mfa.verify("u1", recoveryCodes[0])).valid, true);
    assertEquals(store.consumeCalls, 1);
  });

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
    await assertRejects(
      () => mfa.confirmEnrollment("u1", code),
      Error,
      "db down",
    );
    assertEquals(await mfa.isEnrolled("u1"), false);

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
    assertEquals(await mfa.isEnrolled("u1"), true);
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
    assertEquals(await mfa.verify("u1", code), { valid: true, method: "totp" });
    const replayed = await mfa.verify("u1", code);
    assertEquals(replayed, { valid: false, reason: "replayed" });
    const wrong = await mfa.verify("u1", "000000");
    assertEquals(wrong, { valid: false, reason: "invalid" });

    const eventReasons = events.flatMap((event) =>
      event.type === "mfa.verify.failed" ? [event.reason] : []
    );
    assertEquals(eventReasons, ["replayed", "invalid"]);
    assert(!replayed.valid && !wrong.valid);
    assertEquals([replayed.reason, wrong.reason], eventReasons);
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

    assertEquals(await mfa.verify("u1", "000000"), {
      valid: false,
      reason: "invalid",
    });
    const failed = events.filter((e) => e.type === "mfa.verify.failed");
    assertEquals(failed.length, 1);
    assert(failed[0].type === "mfa.verify.failed");
    assertEquals(failed[0].reason, "invalid");
  });

  it("reports enrollment status across none, pending, and active", async () => {
    using _time = new FakeTime(START);
    const { mfa } = setup();

    assertEquals(await mfa.enrollmentStatus("u1"), "none");

    const start = await mfa.startEnrollment("u1", {
      issuer: "Udibo",
      accountName: "u1@example.com",
    });
    assertEquals(await mfa.enrollmentStatus("u1"), "pending");
    assertEquals(await mfa.isEnrolled("u1"), false);

    const confirmation = await mfa.confirmEnrollment(
      "u1",
      await generateTotpCode({ secret: start.base32 }),
    );
    assert(confirmation.confirmed);
    assertEquals(await mfa.enrollmentStatus("u1"), "active");

    await mfa.disable("u1");
    assertEquals(await mfa.enrollmentStatus("u1"), "none");
  });
});

describe("MemoryMfaStore", () => {
  it("activates only the still-pending secret", async () => {
    const store = new MemoryMfaStore();
    assertEquals(await store.activateTotp("u1", "SECRET", 5), false);

    await store.setPendingTotp("u1", "FIRST");
    await store.setPendingTotp("u1", "SECOND");
    assertEquals(await store.activateTotp("u1", "FIRST", 5), false);
    assertEquals((await store.getTotp("u1"))?.secretBase32, undefined);
    assertEquals(await store.activateTotp("u1", "SECOND", 5), true);
    assertEquals(await store.getTotp("u1"), {
      secretBase32: "SECOND",
      lastStep: 5,
    });
  });

  it("advances the replay guard only forward", async () => {
    const store = new MemoryMfaStore();
    assertEquals(await store.advanceLastStep("u1", 5), false);

    await store.setPendingTotp("u1", "SECRET");
    await store.activateTotp("u1", "SECRET", 5);
    assertEquals(await store.advanceLastStep("u1", 5), false);
    assertEquals(await store.advanceLastStep("u1", 4), false);
    assertEquals(await store.advanceLastStep("u1", 6), true);
    assertEquals((await store.getTotp("u1"))?.lastStep, 6);
  });

  it("consumes a recovery hash exactly once", async () => {
    const store = new MemoryMfaStore();
    await store.setRecoveryHashes("u1", ["a", "b"]);
    assertEquals(await store.consumeRecoveryHash("u1", "a"), true);
    assertEquals(await store.consumeRecoveryHash("u1", "a"), false);
    assertEquals(await store.getRecoveryHashes("u1"), ["b"]);
    assertEquals(await store.consumeRecoveryHash("u2", "b"), false);
  });

  it("returns copies so callers cannot mutate stored state", async () => {
    const store = new MemoryMfaStore();
    await store.setPendingTotp("u1", "SECRET");
    const record = await store.getTotp("u1");
    record!.pendingSecretBase32 = "TAMPERED";
    assertEquals((await store.getTotp("u1"))?.pendingSecretBase32, "SECRET");

    await store.setRecoveryHashes("u1", ["a", "b"]);
    const hashes = await store.getRecoveryHashes("u1");
    hashes.push("c");
    assertEquals(await store.getRecoveryHashes("u1"), ["a", "b"]);
  });
});
