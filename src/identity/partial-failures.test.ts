import { assert, describe, expect, it, vi } from "vitest";
import { rejection } from "../_test_assert.ts";
import type { CodeDeliveryMessage, DeliveryMessage } from "./delivery.ts";
import type { IdentityEvent } from "./events.ts";
import { AccountLockout, MemoryLockoutStore } from "./lockout.ts";
import { MemoryOtpStore, type OtpStore } from "./otp.ts";
import {
  type PasswordCredential,
  PasswordIdentityService,
} from "./password.ts";
import { MemoryRateLimitStore, RateLimiter } from "./rate-limit.ts";
import { IdentityService, type IdentityUserStore } from "./service.ts";
import {
  MemoryTokenFlowStore,
  TokenFlowService,
  type TokenFlowStore,
  TokenPurpose,
} from "./token-flow.ts";

interface User {
  id: string;
  email: string;
}

type Fault =
  | "hash"
  | "setCredential"
  | "clearLegacyCredential"
  | "voidSignInLinks"
  | "voidSignInCode"
  | "revokeAllByUser"
  | "lockoutReset"
  | "resetCredential"
  | "markEmailVerified"
  | "consumeVerification"
  | "signInCodeThrottleReset";

const EMAIL = "a@b.co";
const OLD_PASSWORD = "hunter2hunter2";
const NEW_PASSWORD = "newpassword1";

function harness(options?: {
  atomicReset?: boolean;
  withoutSessions?: boolean;
}) {
  const faults = new Set<Fault>();
  const fail = (fault: Fault): Promise<never> =>
    Promise.reject(new Error(`${fault} failed`));
  const users = new Map<string, User>();
  const credentials = new Map<string, PasswordCredential>();
  const legacy = new Map<string, string>();
  const verified = new Set<string>();
  const liveSessions = new Map<string, string>();
  const calls: string[] = [];
  let sequence = 0;

  function revokeAll(userId: string): number {
    let revoked = 0;
    for (const [id, owner] of liveSessions) {
      if (owner !== userId) continue;
      liveSessions.delete(id);
      revoked++;
    }
    return revoked;
  }

  const store: IdentityUserStore<User> = {
    create(profile, credential) {
      const user = { id: `u${++sequence}`, email: String(profile.email) };
      users.set(user.id, user);
      credentials.set(user.id, credential);
      return Promise.resolve(user);
    },
    findByIdentifier(identifier) {
      return this.findByEmail(identifier);
    },
    findByEmail(email) {
      return Promise.resolve(
        [...users.values()].find((user) => user.email === email),
      );
    },
    getCredential(userId) {
      return Promise.resolve(credentials.get(userId));
    },
    setCredential(userId, credential) {
      calls.push("setCredential");
      if (faults.has("setCredential")) return fail("setCredential");
      credentials.set(userId, credential);
      return Promise.resolve();
    },
    markEmailVerified(userId) {
      if (faults.has("markEmailVerified")) return fail("markEmailVerified");
      verified.add(userId);
      return Promise.resolve();
    },
    getLegacyCredential(userId) {
      return Promise.resolve(legacy.get(userId) ?? null);
    },
    clearLegacyCredential(userId) {
      calls.push("clearLegacyCredential");
      if (faults.has("clearLegacyCredential")) {
        return fail("clearLegacyCredential");
      }
      legacy.delete(userId);
      return Promise.resolve();
    },
  };
  if (options?.atomicReset) {
    store.resetCredential = (userId, credential) => {
      calls.push("resetCredential");
      if (faults.has("resetCredential")) return fail("resetCredential");
      credentials.set(userId, credential);
      legacy.delete(userId);
      return Promise.resolve(revokeAll(userId));
    };
  }

  const tokenStore = new MemoryTokenFlowStore();
  const tokens: TokenFlowStore = {
    save: (record) => tokenStore.save(record),
    get: (hash) => tokenStore.get(hash),
    markConsumed: async (hash, at) => {
      const record = await tokenStore.get(hash);
      if (
        faults.has("consumeVerification") &&
        record?.purpose === TokenPurpose.EmailVerification
      ) {
        return await fail("consumeVerification");
      }
      return await tokenStore.markConsumed(hash, at);
    },
    deleteBySubject: (purpose, subject) =>
      faults.has("voidSignInLinks") && purpose === TokenPurpose.SignIn
        ? fail("voidSignInLinks")
        : tokenStore.deleteBySubject(purpose, subject),
  };
  const otpBacking = new MemoryOtpStore();
  const otp: OtpStore = {
    create: (record) => otpBacking.create(record),
    findActive: (email, purpose) => otpBacking.findActive(email, purpose),
    recordAttempt: (id) => otpBacking.recordAttempt(id),
    consume: (id) => otpBacking.consume(id),
    invalidate: (email, purpose) =>
      faults.has("voidSignInCode")
        ? fail("voidSignInCode")
        : otpBacking.invalidate(email, purpose),
    invalidateById: (id) => otpBacking.invalidateById(id),
  };
  const hasher = new PasswordIdentityService({ iterations: 1_000 });
  const lockout = new AccountLockout({ store: new MemoryLockoutStore() });
  const limiter = new RateLimiter({
    limit: 50,
    windowMs: 60_000,
    store: new MemoryRateLimitStore(),
  });
  const events: IdentityEvent[] = [];
  const resets: DeliveryMessage[] = [];
  const verifications: DeliveryMessage[] = [];
  const links: DeliveryMessage[] = [];
  const codes: CodeDeliveryMessage[] = [];
  const service = new IdentityService<User>({
    failedSignInFloorMs: 0,
    users: store,
    tokens: new TokenFlowService(tokens),
    otp: { store: otp },
    passwords: {
      hash: (password) =>
        faults.has("hash") ? fail("hash") : hasher.hash(password),
      verify: (password, credential) => hasher.verify(password, credential),
    },
    sessions: options?.withoutSessions
      ? undefined
      : {
          revokeAllByUser(userId) {
            calls.push("revokeAllByUser");
            if (faults.has("revokeAllByUser")) return fail("revokeAllByUser");
            return Promise.resolve(revokeAll(userId));
          },
          revokeOthers: () => Promise.resolve(0),
        },
    lockout: {
      status: (userId) => lockout.status(userId),
      recordFailure: (userId) => lockout.recordFailure(userId),
      reset: (userId) =>
        faults.has("lockoutReset")
          ? fail("lockoutReset")
          : lockout.reset(userId),
    },
    rateLimiters: {
      signInCode: {
        check: (key) => limiter.check(key),
        reset: (key) =>
          faults.has("signInCodeThrottleReset")
            ? fail("signInCodeThrottleReset")
            : limiter.reset(key),
      },
    },
    delivery: {
      sendPasswordReset: (message) => {
        resets.push(message);
      },
      sendEmailVerification: (message) => {
        verifications.push(message);
      },
      sendSignInLink: (message) => {
        links.push(message);
      },
      sendSignInCode: (message) => {
        codes.push(message);
      },
    },
    onEvent: (event) => {
      events.push(event);
    },
  });

  async function signUp(): Promise<User> {
    const user = await service.signUp({
      password: OLD_PASSWORD,
      profile: { email: EMAIL },
    });
    legacy.set(user.id, "$imported$hash");
    liveSessions.set("s1", user.id);
    liveSessions.set("s2", user.id);
    liveSessions.set("other", "someone-else");
    return user;
  }

  async function resetLink(): Promise<string> {
    await service.requestPasswordReset(EMAIL);
    return resets.at(-1)!.token;
  }

  async function signsInWith(password: string): Promise<boolean> {
    return (await service.signIn({ identifier: EMAIL, password })) !== null;
  }

  function sessionsOf(userId: string): string[] {
    return [...liveSessions]
      .filter(([, owner]) => owner === userId)
      .map(([id]) => id);
  }

  function failed(): Extract<
    IdentityEvent,
    { type: "password_reset.failed" }
  >[] {
    return events.filter(
      (
        event,
      ): event is Extract<IdentityEvent, { type: "password_reset.failed" }> =>
        event.type === "password_reset.failed",
    );
  }

  function completed(): IdentityEvent[] {
    return events.filter((event) => event.type === "password_reset.completed");
  }

  return {
    service,
    faults,
    calls,
    events,
    legacy,
    verified,
    links,
    codes,
    verifications,
    lockout,
    signUp,
    resetLink,
    signsInWith,
    sessionsOf,
    failed,
    completed,
  };
}

describe("password reset partial failures", () => {
  for (const fault of ["hash", "setCredential"] as const) {
    it(`reports a ${fault} failure after the link is spent as credential_write_failed and changes nothing else`, async () => {
      const h = harness();
      const user = await h.signUp();
      const token = await h.resetLink();
      h.faults.add(fault);

      await rejection(
        () => h.service.resetPassword({ token, password: NEW_PASSWORD }),
        Error,
        `${fault} failed`,
      );
      h.faults.delete(fault);

      expect(h.failed()).toStrictEqual([
        {
          type: "password_reset.failed",
          reason: "credential_write_failed",
          userId: user.id,
        },
      ]);
      expect(h.completed()).toStrictEqual([]);
      expect(h.sessionsOf(user.id)).toStrictEqual(["s1", "s2"]);
      expect(h.legacy.get(user.id)).toStrictEqual("$imported$hash");
      expect(await h.signsInWith(OLD_PASSWORD)).toBe(true);
      expect(
        await h.service.resetPassword({ token, password: NEW_PASSWORD }),
        "the spent link must not be reusable",
      ).toBe(null);
    });
  }

  it("completes the reset when clearing the imported hash fails, leaving only that hash behind", async () => {
    using consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    const h = harness();
    const user = await h.signUp();
    const token = await h.resetLink();
    h.faults.add("clearLegacyCredential");

    expect(
      await h.service.resetPassword({ token, password: NEW_PASSWORD }),
    ).toStrictEqual({ userId: user.id });

    expect(h.legacy.get(user.id)).toStrictEqual("$imported$hash");
    expect(h.sessionsOf(user.id)).toStrictEqual([]);
    expect(h.completed().length).toStrictEqual(1);
    expect(await h.signsInWith(NEW_PASSWORD)).toBe(true);
    expect(consoleError.mock.calls.length).toStrictEqual(1);
  });

  it("still voids the pending sign-in code when voiding sign-in links fails", async () => {
    using consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    const h = harness();
    const user = await h.signUp();
    await h.service.requestSignInLink(EMAIL);
    await h.service.requestSignInCode(EMAIL);
    const token = await h.resetLink();
    h.faults.add("voidSignInLinks");

    expect(
      await h.service.resetPassword({ token, password: NEW_PASSWORD }),
    ).toStrictEqual({ userId: user.id });

    expect(
      await h.service.verifySignInCode({ email: EMAIL, code: h.codes[0].code }),
    ).toStrictEqual({ status: "invalid" });
    expect(
      await h.service.consumeSignInLink(h.links[0].token),
      "the link outlives the reset until it expires",
    ).toStrictEqual({ status: "success", userId: user.id });
    expect(h.sessionsOf(user.id)).toStrictEqual([]);
    expect(consoleError.mock.calls.length).toStrictEqual(1);
  });

  it("still voids pending sign-in links when voiding the sign-in code fails", async () => {
    using consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    const h = harness();
    const user = await h.signUp();
    await h.service.requestSignInLink(EMAIL);
    await h.service.requestSignInCode(EMAIL);
    const token = await h.resetLink();
    h.faults.add("voidSignInCode");

    expect(
      await h.service.resetPassword({ token, password: NEW_PASSWORD }),
    ).toStrictEqual({ userId: user.id });

    expect(await h.service.consumeSignInLink(h.links[0].token)).toStrictEqual({
      status: "invalid",
    });
    expect(
      await h.service.verifySignInCode({ email: EMAIL, code: h.codes[0].code }),
      "the code outlives the reset until it expires",
    ).toStrictEqual({ status: "success", userId: user.id });
    expect(consoleError.mock.calls.length).toStrictEqual(1);
  });

  it("names the user on session_revocation_failed so the operator can revoke again", async () => {
    const h = harness();
    const user = await h.signUp();
    const token = await h.resetLink();
    h.faults.add("revokeAllByUser");

    await rejection(
      () => h.service.resetPassword({ token, password: NEW_PASSWORD }),
      Error,
      "revokeAllByUser failed",
    );

    expect(h.failed()).toStrictEqual([
      {
        type: "password_reset.failed",
        reason: "session_revocation_failed",
        userId: user.id,
      },
    ]);
    expect(h.completed()).toStrictEqual([]);
    expect(h.sessionsOf(user.id)).toStrictEqual(["s1", "s2"]);
    expect(await h.signsInWith(NEW_PASSWORD)).toBe(true);
  });

  it("reports lockout_reset_failed after the password and sessions changed", async () => {
    const h = harness();
    const user = await h.signUp();
    const token = await h.resetLink();
    h.faults.add("lockoutReset");

    await rejection(
      () => h.service.resetPassword({ token, password: NEW_PASSWORD }),
      Error,
      "lockoutReset failed",
    );
    h.faults.delete("lockoutReset");

    expect(h.failed()).toStrictEqual([
      {
        type: "password_reset.failed",
        reason: "lockout_reset_failed",
        userId: user.id,
      },
    ]);
    expect(h.completed()).toStrictEqual([]);
    expect(h.sessionsOf(user.id)).toStrictEqual([]);
    expect(await h.signsInWith(NEW_PASSWORD)).toBe(true);
  });
});

describe("password reset completion event", () => {
  it("omits sessionsRevoked when neither a store transaction nor a sessions service revoked anything", async () => {
    const h = harness({ withoutSessions: true });
    const user = await h.signUp();
    const token = await h.resetLink();

    expect(
      await h.service.resetPassword({ token, password: NEW_PASSWORD }),
    ).toStrictEqual({ userId: user.id });
    expect(h.completed()).toStrictEqual([
      { type: "password_reset.completed", userId: user.id },
    ]);
  });
});

describe("password reset with an atomic resetCredential store", () => {
  it("writes the credential, clears the imported hash and revokes sessions in the store call, then asks the sessions service too", async () => {
    const h = harness({ atomicReset: true });
    const user = await h.signUp();
    await h.service.requestSignInLink(EMAIL);
    const token = await h.resetLink();

    expect(
      await h.service.resetPassword({ token, password: NEW_PASSWORD }),
    ).toStrictEqual({ userId: user.id });

    expect(h.calls).toStrictEqual(["resetCredential", "revokeAllByUser"]);
    expect(h.sessionsOf(user.id)).toStrictEqual([]);
    expect(h.sessionsOf("someone-else")).toStrictEqual(["other"]);
    expect(h.legacy.has(user.id)).toBe(false);
    expect(h.completed()).toStrictEqual([
      { type: "password_reset.completed", userId: user.id, sessionsRevoked: 2 },
    ]);
    expect(await h.signsInWith(NEW_PASSWORD)).toBe(true);
    expect(
      await h.service.consumeSignInLink(h.links[0].token),
      "the atomic path still voids pending sign-in links",
    ).toStrictEqual({ status: "invalid" });
  });

  it("still reports a lockout reset failure after the atomic store call", async () => {
    const h = harness({ atomicReset: true });
    const user = await h.signUp();
    const token = await h.resetLink();
    h.faults.add("lockoutReset");

    await rejection(
      () => h.service.resetPassword({ token, password: NEW_PASSWORD }),
      Error,
      "lockoutReset failed",
    );

    expect(h.failed()).toStrictEqual([
      {
        type: "password_reset.failed",
        reason: "lockout_reset_failed",
        userId: user.id,
      },
    ]);
    expect(h.sessionsOf(user.id)).toStrictEqual([]);
  });

  it("leaves the password, imported hash and sessions untouched when the store call fails", async () => {
    const h = harness({ atomicReset: true });
    const user = await h.signUp();
    const token = await h.resetLink();
    h.faults.add("resetCredential");

    await rejection(
      () => h.service.resetPassword({ token, password: NEW_PASSWORD }),
      Error,
      "resetCredential failed",
    );

    expect(h.calls).toStrictEqual(["resetCredential"]);
    expect(h.failed()).toStrictEqual([
      {
        type: "password_reset.failed",
        reason: "credential_write_failed",
        userId: user.id,
      },
    ]);
    expect(h.completed()).toStrictEqual([]);
    expect(h.sessionsOf(user.id)).toStrictEqual(["s1", "s2"]);
    expect(h.legacy.get(user.id)).toStrictEqual("$imported$hash");
    expect(await h.signsInWith(OLD_PASSWORD)).toBe(true);
  });

  it("reports a hash failure before the store call as credential_write_failed", async () => {
    const h = harness({ atomicReset: true });
    const user = await h.signUp();
    const token = await h.resetLink();
    h.faults.add("hash");

    await rejection(
      () => h.service.resetPassword({ token, password: NEW_PASSWORD }),
      Error,
      "hash failed",
    );

    expect(h.calls).toStrictEqual([]);
    expect(h.failed().map((event) => event.reason)).toStrictEqual([
      "credential_write_failed",
    ]);
    expect(h.sessionsOf(user.id)).toStrictEqual(["s1", "s2"]);
  });

  it("reports session_revocation_failed when the sessions service fails after the store committed", async () => {
    const h = harness({ atomicReset: true });
    const user = await h.signUp();
    const token = await h.resetLink();
    h.faults.add("revokeAllByUser");

    await rejection(
      () => h.service.resetPassword({ token, password: NEW_PASSWORD }),
      Error,
      "revokeAllByUser failed",
    );

    expect(h.calls).toStrictEqual(["resetCredential", "revokeAllByUser"]);
    expect(h.failed()).toStrictEqual([
      {
        type: "password_reset.failed",
        reason: "session_revocation_failed",
        userId: user.id,
      },
    ]);
    expect(h.completed()).toStrictEqual([]);
    expect(
      h.sessionsOf(user.id),
      "the store's own revocation committed",
    ).toStrictEqual([]);
    expect(await h.signsInWith(NEW_PASSWORD)).toBe(true);
  });

  it("revokes through the store alone when no sessions service is configured", async () => {
    const h = harness({ atomicReset: true, withoutSessions: true });
    const user = await h.signUp();
    const token = await h.resetLink();

    expect(
      await h.service.resetPassword({ token, password: NEW_PASSWORD }),
    ).toStrictEqual({ userId: user.id });
    expect(h.calls).toStrictEqual(["resetCredential"]);
    expect(h.sessionsOf(user.id)).toStrictEqual([]);
    expect(h.completed()).toStrictEqual([
      { type: "password_reset.completed", userId: user.id, sessionsRevoked: 2 },
    ]);
  });
});

describe("email verification partial failures", () => {
  it("leaves the link unspent when marking the email verified fails", async () => {
    const h = harness();
    const user = await h.signUp();
    await h.service.requestEmailVerification({ userId: user.id, email: EMAIL });
    h.faults.add("markEmailVerified");

    await rejection(
      () => h.service.verifyEmail(h.verifications[0].token),
      Error,
      "markEmailVerified failed",
    );
    h.faults.delete("markEmailVerified");

    expect(h.verified.has(user.id)).toBe(false);
    expect(
      (await h.service.verifyEmail(h.verifications[0].token)).status,
    ).toStrictEqual("success");
  });

  it("keeps the email verified and the link redeemable when consuming the token fails", async () => {
    const h = harness();
    const user = await h.signUp();
    await h.service.requestEmailVerification({ userId: user.id, email: EMAIL });
    h.faults.add("consumeVerification");

    await rejection(
      () => h.service.verifyEmail(h.verifications[0].token),
      Error,
      "consumeVerification failed",
    );
    h.faults.delete("consumeVerification");

    expect(h.verified.has(user.id)).toBe(true);
    expect(
      h.events.some((event) => event.type === "email_verification.completed"),
    ).toBe(false);
    expect(await h.service.verifyEmail(h.verifications[0].token)).toStrictEqual(
      { status: "success", userId: user.id, email: EMAIL },
    );
  });
});

describe("passwordless sign-in partial failures", () => {
  it("signs the user in when the throttle reset fails after the code is spent", async () => {
    using consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    const h = harness();
    const user = await h.signUp();
    await h.service.requestSignInCode(EMAIL);
    h.faults.add("signInCodeThrottleReset");

    expect(
      await h.service.verifySignInCode({ email: EMAIL, code: h.codes[0].code }),
    ).toStrictEqual({ status: "success", userId: user.id });
    expect(consoleError.mock.calls.length).toStrictEqual(1);
  });

  it("leaves a spent sign-in link spent when the app fails to start the session", async () => {
    const h = harness();
    const user = await h.signUp();
    await h.service.requestSignInLink(EMAIL);
    const consumed = await h.service.consumeSignInLink(h.links[0].token);
    assert(consumed.status === "success");
    expect(consumed.userId).toStrictEqual(user.id);

    expect(
      await h.service.consumeSignInLink(h.links[0].token),
      "a session-start failure after success needs a fresh link",
    ).toStrictEqual({ status: "invalid" });
    await h.service.requestSignInLink(EMAIL);
    expect(await h.service.consumeSignInLink(h.links[1].token)).toStrictEqual({
      status: "success",
      userId: user.id,
    });
  });
});
