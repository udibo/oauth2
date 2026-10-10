import { assert, describe, expect, it, vi } from "vitest";
import { FakeTime } from "../_test_fake-time.ts";
import { delay } from "../utils/_delay.ts";
import { rejection } from "../_test_assert.ts";
import type { CodeDeliveryMessage, DeliveryMessage } from "./delivery.ts";
import type { IdentityEvent } from "./events.ts";
import { MemoryOtpStore } from "./otp.ts";
import {
  DEFAULT_PBKDF2_ITERATIONS,
  generateSalt,
  hashPassword,
  LEGACY_PBKDF2_ITERATIONS,
  type PasswordCredential,
  type PasswordHasherLike,
  PasswordIdentityService,
  PBKDF2_SHA256,
} from "./password.ts";
import {
  MemoryTokenFlowStore,
  TokenFlowService,
  type TokenFlowStore,
  TokenPurpose,
} from "./token-flow.ts";
import { AccountLockout, type AccountLockoutLike } from "./lockout.ts";
import { RateLimiter, type RateLimiterLike } from "./rate-limit.ts";
import { IdentityError } from "./errors.ts";
import {
  type IdentityRateLimiters,
  IdentityService,
  type IdentityServiceOptions,
  type IdentityUserStore,
} from "./service.ts";
import { type LegacyPasswordVerifier, pbkdf2Verifier } from "./migration.ts";

interface TestUser {
  id: string;
  email?: string;
  username?: string;
}

function serviceWithoutSignInFloor(
  options: IdentityServiceOptions<TestUser>,
): IdentityService<TestUser> {
  return new IdentityService<TestUser>({
    failedSignInFloorMs: 0,
    ...options,
  });
}

function makeStore() {
  const byId = new Map<string, TestUser>();
  const emailToId = new Map<string, string>();
  const usernameToId = new Map<string, string>();
  const creds = new Map<string, PasswordCredential>();
  const verified = new Set<string>();
  let seq = 0;

  const store: IdentityUserStore<TestUser> = {
    create(profile, credential) {
      const id = `u${++seq}`;
      const user: TestUser = {
        id,
        email: profile.email as string | undefined,
        username: profile.username as string | undefined,
      };
      byId.set(id, user);
      if (user.email) emailToId.set(user.email, id);
      if (user.username) usernameToId.set(user.username, id);
      creds.set(id, credential);
      return Promise.resolve(user);
    },
    findByIdentifier(identifier) {
      const id = emailToId.get(identifier) ?? usernameToId.get(identifier);
      return Promise.resolve(id ? byId.get(id) : undefined);
    },
    findByEmail(email) {
      const id = emailToId.get(email);
      return Promise.resolve(id ? byId.get(id) : undefined);
    },
    getCredential(userId) {
      return Promise.resolve(creds.get(userId));
    },
    setCredential(userId, credential) {
      creds.set(userId, credential);
      return Promise.resolve();
    },
    replaceCredential(userId, expected, credential) {
      if (creds.get(userId) !== expected) return Promise.resolve(false);
      creds.set(userId, credential);
      return Promise.resolve(true);
    },
    markEmailVerified(userId, email) {
      const user = byId.get(userId);
      if (!user) return Promise.resolve();
      if (email !== undefined && user.email !== email) {
        return Promise.resolve();
      }
      verified.add(userId);
      return Promise.resolve();
    },
  };

  function changeEmail(userId: string, email: string): void {
    const user = byId.get(userId)!;
    if (user.email) emailToId.delete(user.email);
    user.email = email;
    emailToId.set(email, userId);
  }

  return { store, verified, changeEmail };
}

function eventsOfType<T extends IdentityEvent["type"]>(
  events: IdentityEvent[],
  type: T,
): Extract<IdentityEvent, { type: T }>[] {
  return events.filter(
    (event): event is Extract<IdentityEvent, { type: T }> =>
      event.type === type,
  );
}

function lastEventOfType<T extends IdentityEvent["type"]>(
  events: IdentityEvent[],
  type: T,
): Extract<IdentityEvent, { type: T }> {
  const last = eventsOfType(events, type).at(-1);
  assert.exists(last, `expected a ${type} event`);
  return last;
}

function makeEventService(options?: {
  onEvent?: (event: IdentityEvent) => void | Promise<void>;
  limit?: number;
  ttl?: IdentityServiceOptions<TestUser>["ttl"];
  sessions?: IdentityServiceOptions<TestUser>["sessions"];
}) {
  const { store, verified } = makeStore();
  const events: IdentityEvent[] = [];
  const minted = {
    passwordReset: [] as string[],
    emailVerification: [] as string[],
    accountUnlock: [] as string[],
    signInLink: [] as string[],
  };
  const service = serviceWithoutSignInFloor({
    users: store,
    tokens: new TokenFlowService(new MemoryTokenFlowStore()),
    sessions: options?.sessions ?? {
      revokeAllByUser: () => Promise.resolve(1),
      revokeOthers: () => Promise.resolve(0),
    },
    ttl: options?.ttl,
    delivery: {
      sendPasswordReset: (msg) => {
        minted.passwordReset.push(msg.token);
      },
      sendEmailVerification: (msg) => {
        minted.emailVerification.push(msg.token);
      },
      sendAccountUnlock: (msg) => {
        minted.accountUnlock.push(msg.token);
      },
      sendSignInLink: (msg) => {
        minted.signInLink.push(msg.token);
      },
    },
    rateLimiter:
      options?.limit !== undefined
        ? new RateLimiter({ limit: options.limit, windowMs: 60_000 })
        : undefined,
    onEvent:
      options?.onEvent ??
      ((event) => {
        events.push(event);
      }),
  });
  return { service, events, verified, minted };
}

function makeService(extra?: { revoked?: string[] }) {
  const { store, verified, changeEmail } = makeStore();
  const sent: Array<{ hook: string; msg: DeliveryMessage }> = [];
  const revoked = extra?.revoked ?? [];
  const service = serviceWithoutSignInFloor({
    users: store,
    tokens: new TokenFlowService(new MemoryTokenFlowStore()),
    sessions: {
      revokeAllByUser(userId) {
        revoked.push(userId);
        return Promise.resolve(1);
      },
      revokeOthers() {
        return Promise.resolve(0);
      },
    },
    delivery: {
      sendPasswordReset: (msg) => {
        sent.push({ hook: "reset", msg });
      },
      sendEmailVerification: (msg) => {
        sent.push({ hook: "verify", msg });
      },
    },
    baseUrl: "https://app.example",
  });
  return { service, sent, verified, revoked, changeEmail };
}

describe("IdentityService", () => {
  it("signUp rejects a non-string password with no policy configured", async () => {
    const { service } = makeService();
    for (const password of [{}, { a: 1 }, 12345678901234, ["x"], true, null]) {
      const err = await rejection(
        () =>
          service.signUp({
            password: password as unknown as string,
            profile: { email: "a@b.co" },
          }),
        IdentityError,
        undefined,
        `${JSON.stringify(password)} must not reach the hash`,
      );
      expect((err as IdentityError).code).toStrictEqual("weak_password");
    }
  });

  it("resetPassword rejects a non-string password without burning the token", async () => {
    const { service, sent } = makeService();
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestPasswordReset("a@b.co");
    const token = sent[0].msg.token;

    const err = await rejection(
      () =>
        service.resetPassword({
          token,
          password: {} as unknown as string,
        }),
      IdentityError,
    );
    expect((err as IdentityError).code).toStrictEqual("weak_password");

    assert.exists(
      await service.resetPassword({ token, password: "goodpass1" }),
    );
    assert.exists(
      await service.signIn({ identifier: "a@b.co", password: "goodpass1" }),
    );
  });

  it("signUp applies the default password policy when none is configured", async () => {
    const { service } = makeService();
    for (const password of ["short", "a".repeat(257)]) {
      const err = await rejection(
        () => service.signUp({ password, profile: { email: "a@b.co" } }),
        IdentityError,
        undefined,
        `${password.length}-character password must not reach the hash`,
      );
      expect(err.code).toStrictEqual("weak_password");
    }
    assert.exists(
      await service.signUp({
        password: "a".repeat(256),
        profile: { email: "a@b.co" },
      }),
    );
  });

  it("resetPassword applies the default password policy without burning the token", async () => {
    const { service, sent } = makeService();
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestPasswordReset("a@b.co");
    const token = sent[0].msg.token;

    for (const password of ["short", "a".repeat(257)]) {
      const err = await rejection(
        () => service.resetPassword({ token, password }),
        IdentityError,
        undefined,
        `${password.length}-character password must not reach the hash`,
      );
      expect(err.code).toStrictEqual("weak_password");
    }

    assert.exists(
      await service.resetPassword({ token, password: "goodpass1" }),
    );
    assert.exists(
      await service.signIn({ identifier: "a@b.co", password: "goodpass1" }),
    );
  });

  it("signUp creates a user, signIn verifies credentials", async () => {
    const { service } = makeService();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co", username: "alice" },
    });
    assert.exists(user.id);

    expect(
      (
        await service.signIn({
          identifier: "a@b.co",
          password: "hunter2hunter2",
        })
      )?.id,
    ).toStrictEqual(user.id);
    expect(
      (
        await service.signIn({
          identifier: "alice",
          password: "hunter2hunter2",
        })
      )?.id,
    ).toStrictEqual(user.id);
    expect(
      await service.signIn({ identifier: "a@b.co", password: "nope" }),
    ).toStrictEqual(null);
    expect(
      await service.signIn({ identifier: "ghost", password: "hunter2hunter2" }),
    ).toStrictEqual(null);
  });

  it("signIn spends a hash even when the user has no stored credential", async () => {
    const passwords = new PasswordIdentityService();
    using hashSpy = vi.spyOn(passwords, "hash");
    const store: IdentityUserStore<TestUser> = {
      create() {
        throw new Error("unused");
      },
      findByIdentifier(identifier) {
        return Promise.resolve(
          identifier === "sso@b.co"
            ? { id: "u1", email: "sso@b.co" }
            : undefined,
        );
      },
      findByEmail() {
        return Promise.resolve(undefined);
      },
      getCredential() {
        return Promise.resolve(undefined);
      },
      setCredential() {
        return Promise.resolve();
      },
    };
    const service = serviceWithoutSignInFloor({ users: store, passwords });

    expect(
      await service.signIn({ identifier: "sso@b.co", password: "whatever12" }),
    ).toStrictEqual(null);
    expect(hashSpy.mock.calls.length).toStrictEqual(1);
  });

  it("password reset is enumeration-safe and rotates the credential + sessions", async () => {
    const { service, sent, revoked } = makeService();
    await service.signUp({
      password: "oldpassword1",
      profile: { email: "a@b.co", username: "alice" },
    });

    await service.requestPasswordReset("nobody@b.co");
    expect(sent.length).toStrictEqual(0);

    await service.requestPasswordReset("a@b.co");
    expect(sent.length).toStrictEqual(1);
    expect(sent[0].hook).toStrictEqual("reset");
    const { token, url } = sent[0].msg;
    expect(url).toStrictEqual(
      `https://app.example/reset-password?token=${token}`,
    );

    const result = await service.resetPassword({
      token,
      password: "newpassword1",
    });
    assert.exists(result);
    expect(revoked.length).toStrictEqual(1);
    expect(
      await service.signIn({ identifier: "a@b.co", password: "oldpassword1" }),
    ).toStrictEqual(null);
    expect(
      (
        await service.signIn({
          identifier: "a@b.co",
          password: "newpassword1",
        })
      )?.id,
    ).toStrictEqual(result!.userId);

    expect(
      await service.resetPassword({ token, password: "again12345" }),
    ).toStrictEqual(null);
  });

  it("email verification delivers a link and marks verified on consume", async () => {
    const { service, sent, verified } = makeService();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestEmailVerification({
      userId: user.id,
      email: "a@b.co",
    });
    expect(sent.length).toStrictEqual(1);
    expect(sent[0].hook).toStrictEqual("verify");
    const { token, url } = sent[0].msg;
    expect(url).toStrictEqual(
      `https://app.example/verify-email?token=${token}`,
    );

    const result = await service.verifyEmail(token);
    expect(result.status).toStrictEqual("success");
    if (result.status === "success") {
      expect(result.userId).toStrictEqual(user.id);
      expect(result.email).toStrictEqual("a@b.co");
    }
    expect(verified.has(user.id)).toStrictEqual(true);

    expect((await service.verifyEmail(token)).status).toStrictEqual("invalid");
    expect((await service.verifyEmail("garbage")).status).toStrictEqual(
      "invalid",
    );
  });

  it("verifyEmail passes the address the token was issued for, so a link cannot verify an address swapped in afterwards", async () => {
    const { service, sent, verified, changeEmail } = makeService();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "attacker@evil.example" },
    });
    await service.requestEmailVerification({
      userId: user.id,
      email: "attacker@evil.example",
    });
    const { token } = sent[0].msg;

    changeEmail(user.id, "victim@corp.example");
    const result = await service.verifyEmail(token);

    expect(result.status).toStrictEqual("success");
    expect(verified.has(user.id)).toStrictEqual(false);
  });

  it("verifyEmail reports an expired token distinctly", async () => {
    using time = new FakeTime();
    const { service, sent } = makeService();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestEmailVerification({
      userId: user.id,
      email: "a@b.co",
    });
    const { token } = sent[0].msg;

    await time.tickAsync(24 * 60 * 60 * 1000 + 1000);
    expect((await service.verifyEmail(token)).status).toStrictEqual("expired");
  });

  it("invalidates the minted token and stays uniform when delivery throws", async () => {
    const { store } = makeStore();
    const tokens = new TokenFlowService(new MemoryTokenFlowStore());
    let capturedToken = "";
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens,
      delivery: {
        sendPasswordReset: (msg) => {
          capturedToken = msg.token;
          throw new Error("mailer down");
        },
      },
    });
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.requestPasswordReset("a@b.co");
    assert(capturedToken.length > 0);

    expect(
      await service.resetPassword({
        token: capturedToken,
        password: "newpassword1",
      }),
    ).toStrictEqual(null);
  });

  it("reports invalidated: false and leaves the token live when cleanup fails too", async () => {
    const { store } = makeStore();
    const tokens = new TokenFlowService(new MemoryTokenFlowStore());
    const realConsume = tokens.consume.bind(tokens);
    let failNextConsume = true;
    tokens.consume = (purpose, token) => {
      if (failNextConsume) {
        failNextConsume = false;
        return Promise.reject(new Error("store down"));
      }
      return realConsume(purpose, token);
    };
    const events: IdentityEvent[] = [];
    let capturedToken = "";
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens,
      delivery: {
        sendPasswordReset: (msg) => {
          capturedToken = msg.token;
          throw new Error("mailer down");
        },
      },
      onEvent: (event) => {
        events.push(event);
      },
    });
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    expect(await service.requestPasswordReset("a@b.co")).toStrictEqual(
      undefined,
    );
    expect(lastEventOfType(events, "delivery.failed")).toStrictEqual({
      type: "delivery.failed",
      hook: "sendPasswordReset",
      invalidated: false,
      error: "mailer down",
    });
    assert.exists(
      await service.resetPassword({
        token: capturedToken,
        password: "newpassword1",
      }),
      "invalidated: false means exactly this — an undelivered token stays live",
    );
  });

  it("verifyEmail leaves the link usable when markEmailVerified throws", async () => {
    const { store } = makeStore();
    const tokens = new TokenFlowService(new MemoryTokenFlowStore());
    let failNext = true;
    const marked: string[] = [];
    store.markEmailVerified = (userId) => {
      if (failNext) {
        failNext = false;
        return Promise.reject(new Error("db write failed"));
      }
      marked.push(userId);
      return Promise.resolve();
    };
    let capturedToken = "";
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens,
      delivery: {
        sendEmailVerification: (msg) => {
          capturedToken = msg.token;
        },
      },
    });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestEmailVerification({
      userId: user.id,
      email: "a@b.co",
    });

    await rejection(
      () => service.verifyEmail(capturedToken),
      Error,
      "db write failed",
    );

    const result = await service.verifyEmail(capturedToken);
    expect(result.status).toStrictEqual("success");
    expect(marked).toStrictEqual([user.id]);
  });

  it("resetPassword reports failed and rethrows when session revocation throws", async () => {
    const { service, events, minted } = makeEventService({
      sessions: {
        revokeAllByUser: () => Promise.reject(new Error("session store down")),
        revokeOthers: () => Promise.resolve(0),
      },
    });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestPasswordReset("a@b.co");

    await rejection(
      () =>
        service.resetPassword({
          token: minted.passwordReset[0],
          password: "newpassword1",
        }),
      Error,
      "session store down",
    );

    expect(eventsOfType(events, "password_reset.completed")).toStrictEqual([]);
    expect(
      lastEventOfType(events, "password_reset.failed").reason,
    ).toStrictEqual("session_revocation_failed");

    expect(
      (await service.signIn({ identifier: "a@b.co", password: "newpassword1" }))
        ?.id,
    ).toStrictEqual(user.id);
  });

  it("resetPassword lets exactly one of two concurrent submissions of a link set the password", async () => {
    using time = new FakeTime();
    const { store } = makeStore();
    const events: IdentityEvent[] = [];
    let resetToken = "";
    let credentialWrites = 0;
    const service = serviceWithoutSignInFloor({
      users: {
        ...store,
        async setCredential(userId, credential) {
          if (credentialWrites++ === 0) await delay(200);
          await store.setCredential(userId, credential);
        },
      },
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      delivery: {
        sendPasswordReset: (msg) => {
          resetToken = msg.token;
        },
      },
      onEvent: (event) => {
        events.push(event);
      },
    });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestPasswordReset("a@b.co");
    const passwords = ["firstpassword1", "secondpassword2"];

    const pending = Promise.all(
      passwords.map((password) =>
        service.resetPassword({ token: resetToken, password }),
      ),
    );
    const results = await time.settle(pending);

    const winners = results.flatMap((result, i) => (result ? [i] : []));
    expect(winners.length).toStrictEqual(1);
    const [winner] = winners;
    expect(results[winner]).toStrictEqual({ userId: user.id });
    expect(credentialWrites).toStrictEqual(1);
    expect(
      (
        await service.signIn({
          identifier: "a@b.co",
          password: passwords[winner],
        })
      )?.id,
    ).toStrictEqual(user.id);
    expect(
      await service.signIn({
        identifier: "a@b.co",
        password: passwords[1 - winner],
      }),
    ).toStrictEqual(null);
    expect(
      eventsOfType(events, "password_reset.completed").length,
    ).toStrictEqual(1);
  });

  it("enforces the password policy on signUp and resetPassword", async () => {
    const { store } = makeStore();
    const tokens = new TokenFlowService(new MemoryTokenFlowStore());
    let resetToken = "";
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens,
      passwordPolicy: { minLength: 10 },
      delivery: {
        sendPasswordReset: (msg) => {
          resetToken = msg.token;
        },
      },
    });

    const signUpErr = await rejection(
      () => service.signUp({ password: "short", profile: { email: "a@b.co" } }),
      IdentityError,
    );
    expect((signUpErr as IdentityError).code).toStrictEqual("weak_password");

    const user = await service.signUp({
      password: "longenough1",
      profile: { email: "a@b.co" },
    });
    assert.exists(user.id);

    await service.requestPasswordReset("a@b.co");
    const resetErr = await rejection(
      () => service.resetPassword({ token: resetToken, password: "short" }),
      IdentityError,
    );
    expect((resetErr as IdentityError).code).toStrictEqual("weak_password");

    const result = await service.resetPassword({
      token: resetToken,
      password: "newlongpass1",
    });
    assert.exists(result);
  });

  it("throttles signIn per identifier (429 + retryAfterMs)", async () => {
    const { store } = makeStore();
    const service = serviceWithoutSignInFloor({
      users: store,
      rateLimiter: new RateLimiter({ limit: 3, windowMs: 60_000 }),
    });
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    for (let i = 0; i < 3; i++) {
      expect(
        await service.signIn({ identifier: "a@b.co", password: "wrong" }),
      ).toStrictEqual(null);
    }
    const err = await rejection(
      () => service.signIn({ identifier: "a@b.co", password: "wrong" }),
      IdentityError,
    );
    expect((err as IdentityError).code).toStrictEqual("rate_limited");
    expect(typeof (err as IdentityError).retryAfterMs).toStrictEqual("number");

    expect(
      await service.signIn({ identifier: "other@b.co", password: "x" }),
    ).toStrictEqual(null);
  });

  it("throttles an unknown identifier identically (no enumeration via 429)", async () => {
    const { store } = makeStore();
    const service = serviceWithoutSignInFloor({
      users: store,
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60_000 }),
    });
    expect(
      await service.signIn({ identifier: "ghost@b.co", password: "x" }),
    ).toStrictEqual(null);
    expect(
      await service.signIn({ identifier: "ghost@b.co", password: "x" }),
    ).toStrictEqual(null);
    const err = await rejection(
      () => service.signIn({ identifier: "ghost@b.co", password: "x" }),
      IdentityError,
    );
    expect((err as IdentityError).code).toStrictEqual("rate_limited");
  });

  it("resets the signIn throttle on a successful sign-in", async () => {
    const { store } = makeStore();
    const service = serviceWithoutSignInFloor({
      users: store,
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60_000 }),
    });
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    expect(
      await service.signIn({ identifier: "a@b.co", password: "wrong" }),
    ).toStrictEqual(null);
    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    expect(
      await service.signIn({ identifier: "a@b.co", password: "wrong" }),
    ).toStrictEqual(null);
    expect(
      await service.signIn({ identifier: "a@b.co", password: "wrong" }),
    ).toStrictEqual(null);
  });

  it("throttles requestPasswordReset per email, known and unknown alike", async () => {
    const { store } = makeStore();
    const sent: DeliveryMessage[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      delivery: {
        sendPasswordReset: (msg) => {
          sent.push(msg);
        },
      },
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60_000 }),
    });
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.requestPasswordReset("a@b.co");
    await service.requestPasswordReset("a@b.co");
    expect(sent.length).toStrictEqual(2);

    const err = await rejection(
      () => service.requestPasswordReset("a@b.co"),
      IdentityError,
    );
    expect((err as IdentityError).code).toStrictEqual("rate_limited");
    expect(typeof (err as IdentityError).retryAfterMs).toStrictEqual("number");
    expect(sent.length).toStrictEqual(2);

    await service.requestPasswordReset("ghost@b.co");
    await service.requestPasswordReset("ghost@b.co");
    const ghostErr = await rejection(
      () => service.requestPasswordReset("ghost@b.co"),
      IdentityError,
    );
    expect((ghostErr as IdentityError).code).toStrictEqual("rate_limited");
    expect(sent.length).toStrictEqual(2);
  });

  it("throttles requestEmailVerification per user", async () => {
    const { store } = makeStore();
    const sent: DeliveryMessage[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      delivery: {
        sendEmailVerification: (msg) => {
          sent.push(msg);
        },
      },
      rateLimiter: new RateLimiter({ limit: 1, windowMs: 60_000 }),
    });
    const alice = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    const bob = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "b@b.co" },
    });

    await service.requestEmailVerification({
      userId: alice.id,
      email: "a@b.co",
    });
    const err = await rejection(
      () =>
        service.requestEmailVerification({ userId: alice.id, email: "a@b.co" }),
      IdentityError,
    );
    expect((err as IdentityError).code).toStrictEqual("rate_limited");
    expect(sent.length).toStrictEqual(1);

    await service.requestEmailVerification({ userId: bob.id, email: "b@b.co" });
    expect(sent.length).toStrictEqual(2);
  });

  it("case-folds the requestPasswordReset throttle key so casing variants share one window", async () => {
    const { store } = makeStore();
    const sent: DeliveryMessage[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      delivery: {
        sendPasswordReset: (msg) => {
          sent.push(msg);
        },
      },
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60_000 }),
    });

    await service.requestPasswordReset("ghost@b.co");
    await service.requestPasswordReset("Ghost@B.Co");
    const err = await rejection(
      () => service.requestPasswordReset("GHOST@B.CO"),
      IdentityError,
    );
    expect((err as IdentityError).code).toStrictEqual("rate_limited");
    expect(sent.length).toStrictEqual(0);
  });

  it("throttles requestAccountUnlock per user", async () => {
    const { store } = makeStore();
    const sent: DeliveryMessage[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      delivery: {
        sendAccountUnlock: (msg) => {
          sent.push(msg);
        },
      },
      rateLimiter: new RateLimiter({ limit: 1, windowMs: 60_000 }),
    });
    const alice = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.requestAccountUnlock({ userId: alice.id, email: "a@b.co" });
    const err = await rejection(
      () => service.requestAccountUnlock({ userId: alice.id, email: "a@b.co" }),
      IdentityError,
    );
    expect((err as IdentityError).code).toStrictEqual("rate_limited");
    expect(sent.length).toStrictEqual(1);
  });

  it("log-only mode sends the email and never throws on the email-flow throttle", async () => {
    const { store } = makeStore();
    const sent: DeliveryMessage[] = [];
    const events: IdentityEvent[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      delivery: {
        sendPasswordReset: (msg) => {
          sent.push(msg);
        },
      },
      rateLimiter: new RateLimiter({ limit: 1, windowMs: 60_000 }),
      protectionMode: "log-only",
      onEvent: (event) => {
        events.push(event);
      },
    });
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.requestPasswordReset("a@b.co");
    await service.requestPasswordReset("a@b.co");
    expect(sent.length).toStrictEqual(2);

    const limited = lastEventOfType(events, "password_reset.rate_limited");
    expect(limited.email).toStrictEqual("a@b.co");
    expect(limited.enforced).toStrictEqual(false);
  });
});

describe("IdentityService events", () => {
  it("emits sign_up and sign_in.succeeded", async () => {
    const { service, events } = makeEventService();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.signIn({
      identifier: "a@b.co",
      password: "hunter2hunter2",
    });

    expect(lastEventOfType(events, "sign_up")).toStrictEqual({
      type: "sign_up",
      userId: user.id,
    });
    expect(lastEventOfType(events, "sign_in.succeeded")).toStrictEqual({
      type: "sign_in.succeeded",
      userId: user.id,
      identifier: "a@b.co",
    });
  });

  it("emits sign_in.failed with the failure reason", async () => {
    const { service, events } = makeEventService();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.signIn({ identifier: "ghost@b.co", password: "x" });
    await service.signIn({ identifier: "a@b.co", password: "wrong" });

    expect(eventsOfType(events, "sign_in.failed")).toStrictEqual([
      {
        type: "sign_in.failed",
        identifier: "ghost@b.co",
        reason: "unknown_identifier",
      },
      {
        type: "sign_in.failed",
        identifier: "a@b.co",
        reason: "wrong_password",
        userId: user.id,
      },
    ]);
  });

  it("emits sign_in.rate_limited before throwing", async () => {
    const { service, events } = makeEventService({ limit: 1 });
    await service.signIn({ identifier: "ghost@b.co", password: "x" });
    await rejection(
      () => service.signIn({ identifier: "ghost@b.co", password: "x" }),
      IdentityError,
    );

    const limited = lastEventOfType(events, "sign_in.rate_limited");
    expect(limited.identifier).toStrictEqual("ghost@b.co");
    expect(typeof limited.retryAfterMs).toStrictEqual("number");
  });

  it("emits a rate_limited event for each email flow before throwing", async () => {
    const { service, events } = makeEventService({ limit: 1 });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.requestPasswordReset("a@b.co");
    await rejection(
      () => service.requestPasswordReset("a@b.co"),
      IdentityError,
    );
    const resetLimited = lastEventOfType(events, "password_reset.rate_limited");
    expect(resetLimited.email).toStrictEqual("a@b.co");
    expect(resetLimited.enforced).toStrictEqual(true);
    expect(typeof resetLimited.retryAfterMs).toStrictEqual("number");

    await service.requestEmailVerification({
      userId: user.id,
      email: "a@b.co",
    });
    await rejection(
      () =>
        service.requestEmailVerification({ userId: user.id, email: "a@b.co" }),
      IdentityError,
    );
    const verifyLimited = lastEventOfType(
      events,
      "email_verification.rate_limited",
    );
    expect(verifyLimited.userId).toStrictEqual(user.id);
    expect(verifyLimited.enforced).toStrictEqual(true);

    await service.requestAccountUnlock({ userId: user.id, email: "a@b.co" });
    await rejection(
      () => service.requestAccountUnlock({ userId: user.id, email: "a@b.co" }),
      IdentityError,
    );
    const unlockLimited = lastEventOfType(
      events,
      "account_unlock.rate_limited",
    );
    expect(unlockLimited.userId).toStrictEqual(user.id);
    expect(unlockLimited.enforced).toStrictEqual(true);
    expect(typeof unlockLimited.retryAfterMs).toStrictEqual("number");
  });

  it("emits password_reset.requested with userId only for a known email", async () => {
    const { service, events } = makeEventService();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.requestPasswordReset("a@b.co");
    await service.requestPasswordReset("ghost@b.co");

    expect(eventsOfType(events, "password_reset.requested")).toStrictEqual([
      { type: "password_reset.requested", email: "a@b.co", userId: user.id },
      { type: "password_reset.requested", email: "ghost@b.co" },
    ]);
  });

  it("emits password_reset.completed on success and .failed on a bad token", async () => {
    const { service, events, minted } = makeEventService();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestPasswordReset("a@b.co");

    await service.resetPassword({ token: "garbage", password: "newpass123" });
    const result = await service.resetPassword({
      token: minted.passwordReset[0],
      password: "newpass123",
    });
    assert.exists(result);

    expect(lastEventOfType(events, "password_reset.failed")).toStrictEqual({
      type: "password_reset.failed",
      reason: "invalid_token",
    });
    expect(lastEventOfType(events, "password_reset.completed")).toStrictEqual({
      type: "password_reset.completed",
      userId: user.id,
    });
  });

  it("collapses an expired reset token to invalid_token", async () => {
    using time = new FakeTime();
    const { service, events, minted } = makeEventService();
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestPasswordReset("a@b.co");

    await time.tickAsync(60 * 60 * 1000 + 1000);
    expect(
      await service.resetPassword({
        token: minted.passwordReset[0],
        password: "newpass123",
      }),
    ).toStrictEqual(null);
    expect(lastEventOfType(events, "password_reset.failed")).toStrictEqual({
      type: "password_reset.failed",
      reason: "invalid_token",
    });
  });

  it("emits email_verification requested, completed, and invalid-failed", async () => {
    const { service, events, minted } = makeEventService();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestEmailVerification({
      userId: user.id,
      email: "a@b.co",
    });
    await service.verifyEmail("garbage");
    await service.verifyEmail(minted.emailVerification[0]);

    expect(
      lastEventOfType(events, "email_verification.requested"),
    ).toStrictEqual({
      type: "email_verification.requested",
      userId: user.id,
      email: "a@b.co",
    });
    expect(lastEventOfType(events, "email_verification.failed")).toStrictEqual({
      type: "email_verification.failed",
      reason: "invalid",
    });
    expect(
      lastEventOfType(events, "email_verification.completed"),
    ).toStrictEqual({
      type: "email_verification.completed",
      userId: user.id,
      email: "a@b.co",
    });
  });

  it("emits email_verification.failed with reason expired", async () => {
    using time = new FakeTime();
    const { service, events, minted } = makeEventService({
      ttl: { emailVerification: 1000 },
    });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.requestEmailVerification({
      userId: user.id,
      email: "a@b.co",
    });
    time.tick(2000);
    const result = await service.verifyEmail(minted.emailVerification[0]);

    expect(result.status).toStrictEqual("expired");
    expect(lastEventOfType(events, "email_verification.failed")).toStrictEqual({
      type: "email_verification.failed",
      reason: "expired",
    });
  });

  it("a throwing hook is swallowed and never breaks the flow", async () => {
    const errors: unknown[] = [];
    const original = console.error;
    console.error = (...args: unknown[]) => {
      errors.push(args);
    };
    try {
      const { service } = makeEventService({
        onEvent: () => Promise.reject(new Error("audit store down")),
      });
      const user = await service.signUp({
        password: "hunter2hunter2",
        profile: { email: "a@b.co" },
      });
      assert.exists(user.id);
      assert.exists(
        await service.signIn({
          identifier: "a@b.co",
          password: "hunter2hunter2",
        }),
      );
    } finally {
      console.error = original;
    }
    expect(errors.length).toStrictEqual(2);
  });

  it("flows behave identically with no hook configured", async () => {
    const { store } = makeStore();
    const service = serviceWithoutSignInFloor({ users: store });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    expect(user.email).toStrictEqual("a@b.co");
  });
});

describe("IdentityService lockout", () => {
  function makeLockoutService(options?: {
    protectionMode?: "enforce" | "log-only";
    delivery?: { sendAccountUnlock: (msg: DeliveryMessage) => void };
  }) {
    const { store } = makeStore();
    const events: IdentityEvent[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      lockout: new AccountLockout({ maxAttempts: 3, lockDurationMs: 60_000 }),
      protectionMode: options?.protectionMode,
      delivery: options?.delivery,
      baseUrl: "https://app.example",
      onEvent: (event) => {
        events.push(event);
      },
    });
    return { service, events };
  }

  async function signUpAlice(service: IdentityService<TestUser>) {
    return await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
  }

  it("locks after repeated failures and rejects even the correct password", async () => {
    const { service, events } = makeLockoutService();
    const user = await signUpAlice(service);

    for (let i = 0; i < 3; i++) {
      expect(
        await service.signIn({ identifier: "a@b.co", password: "wrong" }),
      ).toStrictEqual(null);
    }

    const lockEvent = lastEventOfType(events, "lockout");
    expect(lockEvent.userId).toStrictEqual(user.id);
    expect(lockEvent.failures).toStrictEqual(3);
    expect(lockEvent.enforced).toStrictEqual(true);

    expect(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    ).toStrictEqual(null);
    lastEventOfType(events, "sign_in.locked");
  });

  it("resets the failure count on a successful sign-in", async () => {
    const { service, events } = makeLockoutService();
    await signUpAlice(service);

    await service.signIn({ identifier: "a@b.co", password: "wrong" });
    await service.signIn({ identifier: "a@b.co", password: "wrong" });
    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    await service.signIn({ identifier: "a@b.co", password: "wrong" });
    await service.signIn({ identifier: "a@b.co", password: "wrong" });
    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    expect(eventsOfType(events, "lockout")).toStrictEqual([]);
  });

  it("log-only mode records lockout events but never blocks", async () => {
    const { service, events } = makeLockoutService({
      protectionMode: "log-only",
    });
    await signUpAlice(service);

    for (let i = 0; i < 4; i++) {
      await service.signIn({ identifier: "a@b.co", password: "wrong" });
    }

    expect(lastEventOfType(events, "lockout").enforced).toStrictEqual(false);
    expect(lastEventOfType(events, "sign_in.locked").enforced).toStrictEqual(
      false,
    );

    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
  });

  it("log-only mode emits rate_limited without throwing", async () => {
    const { store } = makeStore();
    const events: IdentityEvent[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      rateLimiter: new RateLimiter({ limit: 1, windowMs: 60_000 }),
      protectionMode: "log-only",
      onEvent: (event) => {
        events.push(event);
      },
    });
    await service.signIn({ identifier: "ghost@b.co", password: "x" });
    await service.signIn({ identifier: "ghost@b.co", password: "x" });

    expect(
      lastEventOfType(events, "sign_in.rate_limited").enforced,
    ).toStrictEqual(false);
  });

  it("unlockAccount clears the lock via the emailed single-use token", async () => {
    let unlockMessage: DeliveryMessage | undefined;
    const { service, events } = makeLockoutService({
      delivery: {
        sendAccountUnlock: (msg) => {
          unlockMessage = msg;
        },
      },
    });
    const user = await signUpAlice(service);

    for (let i = 0; i < 3; i++) {
      await service.signIn({ identifier: "a@b.co", password: "wrong" });
    }
    expect(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    ).toStrictEqual(null);

    await service.requestAccountUnlock({ userId: user.id, email: "a@b.co" });
    assert.exists(unlockMessage);
    expect(unlockMessage!.url).toStrictEqual(
      `https://app.example/unlock-account?token=${unlockMessage!.token}`,
    );
    lastEventOfType(events, "account_unlock.requested");

    const result = await service.unlockAccount(unlockMessage!.token);
    expect(result).toStrictEqual({ status: "success", userId: user.id });
    lastEventOfType(events, "account_unlock.completed");

    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );

    expect(
      (await service.unlockAccount(unlockMessage!.token)).status,
    ).toStrictEqual("invalid");
    expect((await service.unlockAccount("garbage")).status).toStrictEqual(
      "invalid",
    );
  });

  it("resetPassword clears an active lockout", async () => {
    const { store } = makeStore();
    let resetMessage: DeliveryMessage | undefined;
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      lockout: new AccountLockout({ maxAttempts: 3, lockDurationMs: 60_000 }),
      delivery: {
        sendPasswordReset: (msg) => {
          resetMessage = msg;
        },
      },
    });
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    for (let i = 0; i < 3; i++) {
      await service.signIn({ identifier: "a@b.co", password: "wrong" });
    }
    expect(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    ).toStrictEqual(null);

    await service.requestPasswordReset("a@b.co");
    assert.exists(resetMessage);
    assert.exists(
      await service.resetPassword({
        token: resetMessage!.token,
        password: "brand-new-pass-1",
      }),
    );

    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "brand-new-pass-1",
      }),
    );
  });

  it("resetSignInThrottle clears one identifier's rate window", async () => {
    const { store } = makeStore();
    const service = serviceWithoutSignInFloor({
      users: store,
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60_000 }),
    });
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    await service.signIn({ identifier: "a@b.co", password: "wrong" });
    await service.signIn({ identifier: "a@b.co", password: "wrong" });
    await rejection(
      () =>
        service.signIn({ identifier: "a@b.co", password: "hunter2hunter2" }),
      IdentityError,
    );

    await service.resetSignInThrottle("a@b.co");
    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
  });

  it("resetSignInThrottle clears the window an untrimmed identifier filled", async () => {
    const { store } = makeStore();
    const service = serviceWithoutSignInFloor({
      users: store,
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60_000 }),
    });
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.signIn({ identifier: " a@b.co ", password: "wrong" });
    await service.signIn({ identifier: "a@b.co", password: "wrong" });
    await rejection(
      () =>
        service.signIn({ identifier: "a@b.co ", password: "hunter2hunter2" }),
      IdentityError,
      undefined,
      "whitespace variants must share one sign-in window",
    );

    await service.resetSignInThrottle("  a@b.co  ");
    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
      "the reset must clear the very window sign-in filled",
    );
  });
});

function makeLegacyStore() {
  const byId = new Map<string, TestUser>();
  const emailToId = new Map<string, string>();
  const creds = new Map<string, PasswordCredential>();
  const legacy = new Map<string, string>();
  let seq = 0;

  const store: IdentityUserStore<TestUser> = {
    create(profile, credential) {
      const id = `u${++seq}`;
      const user: TestUser = { id, email: profile.email as string };
      byId.set(id, user);
      if (user.email) emailToId.set(user.email, id);
      creds.set(id, credential);
      return Promise.resolve(user);
    },
    findByIdentifier(identifier) {
      const id = emailToId.get(identifier);
      return Promise.resolve(id ? byId.get(id) : undefined);
    },
    findByEmail(email) {
      const id = emailToId.get(email);
      return Promise.resolve(id ? byId.get(id) : undefined);
    },
    getCredential(userId) {
      return Promise.resolve(creds.get(userId));
    },
    setCredential(userId, credential) {
      creds.set(userId, credential);
      return Promise.resolve();
    },
    replaceCredential(userId, expected, credential) {
      if (creds.get(userId) !== expected) return Promise.resolve(false);
      creds.set(userId, credential);
      return Promise.resolve(true);
    },
    getLegacyCredential(userId) {
      return Promise.resolve(legacy.get(userId) ?? null);
    },
    clearLegacyCredential(userId) {
      legacy.delete(userId);
      return Promise.resolve();
    },
  };

  function importUser(email: string, phc: string): string {
    const id = `u${++seq}`;
    byId.set(id, { id, email });
    emailToId.set(email, id);
    legacy.set(id, phc);
    return id;
  }

  return { store, creds, legacy, importUser };
}

function fakeHashVerifier(id: string, prefix: string) {
  let calls = 0;
  const verifier: LegacyPasswordVerifier = {
    id,
    canVerify: (phc) => phc.startsWith(`${prefix}$`),
    verify: (password, phc) => {
      calls++;
      return Promise.resolve(phc === `${prefix}$${password}`);
    },
  };
  return { verifier, calls: () => calls };
}

function trackReplaceCredential(store: IdentityUserStore<TestUser>) {
  const replaceCredential = store.replaceCredential!;
  const tracked = { calls: 0, wins: 0 };
  store.replaceCredential = async (userId, expected, credential) => {
    tracked.calls++;
    const replaced = await replaceCredential(userId, expected, credential);
    if (replaced) tracked.wins++;
    return replaced;
  };
  return tracked;
}

function countingLockout(failures: string[]): AccountLockoutLike {
  return {
    status: () => Promise.resolve({ locked: false, failures: 0 }),
    recordFailure: (userId) => {
      failures.push(userId);
      return Promise.resolve({ failures: 1, locked: false, justLocked: false });
    },
    reset: () => Promise.resolve(),
  };
}

describe("IdentityService password rehash on sign-in", () => {
  async function seedLegacyUser(store: IdentityUserStore<TestUser>) {
    const salt = generateSalt();
    const credential: PasswordCredential = {
      salt,
      hash: await hashPassword(
        "hunter2hunter2",
        salt,
        LEGACY_PBKDF2_ITERATIONS,
      ),
    };
    const user = await store.create({ email: "a@b.co" }, credential);
    return { user, credential };
  }

  it("verifies a credential stored without params against the original work factor", async () => {
    const { store } = makeLegacyStore();
    const { user } = await seedLegacyUser(store);
    const service = serviceWithoutSignInFloor({ users: store });

    const signedIn = await service.signIn({
      identifier: "a@b.co",
      password: "hunter2hunter2",
    });

    expect(signedIn?.id).toStrictEqual(user.id);
  });

  it("rehashes a credential weaker than the current configuration after it verifies", async () => {
    const { store, creds } = makeLegacyStore();
    const { user, credential } = await seedLegacyUser(store);
    const service = serviceWithoutSignInFloor({ users: store });

    await service.signIn({
      identifier: "a@b.co",
      password: "hunter2hunter2",
    });

    const stored = creds.get(user.id)!;
    expect(stored.params).toStrictEqual({
      algorithm: PBKDF2_SHA256,
      iterations: DEFAULT_PBKDF2_ITERATIONS,
    });
    assert(
      stored.hash !== credential.hash,
      "the stored hash must be replaced, not just re-labelled",
    );
  });

  it("still rejects the wrong password after a credential has been rehashed", async () => {
    const { store } = makeLegacyStore();
    await seedLegacyUser(store);
    const service = serviceWithoutSignInFloor({ users: store });

    await service.signIn({ identifier: "a@b.co", password: "hunter2hunter2" });

    expect(
      await service.signIn({
        identifier: "a@b.co",
        password: "wrong-password",
      }),
    ).toStrictEqual(null);
    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
  });

  it("leaves a credential already at the current work factor untouched", async () => {
    const { store } = makeLegacyStore();
    const passwords = new PasswordIdentityService();
    await store.create(
      { email: "a@b.co" },
      await passwords.hash("hunter2hunter2"),
    );
    const service = serviceWithoutSignInFloor({ users: store, passwords });
    using setCredential = vi.spyOn(store, "setCredential");

    await service.signIn({
      identifier: "a@b.co",
      password: "hunter2hunter2",
    });

    expect(setCredential.mock.calls.length).toStrictEqual(0);
  });

  it("rejects an unavailable credential read after losing a rehash comparison", async () => {
    const { store } = makeLegacyStore();
    await seedLegacyUser(store);
    store.replaceCredential = () => {
      store.getCredential = () =>
        Promise.reject(new Error("credential read unavailable"));
      return Promise.resolve(false);
    };
    const events: IdentityEvent[] = [];
    const failures: string[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      lockout: countingLockout(failures),
      onEvent: (event) => {
        events.push(event);
      },
    });
    await rejection(
      () =>
        service.signIn({
          identifier: "a@b.co",
          password: "hunter2hunter2",
        }),
      Error,
      "credential read unavailable",
    );
    expect(events).toStrictEqual([]);
    expect(failures).toStrictEqual([]);
  });

  it("signs the user in even when persisting the rehash fails", async () => {
    const { store } = makeLegacyStore();
    const { user } = await seedLegacyUser(store);
    store.replaceCredential = () => Promise.reject(new Error("db down"));
    const service = serviceWithoutSignInFloor({ users: store });
    using errorLog = vi.spyOn(console, "error").mockImplementation(() => {});

    const signedIn = await service.signIn({
      identifier: "a@b.co",
      password: "hunter2hunter2",
    });

    expect(signedIn?.id).toStrictEqual(user.id);
    expect(errorLog.mock.calls.length).toStrictEqual(1);
  });
  it("signs in both of two overlapping correct sign-ins when only one rehash can win the compare-and-set", async () => {
    const { store, creds } = makeLegacyStore();
    const { user } = await seedLegacyUser(store);
    const replace = trackReplaceCredential(store);
    const events: IdentityEvent[] = [];
    const failures: string[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      lockout: countingLockout(failures),
      onEvent: (event) => {
        events.push(event);
      },
    });

    const [first, second] = await Promise.all([
      service.signIn({ identifier: "a@b.co", password: "hunter2hunter2" }),
      service.signIn({ identifier: "a@b.co", password: "hunter2hunter2" }),
    ]);

    expect(replace.calls).toStrictEqual(2);
    expect(replace.wins, "exactly one rehash may win the race").toStrictEqual(
      1,
    );
    expect(
      [first?.id, second?.id],
      "the compare-and-set loser verified the same correct password",
    ).toStrictEqual([user.id, user.id]);
    expect(events.map((e) => e.type)).toStrictEqual([
      "sign_in.succeeded",
      "sign_in.succeeded",
    ]);
    expect(
      failures,
      "a lost rehash race is not a failed attempt",
    ).toStrictEqual([]);
    expect(creds.get(user.id)!.params?.iterations).toStrictEqual(
      DEFAULT_PBKDF2_ITERATIONS,
    );
  });

  it("still rejects the sign-in when the compare-and-set misses because the password changed after it verified", async () => {
    const { store, creds } = makeLegacyStore();
    const { user } = await seedLegacyUser(store);
    const changed = await new PasswordIdentityService().hash("changed-pw-1234");
    const replaceCredential = store.replaceCredential!;
    store.replaceCredential = (userId, expected, credential) => {
      creds.set(userId, changed);
      return replaceCredential(userId, expected, credential);
    };
    const events: IdentityEvent[] = [];
    const failures: string[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      lockout: countingLockout(failures),
      onEvent: (event) => {
        events.push(event);
      },
    });

    expect(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    ).toStrictEqual(null);

    expect(
      eventsOfType(events, "sign_in.failed").map((e) => e.reason),
    ).toStrictEqual(["wrong_password"]);
    expect(failures).toStrictEqual([user.id]);
    assert(creds.get(user.id) === changed, "the miss must not write");
    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "changed-pw-1234",
      }),
    );
  });

  it("rejects the sign-in when the compare-and-set misses and the credential is then absent", async () => {
    const { store, creds } = makeLegacyStore();
    const { user } = await seedLegacyUser(store);
    const replaceCredential = store.replaceCredential!;
    store.replaceCredential = (userId, expected, credential) => {
      creds.delete(userId);
      return replaceCredential(userId, expected, credential);
    };
    const events: IdentityEvent[] = [];
    const failures: string[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      lockout: countingLockout(failures),
      onEvent: (event) => {
        events.push(event);
      },
    });

    expect(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
      "an absent credential authenticates nobody",
    ).toStrictEqual(null);

    expect(
      eventsOfType(events, "sign_in.failed").map((e) => e.reason),
    ).toStrictEqual(["wrong_password"]);
    expect(eventsOfType(events, "sign_in.succeeded")).toStrictEqual([]);
    expect(failures).toStrictEqual([user.id]);
    expect(creds.has(user.id), "the miss must not write").toStrictEqual(false);
  });
});

describe("IdentityService upgrade-on-login", () => {
  it("verifies an imported hash via a BYO verifier, rehashes, and emits", async () => {
    const { store, creds, legacy, importUser } = makeLegacyStore();
    const userId = importUser("dev@b.co", "fakebcrypt$s3cret-pw");
    const bcrypt = fakeHashVerifier("bcrypt", "fakebcrypt");
    const events: IdentityEvent[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      legacyVerifiers: [bcrypt.verifier],
      onEvent: (event) => {
        events.push(event);
      },
    });

    const user = await service.signIn({
      identifier: "dev@b.co",
      password: "s3cret-pw",
    });
    expect(user?.id).toStrictEqual(userId);

    const upgraded = creds.get(userId);
    assert.exists(upgraded);
    expect(upgraded.hash.length).toStrictEqual(64);
    expect(upgraded.salt.length).toStrictEqual(32);
    expect(legacy.has(userId)).toStrictEqual(false);

    expect(bcrypt.calls()).toStrictEqual(1);
    expect(events.map((e) => e.type)).toStrictEqual([
      "password.upgraded",
      "sign_in.succeeded",
    ]);
    expect(
      lastEventOfType(events, "password.upgraded").verifierId,
    ).toStrictEqual("bcrypt");
  });

  it("resetPassword clears the imported hash so the old password can't resurrect it", async () => {
    const { store, legacy, importUser } = makeLegacyStore();
    const userId = importUser("reset@b.co", "fakebcrypt$old-pw");
    const bcrypt = fakeHashVerifier("bcrypt", "fakebcrypt");
    const sent: string[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      legacyVerifiers: [bcrypt.verifier],
      delivery: {
        sendPasswordReset: (message) => {
          sent.push(message.token);
        },
      },
    });

    await service.requestPasswordReset("reset@b.co");
    const result = await service.resetPassword({
      token: sent[0],
      password: "brand-new-pw-1",
    });
    assert.exists(result);
    expect(legacy.has(userId)).toStrictEqual(false);

    expect(
      await service.signIn({ identifier: "reset@b.co", password: "old-pw" }),
    ).toStrictEqual(null);
    assert.exists(
      await service.signIn({
        identifier: "reset@b.co",
        password: "brand-new-pw-1",
      }),
    );
  });

  it("rejects an unavailable credential read after losing an imported upgrade comparison", async () => {
    const { store, importUser } = makeLegacyStore();
    importUser("dev@b.co", "fakebcrypt$s3cret-pw");
    store.replaceCredential = () => {
      store.getCredential = () =>
        Promise.reject(new Error("credential read unavailable"));
      return Promise.resolve(false);
    };
    const bcrypt = fakeHashVerifier("bcrypt", "fakebcrypt");
    const events: IdentityEvent[] = [];
    const failures: string[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      legacyVerifiers: [bcrypt.verifier],
      lockout: countingLockout(failures),
      onEvent: (event) => {
        events.push(event);
      },
    });
    await rejection(
      () =>
        service.signIn({
          identifier: "dev@b.co",
          password: "s3cret-pw",
        }),
      Error,
      "credential read unavailable",
    );
    expect(events).toStrictEqual([]);
    expect(failures).toStrictEqual([]);
  });

  it("signs in but does not emit password.upgraded when the upgrade persist fails", async () => {
    const { store, importUser } = makeLegacyStore();
    const userId = importUser("dev@b.co", "fakebcrypt$s3cret-pw");
    store.replaceCredential = () => Promise.reject(new Error("db down"));
    const bcrypt = fakeHashVerifier("bcrypt", "fakebcrypt");
    const events: IdentityEvent[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      legacyVerifiers: [bcrypt.verifier],
      onEvent: (event) => {
        events.push(event);
      },
    });

    const user = await service.signIn({
      identifier: "dev@b.co",
      password: "s3cret-pw",
    });
    expect(user?.id).toStrictEqual(userId);
    expect(events.map((e) => e.type)).toStrictEqual(["sign_in.succeeded"]);
  });

  it("signs in both of two overlapping correct sign-ins on an imported hash and upgrades it once", async () => {
    const { store, creds, legacy, importUser } = makeLegacyStore();
    const userId = importUser("dev@b.co", "fakebcrypt$s3cret-pw");
    const bcrypt = fakeHashVerifier("bcrypt", "fakebcrypt");
    const replace = trackReplaceCredential(store);
    const events: IdentityEvent[] = [];
    const failures: string[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      legacyVerifiers: [bcrypt.verifier],
      lockout: countingLockout(failures),
      onEvent: (event) => {
        events.push(event);
      },
    });

    const [first, second] = await Promise.all([
      service.signIn({ identifier: "dev@b.co", password: "s3cret-pw" }),
      service.signIn({ identifier: "dev@b.co", password: "s3cret-pw" }),
    ]);

    expect(replace.calls).toStrictEqual(2);
    expect(replace.wins, "exactly one upgrade may win the race").toStrictEqual(
      1,
    );
    expect(
      [first?.id, second?.id],
      "the compare-and-set loser verified the same correct password",
    ).toStrictEqual([userId, userId]);
    expect(eventsOfType(events, "password.upgraded").length).toStrictEqual(1);
    expect(eventsOfType(events, "sign_in.succeeded").length).toStrictEqual(2);
    expect(eventsOfType(events, "sign_in.failed")).toStrictEqual([]);
    expect(
      failures,
      "a lost upgrade race is not a failed attempt",
    ).toStrictEqual([]);
    assert.exists(creds.get(userId));
    expect(legacy.has(userId)).toStrictEqual(false);
  });

  it("still rejects the imported-hash sign-in when the compare-and-set misses because a different password was set", async () => {
    const { store, creds, legacy, importUser } = makeLegacyStore();
    const userId = importUser("dev@b.co", "fakebcrypt$s3cret-pw");
    const bcrypt = fakeHashVerifier("bcrypt", "fakebcrypt");
    const changed = await new PasswordIdentityService().hash("changed-pw-1234");
    const replaceCredential = store.replaceCredential!;
    store.replaceCredential = (id, expected, credential) => {
      creds.set(id, changed);
      return replaceCredential(id, expected, credential);
    };
    const events: IdentityEvent[] = [];
    const failures: string[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      legacyVerifiers: [bcrypt.verifier],
      lockout: countingLockout(failures),
      onEvent: (event) => {
        events.push(event);
      },
    });

    expect(
      await service.signIn({ identifier: "dev@b.co", password: "s3cret-pw" }),
    ).toStrictEqual(null);

    expect(
      events.map((e) => e.type),
      "a miss that fails re-verification upgrades nothing",
    ).toStrictEqual(["sign_in.failed"]);
    expect(
      eventsOfType(events, "sign_in.failed").map((e) => e.reason),
    ).toStrictEqual(["wrong_password"]);
    expect(failures).toStrictEqual([userId]);
    assert(creds.get(userId) === changed, "the miss must not write");
    expect(legacy.get(userId)).toStrictEqual("fakebcrypt$s3cret-pw");
  });

  it("resetPassword still revokes sessions and completes when clearLegacyCredential throws", async () => {
    const { store, importUser } = makeLegacyStore();
    const userId = importUser("reset@b.co", "fakebcrypt$old-pw");
    store.clearLegacyCredential = () => Promise.reject(new Error("hook broke"));
    const revoked: string[] = [];
    const sent: string[] = [];
    const events: IdentityEvent[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      sessions: {
        revokeAllByUser(id) {
          revoked.push(id);
          return Promise.resolve(1);
        },
        revokeOthers() {
          return Promise.resolve(0);
        },
      },
      delivery: {
        sendPasswordReset: (message) => {
          sent.push(message.token);
        },
      },
      onEvent: (event) => {
        events.push(event);
      },
    });

    await service.requestPasswordReset("reset@b.co");
    const result = await service.resetPassword({
      token: sent[0],
      password: "brand-new-pw-1",
    });
    expect(result).toStrictEqual({ userId });
    expect(revoked).toStrictEqual([userId]);
    lastEventOfType(events, "password_reset.completed");
  });

  it("uses the native path on the next sign-in — the verifier isn't called again", async () => {
    const { store, importUser } = makeLegacyStore();
    importUser("dev@b.co", "fakebcrypt$s3cret-pw");
    const bcrypt = fakeHashVerifier("bcrypt", "fakebcrypt");
    const service = serviceWithoutSignInFloor({
      users: store,
      legacyVerifiers: [bcrypt.verifier],
    });

    assert.exists(
      await service.signIn({ identifier: "dev@b.co", password: "s3cret-pw" }),
    );
    expect(bcrypt.calls()).toStrictEqual(1);

    assert.exists(
      await service.signIn({ identifier: "dev@b.co", password: "s3cret-pw" }),
    );
    expect(bcrypt.calls()).toStrictEqual(1);
  });

  it("never consults a stale legacy hash once a native credential exists (no downgrade)", async () => {
    const { store, legacy } = makeLegacyStore();
    const bcrypt = fakeHashVerifier("bcrypt", "fakebcrypt");
    const service = serviceWithoutSignInFloor({
      users: store,
      legacyVerifiers: [bcrypt.verifier],
    });

    const user = await service.signUp({
      password: "current-native-pw",
      profile: { email: "dev@b.co" },
    });
    // A stale legacy hash for a DIFFERENT (old) password lingers on the row.
    legacy.set(user.id, "fakebcrypt$old-legacy-pw");

    expect(
      await service.signIn({
        identifier: "dev@b.co",
        password: "old-legacy-pw",
      }),
      "the old imported password must not resurrect via the legacy path",
    ).toStrictEqual(null);
    expect(
      bcrypt.calls(),
      "the legacy verifier is never consulted when a native credential exists",
    ).toStrictEqual(0);
    assert.exists(
      await service.signIn({
        identifier: "dev@b.co",
        password: "current-native-pw",
      }),
    );
  });

  it("wrong password does not upgrade and fails uniformly", async () => {
    const { store, creds, legacy, importUser } = makeLegacyStore();
    const userId = importUser("dev@b.co", "fakebcrypt$s3cret-pw");
    const bcrypt = fakeHashVerifier("bcrypt", "fakebcrypt");
    const events: IdentityEvent[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      legacyVerifiers: [bcrypt.verifier],
      onEvent: (event) => {
        events.push(event);
      },
    });

    expect(
      await service.signIn({ identifier: "dev@b.co", password: "wrong" }),
    ).toStrictEqual(null);
    expect(creds.has(userId)).toStrictEqual(false);
    expect(legacy.get(userId)).toStrictEqual("fakebcrypt$s3cret-pw");
    expect(events.map((e) => e.type)).toStrictEqual(["sign_in.failed"]);
  });

  it("selects the verifier whose canVerify matches; none matching fails", async () => {
    const { store, creds, importUser } = makeLegacyStore();
    const bcryptId = importUser("b@b.co", "fakebcrypt$pw-one");
    const argonId = importUser("a@b.co", "fakeargon$pw-two");
    const orphanId = importUser("o@b.co", "unknownfmt$pw-three");
    const bcrypt = fakeHashVerifier("bcrypt", "fakebcrypt");
    const argon = fakeHashVerifier("argon2", "fakeargon");
    const service = serviceWithoutSignInFloor({
      users: store,
      legacyVerifiers: [bcrypt.verifier, argon.verifier],
    });

    assert.exists(
      await service.signIn({ identifier: "b@b.co", password: "pw-one" }),
    );
    assert.exists(
      await service.signIn({ identifier: "a@b.co", password: "pw-two" }),
    );
    expect(bcrypt.calls()).toStrictEqual(1);
    expect(argon.calls()).toStrictEqual(1);
    assert.exists(creds.get(bcryptId));
    assert.exists(creds.get(argonId));

    expect(
      await service.signIn({ identifier: "o@b.co", password: "pw-three" }),
    ).toStrictEqual(null);
    expect(creds.has(orphanId)).toStrictEqual(false);
  });

  it("verifies and upgrades a built-in PBKDF2 (Django) imported hash", async () => {
    const { store, creds, legacy, importUser } = makeLegacyStore();
    const userId = importUser(
      "dj@b.co",
      "pbkdf2_sha256$100000$saltysaltZ12$EQSwFOiYCoPexswCmQxKexbKLdLHxTCke89Wx+gNvTs=",
    );
    const service = serviceWithoutSignInFloor({
      users: store,
      legacyVerifiers: [pbkdf2Verifier()],
    });

    assert.exists(
      await service.signIn({
        identifier: "dj@b.co",
        password: "correct horse battery staple",
      }),
    );
    assert.exists(creds.get(userId));
    expect(legacy.has(userId)).toStrictEqual(false);
  });

  it("without legacyVerifiers, an imported-only user has no usable password", async () => {
    const { store, importUser } = makeLegacyStore();
    importUser("dev@b.co", "fakebcrypt$s3cret-pw");
    const service = serviceWithoutSignInFloor({ users: store });

    expect(
      await service.signIn({ identifier: "dev@b.co", password: "s3cret-pw" }),
    ).toStrictEqual(null);
  });
});

const DEFAULT_FLOOR_MS = 250;
const FLOOR_MS = 150;
const NATIVE_KDF_MS = 6;
const LEGACY_KDF_MS = 120;
const RATIO_BRANCHES = [
  "unknown identifier",
  "wrong native password",
  "wrong imported password",
];

function costedHasher(costMs: number): PasswordHasherLike {
  return {
    async hash(password) {
      await delay(costMs);
      return { hash: `costed:${password}`, salt: "salt" };
    },
    async verify(password, credential) {
      await delay(costMs);
      return credential.hash === `costed:${password}`;
    },
  };
}

function lockoutHolding(locked: { userId: string }): AccountLockoutLike {
  return {
    status: (userId) =>
      Promise.resolve(
        userId === locked.userId
          ? { locked: true, failures: 3, lockedUntil: Date.now() + 60_000 }
          : { locked: false, failures: 0 },
      ),
    recordFailure: () =>
      Promise.resolve({ failures: 1, locked: false, justLocked: false }),
    reset: () => Promise.resolve(),
  };
}

function costedVerifier(costMs: number): LegacyPasswordVerifier {
  return {
    id: "costed-legacy",
    canVerify: (phc) => phc.startsWith("costed-legacy$"),
    async verify(password, phc) {
      await delay(costMs);
      return phc === `costed-legacy$${password}`;
    },
  };
}

async function elapsedMs(
  time: FakeTime,
  run: () => Promise<unknown>,
): Promise<number> {
  const startedAt = performance.now();
  await time.settle(run());
  return performance.now() - startedAt;
}

describe("IdentityService failed sign-in timing", () => {
  function makeTimingService(
    options?: Partial<IdentityServiceOptions<TestUser>>,
  ) {
    const legacyStore = makeLegacyStore();
    const locked = { userId: "" };
    const service = new IdentityService<TestUser>({
      users: legacyStore.store,
      passwords: costedHasher(NATIVE_KDF_MS),
      legacyVerifiers: [costedVerifier(LEGACY_KDF_MS)],
      failedSignInFloorMs: FLOOR_MS,
      lockout: lockoutHolding(locked),
      ...options,
    });
    return { ...legacyStore, service, locked };
  }

  async function seedBranches() {
    const { store, creds, importUser, service, locked } = makeTimingService();
    await store.create(
      { email: "native@b.co" },
      { hash: "costed:right-password", salt: "salt" },
    );
    importUser("imported@b.co", "costed-legacy$right-password");
    importUser("unreadable@b.co", "no-verifier-claims-this");
    const passwordless = await store.create(
      { email: "none@b.co" },
      {
        hash: "x",
        salt: "x",
      },
    );
    creds.delete(passwordless.id);
    const lockedOut = await store.create(
      { email: "locked@b.co" },
      { hash: "costed:right-password", salt: "salt" },
    );
    locked.userId = lockedOut.id;
    return {
      service,
      branches: {
        "unknown identifier": "ghost@b.co",
        "wrong native password": "native@b.co",
        "wrong imported password": "imported@b.co",
        "imported hash no verifier claims": "unreadable@b.co",
        "account with no password at all": "none@b.co",
        "locked account": "locked@b.co",
      } as Record<string, string>,
    };
  }

  it("holds every rejected branch to the floor, measured from entry", async () => {
    using time = new FakeTime(undefined, { performance: true });
    const { service, branches } = await seedBranches();

    for (const [branch, identifier] of Object.entries(branches)) {
      const took = await elapsedMs(time, async () =>
        expect(
          await service.signIn({ identifier, password: "wrong-password" }),
        ).toStrictEqual(null),
      );
      expect(took, `${branch} returned off the ${FLOOR_MS}ms floor`).toBe(
        FLOOR_MS,
      );
    }
  });

  it("costs the same whether the account is unknown, native, or still on an imported hash", async () => {
    using time = new FakeTime(undefined, { performance: true });
    const { service, branches } = await seedBranches();
    const timings = new Map<string, number>();

    for (const branch of RATIO_BRANCHES) {
      timings.set(
        branch,
        await elapsedMs(time, () =>
          service.signIn({
            identifier: branches[branch],
            password: "wrong-password",
          }),
        ),
      );
    }

    expect(
      Object.fromEntries(timings),
      "every branch that fits inside the floor lands exactly on it, so any difference is a branch becoming visible",
    ).toStrictEqual(
      Object.fromEntries(RATIO_BRANCHES.map((branch) => [branch, FLOOR_MS])),
    );
  });

  it("floors a rejection at 250ms with no option set", async () => {
    using time = new FakeTime(undefined, { performance: true });
    const { store } = makeLegacyStore();
    const service = new IdentityService<TestUser>({
      users: store,
      passwords: costedHasher(NATIVE_KDF_MS),
    });

    const took = await elapsedMs(time, () =>
      service.signIn({ identifier: "ghost@b.co", password: "wrong-password" }),
    );

    expect(took).toBe(DEFAULT_FLOOR_MS);
  });

  it("falls back to the default floor when the option is out of range", async () => {
    using time = new FakeTime(undefined, { performance: true });
    const { store } = makeLegacyStore();
    const service = new IdentityService<TestUser>({
      users: store,
      passwords: costedHasher(NATIVE_KDF_MS),
      failedSignInFloorMs: -1,
    });

    const took = await elapsedMs(time, () =>
      service.signIn({ identifier: "ghost@b.co", password: "wrong-password" }),
    );

    expect(took, "a negative floor must not turn padding off").toBe(
      DEFAULT_FLOOR_MS,
    );
  });

  it("does not delay a successful sign-in", async () => {
    using time = new FakeTime(undefined, { performance: true });
    const { store, service } = makeTimingService({
      failedSignInFloorMs: 5_000,
    });
    await store.create(
      { email: "native@b.co" },
      { hash: "costed:right-password", salt: "salt" },
    );

    const took = await elapsedMs(time, async () =>
      assert.exists(
        await service.signIn({
          identifier: "native@b.co",
          password: "right-password",
        }),
      ),
    );

    expect(took).toBeLessThan(5_000);
  });

  it("returns as soon as the work is done when the floor is disabled", async () => {
    using time = new FakeTime(undefined, { performance: true });
    const { store, service } = makeTimingService({ failedSignInFloorMs: 0 });
    await store.create(
      { email: "native@b.co" },
      { hash: "costed:right-password", salt: "salt" },
    );

    const took = await elapsedMs(time, () =>
      service.signIn({ identifier: "native@b.co", password: "wrong-password" }),
    );

    expect(took).toBe(NATIVE_KDF_MS);
  });
});

describe("IdentityService passwordless", () => {
  function makePasswordlessService(options?: {
    limit?: number;
    protectionMode?: "enforce" | "log-only";
    ttl?: IdentityServiceOptions<TestUser>["ttl"];
    otp?: {
      digits?: number;
      ttlMs?: number;
      maxAttempts?: number;
    };
  }) {
    const { store } = makeStore();
    const events: IdentityEvent[] = [];
    const links: DeliveryMessage[] = [];
    const codes: CodeDeliveryMessage[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      ttl: options?.ttl,
      otp: { store: new MemoryOtpStore(), ...options?.otp },
      delivery: {
        sendSignInLink: (msg) => {
          links.push(msg);
        },
        sendSignInCode: (msg) => {
          codes.push(msg);
        },
      },
      baseUrl: "https://app.example",
      rateLimiter:
        options?.limit !== undefined
          ? new RateLimiter({ limit: options.limit, windowMs: 60_000 })
          : undefined,
      protectionMode: options?.protectionMode,
      onEvent: (event) => {
        events.push(event);
      },
    });
    const signUp = () =>
      service.signUp({
        password: "hunter2hunter2",
        profile: { email: "a@b.co" },
      });
    return { service, events, links, codes, signUp };
  }

  it("requestSignInLink delivers a single-use link that consumeSignInLink redeems once", async () => {
    const { service, links, signUp } = makePasswordlessService();
    const user = await signUp();

    await service.requestSignInLink("a@b.co");
    expect(links.length).toStrictEqual(1);
    expect(links[0].to).toStrictEqual("a@b.co");
    expect(links[0].subject).toStrictEqual(user.id);
    expect(links[0].url).toStrictEqual(
      `https://app.example/signin-link?token=${links[0].token}`,
    );

    expect(await service.consumeSignInLink(links[0].token)).toStrictEqual({
      status: "success",
      userId: user.id,
    });
    expect(await service.consumeSignInLink(links[0].token)).toStrictEqual({
      status: "invalid",
    });
  });

  it("requestSignInLink for an unknown email resolves identically but sends nothing", async () => {
    const { service, links, events, signUp } = makePasswordlessService();
    const user = await signUp();

    expect(await service.requestSignInLink("ghost@b.co")).toStrictEqual(
      undefined,
    );
    expect(await service.requestSignInLink("a@b.co")).toStrictEqual(undefined);
    expect(links.length).toStrictEqual(1);

    expect(eventsOfType(events, "signin_link.requested")).toStrictEqual([
      { type: "signin_link.requested", email: "ghost@b.co" },
      { type: "signin_link.requested", email: "a@b.co", userId: user.id },
    ]);
  });

  it("consumeSignInLink distinguishes expired from invalid", async () => {
    using time = new FakeTime();
    const { service, links, events, signUp } = makePasswordlessService();
    await signUp();

    expect(await service.consumeSignInLink("garbage")).toStrictEqual({
      status: "invalid",
    });

    await service.requestSignInLink("a@b.co");
    time.tick(15 * 60 * 1000 + 1);
    expect(await service.consumeSignInLink(links[0].token)).toStrictEqual({
      status: "expired",
    });

    expect(eventsOfType(events, "signin_link.failed")).toStrictEqual([
      { type: "signin_link.failed", reason: "invalid" },
      { type: "signin_link.failed", reason: "expired" },
    ]);
  });

  it("requestSignInLink honors a custom ttlMs", async () => {
    using time = new FakeTime();
    const { service, links, signUp } = makePasswordlessService();
    const user = await signUp();

    await service.requestSignInLink("a@b.co", { ttlMs: 60_000 });
    expect(links[0].expiresAt).toStrictEqual(time.now + 60_000);
    time.tick(59_999);
    expect(await service.consumeSignInLink(links[0].token)).toStrictEqual({
      status: "success",
      userId: user.id,
    });
  });

  it("takes the sign-in link lifetime from ttl.signInLink; a per-call ttlMs still wins", async () => {
    using time = new FakeTime();
    const { service, links, signUp } = makePasswordlessService({
      ttl: { signInLink: 60_000 },
    });
    await signUp();

    await service.requestSignInLink("a@b.co");
    expect(links[0].expiresAt).toStrictEqual(time.now + 60_000);

    await service.requestSignInLink("a@b.co", { ttlMs: 5_000 });
    expect(links[1].expiresAt).toStrictEqual(time.now + 5_000);

    time.tick(5_001);
    expect(await service.consumeSignInLink(links[1].token)).toStrictEqual({
      status: "expired",
    });
  });

  it("re-requesting a sign-in link invalidates the outstanding one", async () => {
    const { service, links, signUp } = makePasswordlessService();
    const user = await signUp();

    await service.requestSignInLink("a@b.co");
    await service.requestSignInLink("a@b.co");
    expect(await service.consumeSignInLink(links[0].token)).toStrictEqual({
      status: "invalid",
    });
    expect(await service.consumeSignInLink(links[1].token)).toStrictEqual({
      status: "success",
      userId: user.id,
    });
  });

  it("throttles sign-in link requests per email, unknown emails identically", async () => {
    const { service, links, events, signUp } = makePasswordlessService({
      limit: 2,
    });
    await signUp();

    await service.requestSignInLink("a@b.co");
    await service.requestSignInLink("a@b.co");
    const err = await rejection(
      () => service.requestSignInLink("a@b.co"),
      IdentityError,
    );
    expect(err.code).toStrictEqual("rate_limited");
    expect(typeof err.retryAfterMs).toStrictEqual("number");
    expect(links.length).toStrictEqual(2);
    lastEventOfType(events, "signin_link.rate_limited");

    await service.requestSignInLink("ghost@b.co");
    await service.requestSignInLink("ghost@b.co");
    await rejection(
      () => service.requestSignInLink("ghost@b.co"),
      IdentityError,
    );
  });

  it("case-folds the per-email throttle so casing variants share one window", async () => {
    const { service, signUp } = makePasswordlessService({ limit: 2 });
    await signUp();

    await service.requestSignInLink("a@b.co");
    await service.requestSignInLink("A@B.co");
    const err = await rejection(
      () => service.requestSignInLink("a@B.CO"),
      IdentityError,
    );
    expect(
      err.code,
      "casing variants must not each get a fresh rate bucket",
    ).toStrictEqual("rate_limited");
  });

  it("log-only mode emits signin_link.rate_limited without blocking", async () => {
    const { service, links, events, signUp } = makePasswordlessService({
      limit: 1,
      protectionMode: "log-only",
    });
    await signUp();

    await service.requestSignInLink("a@b.co");
    await service.requestSignInLink("a@b.co");
    expect(links.length).toStrictEqual(2);
    const limited = lastEventOfType(events, "signin_link.rate_limited");
    expect(limited.email).toStrictEqual("a@b.co");
    expect(limited.enforced).toStrictEqual(false);
  });

  it("requestSignInCode delivers a code that verifySignInCode redeems once", async () => {
    const { service, codes, events, signUp } = makePasswordlessService();
    const user = await signUp();

    await service.requestSignInCode("a@b.co");
    expect(codes.length).toStrictEqual(1);
    expect(codes[0].to).toStrictEqual("a@b.co");
    expect(codes[0].subject).toStrictEqual(user.id);

    expect(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[0].code,
      }),
    ).toStrictEqual({ status: "success", userId: user.id });
    expect(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[0].code,
      }),
    ).toStrictEqual({ status: "invalid" });

    expect(lastEventOfType(events, "signin_code.requested")).toStrictEqual({
      type: "signin_code.requested",
      email: "a@b.co",
      userId: user.id,
    });
    expect(lastEventOfType(events, "signin_code.verified")).toStrictEqual({
      type: "signin_code.verified",
      userId: user.id,
    });
    expect(lastEventOfType(events, "signin_code.failed")).toStrictEqual({
      type: "signin_code.failed",
      email: "a@b.co",
      reason: "invalid",
    });
  });

  it("invalidates the minted code and stays uniform when code delivery throws", async () => {
    const { store } = makeStore();
    const events: IdentityEvent[] = [];
    let capturedCode = "";
    const service = serviceWithoutSignInFloor({
      users: store,
      otp: { store: new MemoryOtpStore() },
      delivery: {
        sendSignInCode: (msg) => {
          capturedCode = msg.code;
          throw new Error("mailer down");
        },
      },
      onEvent: (event) => {
        events.push(event);
      },
    });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    expect(await service.requestSignInCode("a@b.co")).toStrictEqual(undefined);
    assert(capturedCode.length > 0);

    expect(
      await service.verifySignInCode({ email: "a@b.co", code: capturedCode }),
    ).toStrictEqual({ status: "invalid" });
    expect(lastEventOfType(events, "delivery.failed")).toStrictEqual({
      type: "delivery.failed",
      hook: "sendSignInCode",
      invalidated: true,
      error: "mailer down",
    });
    expect(lastEventOfType(events, "signin_code.requested")).toStrictEqual({
      type: "signin_code.requested",
      email: "a@b.co",
      userId: user.id,
    });
  });

  it("resolves the same for a known and an unknown email when the mailer throws", async () => {
    const { store } = makeStore();
    const service = serviceWithoutSignInFloor({
      users: store,
      otp: { store: new MemoryOtpStore() },
      delivery: {
        sendSignInCode: () => {
          throw new Error("mailer down");
        },
      },
    });
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    expect(await service.requestSignInCode("a@b.co")).toStrictEqual(undefined);
    expect(await service.requestSignInCode("ghost@b.co")).toStrictEqual(
      undefined,
    );
  });

  it("a slow failing send does not invalidate a resend's delivered code", async () => {
    const { store } = makeStore();
    let releaseFirstSend = () => {};
    const firstSendGate = new Promise<void>((resolve) => {
      releaseFirstSend = resolve;
    });
    let announceFirstSend = () => {};
    const firstSendEntered = new Promise<void>((resolve) => {
      announceFirstSend = resolve;
    });
    const delivered: string[] = [];
    let sends = 0;
    const service = serviceWithoutSignInFloor({
      users: store,
      otp: { store: new MemoryOtpStore() },
      delivery: {
        async sendSignInCode(message) {
          sends++;
          if (sends === 1) {
            announceFirstSend();
            await firstSendGate;
            throw new Error("mailer timed out");
          }
          delivered.push(message.code);
        },
      },
    });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    const stalled = service.requestSignInCode("a@b.co");
    await firstSendEntered;
    await service.requestSignInCode("a@b.co");
    releaseFirstSend();
    await stalled;

    expect(delivered.length).toStrictEqual(1);
    expect(
      await service.verifySignInCode({ email: "a@b.co", code: delivered[0] }),
    ).toStrictEqual({ status: "success", userId: user.id });
  });

  it("reports invalidated: false and leaves the code live when cleanup fails too", async () => {
    const { store } = makeStore();
    const otpStore = new MemoryOtpStore();
    otpStore.invalidateById = () => Promise.reject(new Error("store down"));
    const events: IdentityEvent[] = [];
    let capturedCode = "";
    const service = serviceWithoutSignInFloor({
      users: store,
      otp: { store: otpStore },
      delivery: {
        sendSignInCode: (msg) => {
          capturedCode = msg.code;
          throw new Error("mailer down");
        },
      },
      onEvent: (event) => {
        events.push(event);
      },
    });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    expect(await service.requestSignInCode("a@b.co")).toStrictEqual(undefined);
    expect(lastEventOfType(events, "delivery.failed")).toStrictEqual({
      type: "delivery.failed",
      hook: "sendSignInCode",
      invalidated: false,
      error: "mailer down",
    });
    expect(
      await service.verifySignInCode({ email: "a@b.co", code: capturedCode }),
      "invalidated: false means exactly this — an undelivered code stays live",
    ).toStrictEqual({ status: "success", userId: user.id });
  });

  it("calls a delivery hook bound to its object, so a class instance keeps `this`", async () => {
    const { store } = makeStore();
    class Mailer {
      readonly sent: string[] = [];
      #outbox = "outbox";
      sendSignInCode(message: CodeDeliveryMessage): void {
        this.sent.push(`${this.#outbox}:${message.code}`);
      }
    }
    const mailer = new Mailer();
    const service = serviceWithoutSignInFloor({
      users: store,
      otp: { store: new MemoryOtpStore() },
      delivery: mailer,
    });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.requestSignInCode("a@b.co");

    expect(mailer.sent.length).toStrictEqual(1);
    expect(
      await service.verifySignInCode({
        email: "a@b.co",
        code: mailer.sent[0].replace("outbox:", ""),
      }),
    ).toStrictEqual({ status: "success", userId: user.id });
  });

  it("requestSignInCode for an unknown email resolves identically but sends nothing", async () => {
    const { service, codes, events, signUp } = makePasswordlessService();
    await signUp();

    expect(await service.requestSignInCode("ghost@b.co")).toStrictEqual(
      undefined,
    );
    expect(codes.length).toStrictEqual(0);
    expect(lastEventOfType(events, "signin_code.requested")).toStrictEqual({
      type: "signin_code.requested",
      email: "ghost@b.co",
    });
  });

  it("verifySignInCode for an unknown email reports plain invalid", async () => {
    const { service, events, signUp } = makePasswordlessService();
    await signUp();

    expect(
      await service.verifySignInCode({
        email: "ghost@b.co",
        code: "123456",
      }),
    ).toStrictEqual({ status: "invalid" });
    expect(lastEventOfType(events, "signin_code.failed")).toStrictEqual({
      type: "signin_code.failed",
      email: "ghost@b.co",
      reason: "unknown_email",
    });
  });

  it("locks the code after the wrong-attempt budget and reports expiry", async () => {
    using time = new FakeTime();
    const { service, codes, events, signUp } = makePasswordlessService({
      otp: { maxAttempts: 2, ttlMs: 60_000 },
    });
    await signUp();

    await service.requestSignInCode("a@b.co");
    expect(
      await service.verifySignInCode({ email: "a@b.co", code: "000000" }),
    ).toStrictEqual({ status: "invalid" });
    expect(
      await service.verifySignInCode({ email: "a@b.co", code: "000000" }),
    ).toStrictEqual({ status: "invalid" });
    expect(lastEventOfType(events, "signin_code.failed")).toStrictEqual({
      type: "signin_code.failed",
      email: "a@b.co",
      reason: "locked",
    });
    expect(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[0].code,
      }),
    ).toStrictEqual({ status: "invalid" });

    await service.requestSignInCode("a@b.co");
    time.tick(60_001);
    expect(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[1].code,
      }),
    ).toStrictEqual({ status: "invalid" });
    expect(lastEventOfType(events, "signin_code.failed")).toStrictEqual({
      type: "signin_code.failed",
      email: "a@b.co",
      reason: "expired",
    });
  });

  it("re-requesting a sign-in code invalidates the outstanding one", async () => {
    const { service, codes, signUp } = makePasswordlessService();
    const user = await signUp();

    await service.requestSignInCode("a@b.co");
    await service.requestSignInCode("a@b.co");
    expect(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[0].code,
      }),
    ).toStrictEqual({ status: "invalid" });
    expect(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[1].code,
      }),
    ).toStrictEqual({ status: "success", userId: user.id });
  });

  it("request and verify share the code throttle window; success resets it", async () => {
    const { service, events, signUp } = makePasswordlessService({
      limit: 3,
    });
    await signUp();

    await service.requestSignInCode("a@b.co");
    await service.verifySignInCode({ email: "a@b.co", code: "000000" });
    await service.verifySignInCode({ email: "a@b.co", code: "000000" });
    const err = await rejection(
      () => service.verifySignInCode({ email: "a@b.co", code: "000000" }),
      IdentityError,
    );
    expect(err.code).toStrictEqual("rate_limited");
    lastEventOfType(events, "signin_code.rate_limited");

    const other = makePasswordlessService({ limit: 3 });
    const otherUser = await other.signUp();
    await other.service.requestSignInCode("a@b.co");
    await other.service.verifySignInCode({ email: "a@b.co", code: "000000" });
    expect(
      await other.service.verifySignInCode({
        email: "a@b.co",
        code: other.codes[0].code,
      }),
    ).toStrictEqual({ status: "success", userId: otherUser.id });
    await other.service.requestSignInCode("a@b.co");
    await other.service.requestSignInCode("a@b.co");
    expect(other.codes.length).toStrictEqual(3);
  });

  it("log-only mode emits signin_code.rate_limited without blocking", async () => {
    const { service, codes, events, signUp } = makePasswordlessService({
      limit: 1,
      protectionMode: "log-only",
    });
    await signUp();

    await service.requestSignInCode("a@b.co");
    await service.requestSignInCode("a@b.co");
    expect(codes.length).toStrictEqual(2);
    const limited = lastEventOfType(events, "signin_code.rate_limited");
    expect(limited.email).toStrictEqual("a@b.co");
    expect(limited.enforced).toStrictEqual(false);
  });

  it("rate-limits a code request identically for a known and an unknown email", async () => {
    const known = makePasswordlessService({ limit: 1 });
    await known.signUp();
    const unknown = makePasswordlessService({ limit: 1 });

    for (const { service } of [known, unknown]) {
      await service.requestSignInCode("a@b.co");
      const error = await rejection(
        () => service.requestSignInCode("a@b.co"),
        IdentityError,
      );
      expect(error.code).toStrictEqual("rate_limited");
    }

    expect(known.codes.length).toStrictEqual(1);
    expect(unknown.codes.length).toStrictEqual(0);
  });

  function makeStoreOutageService() {
    const { store } = makeStore();
    const events: IdentityEvent[] = [];
    const tokenBacking = new MemoryTokenFlowStore();
    const otpBacking = new MemoryOtpStore();
    let down = false;
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService({
        save: (record) =>
          down
            ? Promise.reject(new Error("token store down"))
            : tokenBacking.save(record),
        get: (hash) => tokenBacking.get(hash),
        markConsumed: (hash, at) => tokenBacking.markConsumed(hash, at),
      }),
      otp: {
        store: {
          create: (record) =>
            down
              ? Promise.reject(new Error("otp store down"))
              : otpBacking.create(record),
          findActive: (email, purpose) => otpBacking.findActive(email, purpose),
          recordAttempt: (id) => otpBacking.recordAttempt(id),
          consume: (id) => otpBacking.consume(id),
          invalidate: (email, purpose) => otpBacking.invalidate(email, purpose),
          invalidateById: (id) => otpBacking.invalidateById(id),
        },
      },
      delivery: {
        sendPasswordReset: () => {},
        sendSignInLink: () => {},
        sendSignInCode: () => {},
      },
      onEvent: (event) => {
        events.push(event);
      },
    });
    const signUp = () =>
      service.signUp({
        password: "hunter2hunter2",
        profile: { email: "a@b.co" },
      });
    return { service, events, signUp, takeDown: () => (down = true) };
  }

  for (const [method, flow] of [
    ["requestPasswordReset", "password_reset"],
    ["requestSignInLink", "signin_link"],
    ["requestSignInCode", "signin_code"],
  ] as const) {
    it(`${method} resolves for a known email when its store throws, as it does for an unknown one`, async () => {
      using consoleError = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});
      const { service, events, signUp, takeDown } = makeStoreOutageService();
      await signUp();
      takeDown();

      expect(await service[method]("ghost@b.co")).toStrictEqual(undefined);
      expect(await service[method]("a@b.co")).toStrictEqual(undefined);

      const failed = eventsOfType(events, "credential_mint.failed");
      expect(failed.length).toStrictEqual(1);
      expect(failed[0].flow).toStrictEqual(flow);
      expect(consoleError.mock.calls.length).toStrictEqual(1);
    });
  }

  it("requires the tokens/otp options for the flows that need them", async () => {
    const { store } = makeStore();
    const service = serviceWithoutSignInFloor({ users: store });
    await rejection(
      () => service.requestSignInLink("a@b.co"),
      Error,
      "requires a `tokens` option",
    );
    await rejection(
      () => service.requestSignInCode("a@b.co"),
      Error,
      "requires an `otp` option",
    );
    await rejection(
      () => service.verifySignInCode({ email: "a@b.co", code: "1" }),
      Error,
      "requires an `otp` option",
    );
  });
});

describe("IdentityService bring-your-own protections", () => {
  async function signUpAlice(service: IdentityService<TestUser>) {
    return await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
  }

  it("accepts a plain-object rateLimiter and drives it from signIn", async () => {
    const { store } = makeStore();
    const checked: string[] = [];
    const cleared: string[] = [];
    const rateLimiter: RateLimiterLike = {
      check(key) {
        checked.push(key);
        const allowed = checked.length < 2;
        return Promise.resolve({
          allowed,
          remaining: 0,
          resetAt: 0,
          retryAfterMs: allowed ? 0 : 90_000,
        });
      },
      reset(key) {
        cleared.push(key);
        return Promise.resolve();
      },
    };
    const service = serviceWithoutSignInFloor({
      users: store,
      rateLimiter,
    });
    await signUpAlice(service);

    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    expect(checked).toStrictEqual(["signin:a@b.co"]);
    expect(cleared).toStrictEqual(["signin:a@b.co"]);

    const error = await rejection(
      () =>
        service.signIn({ identifier: "a@b.co", password: "hunter2hunter2" }),
      IdentityError,
    );
    expect(error.code).toStrictEqual("rate_limited");
    expect(error.retryAfterMs).toStrictEqual(90_000);
  });

  it("accepts a plain-object lockout and drives it from signIn", async () => {
    const { store } = makeStore();
    const events: IdentityEvent[] = [];
    let failures = 0;
    let lockedUntil: number | undefined;
    const lockout: AccountLockoutLike = {
      status(_userId, now = Date.now()) {
        const locked = lockedUntil !== undefined && lockedUntil > now;
        return Promise.resolve({
          locked,
          failures,
          lockedUntil: locked ? lockedUntil : undefined,
        });
      },
      recordFailure(_userId, now = Date.now()) {
        failures++;
        const justLocked = failures === 2;
        if (justLocked) lockedUntil = now + 60_000;
        return Promise.resolve({
          failures,
          locked: lockedUntil !== undefined,
          justLocked,
          lockedUntil,
        });
      },
      reset(_userId) {
        failures = 0;
        lockedUntil = undefined;
        return Promise.resolve();
      },
    };
    const service = serviceWithoutSignInFloor({
      users: store,
      lockout,
      onEvent: (event) => {
        events.push(event);
      },
    });
    await signUpAlice(service);

    for (let i = 0; i < 2; i++) {
      expect(
        await service.signIn({ identifier: "a@b.co", password: "wrong" }),
      ).toStrictEqual(null);
    }
    expect(failures).toStrictEqual(2);
    lastEventOfType(events, "lockout");

    expect(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    ).toStrictEqual(null);
    lastEventOfType(events, "sign_in.locked");
  });
});

describe("IdentityService per-flow rate limiters", () => {
  function recordingLimiter(options: { allowed?: boolean } = {}) {
    const allowed = options.allowed ?? true;
    const checked: string[] = [];
    const cleared: string[] = [];
    const limiter: RateLimiterLike = {
      check(key) {
        checked.push(key);
        return Promise.resolve({
          allowed,
          remaining: 0,
          resetAt: 0,
          retryAfterMs: allowed ? 0 : 60_000,
        });
      },
      reset(key) {
        cleared.push(key);
        return Promise.resolve();
      },
    };
    return { limiter, checked, cleared };
  }

  function makeLimitedService(options: {
    rateLimiter?: RateLimiterLike;
    rateLimiters?: IdentityRateLimiters;
  }) {
    const { store } = makeStore();
    const codes: CodeDeliveryMessage[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(new MemoryTokenFlowStore()),
      otp: { store: new MemoryOtpStore() },
      delivery: {
        sendSignInCode: (msg) => {
          codes.push(msg);
        },
      },
      rateLimiter: options.rateLimiter,
      rateLimiters: options.rateLimiters,
    });
    const signUp = () =>
      service.signUp({
        password: "hunter2hunter2",
        profile: { email: "a@b.co" },
      });
    return { service, codes, signUp };
  }

  async function runEveryFlow(
    service: IdentityService<TestUser>,
    userId: string,
  ): Promise<void> {
    await service.signIn({ identifier: "a@b.co", password: "hunter2hunter2" });
    await service.requestPasswordReset("a@b.co");
    await service.requestEmailVerification({ userId, email: "a@b.co" });
    await service.requestAccountUnlock({ userId, email: "a@b.co" });
    await service.requestSignInLink("a@b.co");
    await service.requestSignInCode("a@b.co");
  }

  it("routes each flow to its own configured limiter", async () => {
    const shared = recordingLimiter();
    const signIn = recordingLimiter();
    const passwordReset = recordingLimiter();
    const emailVerification = recordingLimiter();
    const accountUnlock = recordingLimiter();
    const signInLink = recordingLimiter();
    const signInCode = recordingLimiter();
    const { service, signUp } = makeLimitedService({
      rateLimiter: shared.limiter,
      rateLimiters: {
        signIn: signIn.limiter,
        passwordReset: passwordReset.limiter,
        emailVerification: emailVerification.limiter,
        accountUnlock: accountUnlock.limiter,
        signInLink: signInLink.limiter,
        signInCode: signInCode.limiter,
      },
    });
    const user = await signUp();

    await runEveryFlow(service, user.id);

    expect(shared.checked).toStrictEqual([]);
    expect(signIn.checked).toStrictEqual(["signin:a@b.co"]);
    expect(passwordReset.checked).toStrictEqual(["pwreset:a@b.co"]);
    expect(emailVerification.checked).toStrictEqual([`verifyemail:${user.id}`]);
    expect(accountUnlock.checked).toStrictEqual([`unlock:${user.id}`]);
    expect(signInLink.checked).toStrictEqual(["pwless:a@b.co"]);
    expect(signInCode.checked).toStrictEqual(["otp:signin:a@b.co"]);
  });

  it("falls back to the shared limiter for every unset flow", async () => {
    const shared = recordingLimiter();
    const { service, signUp } = makeLimitedService({
      rateLimiter: shared.limiter,
    });
    const user = await signUp();

    await runEveryFlow(service, user.id);

    expect(shared.checked).toStrictEqual([
      "signin:a@b.co",
      "pwreset:a@b.co",
      `verifyemail:${user.id}`,
      `unlock:${user.id}`,
      "pwless:a@b.co",
      "otp:signin:a@b.co",
    ]);
  });

  it("case-folds every email-addressed key so casing variants share a window", async () => {
    const shared = recordingLimiter();
    const { service, signUp } = makeLimitedService({
      rateLimiter: shared.limiter,
    });
    const user = await signUp();

    await service.requestPasswordReset("A@B.co");
    await service.requestSignInLink("A@B.co");
    await service.requestSignInCode("A@B.co");
    await service.requestEmailVerification({
      userId: user.id,
      email: "A@B.co",
    });

    expect(shared.checked).toStrictEqual([
      "pwreset:a@b.co",
      "pwless:a@b.co",
      "otp:signin:a@b.co",
      `verifyemail:${user.id}`,
    ]);
  });

  it("keys the sign-in window on the identifier as given, casing included", async () => {
    const shared = recordingLimiter();
    const { service, signUp } = makeLimitedService({
      rateLimiter: shared.limiter,
    });
    await signUp();

    await service.signIn({ identifier: "A@b.co", password: "x" });
    await service.signIn({ identifier: " a@b.co ", password: "x" });

    expect(
      shared.checked,
      "identifier equality is the app's to define, so only whitespace is normalized",
    ).toStrictEqual(["signin:A@b.co", "signin:a@b.co"]);
  });

  it("falls back per flow, overriding only the keys that are set", async () => {
    const shared = recordingLimiter();
    const passwordReset = recordingLimiter();
    const { service, signUp } = makeLimitedService({
      rateLimiter: shared.limiter,
      rateLimiters: { passwordReset: passwordReset.limiter },
    });
    const user = await signUp();

    await runEveryFlow(service, user.id);

    expect(passwordReset.checked).toStrictEqual(["pwreset:a@b.co"]);
    expect(shared.checked).toStrictEqual([
      "signin:a@b.co",
      `verifyemail:${user.id}`,
      `unlock:${user.id}`,
      "pwless:a@b.co",
      "otp:signin:a@b.co",
    ]);
  });

  it("throttles an email-sending flow while sign-in stays allowed", async () => {
    const { service, signUp } = makeLimitedService({
      rateLimiter: new RateLimiter({ limit: 10, windowMs: 60_000 }),
      rateLimiters: {
        passwordReset: new RateLimiter({ limit: 1, windowMs: 60_000 }),
      },
    });
    await signUp();

    await service.requestPasswordReset("a@b.co");
    const error = await rejection(
      () => service.requestPasswordReset("a@b.co"),
      IdentityError,
    );
    expect(error.code).toStrictEqual("rate_limited");

    for (let i = 0; i < 3; i++) {
      assert.exists(
        await service.signIn({
          identifier: "a@b.co",
          password: "hunter2hunter2",
        }),
      );
    }
  });

  it("runs a code request through the signInCode limiter once, known email or not", async () => {
    const signInCode = recordingLimiter();
    const { service, codes, signUp } = makeLimitedService({
      rateLimiters: { signInCode: signInCode.limiter },
    });
    await signUp();

    await service.requestSignInCode("a@b.co");
    await service.requestSignInCode("nobody@b.co");

    expect(signInCode.checked).toStrictEqual([
      "otp:signin:a@b.co",
      "otp:signin:nobody@b.co",
    ]);
    expect(codes.length).toStrictEqual(1);
  });

  it("offers no second limiter seam on the otp option", async () => {
    const stray = recordingLimiter();
    const signInCode = recordingLimiter();
    const { store } = makeStore();
    const codes: CodeDeliveryMessage[] = [];
    const options: IdentityServiceOptions<TestUser> = {
      users: store,
      otp: {
        store: new MemoryOtpStore(),
        // @ts-expect-error A limiter here would be checked only after the email
        // resolves to a user, making a known email throttle where an unknown
        // one does not. `rateLimiters.signInCode` is the only seam.
        rateLimiter: stray.limiter,
      },
      delivery: {
        sendSignInCode: (msg) => {
          codes.push(msg);
        },
      },
      rateLimiters: { signInCode: signInCode.limiter },
    };
    const service = serviceWithoutSignInFloor(options);
    await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.requestSignInCode("a@b.co");

    expect(stray.checked).toStrictEqual([]);
    expect(signInCode.checked).toStrictEqual(["otp:signin:a@b.co"]);
    expect(codes.length).toStrictEqual(1);
  });

  it("offers no protection mode of its own on the otp option", () => {
    const { store } = makeStore();
    const options: IdentityServiceOptions<TestUser> = {
      users: store,
      otp: {
        store: new MemoryOtpStore(),
        // @ts-expect-error The mode belongs to a limiter the otp option no
        // longer takes; the service's own `protectionMode` governs the flow.
        protectionMode: "log-only",
      },
    };

    assert.exists(serviceWithoutSignInFloor(options));
  });

  it("applies a per-flow limiter with no shared limiter configured", async () => {
    const passwordReset = recordingLimiter();
    const { service, signUp } = makeLimitedService({
      rateLimiters: { passwordReset: passwordReset.limiter },
    });
    const user = await signUp();

    await runEveryFlow(service, user.id);

    expect(passwordReset.checked).toStrictEqual(["pwreset:a@b.co"]);
  });

  it("resets the sign-in window on the signIn limiter, not the shared one", async () => {
    const shared = recordingLimiter();
    const signIn = recordingLimiter();
    const { service, signUp } = makeLimitedService({
      rateLimiter: shared.limiter,
      rateLimiters: { signIn: signIn.limiter },
    });
    await signUp();

    assert.exists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    await service.resetSignInThrottle("a@b.co");

    expect(signIn.cleared).toStrictEqual(["signin:a@b.co", "signin:a@b.co"]);
    expect(shared.cleared).toStrictEqual([]);
  });

  it("resets the sign-in code window on the signInCode limiter", async () => {
    const shared = recordingLimiter();
    const signInCode = recordingLimiter();
    const { service, codes, signUp } = makeLimitedService({
      rateLimiter: shared.limiter,
      rateLimiters: { signInCode: signInCode.limiter },
    });
    const user = await signUp();

    await service.requestSignInCode("a@b.co");
    expect(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[0].code,
      }),
    ).toStrictEqual({ status: "success", userId: user.id });

    expect(signInCode.cleared).toStrictEqual(["otp:signin:a@b.co"]);
    expect(shared.cleared).toStrictEqual([]);
  });

  it("blocks a flow whose own limiter denies even when the shared one allows", async () => {
    const shared = recordingLimiter();
    const signInLink = recordingLimiter({ allowed: false });
    const { service, signUp } = makeLimitedService({
      rateLimiter: shared.limiter,
      rateLimiters: { signInLink: signInLink.limiter },
    });
    await signUp();

    const error = await rejection(
      () => service.requestSignInLink("a@b.co"),
      IdentityError,
    );
    expect(error.code).toStrictEqual("rate_limited");
    expect(error.retryAfterMs).toStrictEqual(60_000);
    await service.requestPasswordReset("a@b.co");
  });
});

describe("IdentityService resetPassword voids other credentials", () => {
  function makeResetService(
    tokenStore: TokenFlowStore = new MemoryTokenFlowStore(),
  ) {
    const { store } = makeStore();
    const resets: DeliveryMessage[] = [];
    const links: DeliveryMessage[] = [];
    const codes: CodeDeliveryMessage[] = [];
    const service = serviceWithoutSignInFloor({
      users: store,
      tokens: new TokenFlowService(tokenStore),
      otp: { store: new MemoryOtpStore() },
      delivery: {
        sendPasswordReset: (msg) => {
          resets.push(msg);
        },
        sendSignInLink: (msg) => {
          links.push(msg);
        },
        sendSignInCode: (msg) => {
          codes.push(msg);
        },
      },
    });
    const signUp = () =>
      service.signUp({
        password: "hunter2hunter2",
        profile: { email: "a@b.co" },
      });
    const reset = async (password: string) => {
      await service.requestPasswordReset("a@b.co");
      return await service.resetPassword({
        token: resets.at(-1)!.token,
        password,
      });
    };
    return { service, links, codes, signUp, reset };
  }

  it("refuses a sign-in link issued before the reset", async () => {
    const { service, links, signUp, reset } = makeResetService();
    await signUp();
    await service.requestSignInLink("a@b.co");

    assert.exists(await reset("newpassword1"));

    expect(await service.consumeSignInLink(links[0].token)).toStrictEqual({
      status: "invalid",
    });
  });

  it("refuses a sign-in code issued before the reset", async () => {
    const { service, codes, signUp, reset } = makeResetService();
    await signUp();
    await service.requestSignInCode("a@b.co");

    assert.exists(await reset("newpassword1"));

    expect(
      await service.verifySignInCode({ email: "a@b.co", code: codes[0].code }),
    ).toStrictEqual({ status: "invalid" });
  });

  it("still resets on a token store that cannot delete by subject", async () => {
    const backing = new MemoryTokenFlowStore();
    const { service, links, signUp, reset } = makeResetService({
      save: (record) => backing.save(record),
      get: (hash) => backing.get(hash),
      markConsumed: (hash, at) => backing.markConsumed(hash, at),
    });
    const user = await signUp();
    await service.requestSignInLink("a@b.co");

    expect(await reset("newpassword1")).toStrictEqual({ userId: user.id });
    assert.exists(
      await service.signIn({ identifier: "a@b.co", password: "newpassword1" }),
    );
    expect(await service.consumeSignInLink(links[0].token)).toStrictEqual({
      status: "success",
      userId: user.id,
    });
  });

  it("still resets when the token store throws while deleting by subject", async () => {
    using consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    const backing = new MemoryTokenFlowStore();
    const { service, signUp, reset } = makeResetService({
      save: (record) => backing.save(record),
      get: (hash) => backing.get(hash),
      markConsumed: (hash, at) => backing.markConsumed(hash, at),
      deleteBySubject: (purpose, subject) =>
        purpose === TokenPurpose.SignIn
          ? Promise.reject(new Error("store offline"))
          : backing.deleteBySubject(purpose, subject),
    });
    const user = await signUp();

    expect(await reset("newpassword1")).toStrictEqual({ userId: user.id });
    assert.exists(
      await service.signIn({ identifier: "a@b.co", password: "newpassword1" }),
    );
    expect(consoleError.mock.calls.length).toStrictEqual(1);
  });
});
