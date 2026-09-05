import { assert, assertEquals, assertExists, assertRejects } from "@std/assert";
import { delay } from "@std/async/delay";
import { describe, it } from "@std/testing/bdd";
import { spy, stub } from "@std/testing/mock";
import { FakeTime } from "@std/testing/time";

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
  return events.filter((event): event is Extract<IdentityEvent, { type: T }> =>
    event.type === type
  );
}

function lastEventOfType<T extends IdentityEvent["type"]>(
  events: IdentityEvent[],
  type: T,
): Extract<IdentityEvent, { type: T }> {
  const last = eventsOfType(events, type).at(-1);
  assertExists(last, `expected a ${type} event`);
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
    rateLimiter: options?.limit !== undefined
      ? new RateLimiter({ limit: options.limit, windowMs: 60_000 })
      : undefined,
    onEvent: options?.onEvent ?? ((event) => {
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
      const err = await assertRejects(
        () =>
          service.signUp({
            password: password as unknown as string,
            profile: { email: "a@b.co" },
          }),
        IdentityError,
        undefined,
        `${JSON.stringify(password)} must not reach the hash`,
      );
      assertEquals((err as IdentityError).code, "weak_password");
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

    const err = await assertRejects(
      () =>
        service.resetPassword({
          token,
          password: {} as unknown as string,
        }),
      IdentityError,
    );
    assertEquals((err as IdentityError).code, "weak_password");

    assertExists(await service.resetPassword({ token, password: "goodpass1" }));
    assertExists(
      await service.signIn({ identifier: "a@b.co", password: "goodpass1" }),
    );
  });

  it("signUp applies the default password policy when none is configured", async () => {
    const { service } = makeService();
    for (const password of ["short", "a".repeat(257)]) {
      const err = await assertRejects(
        () => service.signUp({ password, profile: { email: "a@b.co" } }),
        IdentityError,
        undefined,
        `${password.length}-character password must not reach the hash`,
      );
      assertEquals(err.code, "weak_password");
    }
    assertExists(
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
      const err = await assertRejects(
        () => service.resetPassword({ token, password }),
        IdentityError,
        undefined,
        `${password.length}-character password must not reach the hash`,
      );
      assertEquals(err.code, "weak_password");
    }

    assertExists(await service.resetPassword({ token, password: "goodpass1" }));
    assertExists(
      await service.signIn({ identifier: "a@b.co", password: "goodpass1" }),
    );
  });

  it("signUp creates a user, signIn verifies credentials", async () => {
    const { service } = makeService();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co", username: "alice" },
    });
    assertExists(user.id);

    assertEquals(
      (await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }))
        ?.id,
      user.id,
    );
    assertEquals(
      (await service.signIn({
        identifier: "alice",
        password: "hunter2hunter2",
      }))
        ?.id,
      user.id,
    );
    assertEquals(
      await service.signIn({ identifier: "a@b.co", password: "nope" }),
      null,
    );
    assertEquals(
      await service.signIn({ identifier: "ghost", password: "hunter2hunter2" }),
      null,
    );
  });

  it("signIn spends a hash even when the user has no stored credential", async () => {
    const passwords = new PasswordIdentityService();
    using hashSpy = spy(passwords, "hash");
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

    assertEquals(
      await service.signIn({ identifier: "sso@b.co", password: "whatever12" }),
      null,
    );
    assertEquals(hashSpy.calls.length, 1);
  });

  it("password reset is enumeration-safe and rotates the credential + sessions", async () => {
    const { service, sent, revoked } = makeService();
    await service.signUp({
      password: "oldpassword1",
      profile: { email: "a@b.co", username: "alice" },
    });

    await service.requestPasswordReset("nobody@b.co");
    assertEquals(sent.length, 0);

    await service.requestPasswordReset("a@b.co");
    assertEquals(sent.length, 1);
    assertEquals(sent[0].hook, "reset");
    const { token, url } = sent[0].msg;
    assertEquals(url, `https://app.example/reset-password?token=${token}`);

    const result = await service.resetPassword({
      token,
      password: "newpassword1",
    });
    assertExists(result);
    assertEquals(revoked.length, 1);
    assertEquals(
      await service.signIn({ identifier: "a@b.co", password: "oldpassword1" }),
      null,
    );
    assertEquals(
      (await service.signIn({
        identifier: "a@b.co",
        password: "newpassword1",
      }))?.id,
      result!.userId,
    );

    assertEquals(
      await service.resetPassword({ token, password: "again12345" }),
      null,
    );
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
    assertEquals(sent.length, 1);
    assertEquals(sent[0].hook, "verify");
    const { token, url } = sent[0].msg;
    assertEquals(url, `https://app.example/verify-email?token=${token}`);

    const result = await service.verifyEmail(token);
    assertEquals(result.status, "success");
    if (result.status === "success") {
      assertEquals(result.userId, user.id);
      assertEquals(result.email, "a@b.co");
    }
    assertEquals(verified.has(user.id), true);

    assertEquals((await service.verifyEmail(token)).status, "invalid");
    assertEquals((await service.verifyEmail("garbage")).status, "invalid");
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

    assertEquals(result.status, "success");
    assertEquals(verified.has(user.id), false);
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
    assertEquals((await service.verifyEmail(token)).status, "expired");
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

    assertEquals(
      await service.resetPassword({
        token: capturedToken,
        password: "newpassword1",
      }),
      null,
    );
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

    assertEquals(await service.requestPasswordReset("a@b.co"), undefined);
    assertEquals(lastEventOfType(events, "delivery.failed"), {
      type: "delivery.failed",
      hook: "sendPasswordReset",
      invalidated: false,
      error: "mailer down",
    });
    assertExists(
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

    await assertRejects(
      () => service.verifyEmail(capturedToken),
      Error,
      "db write failed",
    );

    const result = await service.verifyEmail(capturedToken);
    assertEquals(result.status, "success");
    assertEquals(marked, [user.id]);
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

    await assertRejects(
      () =>
        service.resetPassword({
          token: minted.passwordReset[0],
          password: "newpassword1",
        }),
      Error,
      "session store down",
    );

    assertEquals(eventsOfType(events, "password_reset.completed"), []);
    assertEquals(
      lastEventOfType(events, "password_reset.failed").reason,
      "session_revocation_failed",
    );

    assertEquals(
      (await service.signIn({ identifier: "a@b.co", password: "newpassword1" }))
        ?.id,
      user.id,
    );
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

    const signUpErr = await assertRejects(
      () => service.signUp({ password: "short", profile: { email: "a@b.co" } }),
      IdentityError,
    );
    assertEquals((signUpErr as IdentityError).code, "weak_password");

    const user = await service.signUp({
      password: "longenough1",
      profile: { email: "a@b.co" },
    });
    assertExists(user.id);

    await service.requestPasswordReset("a@b.co");
    const resetErr = await assertRejects(
      () => service.resetPassword({ token: resetToken, password: "short" }),
      IdentityError,
    );
    assertEquals((resetErr as IdentityError).code, "weak_password");

    const result = await service.resetPassword({
      token: resetToken,
      password: "newlongpass1",
    });
    assertExists(result);
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
      assertEquals(
        await service.signIn({ identifier: "a@b.co", password: "wrong" }),
        null,
      );
    }
    const err = await assertRejects(
      () => service.signIn({ identifier: "a@b.co", password: "wrong" }),
      IdentityError,
    );
    assertEquals((err as IdentityError).code, "rate_limited");
    assertEquals(typeof (err as IdentityError).retryAfterMs, "number");

    assertEquals(
      await service.signIn({ identifier: "other@b.co", password: "x" }),
      null,
    );
  });

  it("throttles an unknown identifier identically (no enumeration via 429)", async () => {
    const { store } = makeStore();
    const service = serviceWithoutSignInFloor({
      users: store,
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60_000 }),
    });
    assertEquals(
      await service.signIn({ identifier: "ghost@b.co", password: "x" }),
      null,
    );
    assertEquals(
      await service.signIn({ identifier: "ghost@b.co", password: "x" }),
      null,
    );
    const err = await assertRejects(
      () => service.signIn({ identifier: "ghost@b.co", password: "x" }),
      IdentityError,
    );
    assertEquals((err as IdentityError).code, "rate_limited");
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

    assertEquals(
      await service.signIn({ identifier: "a@b.co", password: "wrong" }),
      null,
    );
    assertExists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    assertEquals(
      await service.signIn({ identifier: "a@b.co", password: "wrong" }),
      null,
    );
    assertEquals(
      await service.signIn({ identifier: "a@b.co", password: "wrong" }),
      null,
    );
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
    assertEquals(sent.length, 2);

    const err = await assertRejects(
      () => service.requestPasswordReset("a@b.co"),
      IdentityError,
    );
    assertEquals((err as IdentityError).code, "rate_limited");
    assertEquals(typeof (err as IdentityError).retryAfterMs, "number");
    assertEquals(sent.length, 2);

    await service.requestPasswordReset("ghost@b.co");
    await service.requestPasswordReset("ghost@b.co");
    const ghostErr = await assertRejects(
      () => service.requestPasswordReset("ghost@b.co"),
      IdentityError,
    );
    assertEquals((ghostErr as IdentityError).code, "rate_limited");
    assertEquals(sent.length, 2);
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
    const err = await assertRejects(
      () =>
        service.requestEmailVerification({ userId: alice.id, email: "a@b.co" }),
      IdentityError,
    );
    assertEquals((err as IdentityError).code, "rate_limited");
    assertEquals(sent.length, 1);

    await service.requestEmailVerification({ userId: bob.id, email: "b@b.co" });
    assertEquals(sent.length, 2);
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
    const err = await assertRejects(
      () => service.requestPasswordReset("GHOST@B.CO"),
      IdentityError,
    );
    assertEquals((err as IdentityError).code, "rate_limited");
    assertEquals(sent.length, 0);
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
    const err = await assertRejects(
      () => service.requestAccountUnlock({ userId: alice.id, email: "a@b.co" }),
      IdentityError,
    );
    assertEquals((err as IdentityError).code, "rate_limited");
    assertEquals(sent.length, 1);
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
    assertEquals(sent.length, 2);

    const limited = lastEventOfType(events, "password_reset.rate_limited");
    assertEquals(limited.email, "a@b.co");
    assertEquals(limited.enforced, false);
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

    assertEquals(lastEventOfType(events, "sign_up"), {
      type: "sign_up",
      userId: user.id,
    });
    assertEquals(lastEventOfType(events, "sign_in.succeeded"), {
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

    assertEquals(eventsOfType(events, "sign_in.failed"), [
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
    await assertRejects(
      () => service.signIn({ identifier: "ghost@b.co", password: "x" }),
      IdentityError,
    );

    const limited = lastEventOfType(events, "sign_in.rate_limited");
    assertEquals(limited.identifier, "ghost@b.co");
    assertEquals(typeof limited.retryAfterMs, "number");
  });

  it("emits a rate_limited event for each email flow before throwing", async () => {
    const { service, events } = makeEventService({ limit: 1 });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.requestPasswordReset("a@b.co");
    await assertRejects(
      () => service.requestPasswordReset("a@b.co"),
      IdentityError,
    );
    const resetLimited = lastEventOfType(events, "password_reset.rate_limited");
    assertEquals(resetLimited.email, "a@b.co");
    assertEquals(resetLimited.enforced, true);
    assertEquals(typeof resetLimited.retryAfterMs, "number");

    await service.requestEmailVerification({
      userId: user.id,
      email: "a@b.co",
    });
    await assertRejects(
      () =>
        service.requestEmailVerification({ userId: user.id, email: "a@b.co" }),
      IdentityError,
    );
    const verifyLimited = lastEventOfType(
      events,
      "email_verification.rate_limited",
    );
    assertEquals(verifyLimited.userId, user.id);
    assertEquals(verifyLimited.enforced, true);

    await service.requestAccountUnlock({ userId: user.id, email: "a@b.co" });
    await assertRejects(
      () => service.requestAccountUnlock({ userId: user.id, email: "a@b.co" }),
      IdentityError,
    );
    const unlockLimited = lastEventOfType(
      events,
      "account_unlock.rate_limited",
    );
    assertEquals(unlockLimited.userId, user.id);
    assertEquals(unlockLimited.enforced, true);
    assertEquals(typeof unlockLimited.retryAfterMs, "number");
  });

  it("emits password_reset.requested with userId only for a known email", async () => {
    const { service, events } = makeEventService();
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });

    await service.requestPasswordReset("a@b.co");
    await service.requestPasswordReset("ghost@b.co");

    assertEquals(eventsOfType(events, "password_reset.requested"), [
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
    assertExists(result);

    assertEquals(lastEventOfType(events, "password_reset.failed"), {
      type: "password_reset.failed",
      reason: "invalid_token",
    });
    assertEquals(lastEventOfType(events, "password_reset.completed"), {
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
    assertEquals(
      await service.resetPassword({
        token: minted.passwordReset[0],
        password: "newpass123",
      }),
      null,
    );
    assertEquals(lastEventOfType(events, "password_reset.failed"), {
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

    assertEquals(lastEventOfType(events, "email_verification.requested"), {
      type: "email_verification.requested",
      userId: user.id,
      email: "a@b.co",
    });
    assertEquals(lastEventOfType(events, "email_verification.failed"), {
      type: "email_verification.failed",
      reason: "invalid",
    });
    assertEquals(lastEventOfType(events, "email_verification.completed"), {
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

    assertEquals(result.status, "expired");
    assertEquals(lastEventOfType(events, "email_verification.failed"), {
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
      assertExists(user.id);
      assertExists(
        await service.signIn({
          identifier: "a@b.co",
          password: "hunter2hunter2",
        }),
      );
    } finally {
      console.error = original;
    }
    assertEquals(errors.length, 2);
  });

  it("flows behave identically with no hook configured", async () => {
    const { store } = makeStore();
    const service = serviceWithoutSignInFloor({ users: store });
    const user = await service.signUp({
      password: "hunter2hunter2",
      profile: { email: "a@b.co" },
    });
    assertExists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    assertEquals(user.email, "a@b.co");
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
      assertEquals(
        await service.signIn({ identifier: "a@b.co", password: "wrong" }),
        null,
      );
    }

    const lockEvent = lastEventOfType(events, "lockout");
    assertEquals(lockEvent.userId, user.id);
    assertEquals(lockEvent.failures, 3);
    assertEquals(lockEvent.enforced, true);

    assertEquals(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
      null,
    );
    lastEventOfType(events, "sign_in.locked");
  });

  it("resets the failure count on a successful sign-in", async () => {
    const { service, events } = makeLockoutService();
    await signUpAlice(service);

    await service.signIn({ identifier: "a@b.co", password: "wrong" });
    await service.signIn({ identifier: "a@b.co", password: "wrong" });
    assertExists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    await service.signIn({ identifier: "a@b.co", password: "wrong" });
    await service.signIn({ identifier: "a@b.co", password: "wrong" });
    assertExists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    assertEquals(eventsOfType(events, "lockout"), []);
  });

  it("log-only mode records lockout events but never blocks", async () => {
    const { service, events } = makeLockoutService({
      protectionMode: "log-only",
    });
    await signUpAlice(service);

    for (let i = 0; i < 4; i++) {
      await service.signIn({ identifier: "a@b.co", password: "wrong" });
    }

    assertEquals(lastEventOfType(events, "lockout").enforced, false);
    assertEquals(lastEventOfType(events, "sign_in.locked").enforced, false);

    assertExists(
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

    assertEquals(
      lastEventOfType(events, "sign_in.rate_limited").enforced,
      false,
    );
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
    assertEquals(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
      null,
    );

    await service.requestAccountUnlock({ userId: user.id, email: "a@b.co" });
    assertExists(unlockMessage);
    assertEquals(
      unlockMessage!.url,
      `https://app.example/unlock-account?token=${unlockMessage!.token}`,
    );
    lastEventOfType(events, "account_unlock.requested");

    const result = await service.unlockAccount(unlockMessage!.token);
    assertEquals(result, { status: "success", userId: user.id });
    lastEventOfType(events, "account_unlock.completed");

    assertExists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );

    assertEquals(
      (await service.unlockAccount(unlockMessage!.token)).status,
      "invalid",
    );
    assertEquals((await service.unlockAccount("garbage")).status, "invalid");
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
    assertEquals(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
      null,
    );

    await service.requestPasswordReset("a@b.co");
    assertExists(resetMessage);
    assertExists(
      await service.resetPassword({
        token: resetMessage!.token,
        password: "brand-new-pass-1",
      }),
    );

    assertExists(
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
    await assertRejects(
      () =>
        service.signIn({ identifier: "a@b.co", password: "hunter2hunter2" }),
      IdentityError,
    );

    await service.resetSignInThrottle("a@b.co");
    assertExists(
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
    await assertRejects(
      () =>
        service.signIn({ identifier: "a@b.co ", password: "hunter2hunter2" }),
      IdentityError,
      undefined,
      "whitespace variants must share one sign-in window",
    );

    await service.resetSignInThrottle("  a@b.co  ");
    assertExists(
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

    assertEquals(signedIn?.id, user.id);
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
    assertEquals(stored.params, {
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

    assertEquals(
      await service.signIn({
        identifier: "a@b.co",
        password: "wrong-password",
      }),
      null,
    );
    assertExists(
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
    using setCredential = spy(store, "setCredential");

    await service.signIn({
      identifier: "a@b.co",
      password: "hunter2hunter2",
    });

    assertEquals(setCredential.calls.length, 0);
  });

  it("signs the user in even when persisting the rehash fails", async () => {
    const { store } = makeLegacyStore();
    const { user } = await seedLegacyUser(store);
    store.replaceCredential = () => Promise.reject(new Error("db down"));
    const service = serviceWithoutSignInFloor({ users: store });
    using errorLog = stub(console, "error");

    const signedIn = await service.signIn({
      identifier: "a@b.co",
      password: "hunter2hunter2",
    });

    assertEquals(signedIn?.id, user.id);
    assertEquals(errorLog.calls.length, 1);
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
    assertEquals(user?.id, userId);

    const upgraded = creds.get(userId);
    assertExists(upgraded);
    assertEquals(upgraded.hash.length, 64);
    assertEquals(upgraded.salt.length, 32);
    assertEquals(legacy.has(userId), false);

    assertEquals(bcrypt.calls(), 1);
    assertEquals(
      events.map((e) => e.type),
      ["password.upgraded", "sign_in.succeeded"],
    );
    assertEquals(
      lastEventOfType(events, "password.upgraded").verifierId,
      "bcrypt",
    );
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
    assertExists(result);
    assertEquals(legacy.has(userId), false);

    assertEquals(
      await service.signIn({ identifier: "reset@b.co", password: "old-pw" }),
      null,
    );
    assertExists(
      await service.signIn({
        identifier: "reset@b.co",
        password: "brand-new-pw-1",
      }),
    );
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
    assertEquals(user?.id, userId);
    assertEquals(events.map((e) => e.type), ["sign_in.succeeded"]);
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
    assertEquals(result, { userId });
    assertEquals(revoked, [userId]);
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

    assertExists(
      await service.signIn({ identifier: "dev@b.co", password: "s3cret-pw" }),
    );
    assertEquals(bcrypt.calls(), 1);

    assertExists(
      await service.signIn({ identifier: "dev@b.co", password: "s3cret-pw" }),
    );
    assertEquals(bcrypt.calls(), 1);
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

    assertEquals(
      await service.signIn({
        identifier: "dev@b.co",
        password: "old-legacy-pw",
      }),
      null,
      "the old imported password must not resurrect via the legacy path",
    );
    assertEquals(
      bcrypt.calls(),
      0,
      "the legacy verifier is never consulted when a native credential exists",
    );
    assertExists(
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

    assertEquals(
      await service.signIn({ identifier: "dev@b.co", password: "wrong" }),
      null,
    );
    assertEquals(creds.has(userId), false);
    assertEquals(legacy.get(userId), "fakebcrypt$s3cret-pw");
    assertEquals(events.map((e) => e.type), ["sign_in.failed"]);
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

    assertExists(
      await service.signIn({ identifier: "b@b.co", password: "pw-one" }),
    );
    assertExists(
      await service.signIn({ identifier: "a@b.co", password: "pw-two" }),
    );
    assertEquals(bcrypt.calls(), 1);
    assertEquals(argon.calls(), 1);
    assertExists(creds.get(bcryptId));
    assertExists(creds.get(argonId));

    assertEquals(
      await service.signIn({ identifier: "o@b.co", password: "pw-three" }),
      null,
    );
    assertEquals(creds.has(orphanId), false);
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

    assertExists(
      await service.signIn({
        identifier: "dj@b.co",
        password: "correct horse battery staple",
      }),
    );
    assertExists(creds.get(userId));
    assertEquals(legacy.has(userId), false);
  });

  it("without legacyVerifiers, an imported-only user has no usable password", async () => {
    const { store, importUser } = makeLegacyStore();
    importUser("dev@b.co", "fakebcrypt$s3cret-pw");
    const service = serviceWithoutSignInFloor({ users: store });

    assertEquals(
      await service.signIn({ identifier: "dev@b.co", password: "s3cret-pw" }),
      null,
    );
  });
});

const DEFAULT_FLOOR_MS = 250;
const FLOOR_MS = 150;
const NATIVE_KDF_MS = 6;
const LEGACY_KDF_MS = 120;
const TIMING_SAMPLES = 5;
const MAX_BRANCH_RATIO = 1.5;
const FLOOR_TOLERANCE_MS = 25;
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

async function elapsedMs(run: () => Promise<unknown>): Promise<number> {
  const startedAt = performance.now();
  await run();
  return performance.now() - startedAt;
}

async function medianElapsedMs(run: () => Promise<unknown>): Promise<number> {
  const samples: number[] = [];
  for (let i = 0; i < TIMING_SAMPLES; i++) samples.push(await elapsedMs(run));
  samples.sort((a, b) => a - b);
  return samples[(samples.length - 1) / 2];
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
    const passwordless = await store.create({ email: "none@b.co" }, {
      hash: "x",
      salt: "x",
    });
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
    const { service, branches } = await seedBranches();

    for (const [branch, identifier] of Object.entries(branches)) {
      const took = await elapsedMs(async () =>
        assertEquals(
          await service.signIn({ identifier, password: "wrong-password" }),
          null,
        )
      );
      assert(
        took >= FLOOR_MS * 0.95,
        `${branch} returned after ${
          took.toFixed(1)
        }ms, under the ${FLOOR_MS}ms floor`,
      );
    }
  });

  it("costs the same whether the account is unknown, native, or still on an imported hash", async () => {
    const { service, branches } = await seedBranches();
    const medians = new Map<string, number>();

    for (const branch of RATIO_BRANCHES) {
      medians.set(
        branch,
        await medianElapsedMs(() =>
          service.signIn({
            identifier: branches[branch],
            password: "wrong-password",
          })
        ),
      );
    }

    const timings = [...medians.values()];
    const ratio = Math.max(...timings) / Math.min(...timings);
    const report = [...medians].map(([branch, ms]) =>
      `${branch} ${ms.toFixed(1)}ms`
    ).join(", ");
    assert(
      ratio <= MAX_BRANCH_RATIO,
      `rejected branches differ by ${
        ratio.toFixed(2)
      }x (bound ${MAX_BRANCH_RATIO}x): ${report}`,
    );
    assert(
      Math.max(...timings) <= FLOOR_MS + FLOOR_TOLERANCE_MS,
      `the slowest branch took ${
        Math.max(...timings).toFixed(1)
      }ms against a ${FLOOR_MS}ms floor — every branch that fits inside the floor lands exactly on it, so anything past it is a branch becoming visible: ${report}`,
    );
  });

  it("floors a rejection at 250ms with no option set", async () => {
    const { store } = makeLegacyStore();
    const service = new IdentityService<TestUser>({
      users: store,
      passwords: costedHasher(NATIVE_KDF_MS),
    });

    const took = await elapsedMs(() =>
      service.signIn({ identifier: "ghost@b.co", password: "wrong-password" })
    );

    assert(
      took >= DEFAULT_FLOOR_MS * 0.95,
      `a rejection returned after ${
        took.toFixed(1)
      }ms; the default floor is ${DEFAULT_FLOOR_MS}ms`,
    );
  });

  it("falls back to the default floor when the option is out of range", async () => {
    const { store } = makeLegacyStore();
    const service = new IdentityService<TestUser>({
      users: store,
      passwords: costedHasher(NATIVE_KDF_MS),
      failedSignInFloorMs: -1,
    });

    const took = await elapsedMs(() =>
      service.signIn({ identifier: "ghost@b.co", password: "wrong-password" })
    );

    assert(
      took >= DEFAULT_FLOOR_MS * 0.95,
      `a negative floor turned padding off: the rejection returned after ${
        took.toFixed(1)
      }ms`,
    );
  });

  it("does not delay a successful sign-in", async () => {
    const { store, service } = makeTimingService({
      failedSignInFloorMs: 5_000,
    });
    await store.create(
      { email: "native@b.co" },
      { hash: "costed:right-password", salt: "salt" },
    );

    const took = await elapsedMs(async () =>
      assertExists(
        await service.signIn({
          identifier: "native@b.co",
          password: "right-password",
        }),
      )
    );

    assert(took < 5_000, `a successful sign-in waited ${took.toFixed(1)}ms`);
  });

  it("returns as soon as the work is done when the floor is disabled", async () => {
    const { store, service } = makeTimingService({ failedSignInFloorMs: 0 });
    await store.create(
      { email: "native@b.co" },
      { hash: "costed:right-password", salt: "salt" },
    );

    const median = await medianElapsedMs(() =>
      service.signIn({ identifier: "native@b.co", password: "wrong-password" })
    );

    assert(
      median < FLOOR_MS / 2,
      `a rejection took ${median.toFixed(1)}ms with the floor disabled`,
    );
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
      rateLimiter: options?.limit !== undefined
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
    assertEquals(links.length, 1);
    assertEquals(links[0].to, "a@b.co");
    assertEquals(links[0].subject, user.id);
    assertEquals(
      links[0].url,
      `https://app.example/signin-link?token=${links[0].token}`,
    );

    assertEquals(await service.consumeSignInLink(links[0].token), {
      status: "success",
      userId: user.id,
    });
    assertEquals(await service.consumeSignInLink(links[0].token), {
      status: "invalid",
    });
  });

  it("requestSignInLink for an unknown email resolves identically but sends nothing", async () => {
    const { service, links, events, signUp } = makePasswordlessService();
    const user = await signUp();

    assertEquals(await service.requestSignInLink("ghost@b.co"), undefined);
    assertEquals(await service.requestSignInLink("a@b.co"), undefined);
    assertEquals(links.length, 1);

    assertEquals(eventsOfType(events, "signin_link.requested"), [
      { type: "signin_link.requested", email: "ghost@b.co" },
      { type: "signin_link.requested", email: "a@b.co", userId: user.id },
    ]);
  });

  it("consumeSignInLink distinguishes expired from invalid", async () => {
    using time = new FakeTime();
    const { service, links, events, signUp } = makePasswordlessService();
    await signUp();

    assertEquals(await service.consumeSignInLink("garbage"), {
      status: "invalid",
    });

    await service.requestSignInLink("a@b.co");
    time.tick(15 * 60 * 1000 + 1);
    assertEquals(await service.consumeSignInLink(links[0].token), {
      status: "expired",
    });

    assertEquals(eventsOfType(events, "signin_link.failed"), [
      { type: "signin_link.failed", reason: "invalid" },
      { type: "signin_link.failed", reason: "expired" },
    ]);
  });

  it("requestSignInLink honors a custom ttlMs", async () => {
    using time = new FakeTime();
    const { service, links, signUp } = makePasswordlessService();
    const user = await signUp();

    await service.requestSignInLink("a@b.co", { ttlMs: 60_000 });
    assertEquals(links[0].expiresAt, time.now + 60_000);
    time.tick(59_999);
    assertEquals(await service.consumeSignInLink(links[0].token), {
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
    assertEquals(links[0].expiresAt, time.now + 60_000);

    await service.requestSignInLink("a@b.co", { ttlMs: 5_000 });
    assertEquals(links[1].expiresAt, time.now + 5_000);

    time.tick(5_001);
    assertEquals(await service.consumeSignInLink(links[1].token), {
      status: "expired",
    });
  });

  it("re-requesting a sign-in link invalidates the outstanding one", async () => {
    const { service, links, signUp } = makePasswordlessService();
    const user = await signUp();

    await service.requestSignInLink("a@b.co");
    await service.requestSignInLink("a@b.co");
    assertEquals(await service.consumeSignInLink(links[0].token), {
      status: "invalid",
    });
    assertEquals(await service.consumeSignInLink(links[1].token), {
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
    const err = await assertRejects(
      () => service.requestSignInLink("a@b.co"),
      IdentityError,
    );
    assertEquals(err.code, "rate_limited");
    assertEquals(typeof err.retryAfterMs, "number");
    assertEquals(links.length, 2);
    lastEventOfType(events, "signin_link.rate_limited");

    await service.requestSignInLink("ghost@b.co");
    await service.requestSignInLink("ghost@b.co");
    await assertRejects(
      () => service.requestSignInLink("ghost@b.co"),
      IdentityError,
    );
  });

  it("case-folds the per-email throttle so casing variants share one window", async () => {
    const { service, signUp } = makePasswordlessService({ limit: 2 });
    await signUp();

    await service.requestSignInLink("a@b.co");
    await service.requestSignInLink("A@B.co");
    const err = await assertRejects(
      () => service.requestSignInLink("a@B.CO"),
      IdentityError,
    );
    assertEquals(
      err.code,
      "rate_limited",
      "casing variants must not each get a fresh rate bucket",
    );
  });

  it("log-only mode emits signin_link.rate_limited without blocking", async () => {
    const { service, links, events, signUp } = makePasswordlessService({
      limit: 1,
      protectionMode: "log-only",
    });
    await signUp();

    await service.requestSignInLink("a@b.co");
    await service.requestSignInLink("a@b.co");
    assertEquals(links.length, 2);
    const limited = lastEventOfType(events, "signin_link.rate_limited");
    assertEquals(limited.email, "a@b.co");
    assertEquals(limited.enforced, false);
  });

  it("requestSignInCode delivers a code that verifySignInCode redeems once", async () => {
    const { service, codes, events, signUp } = makePasswordlessService();
    const user = await signUp();

    await service.requestSignInCode("a@b.co");
    assertEquals(codes.length, 1);
    assertEquals(codes[0].to, "a@b.co");
    assertEquals(codes[0].subject, user.id);

    assertEquals(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[0].code,
      }),
      { status: "success", userId: user.id },
    );
    assertEquals(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[0].code,
      }),
      { status: "invalid" },
    );

    assertEquals(lastEventOfType(events, "signin_code.requested"), {
      type: "signin_code.requested",
      email: "a@b.co",
      userId: user.id,
    });
    assertEquals(lastEventOfType(events, "signin_code.verified"), {
      type: "signin_code.verified",
      userId: user.id,
    });
    assertEquals(lastEventOfType(events, "signin_code.failed"), {
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

    assertEquals(await service.requestSignInCode("a@b.co"), undefined);
    assert(capturedCode.length > 0);

    assertEquals(
      await service.verifySignInCode({ email: "a@b.co", code: capturedCode }),
      { status: "invalid" },
    );
    assertEquals(lastEventOfType(events, "delivery.failed"), {
      type: "delivery.failed",
      hook: "sendSignInCode",
      invalidated: true,
      error: "mailer down",
    });
    assertEquals(lastEventOfType(events, "signin_code.requested"), {
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

    assertEquals(await service.requestSignInCode("a@b.co"), undefined);
    assertEquals(await service.requestSignInCode("ghost@b.co"), undefined);
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

    assertEquals(delivered.length, 1);
    assertEquals(
      await service.verifySignInCode({ email: "a@b.co", code: delivered[0] }),
      { status: "success", userId: user.id },
    );
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

    assertEquals(await service.requestSignInCode("a@b.co"), undefined);
    assertEquals(lastEventOfType(events, "delivery.failed"), {
      type: "delivery.failed",
      hook: "sendSignInCode",
      invalidated: false,
      error: "mailer down",
    });
    assertEquals(
      await service.verifySignInCode({ email: "a@b.co", code: capturedCode }),
      { status: "success", userId: user.id },
      "invalidated: false means exactly this — an undelivered code stays live",
    );
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

    assertEquals(mailer.sent.length, 1);
    assertEquals(
      await service.verifySignInCode({
        email: "a@b.co",
        code: mailer.sent[0].replace("outbox:", ""),
      }),
      { status: "success", userId: user.id },
    );
  });

  it("requestSignInCode for an unknown email resolves identically but sends nothing", async () => {
    const { service, codes, events, signUp } = makePasswordlessService();
    await signUp();

    assertEquals(await service.requestSignInCode("ghost@b.co"), undefined);
    assertEquals(codes.length, 0);
    assertEquals(lastEventOfType(events, "signin_code.requested"), {
      type: "signin_code.requested",
      email: "ghost@b.co",
    });
  });

  it("verifySignInCode for an unknown email reports plain invalid", async () => {
    const { service, events, signUp } = makePasswordlessService();
    await signUp();

    assertEquals(
      await service.verifySignInCode({
        email: "ghost@b.co",
        code: "123456",
      }),
      { status: "invalid" },
    );
    assertEquals(lastEventOfType(events, "signin_code.failed"), {
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
    assertEquals(
      await service.verifySignInCode({ email: "a@b.co", code: "000000" }),
      { status: "invalid" },
    );
    assertEquals(
      await service.verifySignInCode({ email: "a@b.co", code: "000000" }),
      { status: "invalid" },
    );
    assertEquals(lastEventOfType(events, "signin_code.failed"), {
      type: "signin_code.failed",
      email: "a@b.co",
      reason: "locked",
    });
    assertEquals(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[0].code,
      }),
      { status: "invalid" },
    );

    await service.requestSignInCode("a@b.co");
    time.tick(60_001);
    assertEquals(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[1].code,
      }),
      { status: "invalid" },
    );
    assertEquals(lastEventOfType(events, "signin_code.failed"), {
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
    assertEquals(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[0].code,
      }),
      { status: "invalid" },
    );
    assertEquals(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[1].code,
      }),
      { status: "success", userId: user.id },
    );
  });

  it("request and verify share the code throttle window; success resets it", async () => {
    const { service, events, signUp } = makePasswordlessService({
      limit: 3,
    });
    await signUp();

    await service.requestSignInCode("a@b.co");
    await service.verifySignInCode({ email: "a@b.co", code: "000000" });
    await service.verifySignInCode({ email: "a@b.co", code: "000000" });
    const err = await assertRejects(
      () => service.verifySignInCode({ email: "a@b.co", code: "000000" }),
      IdentityError,
    );
    assertEquals(err.code, "rate_limited");
    lastEventOfType(events, "signin_code.rate_limited");

    const other = makePasswordlessService({ limit: 3 });
    const otherUser = await other.signUp();
    await other.service.requestSignInCode("a@b.co");
    await other.service.verifySignInCode({ email: "a@b.co", code: "000000" });
    assertEquals(
      await other.service.verifySignInCode({
        email: "a@b.co",
        code: other.codes[0].code,
      }),
      { status: "success", userId: otherUser.id },
    );
    await other.service.requestSignInCode("a@b.co");
    await other.service.requestSignInCode("a@b.co");
    assertEquals(other.codes.length, 3);
  });

  it("log-only mode emits signin_code.rate_limited without blocking", async () => {
    const { service, codes, events, signUp } = makePasswordlessService({
      limit: 1,
      protectionMode: "log-only",
    });
    await signUp();

    await service.requestSignInCode("a@b.co");
    await service.requestSignInCode("a@b.co");
    assertEquals(codes.length, 2);
    const limited = lastEventOfType(events, "signin_code.rate_limited");
    assertEquals(limited.email, "a@b.co");
    assertEquals(limited.enforced, false);
  });

  it("rate-limits a code request identically for a known and an unknown email", async () => {
    const known = makePasswordlessService({ limit: 1 });
    await known.signUp();
    const unknown = makePasswordlessService({ limit: 1 });

    for (const { service } of [known, unknown]) {
      await service.requestSignInCode("a@b.co");
      const error = await assertRejects(
        () => service.requestSignInCode("a@b.co"),
        IdentityError,
      );
      assertEquals(error.code, "rate_limited");
    }

    assertEquals(known.codes.length, 1);
    assertEquals(unknown.codes.length, 0);
  });

  it("requires the tokens/otp options for the flows that need them", async () => {
    const { store } = makeStore();
    const service = serviceWithoutSignInFloor({ users: store });
    await assertRejects(
      () => service.requestSignInLink("a@b.co"),
      Error,
      "requires a `tokens` option",
    );
    await assertRejects(
      () => service.requestSignInCode("a@b.co"),
      Error,
      "requires an `otp` option",
    );
    await assertRejects(
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

    assertExists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    assertEquals(checked, ["signin:a@b.co"]);
    assertEquals(cleared, ["signin:a@b.co"]);

    const error = await assertRejects(
      () =>
        service.signIn({ identifier: "a@b.co", password: "hunter2hunter2" }),
      IdentityError,
    );
    assertEquals(error.code, "rate_limited");
    assertEquals(error.retryAfterMs, 90_000);
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
      assertEquals(
        await service.signIn({ identifier: "a@b.co", password: "wrong" }),
        null,
      );
    }
    assertEquals(failures, 2);
    lastEventOfType(events, "lockout");

    assertEquals(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
      null,
    );
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

    assertEquals(shared.checked, []);
    assertEquals(signIn.checked, ["signin:a@b.co"]);
    assertEquals(passwordReset.checked, ["pwreset:a@b.co"]);
    assertEquals(emailVerification.checked, [`verifyemail:${user.id}`]);
    assertEquals(accountUnlock.checked, [`unlock:${user.id}`]);
    assertEquals(signInLink.checked, ["pwless:a@b.co"]);
    assertEquals(signInCode.checked, ["otp:signin:a@b.co"]);
  });

  it("falls back to the shared limiter for every unset flow", async () => {
    const shared = recordingLimiter();
    const { service, signUp } = makeLimitedService({
      rateLimiter: shared.limiter,
    });
    const user = await signUp();

    await runEveryFlow(service, user.id);

    assertEquals(shared.checked, [
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

    assertEquals(shared.checked, [
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

    assertEquals(
      shared.checked,
      ["signin:A@b.co", "signin:a@b.co"],
      "identifier equality is the app's to define, so only whitespace is normalized",
    );
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

    assertEquals(passwordReset.checked, ["pwreset:a@b.co"]);
    assertEquals(shared.checked, [
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
    const error = await assertRejects(
      () => service.requestPasswordReset("a@b.co"),
      IdentityError,
    );
    assertEquals(error.code, "rate_limited");

    for (let i = 0; i < 3; i++) {
      assertExists(
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

    assertEquals(signInCode.checked, [
      "otp:signin:a@b.co",
      "otp:signin:nobody@b.co",
    ]);
    assertEquals(codes.length, 1);
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

    assertEquals(stray.checked, []);
    assertEquals(signInCode.checked, ["otp:signin:a@b.co"]);
    assertEquals(codes.length, 1);
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

    assertExists(serviceWithoutSignInFloor(options));
  });

  it("applies a per-flow limiter with no shared limiter configured", async () => {
    const passwordReset = recordingLimiter();
    const { service, signUp } = makeLimitedService({
      rateLimiters: { passwordReset: passwordReset.limiter },
    });
    const user = await signUp();

    await runEveryFlow(service, user.id);

    assertEquals(passwordReset.checked, ["pwreset:a@b.co"]);
  });

  it("resets the sign-in window on the signIn limiter, not the shared one", async () => {
    const shared = recordingLimiter();
    const signIn = recordingLimiter();
    const { service, signUp } = makeLimitedService({
      rateLimiter: shared.limiter,
      rateLimiters: { signIn: signIn.limiter },
    });
    await signUp();

    assertExists(
      await service.signIn({
        identifier: "a@b.co",
        password: "hunter2hunter2",
      }),
    );
    await service.resetSignInThrottle("a@b.co");

    assertEquals(signIn.cleared, ["signin:a@b.co", "signin:a@b.co"]);
    assertEquals(shared.cleared, []);
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
    assertEquals(
      await service.verifySignInCode({
        email: "a@b.co",
        code: codes[0].code,
      }),
      { status: "success", userId: user.id },
    );

    assertEquals(signInCode.cleared, ["otp:signin:a@b.co"]);
    assertEquals(shared.cleared, []);
  });

  it("blocks a flow whose own limiter denies even when the shared one allows", async () => {
    const shared = recordingLimiter();
    const signInLink = recordingLimiter({ allowed: false });
    const { service, signUp } = makeLimitedService({
      rateLimiter: shared.limiter,
      rateLimiters: { signInLink: signInLink.limiter },
    });
    await signUp();

    const error = await assertRejects(
      () => service.requestSignInLink("a@b.co"),
      IdentityError,
    );
    assertEquals(error.code, "rate_limited");
    assertEquals(error.retryAfterMs, 60_000);
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

    assertExists(await reset("newpassword1"));

    assertEquals(await service.consumeSignInLink(links[0].token), {
      status: "invalid",
    });
  });

  it("refuses a sign-in code issued before the reset", async () => {
    const { service, codes, signUp, reset } = makeResetService();
    await signUp();
    await service.requestSignInCode("a@b.co");

    assertExists(await reset("newpassword1"));

    assertEquals(
      await service.verifySignInCode({ email: "a@b.co", code: codes[0].code }),
      { status: "invalid" },
    );
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

    assertEquals(await reset("newpassword1"), { userId: user.id });
    assertExists(
      await service.signIn({ identifier: "a@b.co", password: "newpassword1" }),
    );
    assertEquals(await service.consumeSignInLink(links[0].token), {
      status: "success",
      userId: user.id,
    });
  });

  it("still resets when the token store throws while deleting by subject", async () => {
    using consoleError = stub(console, "error");
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

    assertEquals(await reset("newpassword1"), { userId: user.id });
    assertExists(
      await service.signIn({ identifier: "a@b.co", password: "newpassword1" }),
    );
    assertEquals(consoleError.calls.length, 1);
  });
});
