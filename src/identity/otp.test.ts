import {
  assertEquals,
  assertExists,
  assertMatch,
  assertRejects,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { FakeTime } from "@std/testing/time";

import { RateLimiter, type RateLimiterLike } from "./rate-limit.ts";
import { IdentityError } from "./errors.ts";
import {
  EmailOtpService,
  MemoryOtpStore,
  otpRateKey,
  type OtpRecord,
  type OtpStore,
} from "./otp.ts";

function makeService(options?: {
  digits?: number;
  ttlMs?: number;
  maxAttempts?: number;
  rateLimiter?: RateLimiterLike;
  protectionMode?: "enforce" | "log-only";
}) {
  const store = new MemoryOtpStore();
  const delivered: Array<{ code: string; expiresAt: number }> = [];
  const service = new EmailOtpService({ store, ...options });
  const request = (email: string, purpose = "signin") =>
    service.request({
      email,
      purpose,
      onDeliver: (code, expiresAt) => {
        delivered.push({ code, expiresAt });
      },
    });
  return { service, store, delivered, request };
}

describe("EmailOtpService", () => {
  it("request delivers a numeric code of the configured length", async () => {
    const { delivered, request } = makeService({ digits: 8 });
    await request("a@b.co");
    assertEquals(delivered.length, 1);
    assertMatch(delivered[0].code, /^\d{8}$/);
  });

  it("defaults to 6 digits and a 10 minute lifetime", async () => {
    using time = new FakeTime();
    const { delivered, request } = makeService();
    const { expiresAt } = await request("a@b.co");
    assertMatch(delivered[0].code, /^\d{6}$/);
    assertEquals(expiresAt, time.now + 10 * 60 * 1000);
    assertEquals(delivered[0].expiresAt, expiresAt);
  });

  it("stores only a hash of the code", async () => {
    const { store, delivered, request } = makeService();
    await request("a@b.co");
    const record = await store.findActive("a@b.co", "signin");
    assertExists(record);
    assertEquals(record.attempts, 0);
    assertEquals(record.codeHash.includes(delivered[0].code), false);
  });

  it("verifies the right code once (single-use)", async () => {
    const { service, delivered, request } = makeService();
    await request("a@b.co");
    const code = delivered[0].code;
    assertEquals(
      await service.verify({ email: "a@b.co", purpose: "signin", code }),
      { status: "success" },
    );
    assertEquals(
      await service.verify({ email: "a@b.co", purpose: "signin", code }),
      { status: "invalid" },
    );
  });

  it("tolerates whitespace in the submitted code", async () => {
    const { service, delivered, request } = makeService();
    await request("a@b.co");
    const code = delivered[0].code;
    const spaced = ` ${code.slice(0, 3)} ${code.slice(3)} `;
    assertEquals(
      await service.verify({
        email: "a@b.co",
        purpose: "signin",
        code: spaced,
      }),
      { status: "success" },
    );
  });

  it("rejects a wrong code, the right code for another email, and an unknown email", async () => {
    const { service, delivered, request } = makeService();
    await request("a@b.co");
    const code = delivered[0].code;
    assertEquals(
      await service.verify({
        email: "a@b.co",
        purpose: "signin",
        code: "000000",
      }),
      { status: "invalid" },
    );
    assertEquals(
      await service.verify({ email: "x@b.co", purpose: "signin", code }),
      { status: "invalid" },
    );
    assertEquals(
      await service.verify({
        email: "ghost@b.co",
        purpose: "signin",
        code: "123456",
      }),
      { status: "invalid" },
    );
  });

  it("scopes codes by purpose", async () => {
    const { service, delivered, request } = makeService();
    await request("a@b.co", "signin");
    const code = delivered[0].code;
    assertEquals(
      await service.verify({ email: "a@b.co", purpose: "step-up", code }),
      { status: "invalid" },
    );
    assertEquals(
      await service.verify({ email: "a@b.co", purpose: "signin", code }),
      { status: "success" },
    );
  });

  it("locks the code when the attempt budget is spent, then reports invalid", async () => {
    const { service, delivered, request } = makeService({ maxAttempts: 3 });
    await request("a@b.co");
    const code = delivered[0].code;
    const wrong = { email: "a@b.co", purpose: "signin", code: "000000" };
    assertEquals(await service.verify(wrong), { status: "invalid" });
    assertEquals(await service.verify(wrong), { status: "invalid" });
    assertEquals(await service.verify(wrong), { status: "locked" });
    assertEquals(
      await service.verify({ email: "a@b.co", purpose: "signin", code }),
      { status: "invalid" },
    );
  });

  it("accepts the right code on the last budgeted attempt", async () => {
    const { service, delivered, request } = makeService({ maxAttempts: 3 });
    await request("a@b.co");
    const wrong = { email: "a@b.co", purpose: "signin", code: "000000" };
    assertEquals(await service.verify(wrong), { status: "invalid" });
    assertEquals(await service.verify(wrong), { status: "invalid" });
    assertEquals(
      await service.verify({
        email: "a@b.co",
        purpose: "signin",
        code: delivered[0].code,
      }),
      { status: "success" },
    );
  });

  it("bounds concurrent wrong guesses to the attempt budget (no stale-count bypass)", async () => {
    const store = new MemoryOtpStore();
    let compared = 0;
    const countingStore: OtpStore = {
      create: (record) => store.create(record),
      findActive: async (email, purpose) => {
        const record = await store.findActive(email, purpose);
        if (!record) return null;
        return {
          ...record,
          get codeHash(): string {
            compared++;
            return record.codeHash;
          },
        };
      },
      recordAttempt: (id) => store.recordAttempt(id),
      consume: (id) => store.consume(id),
      invalidateById: (id) => store.invalidateById(id),
      invalidate: (email, purpose) => store.invalidate(email, purpose),
    };
    const delivered: Array<{ code: string; expiresAt: number }> = [];
    const service = new EmailOtpService({
      store: countingStore,
      maxAttempts: 3,
    });
    await service.request({
      email: "a@b.co",
      purpose: "signin",
      onDeliver: (code, expiresAt) => {
        delivered.push({ code, expiresAt });
      },
    });

    const wrong = (n: number) =>
      service.verify({
        email: "a@b.co",
        purpose: "signin",
        code: `90000${n}`.slice(-6),
      });
    await Promise.all([1, 2, 3, 4, 5, 6, 7, 8].map(wrong));
    assertEquals(
      compared,
      3,
      `exactly maxAttempts guesses reach the compare, got ${compared}`,
    );
    assertEquals(
      await service.verify({
        email: "a@b.co",
        purpose: "signin",
        code: delivered[0].code,
      }),
      { status: "invalid" },
      "the budget must be spent — the real code no longer works",
    );
  });

  it("reports expired for a code past its lifetime", async () => {
    using time = new FakeTime();
    const { service, delivered, request } = makeService({ ttlMs: 60_000 });
    await request("a@b.co");
    time.tick(60_001);
    assertEquals(
      await service.verify({
        email: "a@b.co",
        purpose: "signin",
        code: delivered[0].code,
      }),
      { status: "expired" },
    );
  });

  it("re-requesting invalidates the prior code", async () => {
    const { service, delivered, request } = makeService();
    await request("a@b.co");
    await request("a@b.co");
    assertEquals(
      await service.verify({
        email: "a@b.co",
        purpose: "signin",
        code: delivered[0].code,
      }),
      { status: "invalid" },
    );
    assertEquals(
      await service.verify({
        email: "a@b.co",
        purpose: "signin",
        code: delivered[1].code,
      }),
      { status: "success" },
    );
  });

  it("invalidate drops the active code for (email, purpose) only", async () => {
    const { service, delivered, request } = makeService();
    await request("a@b.co");
    await request("a@b.co", "step-up");

    await service.invalidate("a@b.co", "signin");

    assertEquals(
      await service.verify({
        email: "a@b.co",
        purpose: "signin",
        code: delivered[0].code,
      }),
      { status: "invalid" },
    );
    assertEquals(
      await service.verify({
        email: "a@b.co",
        purpose: "step-up",
        code: delivered[1].code,
      }),
      { status: "success" },
    );
  });

  it("invalidate resolves when nothing is active", async () => {
    const { service } = makeService();
    assertEquals(await service.invalidate("ghost@b.co", "signin"), undefined);
  });

  it("invalidateCode drops one code by id and spares a newer one", async () => {
    const { service, delivered, request } = makeService();
    const first = await request("a@b.co");
    const second = await request("a@b.co");

    await service.invalidateCode(first.id);

    assertEquals(
      await service.verify({
        email: "a@b.co",
        purpose: "signin",
        code: delivered[1].code,
      }),
      { status: "success" },
      "the newer code is untouched by an older code's invalidation",
    );
    assertEquals(second.id === first.id, false);
  });

  it("invalidateCode resolves for an unknown id", async () => {
    const { service } = makeService();
    assertEquals(await service.invalidateCode(crypto.randomUUID()), undefined);
  });

  it("hands onDeliver the stored record's id", async () => {
    const store = new MemoryOtpStore();
    const service = new EmailOtpService({ store });
    let deliveredId = "";
    const { id } = await service.request({
      email: "a@b.co",
      purpose: "signin",
      onDeliver: (_code, _expiresAt, codeId) => {
        deliveredId = codeId;
      },
    });
    assertEquals(deliveredId, id);
    assertEquals((await store.findActive("a@b.co", "signin"))?.id, id);
  });

  it("issues a different code per request", async () => {
    const { delivered, request } = makeService({ digits: 10 });
    await request("a@b.co");
    await request("a@b.co");
    assertEquals(delivered[0].code === delivered[1].code, false);
  });

  it("throttles requests per (purpose, email) and throws rate_limited", async () => {
    const { delivered, request } = makeService({
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60_000 }),
    });
    await request("a@b.co");
    await request("a@b.co");
    const err = await assertRejects(() => request("a@b.co"), IdentityError);
    assertEquals(err.code, "rate_limited");
    assertEquals(typeof err.retryAfterMs, "number");
    assertEquals(delivered.length, 2);

    await request("a@b.co", "step-up");
    await request("other@b.co");
    assertEquals(delivered.length, 4);
  });

  it("log-only mode never blocks a throttled request", async () => {
    const { delivered, request } = makeService({
      rateLimiter: new RateLimiter({ limit: 1, windowMs: 60_000 }),
      protectionMode: "log-only",
    });
    await request("a@b.co");
    await request("a@b.co");
    assertEquals(delivered.length, 2);
  });

  it("checks the limiter under the shared otp rate key", async () => {
    const keys: string[] = [];
    const rateLimiter: RateLimiterLike = {
      check: (key) => {
        keys.push(key);
        return Promise.resolve({
          allowed: true,
          remaining: 1,
          resetAt: 0,
          retryAfterMs: 0,
        });
      },
      reset: () => Promise.resolve(),
    };
    const { request } = makeService({ rateLimiter });
    await request("a@b.co");
    await request("a@b.co", "step-up");
    assertEquals(keys, [
      otpRateKey("signin", "a@b.co"),
      otpRateKey("step-up", "a@b.co"),
    ]);
  });

  it("treats casing variants of an email as one mailbox end to end", async () => {
    const { service, delivered, request } = makeService();
    await request("Foo@b.co");
    assertEquals(
      await service.verify({
        email: "foo@b.co",
        purpose: "signin",
        code: delivered[0].code,
      }),
      { status: "success" },
    );
  });

  it("invalidates a prior code across casing variants", async () => {
    const { service, delivered, request } = makeService();
    await request("Foo@b.co");
    await request("foo@b.co");
    assertEquals(
      await service.verify({
        email: "FOO@B.CO",
        purpose: "signin",
        code: delivered[0].code,
      }),
      { status: "invalid" },
    );
    assertEquals(
      await service.verify({
        email: "foo@b.co",
        purpose: "signin",
        code: delivered[1].code,
      }),
      { status: "success" },
    );
  });

  it("shares one throttle window across casing variants of an email", async () => {
    const { delivered, request } = makeService({
      rateLimiter: new RateLimiter({ limit: 2, windowMs: 60_000 }),
    });
    await request("Foo@b.co");
    await request("foo@b.co");
    const error = await assertRejects(
      () => request("FOO@B.CO"),
      IdentityError,
    );
    assertEquals(error.code, "rate_limited");
    assertEquals(delivered.length, 2);
  });

  it("fails closed when the limiter itself throws under enforcement", async () => {
    const rateLimiter: RateLimiterLike = {
      check: () => Promise.reject(new Error("limiter down")),
      reset: () => Promise.resolve(),
    };
    const { delivered, store, request } = makeService({ rateLimiter });
    const error = await assertRejects(
      () => request("a@b.co"),
      IdentityError,
      "too many code requests",
    );
    assertEquals(error.code, "rate_limited");
    assertEquals(delivered.length, 0);
    assertEquals(await store.findActive("a@b.co", "signin"), null);
  });

  it("lets a throwing limiter through in log-only mode", async () => {
    const rateLimiter: RateLimiterLike = {
      check: () => Promise.reject(new Error("limiter down")),
      reset: () => Promise.resolve(),
    };
    const { delivered, request } = makeService({
      rateLimiter,
      protectionMode: "log-only",
    });
    await request("a@b.co");
    assertEquals(delivered.length, 1);
  });
});

describe("MemoryOtpStore", () => {
  function makeRecord(overrides?: Partial<OtpRecord>): OtpRecord {
    return {
      id: crypto.randomUUID(),
      email: "a@b.co",
      purpose: "signin",
      codeHash: "hash",
      expiresAt: Date.now() + 60_000,
      attempts: 0,
      maxAttempts: 5,
      createdAt: Date.now(),
      ...overrides,
    };
  }

  it("findActive returns the newest active record for (email, purpose)", async () => {
    const store: OtpStore = new MemoryOtpStore();
    const older = makeRecord({ createdAt: 1 });
    const newer = makeRecord({ createdAt: 2 });
    await store.create(older);
    await store.create(newer);
    await store.create(makeRecord({ email: "x@b.co", createdAt: 3 }));
    await store.create(makeRecord({ purpose: "step-up", createdAt: 3 }));
    assertEquals((await store.findActive("a@b.co", "signin"))?.id, newer.id);
    assertEquals(await store.findActive("ghost@b.co", "signin"), null);
  });

  it("consume deactivates one record", async () => {
    const store: OtpStore = new MemoryOtpStore();
    const record = makeRecord();
    await store.create(record);
    await store.consume(record.id);
    assertEquals(await store.findActive("a@b.co", "signin"), null);
  });

  it("invalidateById deactivates one record, leaving the rest active", async () => {
    const store: OtpStore = new MemoryOtpStore();
    const older = makeRecord({ createdAt: 1 });
    const newer = makeRecord({ createdAt: 2 });
    await store.create(older);
    await store.create(newer);

    await store.invalidateById(older.id);
    assertEquals((await store.findActive("a@b.co", "signin"))?.id, newer.id);

    await store.invalidateById("missing");
    assertEquals((await store.findActive("a@b.co", "signin"))?.id, newer.id);
  });

  it("invalidate deactivates every record for (email, purpose) only", async () => {
    const store: OtpStore = new MemoryOtpStore();
    await store.create(makeRecord({ createdAt: 1 }));
    await store.create(makeRecord({ createdAt: 2 }));
    const other = makeRecord({ email: "x@b.co" });
    await store.create(other);
    await store.invalidate("a@b.co", "signin");
    assertEquals(await store.findActive("a@b.co", "signin"), null);
    assertEquals((await store.findActive("x@b.co", "signin"))?.id, other.id);
  });

  it("recordAttempt increments and returns the count; unknown id returns 0", async () => {
    const store: OtpStore = new MemoryOtpStore();
    const record = makeRecord();
    await store.create(record);
    assertEquals(await store.recordAttempt(record.id), 1);
    assertEquals(await store.recordAttempt(record.id), 2);
    assertEquals((await store.findActive("a@b.co", "signin"))?.attempts, 2);
    assertEquals(await store.recordAttempt("missing"), 0);
  });

  it("still returns an expired record so the service can report expiry", async () => {
    const store: OtpStore = new MemoryOtpStore();
    const record = makeRecord({ expiresAt: Date.now() - 1 });
    await store.create(record);
    assertEquals((await store.findActive("a@b.co", "signin"))?.id, record.id);
  });
});
