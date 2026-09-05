/**
 * Email one-time-code primitives — the "email me a code" half of passwordless
 * sign-in, and a reusable step-up factor.
 *
 * A short numeric code has a different threat model than a URL token: it is
 * **guessable online** (a 6-digit code is one in a million), so unlike
 * {@link TokenFlowService} tokens every code carries an attempt budget — wrong
 * tries are counted and the code is invalidated (`locked`) when the budget is
 * spent. Codes are stored **hashed** (SHA-256, domain-bound to the email +
 * purpose) and verified with a constant-time compare; the raw code exists only
 * in the delivery callback.
 *
 * Storage is an app-owned {@link OtpStore} (a {@link MemoryOtpStore} ships for
 * dev/tests) and delivery is a caller-supplied callback — the package owns the
 * lifecycle, never your tables or your mailer. `purpose` is a free string, so
 * the same service covers sign-in codes today and step-up / verification codes
 * later.
 *
 * @module
 */

import { sha256Hash } from "../server/utils/hash.ts";
import { timingSafeEqualString } from "../utils/crypto.ts";
import { enforceRateLimit, type RateLimiterLike } from "./rate-limit.ts";

function foldEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * The rate-limit key a one-time-code request is throttled under. Exported so
 * `IdentityService` throttles its sign-in-code flow under the very key
 * {@link EmailOtpService} would, instead of re-typing the format and drifting
 * into two windows for one operation.
 *
 * The email is case-folded, matching how {@link EmailOtpService} folds at its
 * entry points, so casing variants of one mailbox share a window rather than
 * each earning a fresh send budget.
 */
export function otpRateKey(purpose: string, email: string): string {
  return `otp:${purpose}:${foldEmail(email)}`;
}

/**
 * A stored one-time-code record. Holds the code's **hash**, never the raw
 * code — a leaked record can't be replayed, and a 6-digit hash space is only
 * brute-forceable while the record is live and has attempts left.
 */
export interface OtpRecord {
  /** Opaque unique id (the store's key for attempt/consume updates). */
  id: string;
  /** The email the code was issued to, case-folded by the service. */
  email: string;
  /** What the code authorizes (e.g. `"signin"`). */
  purpose: string;
  /** Hash of the raw code (opaque to the store; the service computes it). */
  codeHash: string;
  /** Expiry, epoch ms. */
  expiresAt: number;
  /** Wrong verification attempts so far. */
  attempts: number;
  /** Attempt budget; reaching it invalidates the code. */
  maxAttempts: number;
  /** Created, epoch ms. */
  createdAt: number;
}

/**
 * App-owned persistence for {@link EmailOtpService}. "Active" means neither
 * consumed nor invalidated; expiry stays the service's concern so it can report
 * `expired` distinctly. Back it with your database in production.
 */
export interface OtpStore {
  /** Persist a new active record. */
  create(record: OtpRecord): Promise<void>;
  /**
   * The most recently created active record for `(email, purpose)`, or `null`.
   * Must still return an expired record — the service reports expiry itself.
   */
  findActive(email: string, purpose: string): Promise<OtpRecord | null>;
  /**
   * Atomically increment a record's attempt count and return the new count
   * (0 if unknown). Must be a single atomic operation (e.g.
   * `UPDATE … SET attempts = attempts + 1 RETURNING attempts`), never a
   * read-then-write: {@link EmailOtpService.verify} gates the guess budget on
   * the returned value, so a non-atomic implementation lets concurrent
   * verifies bypass `maxAttempts`.
   */
  recordAttempt(id: string): Promise<number>;
  /**
   * Atomically consume an active code. Return `true` only to the caller that
   * removed it from the active set; concurrent or repeated claims return
   * `false`. Use a conditional delete/update with RETURNING in persistent stores.
   */
  consume(id: string): Promise<boolean>;
  /**
   * Deactivate the one record with this id, for a code that was never usable —
   * the send carrying it failed. Separate from {@link OtpStore.consume} so a
   * store that records *why* a code left the active set can tell a redeemed
   * code from a discarded one, and from {@link OtpStore.invalidate} so a
   * concurrent request's newer code survives. A no-op for an unknown id.
   */
  invalidateById(id: string): Promise<void>;
  /** Deactivate every active record for `(email, purpose)`. */
  invalidate(email: string, purpose: string): Promise<void>;
}

/** Options for {@link EmailOtpService}. */
export interface EmailOtpServiceOptions {
  /** App-owned code storage. */
  store: OtpStore;
  /** Code length in digits. Defaults to `6`. */
  digits?: number;
  /** Code lifetime in ms. Defaults to 10 minutes. */
  ttlMs?: number;
  /** Wrong-attempt budget before the code is invalidated. Defaults to `5`. */
  maxAttempts?: number;
  /**
   * Throttles {@link EmailOtpService.request} per `(purpose, email)` (key
   * {@link otpRateKey}, which case-folds the email so casing variants of one
   * mailbox cannot each earn a fresh send budget). When exceeded and
   * `protectionMode` is `"enforce"`, `request` throws
   * {@link IdentityError} `rate_limited`. A limiter whose
   * `check` itself throws is trapped the way every identity flow traps it:
   * under `"enforce"` it fails closed as the same `rate_limited` error, and
   * under `"log-only"` the attempt proceeds. For direct use of this service;
   * `IdentityService` never sets it, because it throttles the sign-in-code flow
   * itself and a second limiter reachable only on the known-email path would be
   * an enumeration oracle.
   */
  rateLimiter?: RateLimiterLike;
  /**
   * `"enforce"` (default) blocks a rate-limited request; `"log-only"` lets it
   * proceed so adopters can observe thresholds before turning enforcement on.
   */
  protectionMode?: "enforce" | "log-only";
}

/** Options for {@link EmailOtpService.request}. */
export interface RequestOtpOptions {
  /** The email the code is issued to. Case-folded, so casing need not match later. */
  email: string;
  /** What the code authorizes (e.g. `"signin"`); free string. */
  purpose: string;
  /**
   * Receives the raw code for delivery — the only place it ever exists. Send
   * it via your transport; it is not stored or recoverable. `codeId` identifies
   * the stored record, for {@link EmailOtpService.invalidateCode} when a send
   * fails.
   */
  onDeliver: (
    code: string,
    expiresAt: number,
    codeId: string,
  ) => Promise<void> | void;
}

/** What {@link EmailOtpService.request} returns after storing + delivering. */
export interface RequestedOtp {
  /** When the code expires, epoch ms. */
  expiresAt: number;
  /**
   * The stored record's id — pass it to
   * {@link EmailOtpService.invalidateCode} to drop exactly this code.
   */
  id: string;
}

/** Options for {@link EmailOtpService.verify}. */
export interface VerifyOtpOptions {
  /** The email the code was issued to. Case-folded, so any casing matches. */
  email: string;
  /** The purpose the code was issued for. */
  purpose: string;
  /** The submitted code; whitespace is tolerated. */
  code: string;
}

/**
 * The outcome of {@link EmailOtpService.verify}. `invalid` covers both a wrong
 * code and no active code — indistinguishable on purpose. `locked` is reported
 * once, on the attempt that spends the budget; afterwards the code is gone and
 * further tries report `invalid`.
 */
export type VerifyOtpResult =
  | { status: "success" }
  | { status: "invalid" }
  | { status: "expired" }
  | { status: "locked" };

function generateNumericCode(digits: number): string {
  if (!Number.isInteger(digits) || digits < 1) {
    throw new RangeError("digits must be a positive integer");
  }
  let code = "";
  while (code.length < digits) {
    const bytes = crypto.getRandomValues(new Uint8Array(digits * 2));
    for (const byte of bytes) {
      if (byte < 250 && code.length < digits) code += String(byte % 10);
    }
  }
  return code;
}

function hashOtpCode(
  email: string,
  purpose: string,
  code: string,
): Promise<string> {
  return sha256Hash(`${purpose}\n${email}\n${code}`);
}

const DEFAULT_DIGITS = 6;
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const DEFAULT_MAX_ATTEMPTS = 5;

/**
 * Issues and verifies short-lived numeric one-time codes over an app-owned
 * {@link OtpStore}. Purpose-generic: `"signin"` today, step-up or verification
 * codes tomorrow — one instance can serve them all.
 *
 * @example
 * ```ts
 * const otp = new EmailOtpService({ store: new MemoryOtpStore() });
 * await otp.request({
 *   email: user.email,
 *   purpose: "signin",
 *   onDeliver: (code) => mailer.send(user.email, `Your code: ${code}`),
 * });
 * // …the user types the code back in…
 * const result = await otp.verify({ email: user.email, purpose: "signin", code });
 * if (result.status === "success") await establishSession(user);
 * ```
 */
export class EmailOtpService {
  readonly #store: OtpStore;
  readonly #digits: number;
  readonly #ttlMs: number;
  readonly #maxAttempts: number;
  readonly #rateLimiter?: RateLimiterLike;
  readonly #enforce: boolean;

  /** Wires the app-owned store and applies the digit/TTL/attempt defaults. */
  constructor(options: EmailOtpServiceOptions) {
    this.#store = options.store;
    this.#digits = options.digits ?? DEFAULT_DIGITS;
    this.#ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.#maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.#rateLimiter = options.rateLimiter;
    this.#enforce = (options.protectionMode ?? "enforce") === "enforce";
  }

  /**
   * Mint a code for `(email, purpose)`: invalidates any prior active code,
   * stores the new code's hash, and hands the raw code to `onDeliver`. Throws
   * {@link IdentityError} `rate_limited` when a configured `rateLimiter` is
   * exceeded — or is itself broken — in enforce mode; nothing is stored or
   * delivered on that path.
   *
   * A throw from `onDeliver` propagates and the stored code stays active — so a
   * failed send would otherwise leave a live, unsent code behind. Trap it and
   * call {@link EmailOtpService.invalidateCode} with the `codeId` you were
   * handed if that matters (which is what `IdentityService` does for its
   * `sendSignInCode` hook).
   */
  async request(options: RequestOtpOptions): Promise<RequestedOtp> {
    const { purpose } = options;
    const email = foldEmail(options.email);
    await enforceRateLimit({
      rateLimiter: this.#rateLimiter,
      key: otpRateKey(purpose, email),
      message: "too many code requests",
      enforce: this.#enforce,
    });
    await this.#store.invalidate(email, purpose);
    const code = generateNumericCode(this.#digits);
    const now = Date.now();
    const expiresAt = now + this.#ttlMs;
    const id = crypto.randomUUID();
    await this.#store.create({
      id,
      email,
      purpose,
      codeHash: await hashOtpCode(email, purpose, code),
      expiresAt,
      attempts: 0,
      maxAttempts: this.#maxAttempts,
      createdAt: now,
    });
    await options.onDeliver(code, expiresAt, id);
    return { expiresAt, id };
  }

  /**
   * Drop **every** active code for `(email, purpose)` without verifying one —
   * for an abandoned flow, or an email that no longer belongs to the account.
   * A no-op when none is active.
   *
   * Not for a failed send: a slow failure would drop whatever code is active
   * *now*, which may be a newer one a retry already delivered. Use
   * {@link EmailOtpService.invalidateCode} there.
   */
  invalidate(email: string, purpose: string): Promise<void> {
    return this.#store.invalidate(foldEmail(email), purpose);
  }

  /**
   * Drop exactly the code with this id — the `codeId` handed to `onDeliver`, or
   * {@link RequestedOtp.id}. Scoped to the one record, so a code another
   * request has since minted and delivered survives. A no-op for an unknown id.
   */
  invalidateCode(id: string): Promise<void> {
    return this.#store.invalidateById(id);
  }

  /**
   * Check a submitted code against the active record for `(email, purpose)`.
   * The hash compare is constant-time and runs even when no active record
   * exists, so a missing account or code is not distinguishable by timing. The
   * attempt is reserved atomically — via the store's `recordAttempt` return
   * value — **before** the compare, so concurrent verifies of one live code
   * can't each test a guess against a stale pre-increment count: at most
   * `maxAttempts` guesses ever reach the comparison. Spending the budget
   * invalidates the code (`locked`); success consumes it (single-use).
   */
  async verify(options: VerifyOtpOptions): Promise<VerifyOtpResult> {
    const { purpose } = options;
    const email = foldEmail(options.email);
    const code = options.code.replaceAll(/\s+/g, "");
    const submittedHash = await hashOtpCode(email, purpose, code);
    const record = await this.#store.findActive(email, purpose);
    if (!record) {
      timingSafeEqualString(submittedHash, submittedHash);
      return { status: "invalid" };
    }
    if (record.expiresAt <= Date.now()) return { status: "expired" };

    const attempts = await this.#store.recordAttempt(record.id);
    if (attempts > record.maxAttempts) {
      await this.#store.invalidate(email, purpose);
      return { status: "locked" };
    }
    if (timingSafeEqualString(record.codeHash, submittedHash)) {
      return {
        status: await this.#store.consume(record.id) ? "success" : "invalid",
      };
    }
    if (attempts === record.maxAttempts) {
      await this.#store.invalidate(email, purpose);
      return { status: "locked" };
    }
    return { status: "invalid" };
  }
}

/**
 * In-memory {@link OtpStore} for development and tests. Records are lost on
 * restart; back the contract with a database for production.
 */
export class MemoryOtpStore implements OtpStore {
  #records = new Map<string, OtpRecord>();
  #active = new Set<string>();

  /** Persist a record and mark it active. */
  create(record: OtpRecord): Promise<void> {
    this.#records.set(record.id, record);
    this.#active.add(record.id);
    return Promise.resolve();
  }

  /** The newest active record for `(email, purpose)`, expired or not; else `null`. */
  findActive(email: string, purpose: string): Promise<OtpRecord | null> {
    let latest: OtpRecord | null = null;
    for (const id of this.#active) {
      const record = this.#records.get(id);
      if (
        record && record.email === email && record.purpose === purpose &&
        (!latest || record.createdAt >= latest.createdAt)
      ) {
        latest = record;
      }
    }
    return Promise.resolve(latest);
  }

  /** Bump a record's attempt count; returns the new count, or 0 if unknown. */
  recordAttempt(id: string): Promise<number> {
    const record = this.#records.get(id);
    if (!record) return Promise.resolve(0);
    record.attempts++;
    return Promise.resolve(record.attempts);
  }

  /** Atomically deactivate one active record; return whether it was claimed. */
  consume(id: string): Promise<boolean> {
    return Promise.resolve(this.#active.delete(id));
  }

  /** Deactivate one undelivered record; a no-op if the id is unknown. */
  invalidateById(id: string): Promise<void> {
    this.#active.delete(id);
    return Promise.resolve();
  }

  /** Deactivate every active record for `(email, purpose)`. */
  invalidate(email: string, purpose: string): Promise<void> {
    for (const id of [...this.#active]) {
      const record = this.#records.get(id);
      if (record && record.email === email && record.purpose === purpose) {
        this.#active.delete(id);
      }
    }
    return Promise.resolve();
  }
}
