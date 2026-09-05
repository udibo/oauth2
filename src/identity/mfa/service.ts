/**
 * The MFA orchestrator: a small service that wires the TOTP and recovery-code
 * primitives to an app-owned {@link MfaStore} — the same thin storage seam as
 * every other layer here. It owns the lifecycle rules (pending vs. active
 * secrets, TOTP replay rejection, recovery-code burning); the app owns the
 * rows, the routes, and the policy for *when* MFA is required.
 *
 * @module
 */

import { IdentityError } from "../errors.ts";
import {
  dispatchIdentityEvent,
  type IdentityEvent,
  type IdentityEventHook,
} from "../events.ts";
import { enforceRateLimit, type RateLimiterLike } from "../rate-limit.ts";
import {
  generateRecoveryCodes,
  hashRecoveryCode,
  normalizeRecoveryCode,
  RECOVERY_CODE_LENGTH,
} from "./recovery-codes.ts";
import {
  buildOtpauthUri,
  generateTotpSecret,
  type TotpAlgorithm,
  validateTotpParams,
  verifyTotpCode,
} from "./totp.ts";

/**
 * A user's TOTP state as the store persists it. `secretBase32` is a symmetric
 * key — encrypt it at rest. A record may hold only a pending secret (enrollment
 * started but unconfirmed) or only an active one.
 */
export interface MfaTotpRecord {
  /** The active, confirmed secret. Absent until enrollment is confirmed. */
  secretBase32?: string;
  /**
   * The highest time-step counter a code has been accepted for — the replay
   * guard. Present whenever `secretBase32` is.
   */
  lastStep?: number;
  /** A generated-but-unconfirmed secret awaiting {@link MfaService.confirmEnrollment}. */
  pendingSecretBase32?: string;
}

/**
 * App-owned persistence for {@link MfaService}, keyed by user id. Implement it
 * over your database; {@link MemoryMfaStore} ships for dev and tests. The
 * service never reads or writes anything else — encrypt `secretBase32` /
 * `pendingSecretBase32` at rest however your app seals secrets (they are
 * symmetric keys, not hashes).
 *
 * Three methods are the concurrency guards of the whole design and **must be
 * atomic** in a real implementation (a conditional `UPDATE`/`DELETE`, not a
 * read-then-write): {@link activateTotp}, {@link advanceLastStep}, and
 * {@link consumeRecoveryHash}.
 */
export interface MfaStore {
  /** Return the user's TOTP record, or `undefined` when none exists. */
  getTotp(userId: string): Promise<MfaTotpRecord | undefined>;
  /**
   * Save a pending (unconfirmed) secret, preserving any active credential.
   * A repeat call overwrites the previous pending secret.
   */
  setPendingTotp(userId: string, secretBase32: string): Promise<void>;
  /**
   * Atomically promote the pending secret to active — but only when the
   * stored pending secret still equals `secretBase32` (the secret the
   * confirmation code was verified against): set `secretBase32`, set
   * `lastStep`, clear the pending value, and return `true`. Return `false`
   * without changing anything when the pending secret is missing or has been
   * replaced by a newer enrollment.
   */
  activateTotp(
    userId: string,
    secretBase32: string,
    lastStep: number,
  ): Promise<boolean>;
  /** Delete the user's TOTP record entirely (active and pending). */
  clearTotp(userId: string): Promise<void>;
  /**
   * Atomically advance the replay guard: persist `step` and return `true`
   * only when it is greater than the stored `lastStep` (e.g.
   * `UPDATE … SET last_step = $step WHERE last_step < $step`). Return `false`
   * otherwise — a concurrent request already spent this step, so the caller
   * treats the code as replayed.
   */
  advanceLastStep(userId: string, step: number): Promise<boolean>;
  /** Return the user's unused recovery-code hashes (empty when none). */
  getRecoveryHashes(userId: string): Promise<string[]>;
  /**
   * Replace the user's recovery-code hashes with exactly this set — used for
   * initial issue, regeneration, and disable (`[]`).
   */
  setRecoveryHashes(userId: string, hashes: string[]): Promise<void>;
  /**
   * Atomically delete one stored hash and return whether it existed (e.g.
   * `DELETE … WHERE user_id = $user AND hash = $hash` checking the row
   * count). This is what makes a recovery code single-use under concurrent
   * redemption — never implement it as read-filter-write.
   */
  consumeRecoveryHash(userId: string, hash: string): Promise<boolean>;
}

/** TOTP parameters an {@link MfaService} applies to every credential it manages. */
export interface MfaTotpOptions {
  /** Code length. Defaults to `6`. */
  digits?: number;
  /** Time-step length in seconds. Defaults to `30`. */
  periodSeconds?: number;
  /** HMAC hash. Defaults to `"SHA-1"` (see {@link TotpAlgorithm}). */
  algorithm?: TotpAlgorithm;
  /**
   * Clock-skew windows accepted on each side of the current step during
   * {@link MfaService.verify} and {@link MfaService.confirmEnrollment}.
   * Defaults to `1`.
   */
  windows?: number;
}

/** Options for {@link MfaService}. */
export interface MfaServiceOptions {
  /** The app-owned persistence seam. */
  store: MfaStore;
  /**
   * TOTP parameters. Set them once at construction — changing them later
   * invalidates codes for already-enrolled authenticators.
   */
  totp?: MfaTotpOptions;
  /** How many recovery codes to issue on confirm/regenerate. Defaults to `10`. */
  recoveryCodeCount?: number;
  /**
   * Throttles {@link verify} per user id (a 6-digit code is brute-forceable
   * without one). When the limit is hit the service emits
   * `mfa.verify.rate_limited` and — under `protectionMode: "enforce"` —
   * throws an `IdentityError` with code `rate_limited`. A successful
   * verification resets the user's window, so legitimate sign-ins never
   * accumulate toward a lockout.
   */
  rateLimiter?: RateLimiterLike;
  /**
   * `"enforce"` (default) applies the rate limit; `"log-only"` emits the
   * event but lets the attempt through, for observing limits before turning
   * them on.
   */
  protectionMode?: "enforce" | "log-only";
  /** Receives `mfa.*` {@link IdentityEvent}s for audit capture. */
  onEvent?: IdentityEventHook;
}

/** Options for {@link MfaService.startEnrollment}. */
export interface StartEnrollmentOptions {
  /** The service name shown in the authenticator app (e.g. `"Udibo"`). */
  issuer: string;
  /** The account label shown under the issuer (typically the user's email). */
  accountName: string;
}

/** The result of {@link MfaService.startEnrollment}. */
export interface MfaEnrollmentStart {
  /** The pending secret in base32, for manual entry into an authenticator. */
  base32: string;
  /** The `otpauth://` URI to render as a QR code. */
  otpauthUri: string;
}

/** The result of {@link MfaService.confirmEnrollment}. */
export type MfaEnrollmentConfirmation =
  | { confirmed: false }
  | {
    confirmed: true;
    /**
     * The plaintext recovery codes. Display them to the user exactly once;
     * only their hashes are stored.
     */
    recoveryCodes: string[];
  };

/** Per-call options for {@link MfaService.verify} and {@link MfaService.confirmEnrollment}. */
export interface MfaVerifyOptions {
  /**
   * Restrict which factor the code is checked against. Defaults to trying
   * TOTP first, then recovery — pass `"totp"` when your UI has a dedicated
   * recovery-code screen and the authenticator field must never silently burn
   * a recovery code.
   */
  method?: "totp" | "recovery";
  /** Epoch milliseconds to verify against. Defaults to `Date.now()`. */
  timestamp?: number;
}

/**
 * Why {@link MfaService.verify} rejected a code, on the invalid branch of
 * {@link MfaVerification}. Mirrors the `reason` on the `mfa.verify.failed`
 * event — same source of truth — so a caller need not subscribe to `onEvent`
 * to tell the two apart:
 *
 * - `"replayed"` — a *valid* TOTP code whose time step was already spent. A
 *   UI can say "that code was already used, wait for the next one"; it is also
 *   the classic signal of an intercepted or reused code.
 * - `"invalid"` — a wrong code, a non-recovery string, or a code submitted by
 *   a user with no active credential (indistinguishable on purpose).
 */
export type MfaVerifyFailureReason = "invalid" | "replayed";

/** The result of {@link MfaService.verify}. */
export type MfaVerification =
  | {
    valid: false;
    /** Why the code was rejected — see {@link MfaVerifyFailureReason}. */
    reason: MfaVerifyFailureReason;
  }
  | { valid: true; method: "totp" }
  | {
    valid: true;
    method: "recovery";
    /**
     * How many unused recovery codes remain — surface it so the UI can
     * prompt regeneration when low.
     */
    remainingRecoveryCodes: number;
  };

/**
 * A user's TOTP enrollment stage, as {@link MfaService.enrollmentStatus}
 * reports it:
 *
 * - `"none"` — no credential and no enrollment in progress.
 * - `"pending"` — {@link MfaService.startEnrollment} ran but
 *   {@link MfaService.confirmEnrollment} has not; a secret is stored but does
 *   not yet authenticate. An enrollment screen can resume instead of minting a
 *   fresh secret (which would invalidate the one already in the authenticator).
 * - `"active"` — a confirmed credential that {@link MfaService.verify} accepts.
 */
export type MfaEnrollmentStatus = "none" | "pending" | "active";

/**
 * Orchestrates TOTP enrollment, verification, and recovery codes over an
 * app-owned {@link MfaStore}.
 *
 * Lifecycle: {@link startEnrollment} stores a *pending* secret (ignored by
 * {@link verify}, so an unconfirmed enrollment can never lock a user out);
 * {@link confirmEnrollment} proves the user's authenticator works, activates
 * the secret, and issues recovery codes; {@link verify} accepts either a TOTP
 * code (rejecting replays via the stored last step) or a recovery code
 * (burning it on use). Replacing an active credential requires
 * {@link disable} first — gate that route behind a fresh re-authentication,
 * or a hijacked session could silently swap the user's authenticator.
 * Deciding *when* to demand a code — sign-in policy, step-up, admin reset —
 * is the app's job.
 *
 * @example Enroll, confirm, and verify
 * ```ts
 * const mfa = new MfaService({ store, rateLimiter });
 * const { otpauthUri } = await mfa.startEnrollment(user.id, {
 *   issuer: "Udibo", accountName: user.email,
 * });
 * // …render QR, user scans and submits a code…
 * const confirmation = await mfa.confirmEnrollment(user.id, code);
 * // …later, at sign-in…
 * const result = await mfa.verify(user.id, submittedCode);
 * ```
 */
export class MfaService {
  readonly #store: MfaStore;
  readonly #totp: MfaTotpOptions;
  readonly #recoveryCodeCount?: number;
  readonly #rateLimiter?: RateLimiterLike;
  readonly #enforce: boolean;
  readonly #onEvent?: IdentityEventHook;

  /**
   * Builds the service around an app-owned {@link MfaStore}.
   *
   * @throws {TypeError} on unusable configuration — non-positive-integer
   * `digits`/`periodSeconds`/`recoveryCodeCount` or negative `windows` — so a
   * miswired deploy fails at construction instead of silently rejecting every
   * code an enrolled user submits.
   */
  constructor(options: MfaServiceOptions) {
    validateTotpParams(options.totp ?? {});
    const count = options.recoveryCodeCount;
    if (count !== undefined && (!Number.isInteger(count) || count <= 0)) {
      throw new TypeError("recoveryCodeCount must be a positive integer");
    }
    this.#store = options.store;
    this.#totp = options.totp ?? {};
    this.#recoveryCodeCount = count;
    this.#rateLimiter = options.rateLimiter;
    this.#enforce = (options.protectionMode ?? "enforce") === "enforce";
    this.#onEvent = options.onEvent;
  }

  /**
   * Begin TOTP enrollment: generates a fresh secret, stores it as *pending*,
   * and returns what the enrollment screen needs. Repeating the call replaces
   * the pending secret.
   *
   * @throws {IdentityError} `mfa_already_enrolled` when an active credential
   * exists — replacing an authenticator requires {@link disable} first (behind
   * re-authentication), so a stolen session cannot silently swap it.
   */
  async startEnrollment(
    userId: string,
    options: StartEnrollmentOptions,
  ): Promise<MfaEnrollmentStart> {
    this.#assertNotEnrolled(await this.#store.getTotp(userId));
    const { base32 } = generateTotpSecret();
    await this.#store.setPendingTotp(userId, base32);
    return {
      base32,
      otpauthUri: buildOtpauthUri({
        secret: base32,
        issuer: options.issuer,
        accountName: options.accountName,
        digits: this.#totp.digits,
        periodSeconds: this.#totp.periodSeconds,
        algorithm: this.#totp.algorithm,
      }),
    };
  }

  /**
   * Confirm enrollment by verifying a code against the *pending* secret. On
   * success the secret becomes active, a fresh recovery-code set is generated
   * and stored, and the plaintext codes are returned for one-time display.
   * Returns `{ confirmed: false }` when the code is wrong, no enrollment is
   * pending, or the pending secret changed under a concurrent enrollment. If
   * storing the recovery codes fails after activation, the just-activated
   * credential is rolled back and the error rethrown — a failure leaves the
   * user *not* enrolled (free to retry), never enrolled without the recovery
   * codes they were promised.
   *
   * @throws {IdentityError} `mfa_already_enrolled` when an active credential
   * exists (see {@link startEnrollment}).
   */
  async confirmEnrollment(
    userId: string,
    code: string,
    options?: Pick<MfaVerifyOptions, "timestamp">,
  ): Promise<MfaEnrollmentConfirmation> {
    const record = await this.#store.getTotp(userId);
    this.#assertNotEnrolled(record);
    const pending = record?.pendingSecretBase32;
    if (!pending) return { confirmed: false };
    const result = await verifyTotpCode({
      secret: pending,
      code,
      timestamp: options?.timestamp,
      ...this.#totp,
    });
    if (!result.valid) return { confirmed: false };
    const activated = await this.#store.activateTotp(
      userId,
      pending,
      result.matchedStep,
    );
    if (!activated) return { confirmed: false };
    let recoveryCodes: string[];
    try {
      recoveryCodes = await this.#issueRecoveryCodes(userId);
    } catch (error) {
      await this.#store.clearTotp(userId);
      throw error;
    }
    await this.#emit({ type: "mfa.enrollment.confirmed", userId });
    return { confirmed: true, recoveryCodes };
  }

  /**
   * Verify a second-factor code: first as TOTP against the *active* secret
   * (pending secrets are ignored — they need {@link confirmEnrollment}), then
   * as a recovery code (restrict with {@link MfaVerifyOptions.method}). An
   * accepted TOTP code atomically advances the stored last step, so the same
   * code is rejected on replay even under concurrent submission; an accepted
   * recovery code is atomically burned, so it is single-use. Without an
   * active credential every code is rejected — recovery codes are a fallback
   * *for* the enrolled factor, so stale hashes can never authenticate a user
   * whose MFA was disabled. A successful verification resets the per-user
   * rate-limit window. On failure the result carries a
   * {@link MfaVerifyFailureReason} — `"replayed"` for a valid-but-spent TOTP
   * code, `"invalid"` otherwise — so a caller can distinguish a reused code
   * from a wrong one without subscribing to `onEvent`.
   *
   * @throws {IdentityError} `rate_limited` when a `rateLimiter` is configured,
   * the per-user limit is hit, and `protectionMode` is `"enforce"`.
   */
  async verify(
    userId: string,
    code: string,
    options?: MfaVerifyOptions,
  ): Promise<MfaVerification> {
    await this.#throttle(userId);
    const secret = (await this.#store.getTotp(userId))?.secretBase32;
    if (!secret) return await this.#verifyFailed(userId, "invalid");
    const method = options?.method;
    if (method !== "recovery") {
      const outcome = await this.#verifyTotp(
        userId,
        secret,
        code,
        options?.timestamp,
      );
      if (outcome) return outcome;
    }
    if (method !== "totp") {
      const outcome = await this.#verifyRecovery(userId, code);
      if (outcome) return outcome;
    }
    return await this.#verifyFailed(userId, "invalid");
  }

  /** Whether the user has an *active* (confirmed) TOTP credential. */
  async isEnrolled(userId: string): Promise<boolean> {
    const record = await this.#store.getTotp(userId);
    return record?.secretBase32 !== undefined;
  }

  /**
   * The user's TOTP enrollment stage — `"none"`, `"pending"`, or `"active"`
   * (see {@link MfaEnrollmentStatus}). Unlike {@link isEnrolled}, this also
   * reveals a started-but-unconfirmed enrollment, so an enrollment screen can
   * resume a pending secret the user already scanned rather than calling
   * {@link startEnrollment} again and invalidating it.
   */
  async enrollmentStatus(userId: string): Promise<MfaEnrollmentStatus> {
    const record = await this.#store.getTotp(userId);
    if (record?.secretBase32 !== undefined) return "active";
    if (record?.pendingSecretBase32 !== undefined) return "pending";
    return "none";
  }

  /**
   * Remove the user's MFA entirely: recovery codes first, then active and
   * pending secrets — so a partial failure can only leave MFA still *on*,
   * never a "disabled" account whose old recovery codes still authenticate.
   * Gate the route that calls this behind a fresh re-authentication —
   * disabling MFA is what an account takeover wants most.
   */
  async disable(userId: string): Promise<void> {
    await this.#store.setRecoveryHashes(userId, []);
    await this.#store.clearTotp(userId);
    await this.#emit({ type: "mfa.disabled", userId });
  }

  /**
   * Replace the user's recovery codes with a fresh set and return the
   * plaintext for one-time display. All previously issued codes stop working.
   *
   * @throws {IdentityError} `mfa_not_enrolled` when the user has no active
   * TOTP enrollment.
   */
  async regenerateRecoveryCodes(userId: string): Promise<string[]> {
    if (!await this.isEnrolled(userId)) {
      throw new IdentityError(
        "mfa_not_enrolled",
        "cannot regenerate recovery codes: MFA is not enrolled",
      );
    }
    const codes = await this.#issueRecoveryCodes(userId);
    await this.#emit({ type: "mfa.recovery_codes.regenerated", userId });
    return codes;
  }

  async #verifyTotp(
    userId: string,
    secret: string,
    code: string,
    timestamp: number | undefined,
  ): Promise<MfaVerification | undefined> {
    const result = await verifyTotpCode({
      secret,
      code,
      timestamp,
      ...this.#totp,
    });
    if (!result.valid) return undefined;
    if (!await this.#store.advanceLastStep(userId, result.matchedStep)) {
      return await this.#verifyFailed(userId, "replayed");
    }
    await this.#resetThrottle(userId);
    await this.#emit({ type: "mfa.verify.succeeded", userId, method: "totp" });
    return { valid: true, method: "totp" };
  }

  async #verifyRecovery(
    userId: string,
    code: string,
  ): Promise<MfaVerification | undefined> {
    if (normalizeRecoveryCode(code).length !== RECOVERY_CODE_LENGTH) {
      return undefined;
    }
    const consumed = await this.#store.consumeRecoveryHash(
      userId,
      await hashRecoveryCode(code),
    );
    if (!consumed) return undefined;
    const remainingRecoveryCodes =
      (await this.#store.getRecoveryHashes(userId)).length;
    await this.#resetThrottle(userId);
    await this.#emit({
      type: "mfa.verify.succeeded",
      userId,
      method: "recovery",
      remainingRecoveryCodes,
    });
    return { valid: true, method: "recovery", remainingRecoveryCodes };
  }

  #assertNotEnrolled(record: MfaTotpRecord | undefined): void {
    if (record?.secretBase32) {
      throw new IdentityError(
        "mfa_already_enrolled",
        "disable MFA before enrolling a new authenticator",
      );
    }
  }

  async #issueRecoveryCodes(userId: string): Promise<string[]> {
    const { codes, hashes } = await generateRecoveryCodes({
      count: this.#recoveryCodeCount,
    });
    await this.#store.setRecoveryHashes(userId, hashes);
    return codes;
  }

  #rateKey(userId: string): string {
    return `mfa:verify:${userId}`;
  }

  #throttle(userId: string): Promise<void> {
    return enforceRateLimit({
      rateLimiter: this.#rateLimiter,
      key: this.#rateKey(userId),
      message: "too many MFA attempts",
      enforce: this.#enforce,
      event: { type: "mfa.verify.rate_limited", userId },
      emit: (e) => this.#emit(e),
    });
  }

  async #resetThrottle(userId: string): Promise<void> {
    await this.#rateLimiter?.reset(this.#rateKey(userId));
  }

  async #verifyFailed(
    userId: string,
    reason: MfaVerifyFailureReason,
  ): Promise<MfaVerification> {
    await this.#emit({ type: "mfa.verify.failed", userId, reason });
    return { valid: false, reason };
  }

  #emit(event: IdentityEvent): Promise<void> {
    return dispatchIdentityEvent(this.#onEvent, "mfa", event);
  }
}

/**
 * In-memory {@link MfaStore} for development and tests. State is lost on
 * restart; back the contract with a database (secrets encrypted at rest,
 * conditional writes for the atomic methods) for production.
 */
export class MemoryMfaStore implements MfaStore {
  #totp = new Map<string, MfaTotpRecord>();
  #recovery = new Map<string, string[]>();

  /** Return a copy of the user's TOTP record, or `undefined`. */
  getTotp(userId: string): Promise<MfaTotpRecord | undefined> {
    const record = this.#totp.get(userId);
    return Promise.resolve(record ? { ...record } : undefined);
  }

  /** Store a pending secret, keeping any active credential. */
  setPendingTotp(userId: string, secretBase32: string): Promise<void> {
    const record = this.#totp.get(userId) ?? {};
    record.pendingSecretBase32 = secretBase32;
    this.#totp.set(userId, record);
    return Promise.resolve();
  }

  /** Promote the matching pending secret to active; `false` when it changed. */
  activateTotp(
    userId: string,
    secretBase32: string,
    lastStep: number,
  ): Promise<boolean> {
    const record = this.#totp.get(userId);
    if (record?.pendingSecretBase32 !== secretBase32) {
      return Promise.resolve(false);
    }
    this.#totp.set(userId, { secretBase32, lastStep });
    return Promise.resolve(true);
  }

  /** Delete the user's TOTP record. */
  clearTotp(userId: string): Promise<void> {
    this.#totp.delete(userId);
    return Promise.resolve();
  }

  /** Advance the replay guard only forward; `false` when the step was spent. */
  advanceLastStep(userId: string, step: number): Promise<boolean> {
    const record = this.#totp.get(userId);
    if (!record || step <= (record.lastStep ?? -1)) {
      return Promise.resolve(false);
    }
    record.lastStep = step;
    return Promise.resolve(true);
  }

  /** Return the user's stored recovery hashes (empty when none). */
  getRecoveryHashes(userId: string): Promise<string[]> {
    return Promise.resolve([...(this.#recovery.get(userId) ?? [])]);
  }

  /** Replace the user's recovery hashes with exactly this set. */
  setRecoveryHashes(userId: string, hashes: string[]): Promise<void> {
    this.#recovery.set(userId, [...hashes]);
    return Promise.resolve();
  }

  /** Delete one hash, reporting whether it was present. */
  consumeRecoveryHash(userId: string, hash: string): Promise<boolean> {
    const hashes = this.#recovery.get(userId) ?? [];
    const index = hashes.indexOf(hash);
    if (index === -1) return Promise.resolve(false);
    hashes.splice(index, 1);
    this.#recovery.set(userId, hashes);
    return Promise.resolve(true);
  }
}
