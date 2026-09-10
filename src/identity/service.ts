/**
 * `IdentityService` — composable functions for an app that owns its login.
 *
 * Orchestrates the identity primitives ({@link PasswordIdentityService},
 * {@link TokenFlowService}, delivery hooks, {@link RevocableSessionService})
 * over an **app-owned** {@link IdentityUserStore} into the flows a single app
 * needs: sign-up, sign-in, password reset, email verification, and passwordless
 * sign-in (magic links + one-time codes). These are plain
 * methods you call from your own routes/loaders/actions — there is no opinionated
 * mounted framework here. A thin, optional Hono route factory lives in
 * `@udibo/oauth2/hono/identity` for apps that want the endpoints mounted.
 *
 * Storage-agnostic by design: every flow addresses users by opaque id and the
 * {@link IdentityUserStore} is yours — back it with whatever database, ORM, and
 * schema your app already uses. The library composes the flows; it never owns
 * your tables. It stays below the turnkey-identity-service line.
 *
 * @module
 */

import { delay } from "@std/async/delay";

import {
  buildResetUrl,
  buildSignInUrl,
  buildUnlockUrl,
  buildVerificationUrl,
  type DeliveryHooks,
} from "./delivery.ts";
import type { AccountLockoutLike } from "./lockout.ts";
import {
  type PasswordCredential,
  type PasswordHasherLike,
  PasswordIdentityService,
} from "./password.ts";
import {
  type ResolvedToken,
  type TokenFlowService,
  TokenPurpose,
} from "./token-flow.ts";
import type { RevocableSessionService } from "./session.ts";
import {
  assertPasswordPolicy,
  type PasswordPolicy,
} from "./password-policy.ts";
import { enforceRateLimit, type RateLimiterLike } from "./rate-limit.ts";
import { EmailOtpService, otpRateKey, type OtpStore } from "./otp.ts";
import {
  dispatchIdentityEvent,
  type IdentityEvent,
  type IdentityEventHook,
  type RateLimitedEventInit,
} from "./events.ts";
import {
  findLegacyVerifier,
  type LegacyPasswordVerifier,
} from "./migration.ts";

/** The minimum the identity flows require of your user record. */
export interface IdentityUser {
  /** Opaque user id the flows address users by; never interpreted by the library. */
  id: string;
}

/**
 * App-owned user storage the identity flows orchestrate. You implement it over
 * your own database/ORM; the flows only ever address users by opaque id, so the
 * backing store stays entirely yours.
 */
export interface IdentityUserStore<User extends IdentityUser> {
  /**
   * Create a user from a sign-up `profile` (your app's fields — validate them)
   * plus the hashed password credential.
   */
  create(
    profile: Record<string, unknown>,
    credential: PasswordCredential,
  ): Promise<User>;
  /** Find a user by a sign-in identifier (email/username/phone). */
  findByIdentifier(identifier: string): Promise<User | undefined>;
  /** Find a user by email (password-reset / re-verification requests). */
  findByEmail(email: string): Promise<User | undefined>;
  /** The user's stored password credential, or `undefined`. */
  getCredential(userId: string): Promise<PasswordCredential | undefined>;
  /** Replace the user's password credential (reset / change). */
  setCredential(userId: string, credential: PasswordCredential): Promise<void>;
  /**
   * Atomically replace the credential only if it still equals `expected`.
   * `undefined` expects no native credential, for an imported-password upgrade.
   * Return `false` without writing if anything changed. Compare all stored
   * credential fields in the same database operation as the write, never read
   * then write. On `false` the service re-reads the credential and re-verifies
   * the password against it, so a concurrent sign-in that rehashed first still
   * lets this one in while a reset or change to a different password rejects
   * it. Without this capability, sign-in succeeds but automatic rehash and
   * imported credential upgrades are skipped; explicit password resets still
   * work.
   */
  replaceCredential?(
    userId: string,
    expected: PasswordCredential | undefined,
    credential: PasswordCredential,
  ): Promise<boolean>;
  /**
   * Mark the user's email verified. Omit if you don't verify email.
   *
   * `email` is the address the verification token was **issued for**, when the
   * token carried one. Your implementation must only flip the flag when the
   * user's current email still equals it (`WHERE id = $userId AND email =
   * $email`) — otherwise a link minted for one address verifies whatever
   * address the account holds when the link is clicked, letting an attacker
   * mark a victim's address verified by changing the account email after
   * requesting the link.
   *
   * Must be idempotent: it runs before the single-use token is consumed, so a
   * retried link calls it again.
   */
  markEmailVerified?(userId: string, email?: string): Promise<void>;
  /**
   * The user's imported foreign password hash (bcrypt/argon2/PBKDF2/… PHC
   * string), or `null` once migrated or never imported. Implement it — alongside
   * a `legacyCredential` column and {@link IdentityUserStore.clearLegacyCredential}
   * — to enable upgrade-on-login: {@link IdentityService.signIn} verifies this
   * hash with the configured `legacyVerifiers` only while the user has no
   * native credential (the native credential, once set, is authoritative —
   * a wrong password never falls back to the imported hash). Only consulted
   * when `legacyVerifiers` is set.
   */
  getLegacyCredential?(userId: string): Promise<string | null>;
  /**
   * Drop the user's imported foreign hash once it is superseded — after a
   * successful upgrade-on-login and after {@link IdentityService.resetPassword}.
   * **Implement this whenever you implement {@link getLegacyCredential}:** a
   * lingering foreign hash keeps the old imported password alive as a
   * fallback — ignored while a native credential exists, but it would come
   * back to life if the native credential is ever removed. Called at most
   * once per user per supersession.
   */
  clearLegacyCredential?(userId: string): Promise<void>;
}

/**
 * Per-flow limiter overrides for {@link IdentityServiceOptions.rateLimiters}.
 * One key per throttled flow, each falling back to
 * {@link IdentityServiceOptions.rateLimiter} when unset. `signInCode` covers
 * both requesting and verifying a code — they share the `otp:signin:` key.
 */
export interface IdentityRateLimiters {
  /** `signin:<identifier>` — {@link IdentityService.signIn}. */
  signIn?: RateLimiterLike;
  /** `pwreset:<email>` — {@link IdentityService.requestPasswordReset}. */
  passwordReset?: RateLimiterLike;
  /** `verifyemail:<userId>` — {@link IdentityService.requestEmailVerification}. */
  emailVerification?: RateLimiterLike;
  /** `unlock:<userId>` — {@link IdentityService.requestAccountUnlock}. */
  accountUnlock?: RateLimiterLike;
  /** `pwless:<email>` — {@link IdentityService.requestSignInLink}. */
  signInLink?: RateLimiterLike;
  /** `otp:signin:<email>` — request and verify of a sign-in code. */
  signInCode?: RateLimiterLike;
}

/** Options for {@link IdentityService}. */
export interface IdentityServiceOptions<User extends IdentityUser> {
  /** App-owned user storage. */
  users: IdentityUserStore<User>;
  /** Token flow for verify/reset links. Required for those flows. */
  tokens?: TokenFlowService;
  /**
   * Password hasher. Defaults to a new {@link PasswordIdentityService}
   * (PBKDF2-SHA-256). Any {@link PasswordHasherLike} works, so argon2 or scrypt
   * plug in with your own dependency. When the hasher implements
   * `needsRehash`, {@link IdentityService.signIn} transparently re-hashes and
   * stores a credential whose work factor has fallen behind, when the user
   * store implements `replaceCredential`.
   */
  passwords?: PasswordHasherLike;
  /**
   * Foreign password-hash verifiers for **upgrade-on-login**, tried in order.
   * When set, {@link IdentityService.signIn} — for a user with no native
   * credential yet — reads the imported hash via
   * {@link IdentityUserStore.getLegacyCredential} and verifies it with the first
   * verifier whose `canVerify` accepts it. On a match it rehashes the password
   * into the native format ({@link IdentityUserStore.replaceCredential}), clears the
   * imported hash ({@link IdentityUserStore.clearLegacyCredential}), emits a
   * `password.upgraded` event, and signs the user in. The package ships
   * {@link pbkdf2Verifier} built-in; bcrypt/argon2/scrypt are bring-your-own via
   * the {@link LegacyPasswordVerifier} seam (no dep-free implementation exists).
   */
  legacyVerifiers?: LegacyPasswordVerifier[];
  /**
   * Minimum wall-clock duration of a **failed** {@link IdentityService.signIn},
   * in ms. Defaults to `250`. Every rejection — unknown identifier, locked
   * account, no password set, wrong native password, wrong imported password —
   * is held to the same deadline measured from the call's first statement, so
   * the response time reveals nothing about which branch ran.
   *
   * Set it above the cost of your slowest configured
   * {@link IdentityServiceOptions.legacyVerifiers} plus one password hash —
   * that is the expensive branch (a foreign KDF the native branch never runs),
   * and without a floor above it an unauthenticated caller can separate the
   * accounts still carrying an imported hash from the migrated ones by response
   * time alone. A branch that outruns the floor returns as soon as its own work
   * finishes: whatever it spends *above* the floor stays visible, so raising a
   * work factor means re-checking this number.
   *
   * `0` disables the floor entirely, which restores that signal in full — the
   * one value that turns it off. Anything else out of range (negative, `NaN`,
   * `Infinity`) falls back to the default rather than to no floor.
   * Successful sign-ins are never delayed.
   */
  failedSignInFloorMs?: number;
  /** Session revocation, called on a successful password reset. Optional. */
  sessions?: RevocableSessionService;
  /** Delivery transports for verify/reset links. Optional. */
  delivery?: DeliveryHooks;
  /**
   * Base URL (origin, or origin + prefix) used to build the action links
   * passed to delivery hooks. When omitted, hooks receive only the raw `token`.
   */
  baseUrl?: string;
  /**
   * Token lifetimes in ms. Defaults: password reset 1h, email verification 24h,
   * account unlock 1h, sign-in link 15m. A per-call `ttlMs` — currently only
   * {@link IdentityService.requestSignInLink} takes one — overrides the
   * configured default for that request. One-time sign-in **codes** are not
   * tokens; their lifetime is {@link IdentityServiceOptions.otp}'s `ttlMs`.
   */
  ttl?: {
    passwordReset?: number;
    emailVerification?: number;
    accountUnlock?: number;
    signInLink?: number;
  };
  /**
   * One-time sign-in codes ("email me a code"). When set,
   * {@link IdentityService.requestSignInCode} and
   * {@link IdentityService.verifySignInCode} run an {@link EmailOtpService}
   * over the app-owned store. Storage and code shape only — the code flow's
   * single throttle is `rateLimiters.signInCode` (falling back to
   * {@link rateLimiter}) under the key `otp:signin:<email>`, so a request for
   * a known email is throttled exactly like one for an unknown email.
   */
  otp?: {
    /** App-owned code storage. */
    store: OtpStore;
    /** Code length in digits. Defaults to `6`. */
    digits?: number;
    /** Code lifetime in ms. Defaults to 10 minutes. */
    ttlMs?: number;
    /** Wrong-attempt budget before the code locks. Defaults to `5`. */
    maxAttempts?: number;
  };
  /**
   * Password policy enforced by {@link IdentityService.signUp} and
   * {@link IdentityService.resetPassword} before hashing — always, not only
   * when you configure one. Omitting it leaves the
   * {@link PasswordPolicy} defaults in force: 8–256 characters, no composition
   * rules, no extra validators. The maximum is a DoS guard on the hash input
   * (the hasher itself has none), so every password the app can **store** is
   * bounded in every configuration. {@link IdentityService.signIn} is outside
   * the policy by design — it hashes whatever the request carries, because the
   * equal-work path that hides an unknown identifier has to run on the
   * submitted password as-is. A violation — including a non-string password,
   * which the hasher would otherwise `String`-coerce — throws
   * {@link IdentityError} `weak_password`.
   */
  passwordPolicy?: PasswordPolicy;
  /**
   * Auth-flow rate limiter. When set, {@link IdentityService.signIn} throttles
   * by identifier — an unknown and a known identifier throttle identically, so
   * the limit can't be used to enumerate accounts — throws
   * {@link IdentityError} `rate_limited` (with `retryAfterMs`) when exceeded,
   * and resets the counter on a successful sign-in. Every other flow throttles
   * on the same limiter with its own key: the email-sending requests
   * ({@link IdentityService.requestPasswordReset} per case-folded email,
   * {@link IdentityService.requestEmailVerification} and
   * {@link IdentityService.requestAccountUnlock} per user) and the passwordless
   * flows (`pwless:<email>` for sign-in links, `otp:signin:<email>` for sign-in
   * codes — request and verify share the key; a successful verify resets it),
   * so none of them can drive unbounded sends. IP-based limiting stays a
   * route-layer concern: the service has no request context, which is the
   * correct seam.
   *
   * This is the **default** for every flow; {@link rateLimiters} overrides it
   * per flow when one threshold cannot serve them all.
   */
  rateLimiter?: RateLimiterLike;
  /**
   * Per-flow limiter overrides. Set one when a single threshold cannot serve
   * every flow — a limit tuned as a sign-in floor is usually far too permissive
   * for the four flows that make the server **send an email to a
   * caller-supplied address** (`passwordReset`, `emailVerification`,
   * `accountUnlock`, `signInLink`, plus `signInCode`), which typically want a
   * handful of requests per hour rather than per 15 minutes.
   *
   * Each entry is a whole {@link RateLimiterLike} — build one
   * {@link RateLimiter} per flow (they can share a {@link RateLimitStore}; the
   * key prefixes already keep their counters disjoint) or bring your own.
   * Entries left unset fall back to {@link rateLimiter}, so adding this option
   * never changes an existing caller's behavior.
   *
   * @example Throttle the email-sending flows harder than sign-in
   * ```ts
   * const emailFlow = new RateLimiter({
   *   store: sharedStore,
   *   limit: 3,
   *   windowMs: 60 * 60_000,
   * });
   * const identity = new IdentityService<AppUser>({
   *   users: userStore,
   *   rateLimiter: new RateLimiter({ store: sharedStore }),
   *   rateLimiters: {
   *     passwordReset: emailFlow,
   *     emailVerification: emailFlow,
   *     accountUnlock: emailFlow,
   *     signInLink: emailFlow,
   *     signInCode: emailFlow,
   *   },
   * });
   * ```
   */
  rateLimiters?: IdentityRateLimiters;
  /**
   * Failed-attempt account lockout. When set, {@link IdentityService.signIn}
   * records consecutive wrong-password failures per account and — once the
   * threshold locks the account — rejects further attempts with the same
   * uniform, timing-equalized `null` an unknown identifier gets (no lockout
   * oracle). A successful sign-in resets the count;
   * {@link IdentityService.unlockAccount} clears a lock via an emailed
   * single-use token.
   */
  lockout?: AccountLockoutLike;
  /**
   * How the attack protections respond when tripped. `"enforce"` (the safe
   * default) blocks: rate limiting throws and a locked account can't sign in.
   * `"log-only"` never blocks — events still fire (with `enforced: false`) so
   * adopters can observe thresholds before turning enforcement on.
   */
  protectionMode?: "enforce" | "log-only";
  /**
   * Called with an {@link IdentityEvent} after each flow outcome — the seam for
   * audit capture. Awaited, but isolated: a rejection is logged and swallowed
   * so observability can never break the auth flow. Optional; no-op when
   * absent.
   */
  onEvent?: IdentityEventHook;
}

/**
 * Outcome of {@link IdentityService.verifyEmail}. `success` carries the verified
 * user; `expired` and `invalid` are distinguished so the UI can offer to resend
 * an expired link rather than showing one generic error.
 */
export type VerifyEmailResult =
  | { status: "success"; userId: string; email?: string }
  | { status: "expired" }
  | { status: "invalid" };

const DEFAULT_RESET_TTL = 60 * 60 * 1000;
const DEFAULT_VERIFY_TTL = 24 * 60 * 60 * 1000;
const DEFAULT_UNLOCK_TTL = 60 * 60 * 1000;
const DEFAULT_SIGNIN_LINK_TTL = 15 * 60 * 1000;
const DEFAULT_FAILED_SIGN_IN_FLOOR_MS = 250;

function foldEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * The rate-limit key for each throttled flow, one entry per
 * {@link IdentityRateLimiters} key. Every check and every reset derives its key
 * here, so the window a flow fills is always the window its reset clears.
 *
 * Case-folding is a decision per key type. Email-addressed keys fold, so casing
 * variants of one mailbox share a window instead of each earning a fresh send
 * budget (`signInCode` folds inside {@link otpRateKey}, so the window it fills
 * is the one a standalone {@link EmailOtpService} would). Opaque user ids pass
 * through untouched — only the app knows whether they are case-sensitive.
 * `signin:` is trimmed but not folded: an identifier
 * may be a username or phone whose equality only the app's `findByIdentifier`
 * defines, and folding would merge two distinct accounts (`Bob`, `bob`) into
 * one window, letting failures against either deny sign-in to the other.
 */
const RATE_KEYS: Record<
  keyof IdentityRateLimiters,
  (value: string) => string
> = {
  signIn: (identifier) => `signin:${identifier.trim()}`,
  passwordReset: (email) => `pwreset:${foldEmail(email)}`,
  emailVerification: (userId) => `verifyemail:${userId}`,
  accountUnlock: (userId) => `unlock:${userId}`,
  signInLink: (email) => `pwless:${foldEmail(email)}`,
  signInCode: (email) => otpRateKey(TokenPurpose.SignIn, email),
};

/**
 * Outcome of {@link IdentityService.consumeSignInLink}. `expired` and
 * `invalid` are distinguished so the UI can offer a fresh link for an expired
 * one. No session is created — do that in your app on `success`.
 */
export type ConsumeSignInLinkResult =
  | { status: "success"; userId: string }
  | { status: "expired" }
  | { status: "invalid" };

/**
 * Outcome of {@link IdentityService.verifySignInCode}. Deliberately only
 * `success` vs `invalid`: a known email whose code expired or hit its attempt
 * cap collapses to `invalid`, identical to an unknown email, so the caller-
 * facing result is not an account-enumeration oracle. The precise reason
 * (`expired`/`locked`/`unknown_email`) is available server-side via the
 * `signin_code.failed` event.
 */
export type VerifySignInCodeResult =
  | { status: "success"; userId: string }
  | { status: "invalid" };

/**
 * Outcome of {@link IdentityService.unlockAccount}. `expired` and `invalid`
 * are distinguished so the UI can offer a fresh link for an expired one.
 */
export type UnlockAccountResult =
  | { status: "success"; userId: string }
  | { status: "expired" }
  | { status: "invalid" };

type TokenDeliveryHook = Exclude<keyof DeliveryHooks, "sendSignInCode">;

type TokenDeliveryRequest = {
  hook: TokenDeliveryHook;
  to: string;
  subject: string;
  ttlMs: number;
  data?: Record<string, unknown>;
  requested: IdentityEvent;
};

type ConsumedToken =
  | { status: "success"; resolved: ResolvedToken }
  | { status: "expired" }
  | { status: "invalid" };

type AuthenticateOutcome = "authenticated" | "no_password" | "wrong_password";

/**
 * Composable own-auth flows. Construct once with your dependencies and call the
 * methods from your routes; the credential form, copy, and session creation stay
 * in your app.
 */
export class IdentityService<User extends IdentityUser> {
  readonly #users: IdentityUserStore<User>;
  readonly #tokens?: TokenFlowService;
  readonly #passwords: PasswordHasherLike;
  readonly #sessions?: RevocableSessionService;
  readonly #delivery?: DeliveryHooks;
  readonly #baseUrl?: string;
  readonly #ttl: {
    passwordReset: number;
    emailVerification: number;
    accountUnlock: number;
    signInLink: number;
  };
  readonly #passwordPolicy?: PasswordPolicy;
  readonly #rateLimiters: IdentityRateLimiters;
  readonly #otp?: EmailOtpService;
  readonly #lockout?: AccountLockoutLike;
  readonly #enforce: boolean;
  readonly #onEvent?: IdentityEventHook;
  readonly #legacyVerifiers?: readonly LegacyPasswordVerifier[];
  readonly #failedSignInFloorMs: number;

  /** Wires the user store and optional collaborators; applies the TTL and hasher defaults. */
  constructor(options: IdentityServiceOptions<User>) {
    this.#users = options.users;
    this.#tokens = options.tokens;
    this.#passwords = options.passwords ?? new PasswordIdentityService();
    this.#sessions = options.sessions;
    this.#delivery = options.delivery;
    this.#baseUrl = options.baseUrl;
    this.#ttl = {
      passwordReset: options.ttl?.passwordReset ?? DEFAULT_RESET_TTL,
      emailVerification: options.ttl?.emailVerification ?? DEFAULT_VERIFY_TTL,
      accountUnlock: options.ttl?.accountUnlock ?? DEFAULT_UNLOCK_TTL,
      signInLink: options.ttl?.signInLink ?? DEFAULT_SIGNIN_LINK_TTL,
    };
    this.#passwordPolicy = options.passwordPolicy;
    this.#rateLimiters = {
      signIn: options.rateLimiters?.signIn ?? options.rateLimiter,
      passwordReset: options.rateLimiters?.passwordReset ?? options.rateLimiter,
      emailVerification: options.rateLimiters?.emailVerification ??
        options.rateLimiter,
      accountUnlock: options.rateLimiters?.accountUnlock ?? options.rateLimiter,
      signInLink: options.rateLimiters?.signInLink ?? options.rateLimiter,
      signInCode: options.rateLimiters?.signInCode ?? options.rateLimiter,
    };
    this.#otp = options.otp
      ? new EmailOtpService({
        store: options.otp.store,
        digits: options.otp.digits,
        ttlMs: options.otp.ttlMs,
        maxAttempts: options.otp.maxAttempts,
      })
      : undefined;
    this.#lockout = options.lockout;
    this.#enforce = (options.protectionMode ?? "enforce") === "enforce";
    this.#onEvent = options.onEvent;
    this.#legacyVerifiers = options.legacyVerifiers?.length
      ? options.legacyVerifiers
      : undefined;
    const floor = options.failedSignInFloorMs ??
      DEFAULT_FAILED_SIGN_IN_FLOOR_MS;
    this.#failedSignInFloorMs = Number.isFinite(floor) && floor >= 0
      ? floor
      : DEFAULT_FAILED_SIGN_IN_FLOOR_MS;
  }

  /**
   * Create a user with a hashed password. `profile` is your app's own fields.
   *
   * @throws {IdentityError} `weak_password` when `password` fails the password
   * policy — including the 8–256 character defaults that apply when
   * {@link IdentityServiceOptions.passwordPolicy} is omitted, and a non-string
   * password (the hash would `String`-coerce it).
   */
  async signUp(
    input: { password: string; profile: Record<string, unknown> },
  ): Promise<User> {
    await assertPasswordPolicy(input.password, this.#passwordPolicy);
    const credential = await this.#passwords.hash(input.password);
    const user = await this.#users.create(input.profile, credential);
    await this.#emit({ type: "sign_up", userId: user.id });
    return user;
  }

  /**
   * Verify credentials; returns the user, or `null` for an unknown identifier or
   * wrong password (don't reveal which). Establishing a session is your app's
   * job — do it on a non-null result.
   *
   * The throttle window is keyed on the identifier as submitted (trimmed, not
   * case-folded), so pass the same normalized form you resolve accounts by —
   * otherwise casing variants of one account each get their own window, and
   * the identifiers you later hand {@link IdentityService.resetSignInThrottle}
   * won't match the ones that filled it.
   *
   * Every rejection is held to
   * {@link IdentityServiceOptions.failedSignInFloorMs} (250 ms by default),
   * measured from entry, so an unknown identifier, a locked account, a wrong
   * native password, and a wrong password against an imported hash all take the
   * same time — the branch that runs a foreign KDF is not visible from
   * outside. A success returns as soon as it is done.
   *
   * @throws {IdentityError} `rate_limited` (with `retryAfterMs`) when a
   * `rateLimiter` is configured, the identifier's limit is hit, and
   * `protectionMode` is `"enforce"`. Rate-limit rejections throw before the
   * account lookup and are not held to the floor.
   */
  async signIn(
    input: { identifier: string; password: string },
  ): Promise<User | null> {
    const startedAt = performance.now();
    const identifier = input.identifier.trim();
    // Throttle before lookup so 429s don't reveal whether the account exists.
    await this.#throttle("signIn", identifier, "too many sign-in attempts", {
      type: "sign_in.rate_limited",
      identifier,
    });
    const user = await this.#users.findByIdentifier(identifier);
    if (!user) {
      await this.#equalizeTiming(input.password);
      await this.#emit({
        type: "sign_in.failed",
        identifier,
        reason: "unknown_identifier",
      });
      return await this.#rejectSignIn(startedAt);
    }
    if (await this.#isLockedOut(user.id, identifier)) {
      await this.#equalizeTiming(input.password);
      return await this.#rejectSignIn(startedAt);
    }
    const outcome = await this.#authenticate(user.id, input.password);
    if (outcome !== "authenticated") {
      await this.#emit({
        type: "sign_in.failed",
        identifier,
        reason: outcome,
        userId: user.id,
      });
      if (outcome === "wrong_password") {
        await this.#recordSignInFailure(user.id, identifier);
      }
      return await this.#rejectSignIn(startedAt);
    }
    await this.#resetThrottle("signIn", identifier);
    if (this.#lockout) await this.#lockout.reset(user.id);
    await this.#emit({
      type: "sign_in.succeeded",
      userId: user.id,
      identifier,
    });
    return user;
  }

  /**
   * Clear the sign-in rate-limit window for one identifier. Call it after a
   * flow that proves account ownership (account unlock, password reset) with
   * each identifier the user signs in with — otherwise the failed attempts
   * that caused the lockout still fill the window and the user's next sign-in
   * is rejected as rate-limited despite being unlocked. No-op without a
   * `rateLimiter`.
   */
  async resetSignInThrottle(identifier: string): Promise<void> {
    await this.#resetThrottle("signIn", identifier);
  }

  /**
   * Enumeration-safe: always resolves or throws identically whether or not the
   * email maps to a user. If it does, mints a single-use reset token and calls
   * `delivery.sendPasswordReset`. With a `rateLimiter`, requests throttle per
   * target email, case-folded so casing variants share one window — the check
   * runs before the lookup, so a 429 reveals nothing —
   * and throw {@link IdentityError} `rate_limited` when exceeded; catch it and
   * return your uniform success response. Give it a tighter threshold than
   * sign-in via `rateLimiters.passwordReset`.
   */
  async requestPasswordReset(email: string): Promise<void> {
    const tokens = this.#requireTokens("requestPasswordReset");
    const normalized = email.trim();
    await this.#throttle(
      "passwordReset",
      normalized,
      "too many password reset requests",
      { type: "password_reset.rate_limited", email: normalized },
    );
    const user = await this.#users.findByEmail(normalized);
    if (!user) {
      await this.#emit({
        type: "password_reset.requested",
        email: normalized,
      });
      return;
    }
    await this.#issueAndDeliver(tokens, {
      hook: "sendPasswordReset",
      to: normalized,
      subject: user.id,
      data: { email: normalized },
      ttlMs: this.#ttl.passwordReset,
      requested: {
        type: "password_reset.requested",
        email: normalized,
        userId: user.id,
      },
    });
  }

  /**
   * Consume a reset token, set the new password, and (if a `sessions` service
   * was configured) revoke the user's other sessions. Clears any failed-attempt
   * lockout — the emailed token proves the same account ownership the unlock
   * flow does. Returns `{ userId }`, or `null` for an invalid/expired/used
   * token.
   *
   * A reset is the user's "lock everyone else out" action, so the outstanding
   * passwordless credentials for the same account are voided too: sign-in links
   * (needs a token store with `deleteBySubject` — without it they stay
   * redeemable until they expire) and, when an `otp` service is configured, the
   * pending sign-in code. Neither can fail the reset: a store that throws is
   * logged and the reset still completes, since the password has already
   * changed by then.
   *
   * Sessions are revoked **after** the password is changed. If that revocation
   * throws, the reset is reported failed — a `password_reset.failed`
   * (`session_revocation_failed`) event fires, no `password_reset.completed`
   * fires, and the error rethrows — rather than silently returning success with
   * the user's old sessions still live. Retry the reset to clear them.
   *
   * @throws {IdentityError} `weak_password` when `password` fails the password
   * policy — including the 8–256 character defaults that apply when
   * {@link IdentityServiceOptions.passwordPolicy} is omitted. The token is left
   * unconsumed, so the user's link still works.
   */
  async resetPassword(
    input: { token: string; password: string },
  ): Promise<{ userId: string } | null> {
    const tokens = this.#requireTokens("resetPassword");
    // Check the policy before consuming the single-use token so a weak password
    // doesn't burn the user's reset link.
    await assertPasswordPolicy(input.password, this.#passwordPolicy);
    const consumed = await this.#consumeToken({
      tokens,
      purpose: TokenPurpose.PasswordReset,
      token: input.token,
      failed: () => ({
        type: "password_reset.failed",
        reason: "invalid_token",
      }),
    });
    if (consumed.status !== "success") return null;
    const { resolved } = consumed;
    await this.#users.setCredential(
      resolved.subject,
      await this.#passwords.hash(input.password),
    );
    try {
      await this.#users.clearLegacyCredential?.(resolved.subject);
    } catch (error) {
      // A throwing hook must not skip session revocation after the password
      // already changed.
      console.error(
        "[@udibo/oauth2] resetPassword legacy-credential clear failed:",
        error instanceof Error ? error.message : error,
      );
    }
    await this.#voidPasswordlessCredentials(
      tokens,
      resolved.subject,
      emailFromData(resolved.data),
    );
    if (this.#sessions) {
      try {
        await this.#sessions.revokeAllByUser(resolved.subject);
      } catch (error) {
        await this.#emit({
          type: "password_reset.failed",
          reason: "session_revocation_failed",
        });
        throw error;
      }
    }
    await this.#lockout?.reset(resolved.subject);
    await this.#emit({
      type: "password_reset.completed",
      userId: resolved.subject,
    });
    return { userId: resolved.subject };
  }

  /**
   * Mint + deliver an email-verification link for a user. Typically called
   * right after sign-up, or from an authenticated "resend" action — not exposed
   * as an unauthenticated route (you'd be emailing arbitrary user ids). With a
   * `rateLimiter` (or a tighter `rateLimiters.emailVerification`), requests
   * throttle per user and throw {@link IdentityError} `rate_limited` when
   * exceeded — surface it as a friendly cooldown.
   */
  async requestEmailVerification(
    input: { userId: string; email: string },
  ): Promise<void> {
    const tokens = this.#requireTokens("requestEmailVerification");
    await this.#throttle(
      "emailVerification",
      input.userId,
      "too many verification email requests",
      {
        type: "email_verification.rate_limited",
        userId: input.userId,
        email: input.email,
      },
    );
    await this.#issueAndDeliver(tokens, {
      hook: "sendEmailVerification",
      to: input.email,
      subject: input.userId,
      ttlMs: this.#ttl.emailVerification,
      data: { email: input.email },
      requested: {
        type: "email_verification.requested",
        userId: input.userId,
        email: input.email,
      },
    });
  }

  /**
   * Consume a verification token and mark the user's email verified.
   *
   * Returns a discriminated {@link VerifyEmailResult} so the UI can tell an
   * **expired** link (offer to resend) from a generically **invalid** one — the
   * `inspect()` distinction, surfaced through the flow. A `valid` token is
   * consumed; a lost race (consumed between inspect and consume) reports
   * `invalid`.
   *
   * The email is marked verified **before** the token is consumed, so a throw
   * from `markEmailVerified` leaves the single-use link unspent and the user
   * can retry with the same link (`markEmailVerified` must be idempotent).
   *
   * The address the token was issued for is passed to
   * {@link IdentityUserStore.markEmailVerified} alongside the user id, so a
   * store that predicates on both never verifies an address the link was not
   * minted for.
   */
  async verifyEmail(token: string): Promise<VerifyEmailResult> {
    const tokens = this.#requireTokens("verifyEmail");
    const result = await this.#consumeToken({
      tokens,
      purpose: TokenPurpose.EmailVerification,
      token,
      failed: (reason) => ({ type: "email_verification.failed", reason }),
      beforeConsume: (subject, data) =>
        this.#users.markEmailVerified?.(subject, emailFromData(data)),
    });
    if (result.status !== "success") return result;
    const userId = result.resolved.subject;
    const email = emailFromData(result.resolved.data);
    await this.#emit({
      type: "email_verification.completed",
      userId,
      email,
    });
    return { status: "success", userId, email };
  }

  /**
   * Mint + deliver a single-use account-unlock link after a lockout. Call it
   * with the locked account's email (typically from your `lockout` event
   * handler — the service only knows opaque user ids). Requires `tokens` and
   * a `delivery.sendAccountUnlock` hook to actually send. With a `rateLimiter`
   * (or a tighter `rateLimiters.accountUnlock`), requests throttle per user and
   * throw {@link IdentityError} `rate_limited` when exceeded.
   */
  async requestAccountUnlock(
    input: { userId: string; email: string },
  ): Promise<void> {
    const tokens = this.#requireTokens("requestAccountUnlock");
    await this.#throttle(
      "accountUnlock",
      input.userId,
      "too many account unlock requests",
      {
        type: "account_unlock.rate_limited",
        userId: input.userId,
        email: input.email,
      },
    );
    await this.#issueAndDeliver(tokens, {
      hook: "sendAccountUnlock",
      to: input.email,
      subject: input.userId,
      ttlMs: this.#ttl.accountUnlock,
      requested: {
        type: "account_unlock.requested",
        userId: input.userId,
        email: input.email,
      },
    });
  }

  /**
   * Consume an unlock token and clear the account's lockout state (failures
   * and lock). The self-service unlock path: the emailed link lands here.
   */
  async unlockAccount(token: string): Promise<UnlockAccountResult> {
    const tokens = this.#requireTokens("unlockAccount");
    const result = await this.#consumeToken({
      tokens,
      purpose: TokenPurpose.AccountUnlock,
      token,
      failed: (reason) => ({ type: "account_unlock.failed", reason }),
    });
    if (result.status !== "success") return result;
    const userId = result.resolved.subject;
    await this.#lockout?.reset(userId);
    await this.#emit({ type: "account_unlock.completed", userId });
    return { status: "success", userId };
  }

  async #getLegacyCredential(userId: string): Promise<string | null> {
    if (!this.#legacyVerifiers) return null;
    const get = this.#users.getLegacyCredential;
    if (!get) return null;
    return (await get.call(this.#users, userId)) ?? null;
  }

  async #tryLegacy(
    verifier: LegacyPasswordVerifier,
    password: string,
    phc: string,
  ): Promise<boolean> {
    try {
      return await verifier.verify(password, phc);
    } catch {
      // Never log the error object: a BYO verifier may echo the hash or the
      // submitted password in its message. Fail closed.
      console.error(
        `[@udibo/oauth2] legacy password verifier ${verifier.id} threw`,
      );
      return false;
    }
  }

  /**
   * Passwordless request: always resolves with the same `void` result. If the
   * email maps to a user, mints a single-use sign-in token (invalidating any
   * outstanding one) and calls `delivery.sendSignInLink`; an unknown email does
   * neither, so the **return value** never reveals whether an account exists.
   * The synchronous path is not fully timing-uniform, though — only the
   * known-email branch awaits token minting and delivery — so send email from a
   * background queue and apply IP-level throttling at the route to close the
   * residual latency/side-channel oracle. Throttled per email (case-folded,
   * key `pwless:<email>`) when a `rateLimiter` — or a tighter
   * `rateLimiters.signInLink` — is configured; throws {@link IdentityError}
   * `rate_limited` in enforce mode. Default link lifetime is 15 minutes.
   */
  async requestSignInLink(
    email: string,
    options?: { ttlMs?: number },
  ): Promise<void> {
    const tokens = this.#requireTokens("requestSignInLink");
    const normalized = email.trim();
    await this.#throttle(
      "signInLink",
      normalized,
      "too many sign-in link requests",
      { type: "signin_link.rate_limited", email: normalized },
    );
    const user = await this.#users.findByEmail(normalized);
    if (!user) {
      await this.#emit({ type: "signin_link.requested", email: normalized });
      return;
    }
    await this.#issueAndDeliver(tokens, {
      hook: "sendSignInLink",
      to: normalized,
      subject: user.id,
      ttlMs: options?.ttlMs ?? this.#ttl.signInLink,
      requested: {
        type: "signin_link.requested",
        email: normalized,
        userId: user.id,
      },
    });
  }

  /**
   * Consume a sign-in link token (single-use). `success` carries the `userId`
   * to sign in; establishing the session — and running your MFA gate first —
   * stays your app's job. So does re-resolving the user: a user deleted or
   * disabled since the link was minted must be treated as `invalid` by your
   * user store, not signed in. `expired` and `invalid` are distinguished so
   * the UI can offer a fresh link.
   */
  async consumeSignInLink(token: string): Promise<ConsumeSignInLinkResult> {
    const tokens = this.#requireTokens("consumeSignInLink");
    const result = await this.#consumeToken({
      tokens,
      purpose: TokenPurpose.SignIn,
      token,
      failed: (reason) => ({ type: "signin_link.failed", reason }),
    });
    if (result.status !== "success") return result;
    const userId = result.resolved.subject;
    await this.#emit({ type: "signin_link.consumed", userId });
    return { status: "success", userId };
  }

  /**
   * Passwordless request: always resolves with the same `void` result. If the
   * email maps to a user, mints a one-time numeric code (invalidating any
   * outstanding one) and calls `delivery.sendSignInCode`; an unknown email does
   * neither, so the **return value** never reveals whether an account exists.
   * As with {@link IdentityService.requestSignInLink}, only the known-email
   * branch awaits code minting and delivery, so send from a background queue
   * and throttle by IP at the route to close the residual timing oracle.
   * Requires the `otp` option. Throttled per email (case-folded, key
   * `otp:signin:<email>`, shared with {@link IdentityService.verifySignInCode})
   * when a `rateLimiter` — or a tighter `rateLimiters.signInCode` — is
   * configured; throws {@link IdentityError} `rate_limited` in enforce mode.
   * That is the flow's only throttle, and it runs before the lookup, so a
   * known email can never be rate-limited on a request an unknown one survives.
   * A throwing `sendSignInCode` is trapped like the link hooks (see
   * {@link DeliveryHooks}): that exact code is invalidated — never a newer one a
   * retry may have delivered meanwhile — a `delivery.failed` event is emitted,
   * and the call still resolves `void`, so a mailer outage is not an enumeration
   * oracle either.
   */
  async requestSignInCode(email: string): Promise<void> {
    const otp = this.#requireOtp("requestSignInCode");
    const normalized = email.trim();
    await this.#throttle(
      "signInCode",
      normalized,
      "too many sign-in code requests",
      { type: "signin_code.rate_limited", email: normalized },
    );
    const user = await this.#users.findByEmail(normalized);
    if (!user) {
      await this.#emit({ type: "signin_code.requested", email: normalized });
      return;
    }
    await otp.request({
      email: normalized,
      purpose: TokenPurpose.SignIn,
      onDeliver: (code, expiresAt, codeId) =>
        this.#deliverCode(normalized, code, user.id, expiresAt, codeId),
    });
    await this.#emit({
      type: "signin_code.requested",
      email: normalized,
      userId: user.id,
    });
  }

  /**
   * Verify a one-time sign-in code. An unknown email performs the same hash
   * work as a known one and reports plain `invalid` — the result is not an
   * enumeration oracle. Wrong tries spend the code's attempt budget (`locked`
   * once it runs out); success consumes the code (single-use), resets the
   * flow's throttle window, and carries the `userId` to sign in — session
   * creation and your MFA gate stay your app's job, as does treating a
   * since-deleted/disabled user as a failed sign-in.
   */
  async verifySignInCode(
    input: { email: string; code: string },
  ): Promise<VerifySignInCodeResult> {
    const otp = this.#requireOtp("verifySignInCode");
    const email = input.email.trim();
    await this.#throttle(
      "signInCode",
      email,
      "too many sign-in code attempts",
      { type: "signin_code.rate_limited", email },
    );
    const user = await this.#users.findByEmail(email);
    const result = await otp.verify({
      email,
      purpose: TokenPurpose.SignIn,
      code: input.code,
    });
    if (!user) {
      await this.#emit({
        type: "signin_code.failed",
        email,
        reason: "unknown_email",
      });
      return { status: "invalid" };
    }
    if (result.status !== "success") {
      await this.#emit({
        type: "signin_code.failed",
        email,
        reason: result.status,
      });
      return { status: "invalid" };
    }
    await this.#resetThrottle("signInCode", email);
    await this.#emit({ type: "signin_code.verified", userId: user.id });
    return { status: "success", userId: user.id };
  }

  #throttle(
    purpose: keyof IdentityRateLimiters,
    value: string,
    message: string,
    event: RateLimitedEventInit,
  ): Promise<void> {
    return enforceRateLimit({
      rateLimiter: this.#rateLimiters[purpose],
      key: RATE_KEYS[purpose](value),
      message,
      enforce: this.#enforce,
      event,
      emit: (e) => this.#emit(e),
    });
  }

  async #resetThrottle(
    purpose: keyof IdentityRateLimiters,
    value: string,
  ): Promise<void> {
    await this.#rateLimiters[purpose]?.reset(RATE_KEYS[purpose](value));
  }

  async #equalizeTiming(password: string): Promise<void> {
    await this.#passwords.hash(password);
  }

  async #rejectSignIn(startedAt: number): Promise<null> {
    const remaining = this.#failedSignInFloorMs -
      (performance.now() - startedAt);
    if (remaining > 0) await delay(remaining);
    return null;
  }

  async #isLockedOut(userId: string, identifier: string): Promise<boolean> {
    if (!this.#lockout) return false;
    const status = await this.#lockout.status(userId);
    if (!status.locked) return false;
    await this.#emit({
      type: "sign_in.locked",
      userId,
      identifier,
      enforced: this.#enforce,
    });
    return this.#enforce;
  }

  async #authenticate(
    userId: string,
    password: string,
  ): Promise<AuthenticateOutcome> {
    const credential = await this.#users.getCredential(userId);
    // Native credential is authoritative: only try an imported hash when there
    // is none, so a wrong password can't resurrect a stale one (no downgrade).
    const legacyHash = credential ? null : await this.#getLegacyCredential(
      userId,
    );
    if (!credential && !legacyHash) {
      await this.#equalizeTiming(password);
      return "no_password";
    }
    if (credential && await this.#passwords.verify(password, credential)) {
      return await this.#rehashCredential(userId, password, credential)
        ? "authenticated"
        : "wrong_password";
    }
    if (!legacyHash) return "wrong_password";
    const verifier = findLegacyVerifier(this.#legacyVerifiers!, legacyHash);
    if (!verifier || !await this.#tryLegacy(verifier, password, legacyHash)) {
      await this.#equalizeTiming(password);
      return "wrong_password";
    }
    return await this.#upgradeCredential(userId, password, verifier.id)
      ? "authenticated"
      : "wrong_password";
  }

  async #rehashCredential(
    userId: string,
    password: string,
    credential: PasswordCredential,
  ): Promise<boolean> {
    if (
      !this.#users.replaceCredential ||
      !this.#passwords.needsRehash?.(credential)
    ) return true;
    let replaced: boolean;
    try {
      replaced = await this.#users.replaceCredential(
        userId,
        credential,
        await this.#passwords.hash(password),
      );
    } catch (error) {
      this.#logPersistFailure("password rehash", error);
      return true;
    }
    return replaced || await this.#verifyCurrentCredential(userId, password);
  }

  async #upgradeCredential(
    userId: string,
    password: string,
    verifierId: string,
  ): Promise<boolean> {
    if (!this.#users.replaceCredential) return true;
    let upgraded: boolean;
    try {
      upgraded = await this.#users.replaceCredential(
        userId,
        undefined,
        await this.#passwords.hash(password),
      );
    } catch (error) {
      this.#logPersistFailure("upgrade-on-login", error);
      return true;
    }
    if (!upgraded) return await this.#verifyCurrentCredential(userId, password);
    try {
      await this.#users.clearLegacyCredential?.(userId);
    } catch (error) {
      this.#logPersistFailure("upgrade-on-login", error);
    }
    await this.#emit({ type: "password.upgraded", userId, verifierId });
    return true;
  }

  async #verifyCurrentCredential(
    userId: string,
    password: string,
  ): Promise<boolean> {
    const current = await this.#users.getCredential(userId);
    return current !== undefined &&
      await this.#passwords.verify(password, current);
  }

  #logPersistFailure(operation: string, error: unknown): void {
    console.error(
      `[@udibo/oauth2] ${operation} persist failed:`,
      error instanceof Error ? error.message : error,
    );
  }

  async #recordSignInFailure(
    userId: string,
    identifier: string,
  ): Promise<void> {
    if (!this.#lockout) return;
    const result = await this.#lockout.recordFailure(userId);
    if (!result.justLocked) return;
    await this.#emit({
      type: "lockout",
      userId,
      identifier,
      failures: result.failures,
      lockedUntil: result.lockedUntil,
      enforced: this.#enforce,
    });
  }

  async #voidPasswordlessCredentials(
    tokens: TokenFlowService,
    subject: string,
    email: string | undefined,
  ): Promise<void> {
    try {
      await tokens.invalidate(TokenPurpose.SignIn, subject);
      if (email) await this.#otp?.invalidate(email, TokenPurpose.SignIn);
    } catch (error) {
      console.error(
        "[@udibo/oauth2] resetPassword could not void the outstanding " +
          "passwordless credentials; they stay usable until they expire:",
        error instanceof Error ? error.message : error,
      );
    }
  }

  async #issueAndDeliver(
    tokens: TokenFlowService,
    request: TokenDeliveryRequest,
  ): Promise<void> {
    const { token, expiresAt } = await tokens.create({
      purpose: DELIVERY_PURPOSES[request.hook],
      subject: request.subject,
      data: request.data,
      ttlMs: request.ttlMs,
      invalidateExisting: true,
    });
    await this.#deliver(
      request.hook,
      request.to,
      token,
      request.subject,
      expiresAt,
    );
    await this.#emit(request.requested);
  }

  async #consumeToken(input: {
    tokens: TokenFlowService;
    purpose: string;
    token: string;
    failed: (reason: "expired" | "invalid") => IdentityEvent;
    beforeConsume?: (
      subject: string,
      data?: Record<string, unknown>,
    ) => Promise<void> | void;
  }): Promise<ConsumedToken> {
    const { tokens, purpose, token } = input;
    const status = await tokens.inspect(purpose, token);
    if (status.status === "expired") {
      await this.#emit(input.failed("expired"));
      return { status: "expired" };
    }
    if (status.status !== "valid") {
      await this.#emit(input.failed("invalid"));
      return { status: "invalid" };
    }
    await input.beforeConsume?.(status.subject, status.data);
    const resolved = await tokens.consume(purpose, token);
    if (!resolved) {
      await this.#emit(input.failed("invalid"));
      return { status: "invalid" };
    }
    return { status: "success", resolved };
  }

  #emit(event: IdentityEvent): Promise<void> {
    return dispatchIdentityEvent(this.#onEvent, "identity", event);
  }

  #requireTokens(method: string): TokenFlowService {
    if (!this.#tokens) {
      throw new Error(
        `IdentityService.${method}() requires a \`tokens\` option`,
      );
    }
    return this.#tokens;
  }

  #requireOtp(method: string): EmailOtpService {
    if (!this.#otp) {
      throw new Error(
        `IdentityService.${method}() requires an \`otp\` option`,
      );
    }
    return this.#otp;
  }

  async #deliver(
    hook: TokenDeliveryHook,
    to: string,
    token: string,
    subject: string,
    expiresAt: number,
  ): Promise<void> {
    const delivery = this.#delivery;
    const send = delivery?.[hook];
    if (!send) return;
    const url = this.#baseUrl
      ? URL_BUILDERS[hook](this.#baseUrl, token)
      : undefined;
    await this.#trapDeliveryFailure(
      hook,
      () => send.call(delivery, { to, url, token, subject, expiresAt }),
      async () => {
        await this.#tokens?.consume(DELIVERY_PURPOSES[hook], token);
      },
    );
  }

  async #deliverCode(
    to: string,
    code: string,
    subject: string,
    expiresAt: number,
    codeId: string,
  ): Promise<void> {
    const delivery = this.#delivery;
    const send = delivery?.sendSignInCode;
    if (!send) return;
    await this.#trapDeliveryFailure(
      "sendSignInCode",
      () => send.call(delivery, { to, code, subject, expiresAt }),
      async () => {
        await this.#otp?.invalidateCode(codeId);
      },
    );
  }

  async #trapDeliveryFailure(
    hook: keyof DeliveryHooks,
    send: () => Promise<void> | void,
    invalidate: () => Promise<void>,
  ): Promise<void> {
    try {
      await send();
      return;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const invalidated = await this.#invalidateAfterFailedDelivery(
        hook,
        invalidate,
        message,
      );
      await this.#emit({
        type: "delivery.failed",
        hook,
        invalidated,
        error: message,
      });
    }
  }

  async #invalidateAfterFailedDelivery(
    hook: keyof DeliveryHooks,
    invalidate: () => Promise<void>,
    message: string,
  ): Promise<boolean> {
    try {
      await invalidate();
      console.error(
        `[@udibo/oauth2] delivery hook ${hook} failed; minted credential invalidated:`,
        message,
      );
      return true;
    } catch (error) {
      console.error(
        `[@udibo/oauth2] delivery hook ${hook} failed AND the minted ` +
          `credential could not be invalidated — it stays live until it ` +
          `expires. Send failure:`,
        message,
        "Invalidation failure:",
        error instanceof Error ? error.message : error,
      );
      return false;
    }
  }
}

const URL_BUILDERS = {
  sendPasswordReset: buildResetUrl,
  sendAccountUnlock: buildUnlockUrl,
  sendEmailVerification: buildVerificationUrl,
  sendSignInLink: buildSignInUrl,
} as const;

const DELIVERY_PURPOSES = {
  sendPasswordReset: TokenPurpose.PasswordReset,
  sendAccountUnlock: TokenPurpose.AccountUnlock,
  sendEmailVerification: TokenPurpose.EmailVerification,
  sendSignInLink: TokenPurpose.SignIn,
} as const;

function emailFromData(
  data: Record<string, unknown> | undefined,
): string | undefined {
  const email = data?.email;
  return typeof email === "string" ? email : undefined;
}
