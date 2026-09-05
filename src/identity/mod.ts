/**
 * Identity self-service primitives for apps that own their login.
 *
 * The OAuth2/BFF machinery handles tokens and sessions; this layer covers the
 * "own-auth" flows an app otherwise hand-rolls. It is **optional** and
 * composable — own the flows and the token lifecycle, keep storage as thin,
 * app-owned seams (the `SessionStore` philosophy), never a DB-adapter zoo.
 *
 * - {@link IdentityService} — orchestrates the primitives below into sign-up,
 *   sign-in, password-reset, and email-verification flows you call from your
 *   own routes (storage stays an app-owned {@link IdentityUserStore}).
 * - {@link PasswordIdentityService} — PBKDF2 password hashing + constant-time
 *   verify (no more hand-rolled crypto); implement {@link PasswordHasherLike}
 *   instead to plug in argon2 or scrypt.
 * - {@link TokenFlowService} — single-use, hashed-at-rest verify/reset/sign-in
 *   tokens over an app-owned {@link TokenFlowStore} (magic links reuse it via
 *   {@link IdentityService.requestSignInLink}).
 * - {@link EmailOtpService} — short numeric one-time codes over an app-owned
 *   {@link OtpStore}: hashed at rest, attempt-capped (guessable-online threat
 *   model), purpose-generic so it doubles as a step-up factor. Wire it into
 *   {@link IdentityService} via the `otp` option for "email me a code"
 *   sign-in.
 * - {@link createIdentifierResolver} / {@link classifyIdentifier} — accept
 *   "email or username (or phone)" on a sign-in form without the bespoke branch.
 * - {@link DeliveryHooks} + URL builders — the seam your mailer/SMS plugs into.
 * - {@link RevocableSessionService} / {@link ListableSessionService} /
 *   {@link isRecentlyAuthenticated} — session revocation on credential change,
 *   the optional listing half ({@link SessionSummary} rows for a "where you're
 *   signed in" screen), and step-up checks.
 * - {@link RateLimiter} — opt-in throttling (wire it into
 *   {@link IdentityService}); {@link checkPasswordPolicy} — the password rules
 *   {@link IdentityService} already applies to `signUp`/`resetPassword`, at
 *   their 8–256 character defaults unless you pass a tighter `passwordPolicy`.
 * - {@link CaptchaProvider} + {@link verifyCaptcha} — the bring-your-own
 *   bot-challenge seam (Turnstile/hCaptcha/reCAPTCHA), with fail-open/closed
 *   handling; no provider means no challenge.
 * - {@link AccountLockout} — failed-attempt lockout with a self-service unlock
 *   flow ({@link IdentityService.unlockAccount}) and a log-only rollout mode
 *   via `protectionMode`.
 * - {@link IdentityEvent} + {@link IdentityEventHook} — auth-outcome events for
 *   audit capture (wire via {@link IdentityService}'s `onEvent`).
 * - {@link IdentityError} — a stable error contract a front-end can switch on.
 * - Importing users from another auth system without a password reset
 *   (upgrade-on-login) lives on its own subpath,
 *   `@udibo/oauth2/identity/migration`: the `LegacyPasswordVerifier` seam, the
 *   built-in `pbkdf2Verifier`, and `parsePhc`. Wire them through this module's
 *   {@link IdentityServiceOptions.legacyVerifiers}.
 *
 * @module
 */

export {
  DEFAULT_PBKDF2_ITERATIONS,
  generateSalt,
  hashPassword,
  LEGACY_PBKDF2_ITERATIONS,
  type PasswordCredential,
  type PasswordHasherLike,
  type PasswordHashParams,
  PasswordIdentityService,
  type PasswordIdentityServiceOptions,
  PBKDF2_SHA256,
  verifyPassword,
} from "./password.ts";
export {
  classifyIdentifier,
  createIdentifierResolver,
  type IdentifierKind,
  type IdentifierLookups,
} from "./identifier.ts";
export {
  type CreatedToken,
  type CreateTokenOptions,
  MemoryTokenFlowStore,
  type ResolvedToken,
  type TokenFlowRecord,
  TokenFlowService,
  type TokenFlowStore,
  TokenPurpose,
  type TokenStatus,
} from "./token-flow.ts";
export {
  buildResetUrl,
  buildSignInUrl,
  buildTokenUrl,
  buildUnlockUrl,
  buildVerificationUrl,
  type CodeDeliveryHook,
  type CodeDeliveryMessage,
  type DeliveryHook,
  type DeliveryHooks,
  type DeliveryMessage,
} from "./delivery.ts";
export {
  isRecentlyAuthenticated,
  type ListableSessionService,
  type RevocableSessionService,
  type SessionSummary,
  supportsSessionListing,
} from "./session.ts";
export {
  type ConsumeSignInLinkResult,
  type IdentityRateLimiters,
  IdentityService,
  type IdentityServiceOptions,
  type IdentityUser,
  type IdentityUserStore,
  type UnlockAccountResult,
  type VerifyEmailResult,
  type VerifySignInCodeResult,
} from "./service.ts";
export {
  EmailOtpService,
  type EmailOtpServiceOptions,
  MemoryOtpStore,
  type OtpRecord,
  type OtpStore,
  type RequestedOtp,
  type RequestOtpOptions,
  type VerifyOtpOptions,
  type VerifyOtpResult,
} from "./otp.ts";
export {
  AccountLockout,
  type AccountLockoutLike,
  type AccountLockoutOptions,
  type LockoutFailureResult,
  type LockoutRecord,
  type LockoutStatus,
  type LockoutStore,
  MemoryLockoutStore,
} from "./lockout.ts";
export type {
  IdentityEvent,
  IdentityEventHook,
  SignInCodeFailureReason,
  SignInFailureReason,
} from "./events.ts";
export {
  IdentityError,
  type IdentityErrorCode,
  type IdentityErrorOptions,
  type IdentityErrorStatus,
  identityErrorStatus,
  isIdentityError,
} from "./errors.ts";
export {
  MemoryRateLimitStore,
  RateLimiter,
  type RateLimiterLike,
  type RateLimiterOptions,
  type RateLimitResult,
  type RateLimitStore,
} from "./rate-limit.ts";
export {
  type CaptchaOutcome,
  type CaptchaProvider,
  type CaptchaVerifyContext,
  type CaptchaVerifyResult,
  verifyCaptcha,
  type VerifyCaptchaOptions,
} from "./captcha.ts";
export {
  assertPasswordPolicy,
  checkPasswordPolicy,
  type PasswordPolicy,
  type PasswordPolicyResult,
} from "./password-policy.ts";
export {
  type BreachedPasswordOptions,
  breachedPasswordValidator,
} from "./hibp.ts";
