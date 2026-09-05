/**
 * Identity flow events — the observability seam for audit capture.
 *
 * {@link IdentityService} emits an {@link IdentityEvent} after each significant
 * auth outcome (sign-in success/failure, sign-up, credential upgrade-on-login,
 * reset and verification lifecycle, passwordless sign-in links and codes),
 * `MfaService` emits the `mfa.*` events, and a password-policy validator emits
 * `password_policy.check_unavailable` when it cannot complete its check. Wire
 * an {@link IdentityEventHook} via the service's `onEvent`
 * option to persist them in your own audit store — storage stays app-owned,
 * like every other seam in this layer.
 *
 * Some outcomes are *only* visible here, because the flow that produced them
 * resolves uniformly by design: `delivery.failed` is the sole in-band signal
 * that a message never went out (and, when `invalidated` is `false`, that a
 * live credential the user never received is still outstanding). Treat this
 * hook as a monitored surface, not just an audit log.
 *
 * Events describe internal outcomes (including whether an identifier resolved
 * to an account), so they are for server-side capture only — never surface
 * their contents to the end user, or they become an enumeration oracle.
 *
 * @module
 */

import type { DeliveryHooks } from "./delivery.ts";

/** Why a sign-in attempt failed. Internal detail — never shown to the user. */
export type SignInFailureReason =
  | "unknown_identifier"
  | "no_password"
  | "wrong_password";

/**
 * Why a sign-in code verification failed. `unknown_email` is internal-only
 * detail — the caller-facing result reports it as `invalid`.
 */
export type SignInCodeFailureReason =
  | "invalid"
  | "expired"
  | "locked"
  | "unknown_email";

/**
 * An auth outcome emitted by {@link IdentityService}, `MfaService`, or a
 * password-policy validator. Discriminated on `type`; `userId` is present when
 * the flow resolved an account.
 */
export type IdentityEvent =
  | { type: "sign_in.succeeded"; userId: string; identifier: string }
  | {
    type: "sign_in.failed";
    identifier: string;
    reason: SignInFailureReason;
    userId?: string;
  }
  | {
    type: "sign_in.rate_limited";
    identifier: string;
    retryAfterMs: number;
    enforced: boolean;
  }
  | {
    type: "sign_in.locked";
    userId: string;
    identifier: string;
    enforced: boolean;
  }
  | {
    type: "lockout";
    userId: string;
    identifier: string;
    failures: number;
    lockedUntil?: number;
    enforced: boolean;
  }
  | { type: "account_unlock.requested"; userId: string; email: string }
  | {
    type: "account_unlock.rate_limited";
    userId: string;
    email: string;
    retryAfterMs: number;
    enforced: boolean;
  }
  | { type: "account_unlock.completed"; userId: string }
  | { type: "account_unlock.failed"; reason: "expired" | "invalid" }
  | { type: "sign_up"; userId: string }
  | { type: "password.upgraded"; userId: string; verifierId: string }
  | {
    type: "password_policy.check_unavailable";
    /**
     * Which {@link PasswordPolicy} validator could not finish, as a stable
     * snake_case name. {@link breachedPasswordValidator} reports
     * `"breached_password"`.
     */
    validator: string;
    /**
     * `true` when the password was accepted anyway (the validator's `failOpen`
     * default), `false` when it was rejected instead. A run of `true` is a
     * control that stopped running — the question this event exists to answer.
     */
    failedOpen: boolean;
    /**
     * The underlying failure's message — a timeout, a DNS or egress-policy
     * refusal, a non-2xx status from the upstream service.
     */
    error: string;
  }
  | { type: "password_reset.requested"; email: string; userId?: string }
  | {
    type: "password_reset.rate_limited";
    email: string;
    retryAfterMs: number;
    enforced: boolean;
  }
  | { type: "password_reset.completed"; userId: string }
  | {
    type: "password_reset.failed";
    /**
     * `"invalid_token"` — the reset link was unknown, expired, or already used.
     * `"session_revocation_failed"` — the new password was set but the
     * configured {@link RevocableSessionService} threw before the user's other
     * sessions could be revoked, so the reset is reported failed (and rethrown)
     * rather than trusted; retry it so the still-live sessions are cleared.
     */
    reason: "invalid_token" | "session_revocation_failed";
  }
  | { type: "email_verification.requested"; userId: string; email: string }
  | {
    type: "email_verification.rate_limited";
    userId: string;
    email: string;
    retryAfterMs: number;
    enforced: boolean;
  }
  | { type: "email_verification.completed"; userId: string; email?: string }
  | { type: "email_verification.failed"; reason: "expired" | "invalid" }
  | { type: "signin_link.requested"; email: string; userId?: string }
  | { type: "signin_link.consumed"; userId: string }
  | { type: "signin_link.failed"; reason: "expired" | "invalid" }
  | {
    type: "signin_link.rate_limited";
    email: string;
    retryAfterMs?: number;
    enforced: boolean;
  }
  | { type: "signin_code.requested"; email: string; userId?: string }
  | { type: "signin_code.verified"; userId: string }
  | {
    type: "signin_code.failed";
    email: string;
    reason: SignInCodeFailureReason;
  }
  | {
    type: "signin_code.rate_limited";
    email: string;
    retryAfterMs?: number;
    enforced: boolean;
  }
  | {
    type: "delivery.failed";
    /** Which {@link DeliveryHooks} hook threw. */
    hook: keyof DeliveryHooks;
    /**
     * `true` when the just-minted token or code was invalidated after the
     * failed send — the intended outcome, nothing usable left behind. `false`
     * when that cleanup *also* failed: a live credential the recipient never
     * received is still outstanding until it expires. Alert on `false`.
     */
    invalidated: boolean;
    /** The delivery hook's failure message. */
    error: string;
  }
  | { type: "mfa.enrollment.confirmed"; userId: string }
  | {
    type: "mfa.verify.succeeded";
    userId: string;
    method: "totp" | "recovery";
    remainingRecoveryCodes?: number;
  }
  | {
    type: "mfa.verify.failed";
    userId: string;
    /**
     * `"replayed"` marks a *valid* TOTP code rejected because its time step
     * was already spent — the classic signal of code interception or a
     * concurrent session, worth distinguishing from a typo in audit review.
     */
    reason: "invalid" | "replayed";
  }
  | {
    type: "mfa.verify.rate_limited";
    userId: string;
    retryAfterMs: number;
    enforced: boolean;
  }
  | { type: "mfa.recovery_codes.regenerated"; userId: string }
  | { type: "mfa.disabled"; userId: string };

/**
 * Receives each {@link IdentityEvent} after the flow's outcome is decided. The
 * hook is awaited, but it must not affect the flow: a rejection is caught and
 * logged, never rethrown — report failures through your own channel if you
 * need delivery guarantees.
 *
 * Trigger point `event` (see `docs/trigger-points.md`) — the one
 * **fire-and-forget** seam in the identity layer.
 */
export type IdentityEventHook = (
  event: IdentityEvent,
) => void | Promise<void>;

/** The `*.rate_limited` members of {@link IdentityEvent}. */
export type RateLimitedEvent = Extract<
  IdentityEvent,
  { type: `${string}.rate_limited` }
>;

/**
 * A {@link RateLimitedEvent} minus the fields the throttle sequence fills in
 * (`retryAfterMs`, `enforced`) — what a flow passes to `enforceRateLimit`.
 */
export type RateLimitedEventInit<E = RateLimitedEvent> = E extends
  RateLimitedEvent ? Omit<E, "retryAfterMs" | "enforced">
  : never;

/**
 * Deliver an event to an optional {@link IdentityEventHook}, upholding the
 * hook contract: a rejection is logged (prefixed with `label`), never
 * rethrown. Every identity-layer service emits through this.
 */
export async function dispatchIdentityEvent(
  hook: IdentityEventHook | undefined,
  label: string,
  event: IdentityEvent,
): Promise<void> {
  if (!hook) return;
  try {
    await hook(event);
  } catch (error) {
    console.error(`[@udibo/oauth2] ${label} onEvent hook failed:`, error);
  }
}
