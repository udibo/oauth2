/**
 * Delivery seam for identity self-service messages (verification, reset, and
 * passwordless sign-in links, plus one-time sign-in codes).
 *
 * The library owns the **token lifecycle** ({@link TokenFlowService}); your app
 * owns **transport** — SMTP, SES, Resend, Twilio, etc. So delivery is a set of
 * app-supplied async hooks, and the package ships URL builders so apps stop
 * hand-assembling `${protocol}://${host}/verify-email?token=…` strings. This is
 * the Better Auth model (`sendVerificationEmail` / `sendResetPassword`).
 *
 * @module
 */

/** What a delivery hook receives for one message. */
export interface DeliveryMessage {
  /** Recipient — an email address or phone number. */
  to: string;
  /**
   * The ready-to-use action link (already carrying the token), when the caller
   * built one via {@link buildVerificationUrl} / {@link buildResetUrl}. Absent
   * if you'd rather build the message body from `token` yourself.
   */
  url?: string;
  /** The raw token, for apps that compose their own URL or message. */
  token: string;
  /** The subject the token acts on (typically a user id). */
  subject: string;
  /** Token expiry, epoch ms. */
  expiresAt: number;
}

/** A single delivery transport callback. */
export type DeliveryHook = (message: DeliveryMessage) => Promise<void> | void;

/**
 * What a code-delivery hook receives for one message. Unlike a
 * {@link DeliveryMessage} there is no URL — a one-time code is typed in, not
 * clicked — and the raw `code` is the whole payload.
 */
export interface CodeDeliveryMessage {
  /** Recipient — an email address or phone number. */
  to: string;
  /** The one-time code to include in the message body, e.g. `"482913"`. */
  code: string;
  /** The subject the code signs in (typically a user id). */
  subject: string;
  /** Code expiry, epoch ms. */
  expiresAt: number;
}

/** A delivery transport callback for one-time codes. */
export type CodeDeliveryHook = (
  message: CodeDeliveryMessage,
) => Promise<void> | void;

/**
 * App-supplied delivery transports. Omit a hook to disable that message type.
 * The package calls the relevant hook after minting the token; you send it.
 *
 * Trigger point `delivery` (see `docs/trigger-points.md`). The package calls a
 * hook after minting the credential; a **throw** (e.g. a mailer outage) is
 * trapped for every hook here: `IdentityService` invalidates the just-minted
 * token or code — best effort, so a failed send does not leave a live,
 * un-emailed credential in your store — and the requesting flow still resolves
 * with its uniform result, so a transport outage cannot become an
 * account-enumeration oracle. Handle transport failures inside the hook (log,
 * retry, queue) if you need to observe or recover from them; the flow will not
 * surface the throw to your caller.
 *
 * Every trapped failure emits the `delivery.failed` identity event, carrying the
 * hook and an `invalidated` flag. `invalidated: false` means the cleanup failed
 * too and a credential the recipient never received is live until it expires —
 * the one case that needs an alert, and only your `onEvent` hook can see it.
 */
export interface DeliveryHooks {
  /** Deliver an email-verification link. */
  sendEmailVerification?: DeliveryHook;
  /** Deliver a password-reset link. */
  sendPasswordReset?: DeliveryHook;
  /** Deliver an account-unlock link after a failed-attempt lockout. */
  sendAccountUnlock?: DeliveryHook;
  /** Deliver a passwordless sign-in (magic) link. */
  sendSignInLink?: DeliveryHook;
  /** Deliver a one-time sign-in code (no URL; the user types the code in). */
  sendSignInCode?: CodeDeliveryHook;
}

/**
 * Build an absolute action URL that embeds a token as a query parameter.
 *
 * @param base An origin (e.g. `https://app.example`) or origin + path prefix.
 * @param path The route the token is consumed at (e.g. `/reset-password`).
 * @param token The raw token to embed.
 * @param param The query parameter name. Defaults to `"token"`.
 */
export function buildTokenUrl(
  base: string,
  path: string,
  token: string,
  param = "token",
): string {
  const url = new URL(path, base);
  url.searchParams.set(param, token);
  return url.toString();
}

/** Build an email-verification URL (default path `/verify-email`). */
export function buildVerificationUrl(
  base: string,
  token: string,
  path = "/verify-email",
): string {
  return buildTokenUrl(base, path, token);
}

/** Build a password-reset URL (default path `/reset-password`). */
export function buildResetUrl(
  base: string,
  token: string,
  path = "/reset-password",
): string {
  return buildTokenUrl(base, path, token);
}

/** Build a passwordless sign-in (magic-link) URL (default path `/signin-link`). */
export function buildSignInUrl(
  base: string,
  token: string,
  path = "/signin-link",
): string {
  return buildTokenUrl(base, path, token);
}

/** Build an account-unlock URL (default path `/unlock-account`). */
export function buildUnlockUrl(
  base: string,
  token: string,
  path = "/unlock-account",
): string {
  return buildTokenUrl(base, path, token);
}
