/**
 * Bring-your-own bot-challenge verification for auth endpoints — the CAPTCHA
 * analogue of the {@link RateLimiterLike} seam. {@link CaptchaProvider} is the
 * contract a client-issued challenge token is verified against server-side;
 * Cloudflare Turnstile, hCaptcha, and reCAPTCHA all satisfy it, so nothing here
 * depends on a vendor SDK. {@link verifyCaptcha} composes a provider with the
 * fail-open/closed discipline a login flow needs: a missing or rejected token
 * is a refusal, but a provider *outage* degrades to your existing rate-limit and
 * lockout floor rather than locking everyone out.
 *
 * Tenant-agnostic: scope by passing whatever `action` and `ip` your provider
 * scores on. **No provider means no challenge** — {@link verifyCaptcha} passes
 * every request, so wiring the seam without configuring a provider changes
 * nothing about existing behavior.
 *
 * @module
 */

/** What a {@link CaptchaProvider} is told about the request it is scoring. */
export interface CaptchaVerifyContext {
  /**
   * The caller's IP, for providers that fold network reputation into the score
   * (Turnstile's `remoteip`, reCAPTCHA's `remoteip`). Omit when unknown.
   */
  ip?: string;
  /**
   * The flow the token was issued for (`"signup"`, `"signin"`, …). Providers
   * that bind a token to an action (reCAPTCHA v3, Turnstile `action`) verify it
   * against this; providers that don't may ignore it.
   */
  action?: string;
}

/** The outcome of a {@link CaptchaProvider.verify}. */
export interface CaptchaVerifyResult {
  /**
   * Whether the token is a valid, unspent solution to a real challenge. `false`
   * is a genuine rejection (forged, replayed, or expired token) — the caller
   * refuses the request. Reserve *throwing* for the provider being unreachable
   * so {@link verifyCaptcha} can tell a rejection apart from an outage.
   */
  success: boolean;
  /**
   * The provider's confidence in `[0, 1]` when it scores (reCAPTCHA v3,
   * Turnstile enterprise), higher meaning more likely human. Omit for
   * pass/fail providers. Surfaced for score-threshold tuning; {@link
   * verifyCaptcha} decides purely on `success`.
   */
  score?: number;
}

/**
 * The seam a bot-challenge vendor plugs into: verify one client-issued token
 * server-side and report pass/fail. The package ships **no** provider — bring
 * your own: implement this against your provider's siteverify endpoint (a
 * single HTTPS POST, as in the example below — Turnstile, hCaptcha, and
 * reCAPTCHA all take that shape) or against an enterprise bot-detection service
 * you already run. Wire the result through {@link verifyCaptcha} for the
 * fail-open/closed handling, and reject a `"fail"` decision with
 * `IdentityError` `captcha_failed`.
 *
 * @example
 * ```ts
 * const provider: CaptchaProvider = {
 *   async verify(token, context) {
 *     const body = new URLSearchParams({ secret, response: token });
 *     if (context?.ip) body.set("remoteip", context.ip);
 *     const res = await fetch(SITEVERIFY, { method: "POST", body });
 *     if (!res.ok) throw new Error(`siteverify ${res.status}`); // outage
 *     const data = await res.json() as { success: boolean };
 *     return { success: data.success };
 *   },
 * };
 * ```
 */
export interface CaptchaProvider {
  /**
   * Verify `token` server-side. Resolve `{ success: false }` for a genuine
   * rejection; **throw** when the provider cannot be reached (network error,
   * non-2xx) so an outage is distinguishable from a rejection.
   */
  verify(
    token: string,
    context?: CaptchaVerifyContext,
  ): Promise<CaptchaVerifyResult>;
}

/** The decision {@link verifyCaptcha} returns. */
export interface CaptchaOutcome {
  /** `"pass"` lets the flow proceed; `"fail"` is a refusal. */
  decision: "pass" | "fail";
  /**
   * Whether a provider actually evaluated a token. `false` means no provider
   * was configured (the request passes unchallenged) — distinct from a `"pass"`
   * a provider granted.
   */
  challenged: boolean;
  /** The provider's {@link CaptchaVerifyResult.score}, when it returned one. */
  score?: number;
  /**
   * Whether the provider could not be reached, so this outcome came from the
   * `failOpen` policy rather than a real evaluation — `true` on both the
   * fail-open `"pass"` and the fail-closed `"fail"`. Audit it: a degraded pass
   * is the window where only your rate-limit/lockout floor is protecting the
   * endpoint, and a run of degraded fails is an outage locking users out.
   */
  degraded: boolean;
}

/** Options for {@link verifyCaptcha}. */
export interface VerifyCaptchaOptions {
  /**
   * The provider to verify against. `undefined` disables the challenge
   * entirely — {@link verifyCaptcha} returns an unchallenged `"pass"`.
   */
  provider: CaptchaProvider | undefined;
  /**
   * The client-issued token from the request. A missing/empty token with a
   * provider configured is a `"fail"` (the challenge was required and not
   * answered).
   */
  token: string | null | undefined;
  /** Passed through to {@link CaptchaProvider.verify}. */
  context?: CaptchaVerifyContext;
  /**
   * What to do when the provider throws (an outage). `true` (the default)
   * fails open — the request passes with `degraded: true` — so a provider
   * outage falls back to your rate-limit/lockout floor instead of blocking
   * every user. `false` fails closed for a tenant that would rather refuse than
   * degrade.
   */
  failOpen?: boolean;
}

/**
 * Verify a client-issued CAPTCHA token with the fail-open/closed discipline an
 * auth endpoint needs, and return a {@link CaptchaOutcome}.
 *
 * - **No provider** → unchallenged `"pass"` (`challenged: false`).
 * - **Missing/empty token** → `"fail"` (the challenge went unanswered).
 * - **Provider `{ success }`** → `"pass"`/`"fail"` accordingly.
 * - **Provider throws (outage)** → `failOpen` decides `"pass"` or `"fail"`;
 *   either way the outcome is `degraded: true`, because no token was really
 *   evaluated.
 *
 * Never throws — a broken provider becomes a decision, not an exception the
 * route must catch. Compose the result with your rate limiter and lockout; this
 * does not replace them.
 *
 * @example
 * ```ts
 * const outcome = await verifyCaptcha({ provider, token, context: { ip, action: "signin" } });
 * if (outcome.decision === "fail") return uniformRejection();
 * ```
 */
export async function verifyCaptcha(
  options: VerifyCaptchaOptions,
): Promise<CaptchaOutcome> {
  const { provider, token, context } = options;
  const failOpen = options.failOpen ?? true;
  if (!provider) {
    return { decision: "pass", challenged: false, degraded: false };
  }
  if (!token) return { decision: "fail", challenged: true, degraded: false };
  try {
    const result = await provider.verify(token, context);
    return {
      decision: result.success ? "pass" : "fail",
      challenged: true,
      score: result.score,
      degraded: false,
    };
  } catch (error) {
    console.error(
      "[@udibo/oauth2] captcha provider verify failed (%s):",
      failOpen ? "fail-open, allowing" : "fail-closed, refusing",
      error instanceof Error ? error.message : error,
    );
    return {
      decision: failOpen ? "pass" : "fail",
      challenged: true,
      degraded: true,
    };
  }
}
