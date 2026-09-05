# Passwordless sign-in: magic links and email codes

Let users sign in with something they can prove they own — their mailbox —
instead of a password. `IdentityService` ships both shapes: a **magic link**
(`requestSignInLink` → `consumeSignInLink`) and a **one-time email code**
(`requestSignInCode` → `verifySignInCode`). Successful verification consumes the
credential and returns a user ID; your app decides whether to require MFA and
create a session. Request responses should not reveal account existence, but
delivery and storage timing still require attention.

This guide assumes the wiring from [add-login.md](add-login.md): an
`IdentityUserStore`, a `TokenFlowService`, and delivery hooks. Passwordless adds
one store (`OtpStore`, for codes only) and two delivery hooks.

> **Hand-routed by design.** The `honoIdentityRoutes` factory mounts only the
> password-credential path (`/signup`, `/signin`, password reset, email verify).
> Passwordless is not mounted, because the enumeration-safe response shape,
> whether `rate_limited` is swallowed, and IP throttling are app policy the
> factory can't own for you — so you call the service methods from your own
> routes, as shown below.

## Which one, and when

|                    | Magic link                                            | Email code                                    |
| ------------------ | ----------------------------------------------------- | --------------------------------------------- |
| User action        | click                                                 | type 6 digits                                 |
| Cross-device       | breaks — the link opens on whatever device reads mail | works — read on the phone, type on the laptop |
| Wrong-guess budget | not applicable (high-entropy token)                   | 5 attempts, then the code is dead             |
| Link prescanners   | corporate mail scanners can consume the token first   | unaffected                                    |
| Default lifetime   | 15 minutes                                            | 10 minutes                                    |
| Needs              | `tokens`                                              | the `otp` option                              |

Codes survive the two failure modes that make magic links frustrating: a user
signing in on a device that isn't the one holding their mail, and a security
appliance that "clicks" every link in an inbound message and burns the
single-use token before the human sees it. Links win on one thing — no typing.
Shipping both and letting the user pick is a reasonable default; shipping only
codes is a defensible one.

## Wire it up

```ts
import {
  IdentityService,
  MemoryOtpStore,
  MemoryTokenFlowStore,
  RateLimiter,
  TokenFlowService,
} from "@udibo/oauth2/identity";

import type { IdentityUserStore } from "@udibo/oauth2/identity";

export function createIdentityService(
  users: IdentityUserStore<{ id: string }>,
  mail: { enqueue(message: Record<string, unknown>): void },
): IdentityService<{ id: string }> {
  return new IdentityService({
    users,
    tokens: new TokenFlowService(new MemoryTokenFlowStore()),
    otp: { store: new MemoryOtpStore() },
    baseUrl: "https://app.example.com",
    rateLimiter: new RateLimiter(),
    delivery: {
      sendSignInLink: (message) =>
        mail.enqueue({
          to: message.to,
          template: "sign-in-link",
          url: message.url,
          expiresAt: message.expiresAt,
        }),
      sendSignInCode: (message) =>
        mail.enqueue({
          to: message.to,
          template: "sign-in-code",
          code: message.code,
          expiresAt: message.expiresAt,
        }),
    },
  });
}
```

Three things to notice.

`sendSignInCode` receives a `CodeDeliveryMessage`, not a `DeliveryMessage`:
there is no `url`, because a code is typed rather than clicked. Putting the code
behind a link in the email defeats the point — it re-introduces the cross-device
problem you chose codes to avoid.

The magic link lands on `/signin-link?token=…` under your `baseUrl` (see
`buildSignInUrl` to change the path). As with every other emailed link, build it
from configuration and never from the request's `Host` header.

`otp` takes only storage and the code shape (`digits`, `ttlMs`, `maxAttempts`) —
**not** a rate limiter. The service's own `rateLimiter` throttles both halves of
the code flow. Omit `otp` and `requestSignInCode` throws; omit `tokens` and
`requestSignInLink` throws.

## Implement `OtpStore`

Codes need a different store from links because they carry an attempt budget:

```ts
import type { OtpRecord } from "@udibo/oauth2/identity";

interface OtpStore {
  create(record: OtpRecord): Promise<void>;
  findActive(email: string, purpose: string): Promise<OtpRecord | null>;
  recordAttempt(id: string): Promise<number>;
  consume(id: string): Promise<boolean>;
  invalidateById(id: string): Promise<void>;
  invalidate(email: string, purpose: string): Promise<void>;
}
```

One table maps onto `OtpRecord` — `id`, `email`, `purpose`, `codeHash`,
`expiresAt`, `attempts`, `maxAttempts`, `createdAt`. Only the **hash** is stored
(SHA-256, domain-bound to email + purpose). The stored hash cannot be submitted
as a working code, but a six-digit code has a small enough search space to
recover through offline guessing after a database disclosure. Restrict access to
these records and never log codes or hashes.

Contract details a working implementation depends on:

- **`consume` atomically claims an active code and returns `true` only once.**
  Concurrent and repeated claims return `false`; a read followed by a write is
  insufficient. Use a conditional delete/update with `RETURNING`.

- **`recordAttempt` must be atomic and return the new count** —
  `UPDATE … SET attempts = attempts + 1 … RETURNING attempts`. The service
  reserves the attempt _before_ comparing the code, so at most `maxAttempts`
  guesses ever reach the comparison. A read-then-write lets concurrent verifies
  each test a guess against a stale count and blow straight through the budget.
- **`findActive` must still return expired records.** Expiry is the service's
  concern — it needs to see the row to report `expired` distinctly from
  `invalid`.
- **"Active" means neither consumed nor invalidated.** Deleting the row on
  consume/invalidate is the simplest way to satisfy that; reap expired rows on a
  schedule or opportunistically on insert.

`MemoryOtpStore` implements the contract for development and tests.

## The request half: identical for everyone

Both request methods resolve the same way whether or not the email maps to an
account. Your route must not undo that:

```ts
import { isIdentityError } from "@udibo/oauth2/identity";
import type { IdentityService } from "@udibo/oauth2/identity";

export async function requestCode(
  identity: IdentityService<{ id: string }>,
  email: string,
): Promise<{ status: number; body: { ok: true } }> {
  try {
    await identity.requestSignInCode(email);
  } catch (error) {
    if (!isIdentityError(error) || error.code !== "rate_limited") throw error;
  }
  return { status: 200, body: { ok: true } };
}
```

Catching `rate_limited` and returning the same success shape is deliberate: a
`429` on the request endpoint tells an attacker which addresses are worth
retrying. Keep the copy flat too — "If an account exists for that address, we've
sent a code" — for both branches.

The **return value** is uniform; the timing is not quite. Only the known-email
branch awaits token minting and delivery, so an attacker measuring response
latency has a residual oracle. Two mitigations, both at your route:

- **Enqueue the mail, don't await your provider.** A queue hand-off is
  microseconds; an SMTP round-trip is hundreds of milliseconds of signal.
- **Throttle by IP as well as by email.** The service has no request context —
  that seam is deliberately yours — and per-email limits alone don't stop a
  sweep across many addresses.

## The verify half

Codes report only success or invalid:

```ts
import type { IdentityService } from "@udibo/oauth2/identity";

export async function verifyCode(
  identity: IdentityService<{ id: string }>,
  email: string,
  code: string,
): Promise<string | null> {
  const result = await identity.verifySignInCode({ email, code });
  return result.status === "success" ? result.userId : null;
}
```

`VerifySignInCodeResult` is deliberately narrower than the underlying
`VerifyOtpResult`. `EmailOtpService.verify` distinguishes `invalid`, `expired`,
and `locked`; `verifySignInCode` collapses all three — plus "no such email" —
into `invalid`, because "your code expired" tells the sender that the address
has an account. The precise reason is still recorded server-side on the
`signin_code.failed` event, which is where it belongs.

Links get the fuller result, because a high-entropy token is not enumerable and
"this link expired, request a new one" is a real usability win:

```ts
import type { IdentityService } from "@udibo/oauth2/identity";

export async function consumeLink(
  identity: IdentityService<{ id: string }>,
  token: string,
): Promise<{ userId: string } | { retry: boolean }> {
  const result = await identity.consumeSignInLink(token);
  if (result.status === "success") return { userId: result.userId };
  return { retry: result.status === "expired" };
}
```

Whichever half returned a `userId`, three things are still your job:

1. **Re-resolve the user.** An account deleted or disabled since the code or
   link was minted must be treated as a failed sign-in, not signed in.
2. **Run your MFA gate.** Passwordless must not be the path around a second
   factor — see
   [add-mfa.md](add-mfa.md#the-challenge-one-gate-every-sign-in-path).
3. **Create the session.** The library never does.

## Throttling keys

Both flows throttle on the service's `rateLimiter`, keyed by case-folded email
so casing variants share one window:

| Flow                                     | Key                  |
| ---------------------------------------- | -------------------- |
| `requestSignInLink`                      | `pwless:<email>`     |
| `requestSignInCode` / `verifySignInCode` | `otp:signin:<email>` |

The code flow deliberately shares one key between request and verify: an
attacker who can burn attempts _and_ mint fresh codes at will gets an unbounded
number of guesses at six digits. A successful `verifySignInCode` resets the
window. On top of that, each individual code carries its own budget
(`maxAttempts`, default 5) and dies when it is spent — so the two limits cover
"guess this code" and "keep asking for new codes" separately.

Running more than one instance, back the limiter with a shared `RateLimitStore`
over Redis or your database; a per-process counter multiplies every limit by
your instance count.

## A password reset voids both

`IdentityService.resetPassword` drops the subject's pending sign-in links and
the pending sign-in code once the password changes, so a link an attacker
requested before the reset cannot be walked in on afterwards. It needs the
optional `TokenFlowStore.deleteBySubject` to do the link half — a store without
it leaves outstanding links redeemable until they expire — and it reaches the
email-keyed code through the `data.email` that `requestPasswordReset` records on
the reset token, so an app that mints reset tokens through
`TokenFlowService.create` itself gets the link half only.

## Codes for other purposes

`EmailOtpService` is purpose-generic — `purpose` is a free string — so the same
machinery covers step-up confirmation, email change, or high-value action
approval without a second implementation:

```ts
import { EmailOtpService, MemoryOtpStore } from "@udibo/oauth2/identity";

const otp = new EmailOtpService({
  store: new MemoryOtpStore(),
  ttlMs: 5 * 60_000,
  maxAttempts: 3,
});

export async function confirmPayout(
  email: string,
  code: string,
): Promise<boolean> {
  const result = await otp.verify({ email, purpose: "payout", code });
  return result.status === "success";
}
```

Used standalone it takes its own `rateLimiter`; used through `IdentityService`
it does not, because the service throttles for it. Sequential requests for a
`(email, purpose)` pair invalidate earlier codes. Invalidation and creation are
separate operations, so concurrent requests can leave multiple live codes.
Serialize issuance across instances if your app requires only one outstanding
code. Atomic `consume` ensures each individual code can succeed only once.

A six-digit code has only one million possible values. Hash it at rest, restrict
access to the store, and retain it briefly, but do not treat the hash as
protection against offline guessing after a database disclosure.

## Security checklist

Before going live:

- [ ] **Request responses are uniform** in status, body, copy, and — as far as
      you can manage — timing. `rate_limited` is caught and reported as the same
      success.
- [ ] **Mail is enqueued, never awaited in-request**, and the route is throttled
      by IP in addition to the service's per-email limit.
- [ ] **`recordAttempt` is a single atomic statement** returning the new count.
- [ ] **Codes are stored hashed**; nothing logs the raw code, including your
      delivery callback's error paths.
- [ ] **Links are built from configured `baseUrl`**, arrive over HTTPS, and the
      landing route consumes the token on a **POST** (or immediately redirects
      without the token in the URL) so it doesn't leak through `Referer` or
      browser history.
- [ ] **Codes are not embedded in a link** in the email body.
- [ ] **The user is re-resolved and the MFA gate runs** before any session is
      created.
- [ ] **`signin_link.*` and `signin_code.*` events are captured** server-side
      only; their `reason` fields are enumeration-grade detail.
