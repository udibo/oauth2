# Add MFA to an app that owns its login

Add a TOTP second factor with recovery codes to an app already running
`IdentityService`. By the end you have enrollment behind a confirmation code, a
challenge step every sign-in path passes through, single-use recovery codes for
the lost-phone case, and a throttle that makes a six-digit code un-guessable.
The library owns the TOTP math, the replay guard, and the code-burning rules;
your app keeps owning the rows, the routes, and the **policy** — whether MFA is
optional or required, and where in your sign-in flow the challenge happens.

Everything below imports from `@udibo/oauth2/identity/mfa`, except the step-up
helper (`@udibo/oauth2/identity`) and the forms
(`@udibo/oauth2/react/components`).

> **Hand-routed by design.** The `honoIdentityRoutes` factory mounts only the
> password-credential path (`/signup`, `/signin`, password reset, email verify).
> MFA is not mounted, because _when_ a challenge is required, where the pending
> challenge state lives, and the cookie shape are app policy the factory can't
> own for you — so you call `MfaService` from your own routes, as shown below.

## How the pieces fit

| Seam          | You implement                  | Backs                     |
| ------------- | ------------------------------ | ------------------------- |
| `MfaStore`    | one table keyed by user id     | secrets + recovery hashes |
| `RateLimiter` | in-memory, Redis, or your DB   | throttling `verify`       |
| `onEvent`     | your audit log                 | `mfa.*` outcomes          |
| your routes   | enrollment, challenge, step-up | when a code is demanded   |

`MfaService` is the orchestrator. It has no opinion about sessions: it answers
"is this code valid for this user", and your sign-in path decides what that
means.

## Implement `MfaStore`

One table keyed by user id, holding the active secret, the replay guard, the
pending (unconfirmed) secret, and the unused recovery-code hashes:

```ts
import type { MfaTotpRecord } from "@udibo/oauth2/identity/mfa";

interface MfaStore {
  getTotp(userId: string): Promise<MfaTotpRecord | undefined>;
  setPendingTotp(userId: string, secretBase32: string): Promise<void>;
  activateTotp(
    userId: string,
    secretBase32: string,
    lastStep: number,
  ): Promise<boolean>;
  clearTotp(userId: string): Promise<void>;
  advanceLastStep(userId: string, step: number): Promise<boolean>;
  getRecoveryHashes(userId: string): Promise<string[]>;
  setRecoveryHashes(userId: string, hashes: string[]): Promise<void>;
  consumeRecoveryHash(userId: string, hash: string): Promise<boolean>;
}
```

Two rules decide whether your implementation is sound.

**Encrypt the secrets at rest.** `secretBase32` and `pendingSecretBase32` are
symmetric keys, not hashes — anyone holding the column can generate valid codes
forever. Seal them with whatever your app already uses for secrets
(`seal`/`unseal` from `@udibo/oauth2/crypto` over a key from your secret manager
is enough) and unseal them inside the store. Recovery codes are the opposite:
the library hands you hashes and never asks for the plaintext back.

**Three methods must be atomic.** `activateTotp`, `advanceLastStep`, and
`consumeRecoveryHash` are the concurrency guards of the whole design, and a
read-then-write defeats each of them:

- `advanceLastStep(userId, step)` is the TOTP replay guard —
  `UPDATE … SET last_step = $step WHERE last_step IS NULL OR last_step < $step`,
  returning whether a row changed. Two requests submitting the same intercepted
  code must not both win.
- `consumeRecoveryHash(userId, hash)` is what makes a recovery code single-use —
  delete the hash and report the row count, never filter-then-write.
- `activateTotp(userId, secret, lastStep)` promotes the pending secret **only
  when it is still the one the confirmation code was verified against**, so a
  second enrollment started mid-flow can't be activated by the first one's code.

`MemoryMfaStore` implements the contract for development and tests.

## Construct the service

```ts
import { RateLimiter } from "@udibo/oauth2/identity";
import { MemoryMfaStore, MfaService } from "@udibo/oauth2/identity/mfa";

export const mfa = new MfaService({
  store: new MemoryMfaStore(),
  rateLimiter: new RateLimiter({ limit: 5, windowMs: 5 * 60_000 }),
  onEvent: (event) => console.log(event.type),
});
```

The `rateLimiter` is not optional in spirit: a six-digit code is one in a
million, and an unthrottled `verify` endpoint is a brute-force target. It is
keyed `mfa:verify:<userId>`, and a successful verification resets the window so
a legitimate user who fat-fingers a code never accumulates toward a block. When
the limit is hit, `verify` throws `IdentityError("rate_limited")` — map it to
`429` with `Retry-After`, or set `protectionMode: "log-only"` to watch real
traffic for a week before enforcing.

Configure TOTP `digits`, `periodSeconds`, and `algorithm` consistently with
enrollment; changing them requires a migration or re-enrollment. `windows` only
controls accepted clock drift and does not change authenticator provisioning.
The defaults are 6 digits, 30 seconds, SHA-1, and ±1 accepted time step.

## Enrollment: start, then confirm

These service calls assume an authenticated, recently verified application user.
Resolve the user from your session, authorize enrollment changes for that user,
and enforce CSRF on the enclosing POST routes. Never use an arbitrary submitted
`userId`. `MfaService` verifies MFA credentials; it does not authenticate the
HTTP request or decide who may enroll, disable, or regenerate recovery codes.

Enrollment is two steps on purpose. `startEnrollment` stores a **pending**
secret that `verify` ignores, so an abandoned enrollment can never lock a user
out of their account:

```ts
import type {
  MfaEnrollmentStart,
  MfaService,
} from "@udibo/oauth2/identity/mfa";

export function beginEnrollment(
  mfa: MfaService,
  user: { id: string; email: string },
): Promise<MfaEnrollmentStart> {
  return mfa.startEnrollment(user.id, {
    issuer: "Example",
    accountName: user.email,
  });
}
```

You get back `base32` (for manual entry) and `otpauthUri` (to render as a QR
code — the package ships no QR dependency). Neither is a session-independent
credential yet.

`confirmEnrollment` proves the authenticator actually works before anything is
activated. On success the secret becomes active and a fresh recovery-code set is
generated; the plaintext codes are returned **once** and only their hashes are
stored:

```ts
import type { MfaService } from "@udibo/oauth2/identity/mfa";

export async function confirmEnrollment(
  mfa: MfaService,
  userId: string,
  code: string,
): Promise<{ ok: boolean; recoveryCodes?: string[] }> {
  const result = await mfa.confirmEnrollment(userId, code);
  if (!result.confirmed) return { ok: false };
  return { ok: true, recoveryCodes: result.recoveryCodes };
}
```

Show those codes on the next screen and nowhere else — not in an email, not in a
log line, never again from the database. If storing them fails, the
just-activated credential is rolled back and the error rethrown: a failure
leaves the user _not_ enrolled and free to retry, never enrolled without the
recovery codes they were promised.

Re-enrolling requires `disable` first — `startEnrollment` and
`confirmEnrollment` throw `IdentityError("mfa_already_enrolled")` (409) while an
active credential exists, so a hijacked session cannot silently swap the user's
authenticator for its own.

## The challenge: one gate, every sign-in path

`verify` is the whole challenge API:

```ts
import type { MfaService } from "@udibo/oauth2/identity/mfa";

export type SignInStep = "session" | "challenge";

export async function nextStep(
  mfa: MfaService,
  userId: string,
): Promise<SignInStep> {
  return await mfa.isEnrolled(userId) ? "challenge" : "session";
}
```

With Hono identity routes, put this decision in `onAuthenticated`:

```ts
import { honoIdentityRoutes } from "@udibo/oauth2/hono/identity";
import type { IdentityService } from "@udibo/oauth2/identity";
import type { MfaService } from "@udibo/oauth2/identity/mfa";
import type { Context } from "hono";

declare const identity: IdentityService<{ id: string }>;
declare const mfa: MfaService;
declare function beginPendingMfa(c: Context, userId: string): Promise<Response>;
declare function createApplicationSession(
  c: Context,
  userId: string,
): Promise<Response>;

const routes = honoIdentityRoutes(identity, {
  onAuthenticated: async (c, user) => {
    if (await mfa.isEnrolled(user.id)) return await beginPendingMfa(c, user.id);
    return await createApplicationSession(c, user.id);
  },
});
```

The declared functions are application code. `beginPendingMfa` stores a
short-lived, one-use pending login bound to this browser; it must not grant API
access. The challenge route validates that pending state and CSRF, resolves the
account again, calls `mfa.verify`, and creates a session only after a valid
result. Passwordless and social callbacks must follow the same application
decision.

Two rules govern that implementation:

**Put the gate in front of session creation, not after it.** The user has passed
the first factor but is not signed in yet. Carry the pending state in a
short-lived, `HttpOnly`, path-scoped sealed cookie with a server-side expiry —
not in a session — and mint the session only after `verify` returns valid. A
"logged in but not yet MFA'd" session is a session an attacker can use.

**Every login method goes through the same gate.** Password sign-in,
passwordless codes and links, and social callbacks all end with "we believe this
is user X" — and every one of them must ask the same question before minting a
session. A second factor that only the password form enforces is a second factor
an attacker routes around by clicking "email me a link".

Re-resolve the user at the end of the flow, too. An account deleted or disabled
between the first factor and the challenge must fail the sign-in; the pending
cookie only carries an id.

## TOTP versus recovery codes

`verify` tries TOTP against the active secret first, then falls back to a
recovery code. Restrict it when your UI knows which one the user is submitting:

```ts
import type { MfaService, MfaVerification } from "@udibo/oauth2/identity/mfa";

export function verifyAuthenticator(
  mfa: MfaService,
  userId: string,
  code: string,
): Promise<MfaVerification> {
  return mfa.verify(userId, code, { method: "totp" });
}
```

Passing `method: "totp"` on the authenticator field means a mistyped entry can
never silently burn a recovery code; the dedicated "use a recovery code" screen
passes `method: "recovery"`.

A successful recovery redemption reports `remainingRecoveryCodes` — surface it,
and prompt for regeneration when it runs low:

```ts
import type { MfaService } from "@udibo/oauth2/identity/mfa";

export async function lowRecoveryCodeWarning(
  mfa: MfaService,
  userId: string,
  code: string,
): Promise<string | undefined> {
  const result = await mfa.verify(userId, code);
  if (
    result.valid && result.method === "recovery" &&
    result.remainingRecoveryCodes <= 2
  ) {
    return "Running low on recovery codes — generate a new set.";
  }
}
```

`regenerateRecoveryCodes(userId)` replaces the whole set (every previously
issued code stops working) and throws `IdentityError("mfa_not_enrolled")` (409)
for a user with no active credential. Without an active credential every code is
rejected, so stale hashes can never authenticate a user whose MFA was turned
off.

A rejected code that _was_ mathematically valid — a replay of a spent time step
— emits `mfa.verify.failed` with `reason: "replayed"`. That is the signal of an
intercepted code or a duplicated submission, and it is worth alerting on
differently from a typo.

## Step-up: gate the destructive routes

Disabling MFA and regenerating recovery codes are what an account takeover wants
most. Demand fresh proof of presence in front of both. Either check the
session's last authentication:

```ts
import { isRecentlyAuthenticated } from "@udibo/oauth2/identity";

export function needsReauthentication(authenticatedAt: number): boolean {
  return !isRecentlyAuthenticated(authenticatedAt, 5 * 60_000);
}
```

…or collect the credential in the same request as the action — a password for
accounts that have one, a TOTP or recovery code for accounts that don't. The
in-request form is stricter: freshness is exact rather than a window, and there
is no elevated-session flag to steal. Whichever you pick, throttle it on the
same per-user bucket the challenge uses; step-up is another place a code can be
guessed.

## How MFA interacts with reset and lockout

- **Password reset does not clear MFA.** `resetPassword` sets the credential,
  revokes sessions, and clears the failed-attempt lockout; the second factor
  still applies on the next sign-in. That is the point — an attacker with
  mailbox access must not be able to reset their way past the factor.
- **A wrong code never locks the account.** `AccountLockout` counts wrong
  _passwords_. MFA failures are throttled per user instead, so a challenge form
  can't be used to lock a victim out of their own account.
- **Losing both factors needs an operator path.** The library's only reset is
  `disable(userId)`, and it ships no "email me past MFA" flow, deliberately —
  such a flow reduces MFA to email possession. Build an identity-checked support
  path, gate it behind step-up, and audit the `mfa.disabled` event.
- **Reset the sign-in throttle after an unlock**, exactly as in
  [add-login.md](add-login.md#self-service-unlock); MFA changes nothing there.

## Wiring the prebuilt forms

`MfaEnrollmentForm` renders the secret, your QR node, and the one-time recovery
codes, then collects the confirmation code:

```tsx
import { MfaEnrollmentForm } from "@udibo/oauth2/react/components";

export function EnrollmentPanel(props: {
  secret: string;
  otpauthUri: string;
  recoveryCodes: string[];
}) {
  return (
    <MfaEnrollmentForm
      data={props}
      onSubmit={async ({ code }) => {
        const res = await fetch("/auth/mfa/enroll/confirm", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ code }),
        });
        if (!res.ok) return { error: "That code was not valid." };
      }}
    />
  );
}
```

`MfaChallengeForm` collects the code and forwards which credential it is, so
your endpoint can pass the matching `method` through to `verify`:

```tsx
import { MfaChallengeForm } from "@udibo/oauth2/react/components";

export function Challenge() {
  return (
    <MfaChallengeForm
      onSubmit={async (values) => {
        const res = await fetch("/auth/mfa/verify", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(values),
        });
        if (!res.ok) return { error: "That code was not valid." };
      }}
    />
  );
}
```

Both ship unstyled with per-slot `className` hooks and a render-prop escape
hatch; see the
[prebuilt components section](react.md#forms-for-an-app-that-hosts-its-own-login)
of the README for theming and the headless `useAuthForm` path.

## Security checklist

Before going live:

- [ ] **Secrets are encrypted at rest.** `secretBase32` and
      `pendingSecretBase32` are keys, not hashes; a dump of the table must not
      yield working codes.
- [ ] **The three atomic store methods are conditional writes.**
      `advanceLastStep`, `consumeRecoveryHash`, and `activateTotp` are single
      statements whose affected-row count is the answer.
- [ ] **`verify` is rate limited** with a shared store if you run more than one
      instance, and `protectionMode` is `"enforce"`.
- [ ] **Every sign-in path passes the gate** — password, passwordless link,
      passwordless code, and every social callback — and the session is minted
      only after it.
- [ ] **Pending MFA state is a sealed, short-lived, path-scoped cookie**, never
      a session, and the user is re-resolved before the session is created.
- [ ] **Recovery codes are displayed once**, stored only as hashes, and the
      authenticator field passes `method: "totp"` so it can't burn one.
- [ ] **Disable and regenerate are behind step-up**, throttled, and audited.
- [ ] **`mfa.*` events reach a durable audit store**, with `mfa.verify.failed` /
      `reason: "replayed"` alerting separately from an ordinary wrong code.
