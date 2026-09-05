# Add login to an existing app

Wire sign-up, sign-in, password reset, email verification, and brute-force
protection into an app that already has a users table. By the end you have an
`IdentityService` running over your own database and sessions, with delivery
hooks feeding your mailer, explicitly configured rate limits and lockout, and
authentication events for your audit log. The library owns the flows and the
crypto; your app keeps owning its schema, its ORM, its session cookie, and its
UI.

If you are starting from scratch instead, the [quickstart](../quickstart.md)
gets you to a first login on in-memory stores; this guide is the production
version of the same wiring.

## How the pieces fit

`IdentityService` orchestrates a handful of primitives, each of which touches
your app through a small interface you implement:

| Seam                              | You implement           | Backs                         |
| --------------------------------- | ----------------------- | ----------------------------- |
| `IdentityUserStore`               | over your users table   | all flows                     |
| `TokenFlowStore`                  | one small table         | reset / verify / unlock links |
| `RevocableSessionService`         | over your session store | revocation on password reset  |
| `ListableSessionService`          | same store (optional)   | "where you're signed in" list |
| `DeliveryHooks`                   | your mailer             | emailed action links          |
| `RateLimitStore` / `LockoutStore` | Redis or DB (optional)  | shared-state protection       |
| `IdentityEventHook`               | your audit log          | observability                 |

There is no adapter package per database and no migration the library imposes.
Each seam is a few dozen lines over whatever data layer you already run — the
snippets below use Drizzle-style queries over Postgres; any ORM or raw SQL can
implement the contracts.

Everything below imports from `@udibo/oauth2/identity`.

## Implement `IdentityUserStore` over your database

This is the one required seam. The service addresses users only by opaque `id`,
so your schema stays untouched — you add two credential columns (or a
credentials table) and implement its required members:

```ts
import type { IdentityUser, PasswordCredential } from "@udibo/oauth2/identity";

interface IdentityUserStore<User extends IdentityUser> {
  create(
    profile: Record<string, unknown>,
    credential: PasswordCredential,
  ): Promise<User>;
  findByIdentifier(identifier: string): Promise<User | undefined>;
  findByEmail(email: string): Promise<User | undefined>;
  getCredential(userId: string): Promise<PasswordCredential | undefined>;
  setCredential(userId: string, credential: PasswordCredential): Promise<void>;
  replaceCredential?(
    userId: string,
    expected: PasswordCredential | undefined,
    credential: PasswordCredential,
  ): Promise<boolean>;
  markEmailVerified?(userId: string, email?: string): Promise<void>;
}
```

The interface also carries the optional migration hooks `getLegacyCredential` /
`clearLegacyCredential`, used only when importing hashes from another provider —
see [migrate-from-another-provider.md](migrate-from-another-provider.md).

Each method's contract, including what it must do for enumeration safety:

- **`create(profile, credential)`** — insert the user and the hashed credential
  in one step (one transaction; no window where the user exists without a
  password). `profile` is whatever your sign-up form posted, so validate it here
  — it is your app's fields, not the library's. Enforce email uniqueness with a
  database constraint, not a pre-check, and translate the violation to
  `IdentityError("identifier_taken")` so the mounted routes return a `409`.
- **`findByIdentifier(identifier)`** — the sign-in lookup. Normalize the same
  way you normalize at write time (trim, lowercase email) or users will fail to
  sign in with the address they registered. If sign-in accepts email _or_
  username, branch here — `classifyIdentifier` from the same subpath tells them
  apart.
- **`findByEmail(email)`** — the reset/verification-request lookup. Return
  `undefined` for an unknown email and do nothing else; the service already
  guarantees `requestPasswordReset` resolves identically either way, so your
  store must not log, throw, or otherwise behave observably differently.
- **`getCredential(userId)`** — return the stored `{ hash, salt }`, or
  `undefined` for accounts with no password (e.g. SSO-only). The service burns a
  comparable hashing delay on `undefined` so a password-less account is not
  distinguishable by response timing — you just return what's there.
- **`setCredential(userId, credential)`** — overwrite the credential; called by
  password reset. Nothing else: session revocation and lockout clearing are the
  service's job.
- **`replaceCredential(userId, expected, credential)`** — optional atomic
  compare-and-set for automatic rehash and imported-password upgrades. Compare
  the stored hash, salt and params with `expected`; `undefined` means no native
  credential may exist. Return `false` without writing if anything changed.
  Without this hook sign-in still works, but automatic upgrades are skipped.
- **`markEmailVerified(userId, email?)`** — flip your verified flag, for the
  address the verification link was minted for. Optional; omit it if you don't
  verify email. Predicate the update on both the id **and** the address (see
  below) — a one-argument implementation still compiles and is still vulnerable.

Over Drizzle/Postgres:

```ts ignore
import { and, eq, isNull } from "drizzle-orm";
import { IdentityError, type IdentityUserStore } from "@udibo/oauth2/identity";

import { db } from "./db.ts";
import { type AppUser, users } from "./schema.ts";

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

async function findUserByEmail(email: string): Promise<AppUser | undefined> {
  const [user] = await db.select().from(users)
    .where(eq(users.email, normalizeEmail(email)));
  return user;
}

export const userStore: IdentityUserStore<AppUser> = {
  async create(profile, credential) {
    const email = normalizeEmail(String(profile.email ?? ""));
    try {
      const [user] = await db.insert(users).values({
        email,
        name: String(profile.name ?? ""),
        passwordHash: credential.hash,
        passwordSalt: credential.salt,
        passwordParams: credential.params ?? null,
      }).returning();
      return user;
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new IdentityError("identifier_taken", undefined, {
          cause: error,
        });
      }
      throw error;
    }
  },
  findByIdentifier: (identifier) => findUserByEmail(identifier),
  findByEmail: (email) => findUserByEmail(email),
  async getCredential(userId) {
    const [user] = await db.select().from(users).where(eq(users.id, userId));
    if (!user?.passwordHash) return undefined;
    return {
      hash: user.passwordHash,
      salt: user.passwordSalt,
      params: user.passwordParams ?? undefined,
    };
  },
  async setCredential(userId, credential) {
    await db.update(users).set({
      passwordHash: credential.hash,
      passwordSalt: credential.salt,
      passwordParams: credential.params ?? null,
    }).where(eq(users.id, userId));
  },
  async replaceCredential(userId, expected, credential) {
    const unchanged = expected
      ? and(
        eq(users.passwordHash, expected.hash),
        eq(users.passwordSalt, expected.salt),
        expected.params
          ? eq(users.passwordParams, expected.params)
          : isNull(users.passwordParams),
      )
      : and(
        isNull(users.passwordHash),
        isNull(users.passwordSalt),
        isNull(users.passwordParams),
      );
    const updated = await db.update(users).set({
      passwordHash: credential.hash,
      passwordSalt: credential.salt,
      passwordParams: credential.params ?? null,
    }).where(and(eq(users.id, userId), unchanged)).returning({ id: users.id });
    return updated.length === 1;
  },
  async markEmailVerified(userId, email) {
    await db.update(users).set({ emailVerified: true })
      .where(and(eq(users.id, userId), eq(users.email, email!)));
  },
};
```

Two details in that store are load-bearing.

**`markEmailVerified` takes the address the link was minted for.** The service
passes the email carried on the verification token, and the update above only
marks the account verified when that address is _still_ the account's email. A
one-argument implementation compiles and behaves exactly as before — which means
it is still vulnerable: a user can request a link for `a@example.com`, change
their address to `b@example.com`, then click the old link and have
`b@example.com` marked verified without ever proving control of it. A verified
address gates account recovery and account linking, so that is a takeover
primitive. Predicate on the address.

**Persist `credential.params`.** A credential is self-describing: it records the
algorithm and work factor it was minted with, which is what lets the work factor
be raised later without a forced reset. A credential stored with no `params` is
read as the original PBKDF2-SHA-256 at 100,000 iterations and transparently
rehashed on that user's next successful sign-in when `replaceCredential` is
implemented. If a store **drops** `params` from a new or upgraded credential,
verification uses the wrong work factor and the next sign-in fails. Persist the
complete credential together; one `jsonb`/`text` column for `params` is enough.

## Password hashing

You don't wire hashing so much as stop doing it yourself. `IdentityService`
constructs a `PasswordIdentityService` by default — PBKDF2-SHA-256 at
`DEFAULT_PBKDF2_ITERATIONS` (600,000), fresh random salt per hash, constant-time
verify — and calls it before your store ever sees a credential. Your obligations
are the three columns above (`hash` and `salt`, both hex strings, plus `params`)
and never accepting a plaintext password through any other code path.

**The work factor is configurable and upgrades one login at a time.** Pass
`new PasswordIdentityService({ iterations })` as the service's `passwords`
option to raise or lower it. Raising it later is free: each credential records
its own work factor in `params`, so a credential minted under an older setting
still verifies, and `IdentityService` uses `replaceCredential` to rehash it
after it verifies on the owner's next successful sign-in. A credential with no
`params` at all is treated as `LEGACY_PBKDF2_ITERATIONS` (100,000) and upgraded
the same way. A persist failure during that rehash is logged and swallowed — a
storage hiccup must never deny a sign-in the credential just proved. An atomic
replacement that returns `false` rejects that sign-in because a newer credential
has superseded the password just checked.

Measure hashing and verification on your deployment hardware and choose a work
factor consistent with your security and latency requirements.

**Bring your own hasher.** `passwords` is typed as `PasswordHasherLike`, not as
the concrete class, so argon2id or scrypt from your own dependency drops in:

```ts ignore
import type {
  PasswordCredential,
  PasswordHasherLike,
} from "@udibo/oauth2/identity";

const argon2: PasswordHasherLike = {
  hash: (password) => argon2id.hash(password),
  verify: (password, credential) => argon2id.verify(password, credential),
  needsRehash: (credential: PasswordCredential) => isBelowPolicy(credential),
};
```

Implement `hash` and `verify` and you are done; implement the optional
`needsRehash` together with the store's `replaceCredential` to enable
rehash-on-successful-sign-in. This is the answer to "the package only ships
PBKDF2" — PBKDF2 is the zero-dependency floor, not a ceiling.

Construct it explicitly only when something else needs the same hasher — for
example a legacy sign-in path you're migrating:

```ts
import { PasswordIdentityService } from "@udibo/oauth2/identity";

declare const plaintext: string;

const passwords = new PasswordIdentityService();
const credential = await passwords.hash(plaintext);
const ok = await passwords.verify(plaintext, credential);
```

Pass it via the service's `passwords` option so both paths share one
implementation.

## Store reset and verification tokens

Password reset, email verification, and account unlock share one token mechanic:
mint a high-entropy single-use token, store **only its SHA-256 hash**, email the
raw token, consume it once. `TokenFlowService` owns that lifecycle; you give it
a `TokenFlowStore`:

```ts
import type { TokenFlowRecord } from "@udibo/oauth2/identity";

interface TokenFlowStore {
  save(record: TokenFlowRecord): Promise<void>;
  get(tokenHash: string): Promise<TokenFlowRecord | null>;
  markConsumed(tokenHash: string, consumedAt: number): Promise<void>;
  deleteBySubject?(purpose: string, subject: string): Promise<void>;
}
```

One table backs it — `tokenHash` (primary key), `purpose`, `subject`, `data`
(jsonb), `expiresAt`, `consumedAt`, `createdAt` — mapping one-to-one onto
`TokenFlowRecord`. Because only hashes are stored, a leaked table or log line
can't be replayed as a working link. Implement the optional `deleteBySubject`:
the service uses it (via `invalidateExisting`) to void a user's outstanding
reset links whenever a new one is issued, so only the latest emailed link works.

```ts
import { TokenFlowService } from "@udibo/oauth2/identity";
import type { TokenFlowStore } from "@udibo/oauth2/identity";

declare const tokenStore: TokenFlowStore;

const tokens = new TokenFlowService(tokenStore);
```

A `MemoryTokenFlowStore` ships for development and tests.

## Sessions: visibility and revocation

The library never creates sessions — after `signIn` returns a user, setting your
cookie is your code. What the flows need back from your session layer is
revocation, expressed as `RevocableSessionService`:

```ts
interface RevocableSessionService {
  revokeAllByUser(userId: string): Promise<number>;
  revokeOthers(userId: string, keepSessionId: string): Promise<number>;
}
```

Implement both over your session storage and pass it as the service's `sessions`
option. `resetPassword` then calls `revokeAllByUser` — without this, a
compromised account's other devices stay signed in after the rightful owner
resets the password. `revokeOthers` powers "sign out everywhere else" on your
own settings page: it keeps the session the user is sitting in and ends the
rest, which is what someone who has just changed their password expects.

`resetPassword` also voids the subject's outstanding **passwordless**
credentials — a pending sign-in link and a pending sign-in code — so a magic
link an attacker triggered before the reset stops working. Both calls are
best-effort: `TokenFlowStore.deleteBySubject` is optional, and a store that does
not implement it leaves outstanding links redeemable until they expire. See
[known limitations](../known-limitations.md).

### Listing sessions

Revocation without visibility is half a feature: a "where you're signed in"
screen is how a user notices the device they don't recognize, and it is the only
thing that makes the revoke buttons meaningful. The listing half of the same
seam is `ListableSessionService`, an **optional** capability a stateful store
opts into:

```ts
interface SessionSummary {
  id: string;
  createdAt: Date;
  lastSeenAt: Date;
  userAgent?: string; // raw header; the UI parses it into a device label
  location?: string; // coarse place resolved from IP — never the raw address
}

interface ListableSessionService {
  listByUser(userId: string): Promise<SessionSummary[]>;
}
```

Implement it on the same object as `RevocableSessionService` and your "where
you're signed in" screen has one typed shape to render and to wire its revoke
buttons against — instead of every app inventing a different list shape and
making the same mistakes in it. The screen itself is yours to build: the package
ships the seam and the row type, not a prebuilt list component, because the
layout, the device labelling, and the confirmation flow are all product
decisions. A stateless store that can't enumerate its sessions simply omits the
method; `supportsSessionListing(sessions)` narrows to the capability, so you
offer the screen only when the store can back it.

`SessionSummary` is deliberately spare: id, created-at and last-seen timestamps,
and coarse client context. `userAgent` is the raw header your UI summarizes into
a device label; `location` is a human-readable place resolved from the IP at
creation — not the raw address. Both are optional; a store with nothing coarse
to report leaves them unset rather than reaching for a precise value that would
turn a security screen into a tracking log. The current-session marker is yours:
compare each `SessionSummary.id` against the id of the session backing the
request so the UI can label that row and make "revoke" on it mean "sign out".

Two rules keep the list honest:

- **Revocation must be immediate, not advisory.** Deleting the row has to end
  the session on the next request. If your sessions are self-contained tokens
  the server doesn't look up, a revoke button is a lie — keep a server-side
  record, or check a revocation list on every request.
- **Reads are cheap and constant; writes are not.** Bump `lastSeenAt` on a
  throttle (once a minute, say) rather than on every request, or the sessions
  table becomes your hottest write path.

### Step-up before the destructive ones

Revoking sessions, changing a password, and disabling MFA are the actions an
account takeover wants. Demand fresh proof of presence in front of them:

```ts
import { isRecentlyAuthenticated } from "@udibo/oauth2/identity";
import type { Context } from "hono";

declare function redirectToReauthentication(c: Context): Response;

export function requireRecentAuth(
  c: Context,
  session: { authenticatedAt: number },
) {
  if (!isRecentlyAuthenticated(session.authenticatedAt, 5 * 60_000)) {
    return redirectToReauthentication(c);
  }
}
```

`authenticatedAt` is the moment the session last actively authenticated — set it
at sign-in and again after a successful re-authentication, and don't refresh it
on ordinary requests, or the window never closes.

### Back-channel logout, when the IdP owns the session

If your app consumes an external IdP through `@udibo/oauth2/hono/bff` rather
than owning its login, the provider can end sessions from its side via OIDC
Back-Channel Logout. Configure `backchannelLogout.verifyLogoutToken` to verify
the signature against the trusted issuer's keys and check issuer, audience,
timestamps, event claim, and replay policy. The BFF calls that verifier before
it calls `destroyByLogout({ sub, sid })` on your `SessionStore` — a capability
stateful stores opt into by implementing it. `MemorySessionStore` does;
`EncryptedCookieSessionStore` cannot, because a stateless store has no sessions
to enumerate, and the route stays unavailable.

The caveat worth knowing: matching prefers the id_token's `sid` claim and falls
back to `sub` only when the logout token carries no `sid`. So your session
record must **carry `sid` forward across token refreshes** — the BFF's own
refresh path preserves it, and a custom store that drops the field on update
will silently stop matching. The failure mode is quiet and open: no error, and
the sessions that survive a logout the provider believes succeeded are exactly
the long-lived ones. A DB-backed store should index both `sid` and `sub`.

## Delivery hooks: emailing the links

Transport is yours; the service mints the token, builds the URL, and hands you a
`DeliveryMessage`:

```ts
import type { DeliveryHooks } from "@udibo/oauth2/identity";

declare const mailQueue: {
  enqueue(job: {
    to: string;
    template: string;
    url?: string;
    expiresAt: number;
  }): void;
};

const delivery: DeliveryHooks = {
  sendPasswordReset(message) {
    mailQueue.enqueue({
      to: message.to,
      template: "password-reset",
      url: message.url,
      expiresAt: message.expiresAt,
    });
  },
  sendEmailVerification(message) {
    mailQueue.enqueue({
      to: message.to,
      template: "verify-email",
      url: message.url,
      expiresAt: message.expiresAt,
    });
  },
  sendAccountUnlock(message) {
    mailQueue.enqueue({
      to: message.to,
      template: "unlock-account",
      url: message.url,
      expiresAt: message.expiresAt,
    });
  },
};
```

Two rules:

- **Enqueue; don't await your mail provider in-request.** The
  `requestPasswordReset` response body is enumeration-safe, but if the known-
  account path awaits an SMTP round-trip and the unknown-account path doesn't,
  response _timing_ reveals which emails have accounts. Hand the message to a
  queue and return.
- **`message.url` is built from the `baseUrl` you configure** — an origin (or
  origin + prefix) you control, e.g. `https://app.example.com`. Never derive
  emailed links from the incoming request's `Host` header; a host-header
  injection would poison reset emails with attacker-controlled links. The
  default paths are `/reset-password`, `/verify-email`, and `/unlock-account`
  (see `buildResetUrl` and friends to change them), so those routes in your app
  are where the links land. Omit `baseUrl` to receive only the raw
  `message.token` and compose URLs yourself.

During development, hooks that `console.log` the URL make every flow testable
with no mailer — that is exactly what the
[quickstart](../quickstart.md#follow-a-sign-in) and the
[example apps](https://github.com/udibo/oauth2/tree/main/examples/hono/app-with-own-auth)
do.

## Password policy and breached passwords

`signUp` and `resetPassword` check the policy before hashing (and before
consuming a reset token, so a weak password never burns the user's link). A
violation throws `IdentityError("weak_password")` → `422`:

```ts
import { breachedPasswordValidator } from "@udibo/oauth2/identity";

const passwordPolicy = {
  minLength: 8,
  validators: [breachedPasswordValidator()],
};
```

The defaults follow the NIST "length over composition rules" guidance: a length
floor (`minLength` 8, `maxLength` 256 as a hash-input DoS guard), no
character-class requirements. They apply even when you pass no `passwordPolicy`
at all — the check is never skipped, so every password your app can store is
bounded. `signIn` is deliberately outside the policy: it hashes whatever the
request carries, because the equal-work path that hides an unknown identifier
has to run on the submitted password as-is. PBKDF2 pre-hashes an oversized HMAC
key once and then iterates over fixed-size blocks, so a very long submitted
password costs little more than a short one. `breachedPasswordValidator` rejects
passwords found in the Have I Been Pwned corpus using the k-anonymity range API
— only the first five characters of the password's SHA-1 ever leave your
process. It **fails open** by default (an unreachable HIBP shouldn't take down
your sign-up flow); pass `failOpen: false` to invert that, and pass the
`onEvent` hook you gave `IdentityService` so each fail-open reaches your audit
store as a `password_policy.check_unavailable` event instead of a `console.warn`
—
[production deployment](production-deployment.md#rate-limiting-lockout-and-password-policy).

## Rate limiting and lockout

Two distinct protections, both consulted by `signIn`:

- **`RateLimiter`** throttles attempts per fixed window, keyed by identifier.
  Defaults: 10 attempts per 15 minutes. Unknown and known identifiers throttle
  identically, so the `429` can't be used to enumerate accounts. When exceeded
  it throws `IdentityError("rate_limited", …, { retryAfterMs })`, which the Hono
  routes map to `429` with a `Retry-After` header. A successful sign-in resets
  the window.
- **`AccountLockout`** counts _consecutive failures per account_ and locks the
  account once a threshold is crossed. Defaults: 10 failures → 15-minute lock. A
  locked account's sign-in returns the same uniform, timing-equalized `null` an
  unknown identifier gets — lockout must not become an oracle for "this account
  exists and the password was close".

```ts
import { AccountLockout, RateLimiter } from "@udibo/oauth2/identity";

const rateLimiter = new RateLimiter();
const lockout = new AccountLockout();
```

Both default to in-memory stores, which are per-process — one instance of
[the multi-instance rule](production-deployment.md#the-multi-instance-rule).
Running more than one instance, back them with shared state by implementing the
small `RateLimitStore` / `LockoutStore` interfaces over Redis or your database
(lockout columns on the users table also give admins visibility). Both
`increment` contracts require atomicity — a read-modify-write lets concurrent
attempts lose counts, undershooting the lockout threshold or slipping a burst
past the limiter.

If you want a different _algorithm_ rather than different storage, the
`rateLimiter` and `lockout` options are typed against structural interfaces —
`RateLimiterLike` (`check` / `reset`) and `AccountLockoutLike` (`status` /
`recordFailure` / `reset`). Pass a plain object implementing either and the
built-in classes step aside entirely; that is the seam for a sliding window, a
token bucket, or a limiter you already operate.

`rateLimiter` is the default for all six throttled flows; `rateLimiters` gives
any of them (`signIn`, `passwordReset`, `emailVerification`, `accountUnlock`,
`signInLink`, `signInCode`) its own limiter instead, which is how you throttle
"make my server send an email" harder than sign-in — see
[protections](production-deployment.md#rate-limiting-lockout-and-password-policy).

IP-based limiting deliberately stays out of the service: it has no request
context. Apply it at the route layer in front of these endpoints, keyed on
whatever your infrastructure knows (IP, IP+identifier).

### Roll out in log-only mode

`protectionMode: "log-only"` arms both protections without blocking anyone:
every threshold crossing still emits its event (with `enforced: false`), so you
can watch a week of real traffic, confirm the defaults don't catch legitimate
users, then flip to `"enforce"` (the default) with numbers in hand.

```ts ignore
protectionMode: "log-only",
```

### Self-service unlock

The service only knows opaque user ids, so the unlock email starts from your
event hook, where you look up the address:

```ts
import type {
  IdentityEventHook,
  IdentityService,
  IdentityUser,
} from "@udibo/oauth2/identity";

declare const identity: IdentityService<IdentityUser>;
declare function getUserById(
  id: string,
): Promise<{ email?: string } | undefined>;
declare const auditLog: { record(event: unknown): Promise<void> };

const onEvent: IdentityEventHook = async (event) => {
  if (event.type === "lockout") {
    const user = await getUserById(event.userId);
    if (user?.email) {
      await identity.requestAccountUnlock({
        userId: event.userId,
        email: user.email,
      });
    }
  }
  await auditLog.record(event);
};
```

The link lands on your `/unlock-account` route, which consumes it:

```ts
import type { IdentityService, IdentityUser } from "@udibo/oauth2/identity";

declare const identity: IdentityService<IdentityUser>;
declare const token: string;
declare function identifierFor(userId: string): string;

const result = await identity.unlockAccount(token);
if (result.status === "success") {
  await identity.resetSignInThrottle(identifierFor(result.userId));
}
```

`unlockAccount` clears the lock; `resetSignInThrottle` clears the rate-limit
window for the identifier, which is otherwise still full of the failed attempts
that caused the lock. (`resetPassword` clears the lockout on its own — an
emailed reset token proves the same account ownership — but call
`resetSignInThrottle` there too.) The discriminated result (`success` /
`expired` / `invalid`) lets the page offer a fresh link for an expired one.

## The audit seam: `onEvent`

Every flow outcome emits one `IdentityEvent`: `sign_in.succeeded`,
`sign_in.failed` (with the internal reason), `sign_in.rate_limited`,
`sign_in.locked`, `lockout`, `sign_up`, and the requested / completed / failed
lifecycle of password reset, email verification, and account unlock. Persist
them in your own audit store via the `onEvent` option.

The hook is awaited but isolated: a rejection is logged and swallowed, so a down
audit sink can never break sign-in. Two consequences: don't rely on it for
control flow, and report hook failures through your own channel if you need
delivery guarantees.

Events are for **server-side capture only**. They record internal outcomes —
including whether an identifier resolved to an account — so surfacing their
contents to the end user turns your audit trail into the enumeration oracle
every response in this layer is designed not to be.

## Putting it together

```ts
import {
  AccountLockout,
  breachedPasswordValidator,
  IdentityService,
  RateLimiter,
  TokenFlowService,
} from "@udibo/oauth2/identity";
import type {
  DeliveryHooks,
  IdentityUser,
  IdentityUserStore,
  LockoutStore,
  RateLimitStore,
  RevocableSessionService,
  TokenFlowStore,
} from "@udibo/oauth2/identity";

interface AppUser extends IdentityUser {
  email: string;
}

declare const userStore: IdentityUserStore<AppUser>;
declare const tokenStore: TokenFlowStore;
declare const sessionService: RevocableSessionService;
declare const delivery: DeliveryHooks;
declare const rateLimitStore: RateLimitStore;
declare const lockoutStore: LockoutStore;
declare const auditLog: { record(event: unknown): void };

const identity = new IdentityService<AppUser>({
  users: userStore,
  tokens: new TokenFlowService(tokenStore),
  sessions: sessionService,
  delivery,
  baseUrl: "https://app.example.com",
  passwordPolicy: {
    minLength: 8,
    validators: [breachedPasswordValidator()],
  },
  rateLimiter: new RateLimiter({ store: rateLimitStore }),
  lockout: new AccountLockout({ store: lockoutStore }),
  protectionMode: "enforce",
  onEvent: (event) => auditLog.record(event),
});
```

Expose the flows however your app routes. In Hono, `honoIdentityRoutes` from
`@udibo/oauth2/hono/identity` mounts the five **password-credential** POST
endpoints — `/signup`, `/signin`, `/password/reset-request`, `/password/reset`,
`/email/verify` — and maps `IdentityError` codes to statuses
(`invalid_credentials` 401, `invalid_token` 400, `rate_limited` 429,
`weak_password` 422, `identifier_taken` 409, `forbidden_origin` 403); your
`onAuthenticated` hook creates the session. Those routes carry a same-origin
guard on unsafe methods by default — see the [quickstart](../quickstart.md) for
the `csrf` option. In any other framework — or when you want your own request
shapes — call the service methods directly from your handlers, as the flows are
plain async methods. The [quickstart](../quickstart.md) shows the mounted
version; the
[Hono](https://github.com/udibo/oauth2/tree/main/examples/hono/app-with-own-auth)
and
[Juniper](https://github.com/udibo/oauth2/tree/main/examples/juniper/app-with-own-auth)
examples show direct calls from server-rendered form routes.

The factory scope stops at the password path **by design**. Passwordless, MFA,
and social carry policy the factory can't guess — where pending state lives, the
enumeration-safe response shape, transient `state`/PKCE custody, account linking
— so they stay hand-routed. Each is documented as a call-the-service path:
[passwordless](passwordless.md), [MFA](add-mfa.md), and
[social sign-in](social-sign-in.md).

## Before going live

The security checklist that used to live here is now the "if your app runs its
own login" section of the
[hardening checklist](hardening-checklist.md#if-your-app-hosts-login) — same
items, alongside everything else a deployment has to answer for (configuration,
stores, TLS, cookies, headers, backups, observability), each linked to the
section of [Deploy and Operate in Production](production-deployment.md) that
explains it.

One thing that page makes explicit and this guide's snippets can obscure:
`rateLimiter` and `lockout` are **opt-in**. Construct both, or the flows run
with no throttling and no lockout. `passwordPolicy` is the exception — it runs
whether or not you pass one, at its 8–256 character defaults.
