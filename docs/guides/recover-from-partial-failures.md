# Recover from partial failures in the identity flows

The identity flows write to several app-owned stores in sequence: a token or
code store, your user store, your session store, the lockout store and the rate
limiter. A store can fail between two of those writes. This guide lists every
state such a failure can leave behind in password reset, email verification,
passwordless sign-in and MFA recovery codes. For each state it gives the signal
your app receives and the steps that finish or undo the change.

Single-use credentials are spent **before** the change they authorize, with
one exception. Two concurrent submissions of one link or code therefore resolve
to exactly one success, and the loser writes nothing. The cost of that ordering
is that a failure after the spend leaves the credential used up. The user then
asks for a new one. No state below leaves a spent credential usable.

The exception is email verification: `markEmailVerified` runs before the link is
spent. Marking an address verified twice is harmless, while spending the link
first would cost the user a new link whenever the write failed. That is why
`markEmailVerified` must be idempotent.

Subscribe to `onEvent` and alert on the events named here. The flows also log
the best-effort failures with `console.error`, prefixed `[@udibo/oauth2]`.

## Password reset

`resetPassword` spends the reset link, then writes the new password, clears an
imported hash, voids pending sign-in links and codes, revokes the user's
sessions and clears the failed-attempt lockout. Only the link spend comes
first; the rest run in that order.

| Failing step                             | Already changed                                     | Signal                                                                                | Recovery                                                                                                                                       |
| ---------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Hashing or `setCredential`               | Link spent                                          | `password_reset.failed` with `credential_write_failed` and `userId`, error rethrown   | None needed. The old password still works and no session was touched. The user requests a fresh link                                          |
| `clearLegacyCredential`                  | Password changed                                    | Logged; the reset succeeds                                                            | Clear the imported hash for the user. It is ignored while a native credential exists, but it would work again if that credential were removed |
| `TokenFlowStore.deleteBySubject`         | Password changed                                    | Logged; the reset succeeds                                                            | Pending sign-in links stay redeemable until they expire (15 minutes by default). Delete them from your token store to close that window      |
| `OtpStore.invalidate`                    | Password changed, links voided                      | Logged; the reset succeeds                                                            | The pending sign-in code stays usable until it expires (10 minutes by default). Invalidate it in your code store                               |
| `RevocableSessionService.revokeAllByUser` | Password changed, passwordless credentials voided   | `password_reset.failed` with `session_revocation_failed` and `userId`, error rethrown | Call `revokeAllByUser(userId)` again until it succeeds. Until then, every session the user had before the reset stays signed in                |
| `AccountLockoutLike.reset`               | Password changed, sessions revoked                  | `password_reset.failed` with `lockout_reset_failed` and `userId`, error rethrown      | Call `reset(userId)` on your lockout, or let the lock lapse. Until then a locked account cannot sign in with the new password                 |

A failed reset never emits `password_reset.completed`, and the error reaches
your route without saying how far the reset got. The new password is already in
effect after `session_revocation_failed` and `lockout_reset_failed`, but not
after `credential_write_failed`. So the message to the user should say that the
password may have changed, and suggest signing in with the new password before
requesting a new link. A locked account may still refuse it until the lock
lapses.

### Make the password write and the revocation one transaction

The `session_revocation_failed` row is the dangerous one: the user reset the
password to lock someone out, and that person's session is still live. When
your users and sessions share a database, implement the optional
`IdentityUserStore.resetCredential`. It replaces the credential, drops any
imported hash and revokes every session of the user in one transaction, and
returns the number of sessions revoked. `resetPassword` then calls it instead
of `setCredential` and `clearLegacyCredential`. A failure inside it rolls
everything back, so it reports `credential_write_failed` with the old password
and sessions intact. `password_reset.completed` carries `sessionsRevoked`, the
number of sessions the reset revoked.

```ts
import type {
  IdentityUserStore,
  PasswordCredential,
} from "@udibo/oauth2/identity";

interface AppUser {
  id: string;
}
interface Transaction {
  updateCredential(userId: string, credential: PasswordCredential): Promise<void>;
  clearImportedHash(userId: string): Promise<void>;
  revokeSessions(userId: string): Promise<number>;
}
declare const users: IdentityUserStore<AppUser>;
declare function transaction<T>(
  work: (tx: Transaction) => Promise<T>,
): Promise<T>;

const store: IdentityUserStore<AppUser> = {
  ...users,
  resetCredential: (userId, credential) =>
    transaction(async (tx) => {
      await tx.updateCredential(userId, credential);
      await tx.clearImportedHash(userId);
      return await tx.revokeSessions(userId);
    }),
};
```

Session state that lives outside that database, such as a cache of accepted
session ids, is outside the transaction. If you also configure a `sessions`
service, `resetPassword` calls its `revokeAllByUser` after the transaction
commits, so that state is revoked too. The sessions already revoked in the
database are not revoked again, and a failure there reports
`session_revocation_failed` with the password changed and the stored sessions
already revoked. Leave `sessions` unset only when the transaction covers every
place a session lives. Verify the implementation with the `resetCredential` option of
`runIdentityUserStoreContractTests` ([Integration testing](testing.md)).

## Email verification

`verifyEmail` marks the address verified **before** it spends the link, so the
link stays usable whenever the flag did not change. `markEmailVerified` must be
idempotent for this to be safe.

| Failing step                    | Already changed                    | Signal                                                         | Recovery                                                                                                                                   |
| ------------------------------- | ---------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `markEmailVerified`             | Nothing                            | Error rethrown                                                 | The user opens the same link again                                                                                                         |
| Spending the link               | Address verified                   | Error rethrown; no `email_verification.completed`              | The user opens the same link again, which verifies idempotently and spends it. Left alone, the link expires. Until then it can verify only the address it was issued for, provided the token carries that email and your `markEmailVerified` filters on it |
| Spending the link loses a race  | Address verified                   | Result `invalid` for this caller, `completed` for the winner   | None needed                                                                                                                                |

## Passwordless sign-in

The request half never surfaces a store or mailer failure, so that an outage is
not an account-enumeration oracle. The events are the only signal.

| Failing step                                   | Already changed                         | Signal                                     | Recovery                                                                                         |
| ---------------------------------------------- | --------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| Minting a link or code                         | Nothing                                 | `credential_mint.failed`                   | The user requests again once the store is back                                                   |
| Delivery, then invalidating the minted credential | Nothing usable                       | `delivery.failed` with `invalidated: true` | The user requests again once the mailer is back                                                  |
| Delivery, and invalidation also fails          | A link or code nobody received is live  | `delivery.failed` with `invalidated: false` | Invalidate it in your token or code store, or let it expire. Nobody holds it, so this is a window, not a leak |
| Throttle reset after a verified code           | Code spent                              | Logged; the result is still `success`      | None needed. The throttle window stays filled until it lapses                                    |
| Your session start after `success`             | Link or code spent                      | Your own error handling                    | The user requests a fresh link or code. The flow cannot replay a spent one                       |

## MFA recovery codes

`MfaService.verify` reads the user's remaining recovery codes before it burns
the submitted one. A read failure therefore fails the attempt with the code
still unspent, and the reported `remainingRecoveryCodes` comes from that read.

| Failing step                              | Already changed                    | Signal                    | Recovery                                                                                                   |
| ----------------------------------------- | ---------------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Reading the remaining codes               | Nothing                            | Error rethrown            | The user submits the same code again                                                                       |
| `consumeRecoveryHash`                     | Nothing, if the store is atomic    | Error rethrown            | The user submits the same code again                                                                       |
| Throttle reset after a burned code        | Code spent                         | Logged; verification succeeds | None needed                                                                                            |
| `setRecoveryHashes` in `regenerateRecoveryCodes` | Nothing; the old codes still work | Error rethrown        | The user regenerates again. A store must replace the set in one write for this to hold                    |
| Recovery codes stored after enrollment activates | Activation rolled back       | Error rethrown            | The user enrolls again. If the rollback also fails, MFA stays active without recovery codes: have the user regenerate them |
| `clearTotp` in `disable`, after the codes were cleared | Recovery codes removed     | Error rethrown            | MFA stays on with TOTP only. Call `disable` again                                                          |
