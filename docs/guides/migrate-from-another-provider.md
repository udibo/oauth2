# Migrate existing passwords into your application

Import existing password hashes when moving your application to its own login.
This requires an export you are authorized to use and a verifier for its format.
When those are available, users can keep their passwords.
`@udibo/oauth2/identity` verifies each user's existing (foreign-format) password
hash on their first sign-in and, on a match, transparently rehashes the password
into the package's native format. Users keep signing in with the password they
already have; the migration completes one login at a time.

- **[The model: upgrade-on-login](#the-model-upgrade-on-login)**
- **[Which algorithms are built-in vs. bring-your-own](#which-algorithms-are-built-in-vs-bring-your-own)**
- **[Wiring it up](#wiring-it-up)**
- **[Bring-your-own verifiers (bcrypt / argon2 / scrypt)](#bring-your-own-verifiers)**
- **[Bulk-importing your users](#bulk-importing-your-users)**
- **[Auditing the migration](#auditing-the-migration)**

Automatic upgrades require the optional `IdentityUserStore.replaceCredential`
capability. It atomically compares the currently stored credential with the
expected credential before replacing it; `undefined` expects no native
credential during legacy import. If a password reset won the race, return
`false`. Stores without this capability still authenticate, but skip automatic
rehashing and legacy migration. Explicit resets use `setCredential`.

## The model: upgrade-on-login

You import each user with their **foreign password hash** stored in a
`legacyCredential` column and **no native credential**. On sign-in,
`IdentityService`:

1. Checks the native credential first (absent for a not-yet-migrated user).
2. Reads the foreign hash via `IdentityUserStore.getLegacyCredential` and runs
   it through the configured `legacyVerifiers` (the first whose `canVerify`
   accepts the hash string).
3. On a match: rehashes the plaintext into the native PBKDF2 format
   (`replaceCredential`), clears the foreign hash (`clearLegacyCredential`),
   emits a `password.upgraded` event, and signs the user in.
4. From then on the native path is used — the foreign verifier is never called
   for that user again.

The response is uniform (`null`), the return value never reveals whether an
account exists, and the timing does not either: a wrong password for a
not-yet-migrated account runs your (possibly slow, BYO) verifier where a
migrated one runs a single native verify, so every rejected `signIn` is held to
`failedSignInFloorMs` — 250 ms by default, measured from the start of the call
rather than added to its work. Unpadded, that difference would name exactly the
accounts still carrying an imported hash to any unauthenticated caller.

**Size that floor against your slowest verifier.** A branch that outruns it
returns as soon as its own work finishes, and whatever it spends above the floor
is visible again — bcrypt at a high cost factor, or an argon2 verifier, can
easily cost more than 250 ms, so measure yours and raise the option to suit.
Per-IP throttling at your route is still worth having during the migration
window; it bounds the volume the floor makes uniform.

Native credentials are authoritative: once a user has a native credential (after
their first legacy sign-in, or any password reset/change), the imported hash is
never consulted again — a wrong password can't fall back to a stale foreign hash
— so a reset can't be silently reverted.

## Which algorithms are built-in vs. bring-your-own

The package ships **zero new runtime dependencies** — it uses Web Crypto only.
That single constraint decides what can be built-in:

| Family                     | Status       | Why                                                                                                    |
| -------------------------- | ------------ | ------------------------------------------------------------------------------------------------------ |
| **PBKDF2** (SHA-1/256/512) | **Built-in** | PBKDF2 is a Web Crypto primitive (`crypto.subtle.deriveBits`); `pbkdf2Verifier()` handles it dep-free. |
| **bcrypt**                 | BYO          | No Web Crypto primitive; needs a bcrypt implementation (Blowfish key schedule).                        |
| **argon2** (id/i/d)        | BYO          | No Web Crypto primitive; memory-hard, needs a native/WASM argon2.                                      |
| **scrypt**                 | BYO          | Not exposed by Web Crypto **or** `@std/crypto`; memory-hard (Salsa20/8 core).                          |
| **MD5-crypt / SHA-crypt**  | BYO          | `$1$` / `$5$` / `$6$` use custom multi-round mixing, not a single digest.                              |

**Built-in** means the package can verify it dep-free. **BYO (bring-your-own)**
means you implement the tiny `LegacyPasswordVerifier` seam using your app's own
dependency and pass it in. This is deliberate: shipping bcrypt/argon2/scrypt
would force a dependency on every consumer, and the package stays a thin,
composable layer — the same seam philosophy as `SessionStore` and the rate
limiter. Most providers store **bcrypt**, so in practice you add one small BYO
verifier.

`parsePhc` is exported to parse the PHC / modular-crypt strings
(`$argon2id$v=19$m=…$salt$hash`, `$scrypt$…`) those algorithms use, so a BYO
verifier is only a few lines.

## Wiring it up

Add a `legacyCredential` column to your users table (nullable text) and
implement the two legacy hooks below. The existing store must also implement
atomic `replaceCredential` as shown in
[add-login.md](add-login.md#implement-identityuserstore-over-your-database);
without it passwords verify but are never migrated.

```ts
import {
  IdentityService,
  type IdentityUserStore,
} from "@udibo/oauth2/identity";
import type { IdentityUser } from "@udibo/oauth2/identity";
import {
  type LegacyPasswordVerifier,
  pbkdf2Verifier,
} from "@udibo/oauth2/identity/migration";

interface User extends IdentityUser {
  email: string;
}

declare const existingStore:
  & IdentityUserStore<User>
  & Required<Pick<IdentityUserStore<User>, "replaceCredential">>;
declare const bcryptVerifier: LegacyPasswordVerifier;
declare const db: {
  users: {
    find(id: string): Promise<{ legacyCredential: string | null } | undefined>;
    update(
      id: string,
      patch: { legacyCredential: string | null },
    ): Promise<void>;
  };
};

const users: IdentityUserStore<User> = {
  ...existingStore,

  async getLegacyCredential(userId) {
    const row = await db.users.find(userId);
    return row?.legacyCredential ?? null;
  },
  async clearLegacyCredential(userId) {
    await db.users.update(userId, { legacyCredential: null });
  },
};

const identity = new IdentityService({
  users,
  legacyVerifiers: [pbkdf2Verifier(), bcryptVerifier],
});
```

`legacyVerifiers` is tried in order; put the formats you actually imported in
the list. When it's unset (or the store lacks `getLegacyCredential`), the legacy
path is skipped entirely and sign-in behaves exactly as before — imported-only
users simply have no usable password until you enable it.

## Bring-your-own verifiers

The seam is three members: a stable `id`, a synchronous `canVerify` format
sniff, and an async constant-time `verify`.

### bcrypt (the common case)

The app adds a bcrypt dependency — e.g. `npm:bcryptjs` (pure JS, no native
build) — the package never does:

```ts ignore
import { compare } from "bcryptjs";
import type { LegacyPasswordVerifier } from "@udibo/oauth2/identity/migration";

const bcryptVerifier: LegacyPasswordVerifier = {
  id: "bcrypt",
  canVerify: (phc) => /^\$2[aby]?\$/.test(phc),
  verify: (password, phc) => compare(password, phc),
};
```

### argon2

```ts ignore
import { verify as argon2Verify } from "@node-rs/argon2";
import type { LegacyPasswordVerifier } from "@udibo/oauth2/identity/migration";

const argon2Verifier: LegacyPasswordVerifier = {
  id: "argon2",
  canVerify: (phc) => phc.startsWith("$argon2"),
  verify: (password, phc) => argon2Verify(phc, password).catch(() => false),
};
```

### scrypt

`parsePhc` gives you the parameters and salt/hash bytes; feed them to your
scrypt dependency and compare:

```ts ignore
import { scrypt } from "node:crypto";
import { timingSafeEqual } from "@std/crypto/timing-safe-equal";
import {
  type LegacyPasswordVerifier,
  parsePhc,
} from "@udibo/oauth2/identity/migration";

const scryptVerifier: LegacyPasswordVerifier = {
  id: "scrypt",
  canVerify: (phc) => phc.startsWith("$scrypt$"),
  verify: (password, phc) =>
    new Promise((resolve) => {
      const parsed = parsePhc(phc);
      if (!parsed?.salt || !parsed.hash) return resolve(false);
      const N = Number(
        parsed.params.ln ? 2 ** Number(parsed.params.ln) : parsed.params.N,
      );
      const r = Number(parsed.params.r);
      const p = Number(parsed.params.p);
      scrypt(
        password,
        parsed.salt,
        parsed.hash.length,
        { N, r, p },
        (err, dk) => {
          resolve(!err && timingSafeEqual(dk, parsed.hash!));
        },
      );
    }),
};
```

## Bulk-importing your users

> **Handle the export as password material.** A foreign hash export is not a
> harmless identifier list — each hash is an offline-crackable representation of
> a real password. Move it over an encrypted channel, keep it out of logs and
> object storage, delete it once the import lands, and lock down (authn + authz)
> whatever endpoint performs the import — anyone who can write
> `legacyCredential` can set a password hash they control on any account.

Export your users from the old system and insert them with the foreign hash in
`legacyCredential` and no native credential. Nothing special is required — it's
your own insert:

```ts
declare const oldExport: {
  email: string;
  emailVerified: boolean;
  passwordHash: string;
}[];
declare const db: {
  users: { insert(row: Record<string, unknown>): Promise<void> };
};

for (const record of oldExport) {
  await db.users.insert({
    email: record.email,
    emailVerified: record.emailVerified,
    passwordHash: null, // native credential — filled on first login
    legacyCredential: record.passwordHash, // the foreign PHC/modular-crypt string
  });
}
```

Then set `legacyVerifiers` for the formats present in the export. As users sign
in, `legacyCredential` clears and `passwordHash` fills. You can optionally sweep
rows that still have a non-null `legacyCredential` after a cutoff and send those
users a password-reset link.

Before the cutover, do a dry-run validation pass with `verifyLegacyPassword` to
confirm your verifiers accept the exported hashes (against a known test
account).

## Auditing the migration

Every upgrade emits a `password.upgraded` event carrying the `verifierId` that
matched, so you can watch migration progress through your existing `onEvent`
audit sink:

```ts
import { IdentityService } from "@udibo/oauth2/identity";
import type { IdentityUser, IdentityUserStore } from "@udibo/oauth2/identity";
import {
  type LegacyPasswordVerifier,
  pbkdf2Verifier,
} from "@udibo/oauth2/identity/migration";

interface User extends IdentityUser {
  email: string;
}

declare const users: IdentityUserStore<User>;
declare const bcryptVerifier: LegacyPasswordVerifier;
declare const metrics: {
  increment(name: string, tags: Record<string, string>): void;
};
declare const auditLog: { write(event: unknown): void };

const identity = new IdentityService({
  users,
  legacyVerifiers: [pbkdf2Verifier(), bcryptVerifier],
  onEvent: (event) => {
    if (event.type === "password.upgraded") {
      metrics.increment("auth.password_upgraded", { from: event.verifierId });
    }
    auditLog.write(event);
  },
});
```

This guide documents the package's password-verification API. Export
availability, account provisioning, and migration into Udibo's hosted service
follow that service's own documentation and beta support process.
