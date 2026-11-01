# Add passkeys to an app that owns its login

Let people sign in with a passkey, and use a passkey as their second factor,
in an app already running `IdentityService`. By the end you have registration
from an account page, passkey sign-in with autofill, a passkey option at your
MFA challenge, and per-passkey rename and remove.

The library owns the WebAuthn ceremonies — options, verification (through
[`@simplewebauthn/server`](https://simplewebauthn.dev)), single-use challenges,
the per-user cap, and sign-count checks. Your app owns the rows, the routes,
the session, and the **policy**: whether a passkey satisfies your MFA
requirement, and which other sign-in methods an account keeps.

Everything below imports from `@udibo/oauth2/identity/passkeys`, except the
forms (`@udibo/oauth2/react/components`) and the test authenticator
(`@udibo/oauth2/testing`).

## What the module decides for you

- **No attestation.** Registration asks for `attestation: "none"` and stores
  every passkey as unattested. Any passkey manager, operating system, or FIDO2
  security key works; there is no list of approved authenticators.
- **Discoverable credentials.** Every passkey is created with
  `residentKey: "required"`, so a person can sign in without typing an
  identifier.
- **User verification is preferred and reported.** A passkey unlocked with a
  PIN or biometric reports `userVerified: true`; a security key without a PIN
  still works and reports `false`. You decide what each is worth.
- **Nothing reveals which accounts exist.** Sign-in without a known user sends
  no credential list.
- **Single-use challenges** that expire after five minutes, a cap of 25 passkeys
  per user, and refusal of a signature counter that goes backwards — the sign of
  a cloned authenticator.

## How the pieces fit

| Seam                    | You implement                              | Backs                          |
| ----------------------- | ------------------------------------------ | ------------------------------ |
| `PasskeyStore`          | one table, many rows per user              | public keys, counters, names   |
| `PasskeyChallengeStore` | a short-lived key-value entry              | single-use ceremony challenges |
| `RateLimiter`           | a `RateLimitStore`: Redis or DB            | throttling sign-in attempts    |
| `onEvent`               | your audit log                             | `passkey.*` outcomes           |
| your routes             | register, sign in, challenge, manage       | when a ceremony runs           |

## Choose the relying party

A passkey is bound forever to its **RP ID**, the host your sign-in page is
served on. Pass it as configuration; never derive it from a request's `Host`
header, which a client controls.

```ts
import type { PasskeyRelyingParty } from "@udibo/oauth2/identity/passkeys";

const relyingParty: PasskeyRelyingParty = {
  id: "login.example.com",
  name: "Example",
  origins: ["https://login.example.com"],
};
```

The RP ID may be the page's host or a parent domain (`example.com` would also
cover `app.example.com`), and a passkey works only on hosts under it. Pick the
narrowest host that serves your sign-in page: moving sign-in to a different
domain later means people add new passkeys there. Development hosts such as
`localhost` are a separate set of passkeys from production.

## Implement the stores

`PasskeyStore` holds one row per passkey. Nothing in it is secret — the public
key verifies signatures, it cannot make them — so no encryption is needed.

```ts
import type {
  Passkey,
  PasskeyAddResult,
  PasskeyUse,
} from "@udibo/oauth2/identity/passkeys";

interface PasskeyStore {
  listPasskeys(userId: string, rpId?: string): Promise<Passkey[]>;
  findPasskey(credentialId: string): Promise<Passkey | undefined>;
  addPasskey(passkey: Passkey, limit: number): Promise<PasskeyAddResult>;
  recordUse(credentialId: string, use: PasskeyUse): Promise<boolean>;
  renamePasskey(
    userId: string,
    credentialId: string,
    name: string,
  ): Promise<boolean>;
  removePasskey(userId: string, credentialId: string): Promise<boolean>;
}
```

Two methods must be atomic. `addPasskey` checks credential uniqueness and the
per-user cap in one transaction, so concurrent registrations cannot exceed it.
`recordUse` is a conditional update —
`UPDATE … SET sign_count = $new WHERE credential_id = $id AND sign_count = $previous`
— so two concurrent sign-ins cannot both spend one counter value.

`PasskeyChallengeStore` holds each ceremony's challenge for a few minutes. Its
`take` must read and delete in one step (Redis `GETDEL`, SQL
`DELETE … RETURNING`); that is what makes a challenge single-use.

Run the contract suites against your implementations:

```ts
import {
  runPasskeyChallengeStoreContractTests,
  runPasskeyStoreContractTests,
} from "@udibo/oauth2/testing/contract";
import type {
  PasskeyChallengeStore,
  PasskeyStore,
} from "@udibo/oauth2/identity/passkeys";

declare function freshPasskeyStore(): Promise<PasskeyStore>;
declare function freshChallengeStore(): Promise<PasskeyChallengeStore>;

runPasskeyStoreContractTests({ makeStore: freshPasskeyStore });
runPasskeyChallengeStoreContractTests({ makeStore: freshChallengeStore });
```

## Wire the service

```ts
import {
  MemoryRateLimitStore,
  RateLimiter,
} from "@udibo/oauth2/identity";
import {
  MemoryPasskeyChallengeStore,
  MemoryPasskeyStore,
  PasskeyService,
} from "@udibo/oauth2/identity/passkeys";

const passkeys = new PasskeyService({
  store: new MemoryPasskeyStore(),
  challenges: new MemoryPasskeyChallengeStore(),
  rateLimiter: new RateLimiter({
    limit: 10,
    windowMs: 15 * 60 * 1000,
    store: new MemoryRateLimitStore(),
  }),
  onEvent: (event) => console.info(event.type),
});
```

The memory stores are for development and tests; back both seams with your
database or Redis in production.

## Register a passkey

Registration runs from a signed-in page, after you have confirmed it is really
the account holder (a recent password, an existing factor, or a fresh sign-in).
A stolen session must not be able to add its own passkey.

```ts
import type {
  PasskeyRegistrationResponse,
  PasskeyRelyingParty,
  PasskeyService,
} from "@udibo/oauth2/identity/passkeys";

declare const passkeys: PasskeyService;
declare const relyingParty: PasskeyRelyingParty;
declare const user: { id: string; email: string };

// 1. Start: keep ceremonyId server-side or in an HttpOnly cookie.
const { ceremonyId, options } = await passkeys.startRegistration({
  relyingParty,
  user: { id: user.id, name: user.email },
});

// 2. The browser creates the passkey with `options` and posts the result back.
declare const response: PasskeyRegistrationResponse;

// 3. Finish.
const result = await passkeys.finishRegistration({
  relyingParty,
  ceremonyId,
  userId: user.id,
  response,
  name: "Work laptop",
});
if (!result.registered) {
  console.warn(result.reason);
}
```

`startRegistration` throws `IdentityError` `passkey_limit_reached` when the
user already has the maximum number of passkeys.

In the browser, `@simplewebauthn/browser` turns the options into a
`navigator.credentials.create()` call and the result back into JSON:

```ts
import { startRegistration } from "@simplewebauthn/browser";

declare const optionsJSON: Parameters<typeof startRegistration>[0]["optionsJSON"];
const response = await startRegistration({ optionsJSON });
await fetch("/account/passkeys", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(response),
});
```

Browsers that implement `PublicKeyCredential.parseCreationOptionsFromJSON` and
`toJSON()` can do the same without a library.

## Sign in with a passkey

Start the ceremony without a user, and learn the account from the response:

```ts
import type {
  PasskeyAuthenticationResponse,
  PasskeyRelyingParty,
  PasskeyService,
} from "@udibo/oauth2/identity/passkeys";

declare const passkeys: PasskeyService;
declare const relyingParty: PasskeyRelyingParty;

const { ceremonyId, options } = await passkeys.startAuthentication({
  relyingParty,
});

declare const response: PasskeyAuthenticationResponse;
declare const clientIp: string;
const result = await passkeys.finishAuthentication({
  relyingParty,
  ceremonyId,
  response,
  rateLimitKey: clientIp,
});
if (result.valid) {
  // result.userId is the account; result.userVerified says whether the
  // person unlocked the passkey with a PIN or biometric.
}
```

`finishAuthentication` never starts a session. Before you mint one, apply the
same checks every other sign-in method passes — a disabled or locked account,
and your MFA policy:

- **`userVerified: true`** — the passkey is a multi-factor authenticator on its
  own: something the person has, unlocked by something they know or are. It is
  reasonable to treat it as satisfying a required second factor.
- **`userVerified: false`** — possession only. Send the person through your MFA
  challenge exactly as you would after a password.

`rateLimitKey` throttles passkey sign-in per caller; the service never keys a
limit on a credential id, which anyone who learned it could use to lock its
owner out.

Report every failure to the person the same way ("That passkey didn't work");
the `reason` is for your logs.

### Autofill

Pass `passkey` to `SignInForm` and the identifier field becomes
`autocomplete="username webauthn"`. Start a conditional request when the page
loads, and the browser offers saved passkeys in that field's autofill:

```tsx
import { startAuthentication, WebAuthnError } from "@simplewebauthn/browser";
import { SignInForm } from "@udibo/oauth2/react/components";

declare function passkeyOptions(): Promise<
  Parameters<typeof startAuthentication>[0]["optionsJSON"]
>;
declare function finishPasskeySignIn(response: unknown): Promise<void>;

async function signInWithPasskey(autofill: boolean): Promise<void> {
  try {
    const response = await startAuthentication({
      optionsJSON: await passkeyOptions(),
      useBrowserAutofill: autofill,
    });
    await finishPasskeySignIn(response);
  } catch (error) {
    if (error instanceof WebAuthnError && error.code === "ERROR_CEREMONY_ABORTED") {
      return;
    }
    throw error;
  }
}

function SignIn() {
  return (
    <SignInForm
      onSubmit={() => {}}
      passkey={{ onSelect: () => signInWithPasskey(false) }}
    />
  );
}
```

Call `signInWithPasskey(true)` once after the form mounts. Starting the button
flow cancels a pending autofill request, which rejects with
`ERROR_CEREMONY_ABORTED`; ignore that one error. Each flow needs its own
ceremony.

## Use a passkey as the second factor

After a first factor, start the ceremony **with** the user's id, and finish
it with the same id. Only their passkeys are offered, and the finish refuses a
passkey belonging to anyone else — including one presented with a ceremony
that was started without a user, which a person could otherwise obtain from
your passkey sign-in route and answer with their own passkey.

```ts
import type {
  PasskeyAuthenticationResponse,
  PasskeyRelyingParty,
  PasskeyService,
} from "@udibo/oauth2/identity/passkeys";

declare const passkeys: PasskeyService;
declare const relyingParty: PasskeyRelyingParty;
declare const pendingUserId: string;

const { ceremonyId, options } = await passkeys.startAuthentication({
  relyingParty,
  userId: pendingUserId,
});

declare const response: PasskeyAuthenticationResponse;
const result = await passkeys.finishAuthentication({
  relyingParty,
  ceremonyId,
  response,
  userId: pendingUserId,
});
```

Always pass `userId` here. Without it, `result.valid` only means *some*
account's passkey signed.

It throws `IdentityError` `passkey_not_registered` when the user has none, so
check `listPasskeys(userId, relyingParty.id)` before offering the option.
`MfaChallengeForm` renders a "Use a passkey" button when you pass `passkey`.

## Manage passkeys

`listPasskeys`, `renamePasskey`, and `removePasskey` back an account page.
Show each passkey's name, `createdAt`, `lastUsedAt`, and whether it is
`multiDevice` (synced by a passkey manager) or bound to one device or security
key. Before removing a passkey, check the account keeps another way to sign in —
only your app knows which methods are usable — and gate removal behind the same
confirmation as registration. Emailing the person when a passkey is added or
removed lets them spot one they did not create.

## Describe the sign-in in tokens

A passkey contributes the `amr` value `pop` (proof of possession of a key,
`PASSKEY_AMR`). Add `mfa` when the passkey was user-verified or followed another
factor of a different kind. Do not claim `hwk`: without attestation you cannot
tell a hardware-bound key from a synced one.

## Test it

`TestPasskeyAuthenticator` answers the service's options with real signed
responses, so the full ceremony runs in a unit test:

```ts
import {
  MemoryPasskeyChallengeStore,
  MemoryPasskeyStore,
  PasskeyService,
} from "@udibo/oauth2/identity/passkeys";
import { TestPasskeyAuthenticator } from "@udibo/oauth2/testing";

const relyingParty = {
  id: "login.example.com",
  name: "Example",
  origins: ["https://login.example.com"],
};
const passkeys = new PasskeyService({
  store: new MemoryPasskeyStore(),
  challenges: new MemoryPasskeyChallengeStore(),
});
const authenticator = new TestPasskeyAuthenticator({
  origin: "https://login.example.com",
});

const registration = await passkeys.startRegistration({
  relyingParty,
  user: { id: "user-1", name: "ada@example.com" },
});
await passkeys.finishRegistration({
  relyingParty,
  ceremonyId: registration.ceremonyId,
  userId: "user-1",
  response: await authenticator.register(registration.options),
});

const signIn = await passkeys.startAuthentication({ relyingParty });
const result = await passkeys.finishAuthentication({
  relyingParty,
  ceremonyId: signIn.ceremonyId,
  response: await authenticator.authenticate(signIn.options),
});
```

Options such as `userVerified: false`, `synced: false`, and
`countSignatures: true` model a security key; `authenticate(options, { origin })`
models a phishing page. Real browser behavior — autofill, the cross-device QR
flow, platform prompts — still needs a browser test; Chromium's DevTools
protocol offers a virtual authenticator (`WebAuthn.addVirtualAuthenticator`) for
that.
