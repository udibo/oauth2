# Social and OIDC sign-in

Add "Continue with Google", "Continue with GitHub", "Sign in with Apple",
"Continue with Discord", any spec-compliant OpenID Connect provider, or any
plain-OAuth2 provider to an app that owns its login.
`@udibo/oauth2/identity/external` drives the redirect dance — CSRF `state`,
PKCE, OIDC nonce, code exchange, id_token validation, profile normalization —
and stops at a verified `ExternalProfile`. What happens next (create a user,
link to an existing one, refuse) is app policy, and it is where every
account-takeover bug in this feature lives, so most of this guide is about that
half.

The library stores **nothing**. The only state between the two legs is a
JSON-serializable transient you keep.

> **Hand-routed by design.** The `honoIdentityRoutes` factory mounts only the
> password-credential path (`/signup`, `/signin`, password reset, email verify).
> Social is not mounted, because the transient `state`/PKCE custody and the
> account-resolution/linking policy — where the account-takeover bugs live — are
> app policy the factory can't own for you, so you wire the start/callback legs
> in your own routes, as shown below.

## How the pieces fit

| Piece                   | Owned by | Job                                           |
| ----------------------- | -------- | --------------------------------------------- |
| `ExternalProvider`      | library  | wire protocol for one provider                |
| `ExternalAuthFlow`      | library  | `state`, PKCE, nonce, expiry, error surfacing |
| `ExternalAuthTransient` | you      | per-attempt state, in a sealed cookie         |
| identity table          | you      | `(provider, subject)` → user id               |
| linking policy          | you      | what a profile is allowed to do to an account |

## Configure a provider

`@udibo/oauth2/identity/external` ships six connectors. Pick by what the
provider speaks, not by how popular it is:

| Connector         | Provider shape                                   | Needs                                                                          |
| ----------------- | ------------------------------------------------ | ------------------------------------------------------------------------------ |
| `googleProvider`  | OIDC, fixed endpoints                            | client id + secret                                                             |
| `githubProvider`  | plain OAuth2 (no `id_token`)                     | client id + secret                                                             |
| `discordProvider` | plain OAuth2 (no discovery, no `id_token`)       | client id + secret                                                             |
| `appleProvider`   | OIDC-shaped, but a signed-JWT client secret      | Services ID, Team ID, Key ID, `.p8` private key ([below](#sign-in-with-apple)) |
| `oidcProvider`    | any issuer with a discovery document             | issuer URL, client id, optional secret                                         |
| `oauth2Provider`  | any plain-OAuth2 provider, no discovery, no OIDC | both endpoints, a userinfo endpoint, and a `mapProfile`                        |

The Google and GitHub presets need only a client id and secret:

```ts
import {
  ExternalAuthFlow,
  githubProvider,
  googleProvider,
} from "@udibo/oauth2/identity/external";

export const google = new ExternalAuthFlow({
  provider: googleProvider({
    clientId: Deno.env.get("GOOGLE_CLIENT_ID")!,
    clientSecret: Deno.env.get("GOOGLE_CLIENT_SECRET")!,
  }),
});

export const github = new ExternalAuthFlow({
  provider: githubProvider({
    clientId: Deno.env.get("GITHUB_CLIENT_ID")!,
    clientSecret: Deno.env.get("GITHUB_CLIENT_SECRET")!,
  }),
});
```

Anything else that speaks OIDC works through the generic connector, which
resolves its endpoints from the issuer's discovery document:

```ts
import {
  ExternalAuthFlow,
  MemoryDiscoveryCache,
  oidcProvider,
} from "@udibo/oauth2/identity/external";

const discoveryCache = new MemoryDiscoveryCache();

export function acmeFlow(clientSecret: string): ExternalAuthFlow {
  return new ExternalAuthFlow({
    provider: oidcProvider({
      id: "acme",
      displayName: "Acme SSO",
      issuer: "https://sso.acme.example",
      clientId: "my-app",
      clientSecret,
      discoveryCache,
    }),
  });
}
```

Pass a shared `discoveryCache` whenever connectors are rebuilt per request — a
server resolving provider config from a database, for instance — or every
sign-in leg re-fetches the discovery document. Omit `clientSecret` for a public
client; PKCE is on either way.

**Getting the credentials.** Both presets need an OAuth client registered with
the provider, and the redirect URI you register must match the `redirectUri` you
pass to `start` **exactly** — scheme, host, port, path, no trailing slash
mismatch. A mismatch shows up as a `provider_error` naming
`redirect_uri_mismatch`.

- **Google** — Google Cloud console → APIs & Services → Credentials → OAuth
  client ID, application type "Web application". Add
  `https://app.example.com/auth/social/google/callback` (plus your localhost
  variant) as an authorized redirect URI.
- **GitHub** — Settings → Developer settings → OAuth Apps → New OAuth App. One
  callback URL per app, so development usually gets its own app.
- **Generic OIDC** — whatever the provider's console calls a confidential
  client; you need the issuer URL, a client id, and a secret.

Register the localhost callbacks separately rather than pointing production
credentials at a development host.

### Sign in with Apple

Apple is OpenID-Connect-shaped but does not fit `oidcProvider`, which is why it
has its own connector. Three things are different, and all three are handled for
you:

- **The client secret is a signed ES256 JWT, not a string.** Apple wants a
  short-lived JWT signed with a `.p8` key you download once. `appleProvider`
  builds and caches it (`generateAppleClientSecret` /
  `createAppleClientSecretFactory` are exported if you need one directly), with
  a default lifetime of ~180 days under Apple's 6-month cap
  (`APPLE_CLIENT_SECRET_MAX_TTL_SECONDS`). No `openssl` step, no cron job to
  rotate a string, no dependency — Web Crypto signs it.
- **The client authenticates in the token body** (`client_secret_post`), not
  with a Basic header.
- **`response_mode=form_post` is required** whenever a profile scope is
  requested, so Apple returns to your `redirect_uri` with a **POST**, not a GET.
  Your callback route must accept `POST` and read `code` / `state` from the form
  body. This is the single most common way an Apple integration fails.

```ts
import {
  appleProvider,
  ExternalAuthFlow,
} from "@udibo/oauth2/identity/external";

export const apple = new ExternalAuthFlow({
  provider: appleProvider({
    clientId: Deno.env.get("APPLE_SERVICES_ID")!,
    teamId: Deno.env.get("APPLE_TEAM_ID")!,
    keyId: Deno.env.get("APPLE_KEY_ID")!,
    privateKey: Deno.env.get("APPLE_PRIVATE_KEY")!,
  }),
});
```

Four values, from three places in the Apple Developer console: the **Services
ID** (Certificates, Identifiers & Profiles → Identifiers, of type "Services IDs"
— _not_ your app's bundle id) is the `clientId`; the **Team ID** is top-right on
the membership page; the **Key ID** and the `.p8` file come from Keys → a key
with "Sign in with Apple" enabled. The `.p8` is downloadable exactly once —
store its PKCS#8 PEM contents as a secret. Both the full
`-----BEGIN PRIVATE KEY-----` block and the bare base64 body are accepted.

The connector verifies the returned `id_token`'s signature against Apple's
published JWKS and checks `iss`, `aud`, `azp`, `exp` and the `nonce` before
trusting any claim. Generic `oidcProvider` has a different validation boundary,
described below. Two Apple-specific facts about the profile that reaches your
code:

- **The user's name arrives once, and never in the `id_token`.** Apple puts it
  in the `form_post` body's `user` field on the _first_ authorization only. The
  connector returns what the `id_token` carries (subject, email), so capturing
  the name is your callback route's job — it is the only code that sees the form
  body. Miss it and it is gone; Apple will not send it again.
- **Private-relay addresses are ordinary verified emails.**
  `…@privaterelay.appleid.com` comes back as-is. Treat it as a real, verified
  address (it forwards), and note that the user can turn forwarding off later.
  The raw claims, including `is_private_email`, stay on `profile.raw`.

### Discord, and other plain-OAuth2 providers

Discord speaks plain OAuth2 — no discovery document, no `id_token` — so
`discordProvider` is a thin preset over the generic `oauth2Provider`, pinned to
Discord's endpoints. It reads the profile from `GET /users/@me`: the subject is
the Discord user id, `emailVerified` reflects Discord's `verified` flag, and the
display name prefers the global display name over the legacy username.

```ts
import {
  discordProvider,
  ExternalAuthFlow,
} from "@udibo/oauth2/identity/external";

export const discord = new ExternalAuthFlow({
  provider: discordProvider({
    clientId: Deno.env.get("DISCORD_CLIENT_ID")!,
    clientSecret: Deno.env.get("DISCORD_CLIENT_SECRET")!,
  }),
});
```

Anything else that speaks plain OAuth2 gets the same treatment through
`oauth2Provider` directly. You supply the endpoints and a `mapProfile` that
turns the provider's userinfo payload into an `ExternalProfile`; the connector
runs the exchange (`client_secret_post`), fetches the profile with the bearer
token, and hands it to your mapper:

```ts
import {
  ExternalAuthFlow,
  oauth2Provider,
} from "@udibo/oauth2/identity/external";

export const twitch = new ExternalAuthFlow({
  provider: oauth2Provider({
    id: "twitch",
    displayName: "Twitch",
    authorizationEndpoint: "https://id.twitch.tv/oauth2/authorize",
    tokenEndpoint: "https://id.twitch.tv/oauth2/token",
    userInfoEndpoint: "https://id.twitch.tv/oauth2/userinfo",
    clientId: Deno.env.get("TWITCH_CLIENT_ID")!,
    clientSecret: Deno.env.get("TWITCH_CLIENT_SECRET")!,
    defaultScopes: ["openid", "user:read:email"],
    usesPkce: true,
    mapProfile: ({ profile }) => ({ subject: String(profile.sub) }),
  }),
});
```

`mapProfile` is a trigger point with a sharp edge: a missing or empty `subject`
in what you **return** surfaces as `provider_error`, but a mapper that
**throws** surfaces raw. Return, don't throw. `usesPkce` defaults to `false`
because many plain-OAuth2 providers reject the parameters — turn it on when the
provider supports S256, as Twitch does.

**Validation depends on the connector.** Apple verifies the ID-token signature
against its JWKS and validates the claims. Generic `oidcProvider` and Google
validate issuer, audience, expiry, nonce, and applicable authorized-party
claims, while relying on the direct HTTPS token exchange for token integrity;
they do not verify the ID-token signature. Generic OIDC rejects insecure
non-loopback endpoints and provider-fetch redirects. Never feed it an ID token
received through another channel.

Plain OAuth2 connectors obtain profiles through authenticated provider API
requests. In either case, the provider must be trusted for the identities it
asserts. A verified email flag alone does not make an arbitrary provider
trusted.

## The two routes

`start` builds the provider URL and hands back the transient. Persist the
transient and redirect:

```ts
import type { ExternalAuthFlow } from "@udibo/oauth2/identity/external";

export async function beginSignIn(
  flow: ExternalAuthFlow,
  origin: string,
  seal: (value: unknown) => Promise<string>,
  formPost = false,
): Promise<Response> {
  const { url, transient } = await flow.start({
    redirectUri: `${origin}/auth/social/${flow.provider.id}/callback`,
  });
  return new Response(null, {
    status: 302,
    headers: {
      location: url,
      "set-cookie": `social_transient=${await seal({ transient })}; ` +
        `Path=/auth/social; HttpOnly; Secure; SameSite=${
          formPost ? "None" : "Lax"
        }; Max-Age=600`,
    },
  });
}
```

For Apple, call `beginSignIn` with `formPost: true`, because its callback is a
cross-site form POST. That transient cookie needs `SameSite=None; Secure`. Other
redirect-based connectors use `SameSite=Lax`. This choice belongs to the
configured provider, never to a browser-supplied parameter.

The callback must read and unseal the browser's transient cookie, reject a
missing or invalid value, and clear it before finishing the attempt. Accept form
POSTs only for providers configured to use them, require the form content type,
and apply a request-body size limit. Validate the transient even though Apple's
POST cannot pass an ordinary same-origin form guard.

`finish` validates state and provider binding, then returns the normalized
profile:

```ts
import type {
  ExternalAuthFlow,
  ExternalAuthTransient,
  ExternalProfile,
} from "@udibo/oauth2/identity/external";

export async function completeSignIn(
  flow: ExternalAuthFlow,
  request: Request,
  transient: ExternalAuthTransient,
): Promise<ExternalProfile> {
  const params = request.method === "POST"
    ? new URLSearchParams(await request.text())
    : new URL(request.url).searchParams;
  return await flow.finish({ params, transient });
}
```

Between those two calls the flow has enforced the transient's max age (10
minutes by default, `maxTransientAgeMs`), compared `state` in constant time,
surfaced any provider `error` parameter, exchanged the code, and — for OIDC
providers — validated the id_token's `iss`, `aud`, `azp`, `exp`, and `nonce`.
Route each provider's callback to the flow built with _that_ provider; a
mismatched transient is rejected as a `configuration` error rather than silently
trusted.

## Transient custody

The transient holds the `state`, the PKCE verifier, and the nonce. It is not a
credential, but it is the CSRF defense, so treat the cookie carrying it as one:

- **Sealed, not plaintext.** `sealJson`/`unsealJson` from `@udibo/oauth2/crypto`
  over a server-held key is enough; a readable transient lets an attacker craft
  a matching `state`.
- **`HttpOnly`, `Secure`, and path-scoped** to the callback. Use `SameSite=Lax`
  for redirects and `SameSite=None` for Apple's form POST.
- **Short-lived.** Give the cookie a `Max-Age` no longer than
  `maxTransientAgeMs`, so the browser drops it around when the flow would reject
  it anyway.
- **One-shot.** Clear it at the top of the callback, before any branch can
  return. A transient that survives its callback is a replayable attempt.

A session works too if you already have one for anonymous visitors, but a cookie
keeps the sign-in flow stateless and is what the flow's design assumes.

## Resolving the profile to an account

`ExternalProfile` carries `provider`, `subject`, `email`, `emailVerified`, some
display fields, and the provider's `raw` claims. Two rules govern what you do
with it.

**Key identities by `(provider, subject)`, never by email.** `subject` is the
provider's stable id (OIDC `sub`, GitHub user id). Email addresses change, get
reassigned inside a company domain, and — from a provider you don't control —
are simply a string the provider chose to send you. Store a separate identities
table so one user can hold several sign-in methods.

**Treat `emailVerified: false` as attacker-controlled input.** It is `false`
unless the provider positively asserted verification (`email_verified: true`, or
GitHub's flag on the chosen primary address).

Which gives three branches:

```ts
import type { ExternalProfile } from "@udibo/oauth2/identity/external";

export type Resolution =
  | { action: "sign_in"; userId: string }
  | { action: "auto_link"; userId: string }
  | { action: "create" }
  | { action: "verify_first" };

export async function resolveProfile(
  profile: ExternalProfile,
  store: {
    findIdentity(
      provider: string,
      subject: string,
    ): Promise<{ userId: string } | null>;
    findUserByEmail(
      email: string,
    ): Promise<{ id: string; emailVerified: boolean } | null>;
  },
): Promise<Resolution> {
  const identity = await store.findIdentity(profile.provider, profile.subject);
  if (identity) return { action: "sign_in", userId: identity.userId };

  const collision = profile.email
    ? await store.findUserByEmail(profile.email)
    : null;
  if (!collision) return { action: "create" };

  if (!profile.emailVerified || !collision.emailVerified) {
    return { action: "verify_first" };
  }
  return { action: "auto_link", userId: collision.id };
}
```

The `verify_first` branch is the one that matters. Auto-linking on an
**unverified** address on either side is an account takeover: anyone who can
make a provider assert `victim@example.com` inherits the victim's account
without presenting a credential. When either side is unverified, refuse the
sign-in and tell the user to sign in with their existing method and connect the
provider from their account settings — an explicitly initiated link, from an
authenticated session, is safe where an implicit one is not.

Some further hardening the branches don't show:

- **Insert the identity row under a unique constraint** on `(provider, subject)`
  and handle the `409` by re-reading the winner. Two concurrent first-time
  callbacks otherwise create two users.
- **Notify the account owner whenever a sign-in method is attached**,
  auto-linked or not. It is the only signal a user gets that a new key to their
  account exists.
- **Start user-initiated linking from a same-origin POST**, not a GET. A GET
  link-start can be laundered cross-site into a forced-linking attack (RFC 6819
  §4.4.1.13); a cross-site POST carries no cookie under `SameSite=Lax`.
- **Refuse to link from an impersonated or elevated support session.** A link
  outlives the session that created it.

## Trust configured providers

Configure provider endpoints in trusted application code or deployment settings.
Do not let a sign-in request choose an issuer, profile endpoint, or automatic
account-linking policy. Only enable automatic linking for providers your app
trusts to verify that address; otherwise require the user to authenticate with
an existing method before linking.

## When it goes wrong

Every failure is an `ExternalAuthError` whose message names the provider, what
failed, and the likely fix. Switch on `code` to decide who the failure belongs
to:

```ts
import { isExternalAuthError } from "@udibo/oauth2/identity/external";

export function describeFailure(error: unknown): string {
  if (!isExternalAuthError(error)) throw error;
  switch (error.code) {
    case "configuration":
      console.error("[social] miswired provider:", error.message);
      return "Sign-in with that provider is unavailable right now.";
    case "provider_error":
    case "invalid_callback":
    case "state_mismatch":
    case "transient_expired":
    case "nonce_mismatch":
      return "That sign-in attempt didn't complete. Please try again.";
  }
}
```

`configuration` is a deploy-time bug — alert an operator, because retrying will
not help. The other five are per-attempt failures: log the detail server-side
and show the user one flat "try again". Don't echo the provider's error text
into your UI; `access_denied` (the user pressed Cancel) and
`redirect_uri_mismatch` (your registration is wrong) both arrive as
`provider_error`, and only one of them is the user's business.

## Rendering the buttons

The prebuilt sign-in and sign-up forms render a social section automatically
when you pass `socialProviders`. Use `socialHref` so each button is a full-page
navigation to your start route — a `fetch` can't follow the provider's redirect:

```tsx
import { SignInForm } from "@udibo/oauth2/react/components";

const providers = [
  { id: "google", name: "Google" },
  { id: "github", name: "GitHub" },
];

export function SignIn() {
  return (
    <SignInForm
      socialProviders={providers}
      socialHref={(provider) => `/auth/social/${provider.id}`}
      onSubmit={async (values) => {
        const res = await fetch("/auth/sign-in", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(values),
        });
        if (!res.ok) return { error: "Those credentials didn't work." };
      }}
    />
  );
}
```

Pass `iconSlot` on a provider to render a logo before the label, and
`classNames.socialButton` to theme them.

## Security checklist

Before going live:

- [ ] **Redirect URIs are registered exactly**, per environment, and production
      credentials never point at a development host.
- [ ] **The transient cookie is sealed, `HttpOnly`, `Secure`, has the
      appropriate SameSite setting, path-scoped, short-lived, and cleared at the
      top of the callback.**
- [ ] **Identities are keyed by `(provider, subject)`** under a unique
      constraint, never by email.
- [ ] **Auto-link requires `emailVerified` on both sides**; anything else falls
      through to verify-first.
- [ ] **User-initiated linking is a same-origin POST from an authenticated,
      non-impersonated session**, and the owner is notified on every link.
- [ ] **Provider configuration is trusted application configuration**; users
      cannot supply arbitrary issuers or linking rules.
- [ ] **The MFA gate runs before the session is minted** — see
      [add-mfa.md](add-mfa.md#the-challenge-one-gate-every-sign-in-path) — and
      the user is re-resolved for a disabled account.
- [ ] **`configuration` errors alert an operator**; the rest show one flat
      message and log the detail server-side.
