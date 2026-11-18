# Use authentication in React

Use `@udibo/oauth2/react` to share session state and sign-in actions with your
components. For a browser app with a backend, connect it to `BffClient` so
tokens stay on the server. First mount your BFF using
[the integration guide](use-udibo.md) or the
[app-owned authorization example](../../examples/hono/app-with-own-auth/README.md).

## Provide the client once

```tsx
import { BffClient } from "@udibo/oauth2/client";
import { OAuth2Provider, RequireAuth, useOAuth2 } from "@udibo/oauth2/react";

const client = new BffClient();

function Account() {
  const { user, logout } = useOAuth2();
  return (
    <section>
      <p>Signed in as {String(user?.name ?? user?.sub ?? "user")}</p>
      <button onClick={() => logout()}>Sign out</button>
    </section>
  );
}

export function App() {
  return (
    <OAuth2Provider client={client}>
      <RequireAuth fallback={<p>Checking your session…</p>}>
        <Account />
      </RequireAuth>
    </OAuth2Provider>
  );
}
```

`RequireAuth` starts sign-in when the session is unauthenticated. It starts none
while a `logout()` from `useOAuth2()` is signing out, so a sign-out button on a
protected page ends at the logout destination rather than the login page. The
guard covers only that hook: calling `client.logout()` directly bypasses it. If
the logout navigation never completes, for example a `beforeunload` handler
cancels it or the logout URL answers `204` or a download, the page stays on
`fallback` until it is reloaded. Use
`useOAuth2()` directly when a page should stay public and offer an explicit
sign-in button. Construct the client once per browser app, not on every render.
For server rendering, derive any initial auth state from the current request; do
not share a token-owning `DirectClient` across users.

With a `HonoBff`, `bff.readSession(c)` gives the server the answer
`GET /auth/session` gives the browser, without tokens. Pass it to the provider
as `initialState`, and a signed-in page renders signed in on the first paint
instead of waiting for the session probe:

```tsx
import type { SessionState } from "@udibo/oauth2/client";
import { BffClient } from "@udibo/oauth2/client";
import { OAuth2Provider } from "@udibo/oauth2/react";
import type { ReactNode } from "react";

const client = new BffClient();

export function Root(
  props: { session: SessionState; children: ReactNode },
) {
  return (
    <OAuth2Provider client={client} initialState={props.session}>
      {props.children}
    </OAuth2Provider>
  );
}
```

`readSession` applies the same session lifetime as the probe. In
`sessionMode:
"own"`, it destroys a session past `sessionMaxAgeMs` and clears
its cookie. Shared mode leaves lifetime enforcement to the application and its
session store. It sets no caching policy, so send a page rendered from its
answer with a private or `no-store` `Cache-Control`.

While signed in, the provider re-checks the session shortly before
`sessionExpiresIn` elapses. A BFF session whose access token has expired reports
`sessionExpiresIn: 0` until a proxied call refreshes the token, so the provider
backs off rather than polling: it checks after 5 seconds, then doubles the wait
after each check that fails or reports no later expiry, up to one check every 5
minutes per tab. A check that reports a later expiry returns it to the
pre-expiry schedule, never more often than every 5 seconds. A `BffClient.fetch` that gets a `401` still signs the UI
out immediately.

A rendering guard does not protect data. Keep bearer/session validation,
required scopes, and record-level authorization on the server. Use the same
`BffClient.fetch` for credentialed API calls so the CSRF header is included.

## Forms for an app that hosts its own login

Applications using Udibo redirect to hosted sign-in. Use the optional components
below only on login pages your own application hosts. They provide fields and
submission state; they do not create routes, sessions, or an identity service.

| Component                                       | Use                                       |
| ----------------------------------------------- | ----------------------------------------- |
| `SignInForm`, `SignUpForm`                      | App-owned password login and registration |
| `RequestPasswordResetForm`, `ResetPasswordForm` | Request and complete a password reset     |
| `MfaEnrollmentForm`, `MfaChallengeForm`         | Display enrollment and challenge controls |
| `UserMenu`                                      | User display and sign-out action          |

```tsx
import { SignInForm } from "@udibo/oauth2/react/components";

export function SignInPage() {
  return (
    <SignInForm
      action="/auth/signin"
      onSubmit={async (values) => {
        const response = await fetch("/auth/signin", {
          method: "POST",
          headers: { "content-type": "application/json", "x-csrf": "1" },
          body: JSON.stringify(values),
        });
        if (!response.ok) {
          return {
            error: "Sign-in failed. Check your credentials.",
          };
        }
      }}
      onSuccess={() => location.assign("/")}
    />
  );
}
```

This assumes your application has mounted that sign-in endpoint. Validate the
request and create a session in the backend's authentication hook. If MFA is
enabled, route first-factor success to the challenge instead of immediately
navigating to an authenticated page; see [MFA](add-mfa.md).

`onSubmit` returns nothing for success or `{ error, fieldErrors }` for a form
failure. `onSuccess` is a UI side effect, not an authorization gate; errors in
that callback are isolated.

Every form renders `method="post"` unless you pass `method`, with or without an
`action`. A submit before React hydrates, or after the bundle fails to load, is
a native browser submit, and posting keeps passwords and codes out of the URL,
browser history and access logs. Without an `action` it posts back to the
current page, so that route must accept a `POST` or the person sees an error;
set `action` to the backend route that handles a no-JavaScript submit and
return the appropriate redirect from it. Do not pass `method="get"` to these
forms: it puts their fields in the URL.

A route that handles that native submit receives a form-encoded `POST`, which
any other site can also send with the person's cookies. Point `action` at the
`honoIdentityRoutes` route, which checks the request is same-origin, or check
`Origin` or `Sec-Fetch-Site` in your own handler.

## Account settings components

Three components cover the signed-in half of an account page: where the account
is signed in, which social accounts are linked, and its password. Each takes
its data as props and reports each action through a callback or `onSubmit`.
They do not load data, call your server, or add routes. Load the data in your
route and pass it in, then pass the updated data once an action succeeds.
Applications that use Udibo's hosted sign-in already have this page there; use
these where your application runs its own account backend.

| Component            | Use                                                                    |
| -------------------- | ---------------------------------------------------------------------- |
| `SessionList`        | Signed-in sessions, with sign-out for one session or every other one    |
| `LinkedAccounts`     | Linked social accounts, with disconnect and connect                    |
| `ChangePasswordForm` | Change a password, or set a first one on an account that has none      |

```tsx
import {
  ChangePasswordForm,
  type LinkedAccount,
  LinkedAccounts,
  SessionList,
  type SessionListItem,
} from "@udibo/oauth2/react/components";

async function send(path: string, init: RequestInit) {
  const response = await fetch(path, {
    ...init,
    headers: { "content-type": "application/json", "x-csrf": "1" },
  });
  if (!response.ok) return { error: "That didn't work. Try again." };
}

export function SecurityPage(props: {
  sessions: SessionListItem[];
  accounts: LinkedAccount[];
  hasPassword: boolean;
  reload: () => void;
}) {
  return (
    <>
      <h2>Sessions</h2>
      <SessionList
        sessions={props.sessions}
        onRevoke={async (session) => {
          const failed = await send(`/account/sessions/${session.id}`, {
            method: "DELETE",
          });
          if (failed) return failed;
          props.reload();
        }}
        onRevokeOthers={async () => {
          const failed = await send("/account/sessions", { method: "DELETE" });
          if (failed) return failed;
          props.reload();
        }}
      />

      <h2>Connected accounts</h2>
      <LinkedAccounts
        accounts={props.accounts.map((account) => ({
          ...account,
          canUnlink: props.hasPassword || props.accounts.length > 1,
        }))}
        onUnlink={async (account) => {
          const failed = await send(`/account/identities/${account.id}`, {
            method: "DELETE",
          });
          if (failed) return failed;
          props.reload();
        }}
      />

      <h2>Password</h2>
      <ChangePasswordForm
        hasPassword={props.hasPassword}
        minLength={12}
        onSubmit={(values) =>
          send("/account/password", {
            method: "POST",
            body: JSON.stringify(values),
          })
        }
        onSuccess={props.reload}
      />
    </>
  );
}
```

The components only offer actions; your server decides them. Check on the
server that the session or linked account belongs to the signed-in person, and
refuse an unlink that would leave no way to sign in. `canUnlink: false` only
hides that account's Disconnect button.

`SessionList` never offers to sign out the session marked `current`. Summarize
each session's user agent into `device` on your server. Leave out `onRevoke` and
`onRevokeOthers`, or `onUnlink`, for a read-only list.

Give each session and linked account an opaque, non-secret `id`, such as a
public row id. Never use the session token or cookie value: the id is not shown
as text, but it is written into the page's attributes and hidden inputs.

`ChangePasswordForm` sends `revokeOtherSessions: true` by default and says that
other sessions will be signed out. Pass `revokeOtherSessions="optional"` to give
the person a checkbox, or `false` to keep other sessions. Your server signs the
sessions out. With `hasPassword={false}` the form drops the current-password
field to set a first password. Without a current password, check on the server
that the request comes from the account owner, for example with a recent
sign-in, a passkey, or a code. Decide between setting and changing from the
account your server has stored, not from the request: refuse a request without
the current password for an account that already has one.

Dates use the runtime's locale and time zone by default. On a server-rendered
page, pass `formatDate` with a fixed locale and `timeZone` so the server and
browser render the same text.

With `action` set, the components post a form when JavaScript has not loaded.
Their forms always use `post`, so passwords and ids never reach a URL:

- Sign out posts `intent=revoke-session` and `sessionId`.
- Sign out everywhere else posts `intent=revoke-other-sessions`.
- Disconnect posts `intent=unlink-identity` and `identityId`.
- `ChangePasswordForm` posts `currentPassword` (when it has the field),
  `newPassword`, `confirmPassword`, and `revokeOtherSessions` as `"true"` or
  `"false"`. With `revokeOtherSessions="optional"`, an unchecked box posts no
  `revokeOtherSessions`.

A native post cannot carry a CSRF header such as `x-csrf`, so the route that
receives it checks the `Origin` or `Sec-Fetch-Site` header instead.

## Styling and custom markup

Components are unstyled. Use `className`, the per-slot `classNames` map, or
stable `data-oauth2-*` attributes. `AuthFormClassNamesProvider` supplies shared
form classes, including `ChangePasswordForm`'s; an individual form can override
a slot. `UserMenu`, `SessionList` and `LinkedAccounts` have their own styling
props.

While a submit is in flight, the submit button shows its pending label and
carries `aria-disabled="true"` instead of `disabled`, so it keeps keyboard
focus; repeat clicks, Enter, and Space are ignored until the submit settles.
Style the pending state with `[data-oauth2-submit][aria-disabled="true"]`, not
`:disabled`. Custom markup built on `useAuthForm` gets the same guard from
`handleSubmit`; mark its button with
`aria-disabled={form.isSubmitting || undefined}`.

For full markup control, use `useAuthForm` or a component's render-prop
children. Your own `<form>` does not get the `method="post"` default: set it,
or a submit before hydration puts the fields in the URL. Keep labels, error associations, focus behavior, and autocomplete
attributes when replacing markup. The
[component API](https://jsr.io/@udibo/oauth2/doc/react/components) lists the
slots and props.

See the [React Router template](../../templates/react-router/README.md) for a
complete app, and [testing](testing.md) for mock providers and BFF session
fixtures.
