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

`RequireAuth` starts sign-in when the session is unauthenticated. Use
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
      method="post"
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
that callback are isolated. For a no-JavaScript form post, `action`/`method`
identify the backend route and that route must return the appropriate redirect.

## Styling and custom markup

Components are unstyled. Use `className`, the per-slot `classNames` map, or
stable `data-oauth2-*` attributes. `AuthFormClassNamesProvider` supplies shared
form classes; an individual form can override a slot. `UserMenu` has its own
styling props.

While a submit is in flight, the submit button shows its pending label and
carries `aria-disabled="true"` instead of `disabled`, so it keeps keyboard
focus; repeat clicks, Enter, and Space are ignored until the submit settles.
Style the pending state with `[data-oauth2-submit][aria-disabled="true"]`, not
`:disabled`. Custom markup built on `useAuthForm` gets the same guard from
`handleSubmit`; mark its button with
`aria-disabled={form.isSubmitting || undefined}`.

For full markup control, use `useAuthForm` or a component's render-prop
children. Keep labels, error associations, focus behavior, and autocomplete
attributes when replacing markup. The
[component API](https://jsr.io/@udibo/oauth2/doc/react/components) lists the
slots and props.

See the [Juniper](../../templates/juniper/README.md) and
[React Router](../../templates/react-router/README.md) templates for complete
apps, and [testing](testing.md) for mock providers and BFF session fixtures.
