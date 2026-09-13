# Application deployment checklist

Use the items that apply to your integration. For explanations, see
[deploy your application](production-deployment.md). If Udibo hosts sign-in,
review your client/BFF/API boundaries; the app-owned identity and issuer
sections apply only when you host those flows.

## Configuration and secrets

- [ ] Issuer, app origin, and exact callbacks are configured for this
      environment.
- [ ] Production credentials and data are separate from local and preview
      environments.
- [ ] No demo credentials, fallback secrets, or local test-provider endpoints
      remain.
- [ ] Client secrets, cookie keys, and signing keys stay on the backend and out
      of logs.

## Browser, BFF, and API

- [ ] HTTPS cookie and CSRF defaults are enabled; custom browser requests send
      the CSRF header.
- [ ] Login state and PKCE verifier survive callbacks to a different app
      instance.
- [ ] Sessions expire consistently and stateful updates reject revoked or
      missing sessions.
- [ ] Local logout, upstream revocation, and optional SSO logout have each been
      tested.
- [ ] Session listings expose non-secret row IDs, never cookie credentials or
      token material.
- [ ] The API validates issuer, token type, applicable audience, and required
      scopes.
- [ ] Record-level authorization runs on the server, independently of React
      rendering guards.
- [ ] The app handles invalid tokens separately from issuer outages.
- [ ] Any proxy has a fixed trusted target; trusted-forwarded-header policy
      matches deployment.

## If your app hosts an authorization server

- [ ] PKCE, state, and confidential-client authentication are enabled.
- [ ] Registered callbacks and allowed grants are restricted to the app's actual
      clients.
- [ ] Codes and refresh-token rotation claims are consumed atomically.
- [ ] Replay-family revocation cannot be undone by a concurrent token save.
- [ ] Client-credentials tokens represent the client or its service account, not
      its human owner.
- [ ] Consent and scope policy match the clients you allow.
- [ ] Persisted signing keys survive deployment; rotation and JWT revocation
      limits are understood.
- [ ] Deprecated password/implicit grants are not enabled for new integrations.

## If your app hosts login

- [ ] The full password credential, including `params`, is persisted.
- [ ] Automatic rehash/import uses atomic `replaceCredential`; a failed
      comparison writes nothing, and the sign-in proceeds only if the password
      re-verifies against the credential now stored.
- [ ] Rate limiting and lockout are explicitly configured and enforced.
- [ ] Email requests and OTP/MFA attempts are throttled; concurrent resend
      policy is explicit.
- [ ] OTP consumption and recovery-code consumption permit one successful
      caller.
- [ ] Password reset invalidates sessions; optional sign-in-link/OTP cleanup is
      implemented and monitored.
- [ ] Email verification is conditional on the current address matching the
      address proved.
- [ ] MFA enrollment, disable, recovery, and verification routes authenticate
      and authorize the user.
- [ ] A completed first factor creates pending MFA state, not a full application
      session.
- [ ] External identities are keyed by trusted provider and subject; linking
      requires account proof.
- [ ] Apple callbacks accept form POSTs and use the required Secure,
      SameSite=None transient cookie.

## Verification and maintenance

- [ ] Contract suites pass against the actual persistent adapters.
- [ ] Tests cover concurrent redemption, callback mismatch, expired/revoked
      sessions, and insufficient scope.
- [ ] Backups, retention, and recovery are exercised without restoring revoked
      access unintentionally.
- [ ] Audit records omit credentials; delivery and persistence failures are
      observable.
- [ ] The [known limitations](../known-limitations.md) have been reviewed for
      enabled features.
