# Changelog

Release history for `@udibo/oauth2`. See
[the stability policy](docs/stability.md) for pre-1.0 compatibility
expectations.

## Unreleased — 0.1.0 preparation

Initial public package:

- OAuth2 authorization and resource servers with PKCE, refresh-token rotation,
  revocation, introspection, discovery, and device authorization.
- OIDC issuance, signing-key providers, and JWT or introspection token readers.
- Direct clients, a Hono BFF, Hono route adapters, and React bindings/forms.
- App-owned identity flows: signup, login, reset, email verification,
  passwordless, MFA, social/OIDC login, and password-hash migration.
- Development identity provider, examples, starter templates, and storage
  contract suites.

Release hardening:

- Require confidential-client authentication alongside PKCE by default.
- Enforce single-winner refresh rotation and OTP consumption.
- Keep logout and replacement login authoritative during asynchronous refreshes.
- Reject updates that would restore revoked stateful BFF sessions.
- Use atomic credential replacement for automatic password upgrades.
- Require secure OIDC endpoints and reject redirects during provider fetches.
- Include consumer documentation in the JSR payload and verify standalone,
  Windows-path, and Node compatibility.
- Take the Hono BFF's login `scope` and `prompt` from server configuration.
  `/auth/login` no longer reads either off its own query string, so a login link
  can no longer widen the scope a session is minted with or steer the
  authentication ceremony. Both are ordinary names on `HonoBffOptions`
  `extraParams` and `forwardedParams` now: pin a prompt with
  `extraParams: { prompt: "login" }`, set the scope with `HonoBffOptions.scope`
  (pinning `scope` in `extraParams` beside it is refused), and restore a
  browser-chosen value by listing the name in `forwardedParams`. Applications
  whose SPA starts a silent renew at `/auth/login?prompt=none` must add
  `forwardedParams: ["prompt"]` for it to keep working.
