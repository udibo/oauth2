# [0.3.0](https://github.com/udibo/oauth2/compare/0.2.0...0.3.0) (2026-09-22)

### Features

- **testing:** serve the caller's memberships from the fake tenant
  ([#27](https://github.com/udibo/oauth2/issues/27))
  ([3932416](https://github.com/udibo/oauth2/commit/393241615bc08e2ea683fd308df8db7e0095d482))

# [0.2.0](https://github.com/udibo/oauth2/compare/0.1.0...0.2.0) (2026-09-22)

### Features

- **testing:** add a fake Udibo tenant for testing apps built on one
  ([#26](https://github.com/udibo/oauth2/issues/26))
  ([4e435c4](https://github.com/udibo/oauth2/commit/4e435c4f8c5038641fd439d677e83144b855bc7d))

# [0.1.0](https://github.com/udibo/oauth2/compare/0.0.0...0.1.0) (2026-09-21)

- feat!: preserve authentication event context
  ([be79fc7](https://github.com/udibo/oauth2/commit/be79fc749088794333c8c031b37b66e6fc9656e4))
- feat(hono)!: server-configure the BFF login scope and prompt
  ([03d57f0](https://github.com/udibo/oauth2/commit/03d57f05cc97d7721e4d810cd232a51690e469c9))

### Bug Fixes

- **release:** drop the tarballDir value the npm plugin rejects
  ([#20](https://github.com/udibo/oauth2/issues/20))
  ([969af10](https://github.com/udibo/oauth2/commit/969af103ff9713e843d81c1cce0c161212ca48d9))
- **release:** give the dry run the npm credential too
  ([#22](https://github.com/udibo/oauth2/issues/22))
  ([7da21fd](https://github.com/udibo/oauth2/commit/7da21fd5b66c8c8ff5b5ab90c03c968dd35c8cdd))
- **identity:** re-verify after a lost credential compare-and-set
  ([#6](https://github.com/udibo/oauth2/issues/6))
  ([c473b4d](https://github.com/udibo/oauth2/commit/c473b4dbe3ed86694daf07a63f3732d1aab52d01))
- **release:** stop setup-node seeding a placeholder npm token
  ([#21](https://github.com/udibo/oauth2/issues/21))
  ([4b298da](https://github.com/udibo/oauth2/commit/4b298da6883d373cbf6ea0306528a192c71988e3))

### Features

- **server:** authorize token introspection
  ([#4](https://github.com/udibo/oauth2/issues/4))
  ([f4e82d1](https://github.com/udibo/oauth2/commit/f4e82d141334c28f1a7e79fa5e4fe0498c8ff128))
- **release:** publish the npm artifact alongside the JSR one
  ([#18](https://github.com/udibo/oauth2/issues/18))
  ([569f151](https://github.com/udibo/oauth2/commit/569f151a6cec1f32bd43e928d3c25e6ce3d24384))
- **hono:** redact query values in request logs
  ([#5](https://github.com/udibo/oauth2/issues/5))
  ([3e10d2e](https://github.com/udibo/oauth2/commit/3e10d2e23fe85167281a2859de4b8165ee3ee1b1))

### BREAKING CHANGES

- BFF forwardedParams rejects acr_values and max_age, case-insensitively. Pin
  server-chosen requirements in extraParams.
- Login ignores browser scope and prompt unless explicitly listed in
  forwardedParams. Configure forwardedParams: ["prompt"] to retain
  browser-triggered silent renewal or signup navigation. Scope forwarding
  replaces the configured scope; an empty value falls back.

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

- Preserve application-supplied authentication context on authorization codes,
  token records, and refresh descendants. Claims hooks receive the credential's
  original event for ID tokens, UserInfo, and JWT access tokens; introspection
  hooks can read it from the token. Custom stores must persist and restore
  `authenticationContext`, and JWT generator wrappers must forward its fourth
  argument. Missing legacy context stays absent. Authorization request parsing
  exposes raw `acrValues`, `maxAge`, and `prompt`; applications own enforcement.
- **Breaking:** reject `acr_values` and `max_age` in BFF `forwardedParams`
  (including mixed-case names). Move each requirement to a fixed value in
  `extraParams` so browser input cannot weaken assurance or freshness.
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
