# [0.8.0](https://github.com/udibo/oauth2/compare/0.7.0...0.8.0) (2026-09-26)

- feat!: add readSession and fake tenant org/account APIs
  ([#46](https://github.com/udibo/oauth2/issues/46))
  ([17e28ab](https://github.com/udibo/oauth2/commit/17e28ab5750b807ba0d3d85cd931071a9491b01c))

### BREAKING CHANGES

- TenantContractFixture asks more of a fixture. linkAccount is now required and
  links an external account to a person. addUser must honor its optional
  profile: give the person profile.email, verify it unless emailVerified is
  false, and with password false leave them no password while signIn can still
  sign them in. signIn takes a third argument, and with { sameBrowser: true } it
  must sign the person in from the browser their previous sign-in used. The
  fixture's client must be first-party. createFakeTenant also changed: a second
  authorization under one signInAs revokes a first-party application's earlier
  credentials, so call signInAs before each sign-in that should stay
  independent, or register the client with type "third-party". A membership
  seeded without roles, or with [], now holds ["member"] instead of none.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

- fix(testing): isolate concurrent session issuance

# [0.7.0](https://github.com/udibo/oauth2/compare/0.6.0...0.7.0) (2026-09-25)

- feat(client)!: report pre-header timeouts as unavailable
  ([#49](https://github.com/udibo/oauth2/issues/49))
  ([f56a5f4](https://github.com/udibo/oauth2/commit/f56a5f48596e3b18cb635e041c1799aabf0e9001)),
  closes [#43](https://github.com/udibo/oauth2/issues/43)

### Features

- **server:** cap unauthenticated request bodies
  ([#53](https://github.com/udibo/oauth2/issues/53))
  ([2d1a556](https://github.com/udibo/oauth2/commit/2d1a5560d0464c54da307ab2fc5ac3416ffa6086)),
  closes [#44](https://github.com/udibo/oauth2/issues/44)
  [#44](https://github.com/udibo/oauth2/issues/44)
- **testing:** let a shared auth-request store scope clear
  ([#51](https://github.com/udibo/oauth2/issues/51))
  ([eeb833d](https://github.com/udibo/oauth2/commit/eeb833d341603aa813c80f14a4502733fa127191))

### BREAKING CHANGES

- an unreachable endpoint or a deadline before response headers now throws
  TemporarilyUnavailableError (not a ServerError subclass) with the original
  error as cause; the BffClient session probe error event changes the same way.
  Callers catching ServerError for these cases should check
  TemporarilyUnavailableError or extensions.error === "temporarily_unavailable".

# [0.6.0](https://github.com/udibo/oauth2/compare/0.5.1...0.6.0) (2026-09-24)

### Bug Fixes

- **client:** report a stalled body as unavailable
  ([#41](https://github.com/udibo/oauth2/issues/41))
  ([4fc7345](https://github.com/udibo/oauth2/commit/4fc73451a20e50b597c4974b1dde7c15a941a9d1)),
  closes [#39](https://github.com/udibo/oauth2/issues/39)

### Features

- **testing:** add the AuthRequestStorage contract
  ([#42](https://github.com/udibo/oauth2/issues/42))
  ([183d9a0](https://github.com/udibo/oauth2/commit/183d9a0b3dccb22710fad6f1087a6827923a78cd)),
  closes [#40](https://github.com/udibo/oauth2/issues/40)

## [0.5.1](https://github.com/udibo/oauth2/compare/0.5.0...0.5.1) (2026-09-23)

### Bug Fixes

- **testing:** name the fake tenant by its product
  ([#38](https://github.com/udibo/oauth2/issues/38))
  ([980346c](https://github.com/udibo/oauth2/commit/980346ce7e2b2aa6b1dbfe31ab3c42ceed9fa465))

# [0.5.0](https://github.com/udibo/oauth2/compare/0.4.1...0.5.0) (2026-09-23)

### Bug Fixes

- **server:** close five audit findings in the authorization server
  ([#37](https://github.com/udibo/oauth2/issues/37))
  ([692706f](https://github.com/udibo/oauth2/commit/692706f3c26c48141b6981e67ee8eda067010a15))

### Features

- **client:** claim auth requests atomically and harden client storage and check
  calls ([#35](https://github.com/udibo/oauth2/issues/35))
  ([91e216d](https://github.com/udibo/oauth2/commit/91e216daffd56d20768a47cbf5a47890d9374989))
- **identity:** close identity hardening gaps
  ([#36](https://github.com/udibo/oauth2/issues/36))
  ([1f2a58a](https://github.com/udibo/oauth2/commit/1f2a58af05988438e90c51ca1beb2a3ecc6bcddb))

## [0.4.1](https://github.com/udibo/oauth2/compare/0.4.0...0.4.1) (2026-09-23)

### Bug Fixes

- **server:** refresh the bundled Public Suffix List to 2026-09-22
  ([#30](https://github.com/udibo/oauth2/issues/30))
  ([176c1e4](https://github.com/udibo/oauth2/commit/176c1e4ad67f2ea93bacbf3b3a611f26e8466d68)),
  closes [#3](https://github.com/udibo/oauth2/issues/3)

# [0.4.0](https://github.com/udibo/oauth2/compare/0.3.1...0.4.0) (2026-09-22)

- fix(react)!: keep focus on pending submit buttons
  ([#29](https://github.com/udibo/oauth2/issues/29))
  ([c036820](https://github.com/udibo/oauth2/commit/c036820af059dafdbac228af589cf83826d7bfe2))

### BREAKING CHANGES

- a pending submit button carries aria-disabled="true" instead of disabled and
  no longer matches :disabled; style [data-oauth2-submit][aria-disabled="true"].

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

## [0.3.1](https://github.com/udibo/oauth2/compare/0.3.0...0.3.1) (2026-09-22)

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
