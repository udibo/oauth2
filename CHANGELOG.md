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
- **Breaking:** refuse a public client that presents a client secret. A client
  registered without a secret now fails authentication with `invalid_client`
  (HTTP 401) when a request carries a non-empty `client_secret`, instead of
  being authenticated as a public client. An empty secret — what a `client_id:`
  Basic header decodes to — still counts as presenting none.
  `runClientServiceContractTests` pins the rule and `MemoryClientService`
  implements it, so a consumer relying on the memory fixture's leniency must
  either stop sending the unissued secret or register the client as
  confidential.
- Enforce single-winner refresh rotation and OTP consumption.
- Keep logout and replacement login authoritative during asynchronous refreshes.
- Reject updates that would restore revoked stateful BFF sessions.
- Use atomic credential replacement for automatic password upgrades.
- Require secure OIDC endpoints and reject redirects during provider fetches.
- Include consumer documentation in the JSR payload and verify standalone,
  Windows-path, and Node compatibility.
