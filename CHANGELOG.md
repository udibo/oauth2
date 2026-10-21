## [0.36.0](https://github.com/udibo/oauth2/compare/0.35.0...0.36.0) (2026-10-21)

### ⚠ BREAKING CHANGES

* **testing:** `runTokenServiceContractTests` now fails a token store
whose `revokeCode(code, client)` revokes only the tokens saved with the
code. A refresh token rotated from them carries no code, so a replayed
code left the rotated session live. Migration: in `revokeCode`, also
revoke every live member of the rotation families of the code's tokens,
as `revokeFamily` does, after the client check.

Co-authored-by: Claude Opus 5.5 <noreply@anthropic.com>

### Bug Fixes

* **testing:** revoke a replayed code's rotation families ([#152](https://github.com/udibo/oauth2/issues/152)) ([0739f64](https://github.com/udibo/oauth2/commit/0739f6491905d840d853ea6ffa86a411c4231dc3)), closes [#150](https://github.com/udibo/oauth2/issues/150)

## [0.35.0](https://github.com/udibo/oauth2/compare/0.34.0...0.35.0) (2026-10-17)

### ⚠ BREAKING CHANGES

* **server:** `runTokenServiceContractTests` now checks that
`revokeCode(code, client)` revokes nothing for a client other than the
one the code's tokens were issued to, so a custom token store that
ignores the new `client` argument fails it. Migration: honor `client` in
`revokeCode`, or pass `revokeCodeChecksClient: false` to register an
ignored case instead. A client or backend-for-frontend that exchanges
one code twice concurrently, for example two callbacks through
`EncryptedCookieAuthRequestStorage`, which has no atomic `take`, now
signs the user out: the losing exchange revokes the tokens the winner
received. Another client's replay of a spent code now fails with
`invalid code` rather than `code already used`. The new `onCodeReuse`
hook reports `codeHash`, the SHA-256 hex digest of the code, never the
code itself.

### Features

* **server:** gate code replay on the client, add atomic exchange ([#147](https://github.com/udibo/oauth2/issues/147)) ([6cda17b](https://github.com/udibo/oauth2/commit/6cda17b1fafaae30f5172b17ba6cbe0673fdfd51)), closes [udibo/oauth2#149](https://github.com/udibo/oauth2/issues/149) [#104](https://github.com/udibo/oauth2/issues/104) [#146](https://github.com/udibo/oauth2/issues/146) [#142](https://github.com/udibo/oauth2/issues/142) [#104](https://github.com/udibo/oauth2/issues/104)

## [0.34.0](https://github.com/udibo/oauth2/compare/0.33.0...0.34.0) (2026-10-17)

### ⚠ BREAKING CHANGES

* **bff:** `EncryptedCookieSessionStore` and
`EncryptedCookieAuthRequestStorage` now derive their AES-256-GCM keys
with HKDF-SHA-256, each under its own label, instead of
`SHA-256(secret)`. Cookies sealed by an earlier version no longer open.
After upgrading, each signed-in user is signed out once. A sign-in in
flight across the upgrade fails once with `unknown state parameter` and
succeeds when retried. On a rolling deploy, old and new instances can't
read each other's cookies until every instance runs this version.
`EncryptedCookieSessionStore` also refuses a cookie without its
seal-time stamp; it no longer ages one from `updatedAt`. `deriveAesKey`
is removed from `@udibo/oauth2/crypto`; use `deriveSealKey` with a
distinct `info` per purpose. No configuration change is needed. Give
each store instance and each app a secret of its own.

### Bug Fixes

* **bff:** derive each cookie store's key under its own label ([#146](https://github.com/udibo/oauth2/issues/146)) ([38cee6a](https://github.com/udibo/oauth2/commit/38cee6af8588231ed733a789835bebb706c7a7cf)), closes [#113](https://github.com/udibo/oauth2/issues/113)

## [0.33.0](https://github.com/udibo/oauth2/compare/0.32.1...0.33.0) (2026-10-17)

### ⚠ BREAKING CHANGES

* **testing:** `runSessionStoreContractTests` fails a store whose
`withRefreshLock` passes no `RefreshLease`, where it skipped the lease
checks before. Pass a lease, or set `refreshLockNeverExpires: true` when
no holder can lose the lock while its refresh runs.
`runTokenServiceContractTests` fails a token service without `rotate`
whose `save` stores a member of a revoked family as live; record revoked
families in `revokeFamily` and store any later member already revoked.
The family cases in it and in `runTokenRotationContractTests` use a
fresh `crypto.randomUUID()` per family, not `family-1` and `family-2`;
pass `makeFamilyId` if your store needs another format.

### Features

* **testing:** tighten the token and session store contracts ([#144](https://github.com/udibo/oauth2/issues/144)) ([bde0e77](https://github.com/udibo/oauth2/commit/bde0e77cf02bf8d335002b01fab56388c1c45a42)), closes [#119](https://github.com/udibo/oauth2/issues/119) [#121](https://github.com/udibo/oauth2/issues/121) [#143](https://github.com/udibo/oauth2/issues/143)

## [0.32.1](https://github.com/udibo/oauth2/compare/0.32.0...0.32.1) (2026-10-17)

### Bug Fixes

* **react:** back off renewals and let logout beat RequireAuth ([#145](https://github.com/udibo/oauth2/issues/145)) ([36f55d3](https://github.com/udibo/oauth2/commit/36f55d3c06f138f21df33d60388a23b08844aec4)), closes [#114](https://github.com/udibo/oauth2/issues/114) [#86](https://github.com/udibo/oauth2/issues/86)

## [0.32.0](https://github.com/udibo/oauth2/compare/0.31.0...0.32.0) (2026-10-16)

### Features

* **bff:** check auth_time against the recorded max_age ([#141](https://github.com/udibo/oauth2/issues/141)) ([bac1c4b](https://github.com/udibo/oauth2/commit/bac1c4bc8b9052bc148bc300e96fc3f50bf8ab6a)), closes [#140](https://github.com/udibo/oauth2/issues/140)

## [0.31.0](https://github.com/udibo/oauth2/compare/0.30.0...0.31.0) (2026-10-16)

### Features

* **server:** let the token store judge the replay grace ([#135](https://github.com/udibo/oauth2/issues/135)) ([8dd1a86](https://github.com/udibo/oauth2/commit/8dd1a867643e69157d8c24bb12a3472b3294b267)), closes [#111](https://github.com/udibo/oauth2/issues/111) [#116](https://github.com/udibo/oauth2/issues/116) [#124](https://github.com/udibo/oauth2/issues/124)

## [0.30.0](https://github.com/udibo/oauth2/compare/0.29.0...0.30.0) (2026-10-16)

### ⚠ BREAKING CHANGES

* **server:** `JwksTokenReader` refuses a JWT access token that lacks
`sub`, `iat` or `jti`, or carries one with the wrong type (`sub` and
`jti` must be non-empty strings, `iat` a number), as RFC 9068 §2.2
requires. `JwtAccessTokenClaims` now types `sub` and `iat` as required.
Migration: make sure your issuer emits these claims
(`createJwtAccessTokenGenerator` always has). For an issuer that names
its token identifier differently, set `tokenIdClaim` (for example
`tokenIdClaim: "uti"` for Microsoft Entra ID).

## Closes

Nothing. No issue in this repository tracks it.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

### Bug Fixes

* **server:** require RFC 9068 claims in JwksTokenReader ([#139](https://github.com/udibo/oauth2/issues/139)) ([53add29](https://github.com/udibo/oauth2/commit/53add29e39ec774d70af6b39351cd0eceb57dd4f))

## [0.29.0](https://github.com/udibo/oauth2/compare/0.28.0...0.29.0) (2026-10-16)

### ⚠ BREAKING CHANGES

* **server:** a request that combines HTTP Basic with a body
`client_secret` or `client_assertion`, or a body `client_secret` with a
`client_assertion`, is refused with `400 invalid_request` instead of
authenticating by the Basic header. A body `client_id` sent with Basic
credentials must name the same client, and a malformed Basic header is
answered with `401 invalid_client` even when the body names a client.
Migration: configure each client to send its credentials by one method
only, either HTTP Basic (`client_secret_basic`) or `client_id` and
`client_secret` in the body (`client_secret_post`).

## Closes

Nothing. No issue in this repository tracks it.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

### Bug Fixes

* **server:** refuse more than one client auth method ([#137](https://github.com/udibo/oauth2/issues/137)) ([267d9e3](https://github.com/udibo/oauth2/commit/267d9e31c9a377de7c9e4da1bae05e1cc152c49f))

## [0.28.0](https://github.com/udibo/oauth2/compare/0.27.0...0.28.0) (2026-10-16)

### ⚠ BREAKING CHANGES

* `DirectClient.handleAuthorizationCallback` throws the
typed error class for an authorization-response error code that has one
(`AccessDeniedError`, `LoginRequiredError`, `ConsentRequiredError`,
`InteractionRequiredError`, `AccountSelectionRequiredError`, …) instead
of a generic `OAuth2Error`; such an error is no longer `instanceof
OAuth2Error`, and its `status` and `name` are the class's
(`access_denied` is 401, the OIDC codes 400, `temporarily_unavailable`
503). Check `isOAuth2Error(error)` and `error.extensions.error` instead
of `instanceof OAuth2Error`. `HonoBff` throws at construction for a
pinned `max_age` that is not a non-negative integer, and with `max_age`
pinned, `/auth/callback` fails with `login_required` when the ID token's
`auth_time` is missing, more than 60 seconds in the future, or older
than `max_age` plus 60 seconds, or when `scope` is in `forwardedParams`
and the token response has no ID token.

## Testing

- `pnpm check` passes. `pnpm test --maxWorkers=6`: 139 files, 3701
passed, 14 skipped.
- Every new test was run against the unfixed code first:
- `direct-client.test.ts`: four callback cases and four token-endpoint
cases. All 8 failed at `instanceof`.
- `bff.test.ts`, "ID token auth_time against a pinned max_age": 8 of the
refusal tests failed with `302` where they expect `400`, and the
construction test failed with "not to be reached". The guards passed
before and after: within `max_age`, no pinned `max_age`, no ID token.
- Example `main.test.ts` and template `auth.test.ts`, "prompt and
max_age on the embedded authorization server": all 4 failed in each. The
`prompt=login` tests landed on `/auth/callback` (`login_required`)
instead of `/login`, and the `max_age` test got no code.
- Security-review follow-ups, each checked against a mutation:
- The missing ID token with a forwarded `scope` is refused. Reverting
the condition to `idToken` alone fails `refuses a missing ID token when
the browser chooses the scope`.
- With two spellings pinned, the stricter value wins. Swapping
`Math.min` for `Math.max` fails `checks the strictest max_age when two
spellings are pinned`.
- Prototype codes stay generic: `?error=constructor`, `__proto__`,
`toString` and `hasOwnProperty` give a generic `OAuth2Error` with status
500. Dropping the `Object.hasOwn` guard fails all 4.
- The future clock-skew allowance is pinned. An `auth_time` 50 seconds
ahead of the BFF is accepted, and dropping the allowance (`age < 0`)
fails `allows an auth_time up to a minute ahead of the BFF's clock`.
- Seeded mutations, each killed by the named test:
  - Skew allowance removed or doubled.
  - Future check removed.
  - `max_age=0` given an age limit.
  - Exact-case name match.
  - Check removed (8 failures).
  - Construction validation removed.
  - Callback errors left untyped (4 failures).
  - `login_required` map entry removed (2 failures).
- In the example and in the template: any-request match (2 failures),
unbounded window, `auth_time` dropped.

## Not in this PR

- The `claims` request parameter. It needs request parsing and
validation, persistence on the authorization code and token records, a
`userClaims` signature that receives the requested claims, the UserInfo
and ID-token paths, and the discovery flag. That's too large for this

### Features

* check auth_time for a pinned max_age and type OIDC errors ([#138](https://github.com/udibo/oauth2/issues/138)) ([eb5850a](https://github.com/udibo/oauth2/commit/eb5850aa6f5fb2bc4de093554d61a219b3be6a95)), closes [#132](https://github.com/udibo/oauth2/issues/132) [#130](https://github.com/udibo/oauth2/issues/130) [#132](https://github.com/udibo/oauth2/issues/132) [#134](https://github.com/udibo/oauth2/issues/134) [#140](https://github.com/udibo/oauth2/issues/140) [#134](https://github.com/udibo/oauth2/issues/134)
* **identity:** check iss in external sign-in callbacks ([#136](https://github.com/udibo/oauth2/issues/136)) ([b1a910e](https://github.com/udibo/oauth2/commit/b1a910ea2500467cc6dbcbcd4e1231405f9b5908)), closes [#130](https://github.com/udibo/oauth2/issues/130) [#130](https://github.com/udibo/oauth2/issues/130) [#133](https://github.com/udibo/oauth2/issues/133)

## [0.27.0](https://github.com/udibo/oauth2/compare/0.26.0...0.27.0) (2026-10-16)

### ⚠ BREAKING CHANGES

* **server:** the authorize endpoint now enforces OpenID Connect
authentication controls it used to ignore. prompt=login and max_age=0
answer login_required unless authenticateUser returns reauthenticated:
true (true only when the user signed in again for this request). Any
max_age answers login_required when the returned authenticationContext
has no auth_time (even after a re-authentication), when auth_time is
more than 60 seconds ahead of the server clock, or, for max_age above
zero, when auth_time is older than max_age (also after a
re-authentication). Use satisfiesAuthenticationRequest(authentication,
result) in authenticateUser to redirect to login instead. prompt=none
turns a login or consent Response into login_required or
consent_required. prompt=consent with no handleConsent answers
consent_required. prompt values other than none, login and consent are
refused with invalid_request unless listed in the new
promptValuesSupported option. A repeated or malformed prompt, max_age or
acr_values is invalid_request. The ID token's auth_time and acr now come
from the recorded authenticationContext, present exactly when it has
them, whatever userClaims returns.
createMemoryAuthorizationServer().authorize() with its default user now
gives login_required for prompt=login and for any max_age, and
consent_required for prompt=consent without handleConsent; pass an
authenticateUser that reports auth_time and reauthenticated, and a
handleConsent, to drive those flows.
🤖 Generated with [Claude Code](https://claude.com/claude-code)

### Features

* **server:** enforce prompt, max_age and acr_values ([#132](https://github.com/udibo/oauth2/issues/132)) ([085d6b3](https://github.com/udibo/oauth2/commit/085d6b39aefd9268b90fe6c92779ac81f360f4c6)), closes [#130](https://github.com/udibo/oauth2/issues/130) [#129](https://github.com/udibo/oauth2/issues/129)

## [0.26.0](https://github.com/udibo/oauth2/compare/0.25.0...0.26.0) (2026-10-16)

### ⚠ BREAKING CHANGES

* DirectClient (with `issuer`) and HonoBff refuse an
authorization response whose `iss` is not the discovered issuer, or that
omits `iss` when the server advertises
`authorization_response_iss_parameter_supported`. If your authorization
endpoint is served from a host whose issuer differs from the one clients
discover, pass that origin through `login({ origin })` /
`resolveOrigin`, or give the server one issuer for every host.

## Testing

- Rebased on main with #131. `pnpm check` passes, and `pnpm test
--maxWorkers=6` passes: 138 files, 3592 tests.
- Security-review follow-up (L1): `keeps the discovery endpoint's own
error out of the callback response` points discovery at a 404 OAuth JSON
body containing a sentinel. It failed against the previous head
(`not_found` plus the sentinel came back), including under an
`exposedMessage` → `message` mutation. It now gets `server_error` and
the exact fixed description. Two seeded mutations were also killed:
treating every error as a refusal, and dropping the
`temporarily_unavailable` mapping. The new
`handleAuthorizationCallback(…, { origin })` tests failed before the
origin was threaded through.
- New tests in `authorization-server.test.ts`, `direct-client.test.ts`
and `bff.test.ts` (each in an "RFC 9207" block). Before the change,
every server, client and BFF test that asserts the new behavior failed
at its assertion. The guard tests passed throughout: missing `iss`
accepted when not advertised, endpoints-mode clients, and no issuer
resolved.
- Seeded mutations, each killed by named tests: error redirect without
`iss`, metadata flag dropped, any `iss` accepted, missing `iss`
accepted, duplicates accepted, origin retargeting dropped (client and
BFF), error path unchecked, trailing-slash-tolerant compare, BFF check
removed, BFF origin not passed, no `error` event on refusal.

## Not in this PR

The external sign-in connectors (`oidcProvider`, `oauth2Provider`,
Google, Apple) still don't check the upstream provider's `iss`.
`ExternalProfileInput` carries only the code, so checking it means
widening that seam. This is listed in known limitations as a follow-up.

## Closes

### Features

* send and check iss in authorization responses ([#130](https://github.com/udibo/oauth2/issues/130)) ([b3119e7](https://github.com/udibo/oauth2/commit/b3119e720b65eab6f181c0ba679ba0204fac6ad4)), closes [#128](https://github.com/udibo/oauth2/issues/128)

## [0.25.0](https://github.com/udibo/oauth2/compare/0.24.0...0.25.0) (2026-10-15)

### Features

* **server:** add an atomic rotate capability to the token store ([#123](https://github.com/udibo/oauth2/issues/123)) ([34224ef](https://github.com/udibo/oauth2/commit/34224efe9e0fb79eb359998b857d3dc51f38a5aa)), closes [#119](https://github.com/udibo/oauth2/issues/119) [#119](https://github.com/udibo/oauth2/issues/119) [#104](https://github.com/udibo/oauth2/issues/104) [#122](https://github.com/udibo/oauth2/issues/122)

## [0.24.0](https://github.com/udibo/oauth2/compare/0.23.0...0.24.0) (2026-10-14)

### Features

* **bff:** fence refresh writes on the refresh lock's lease ([#120](https://github.com/udibo/oauth2/issues/120)) ([033cdfe](https://github.com/udibo/oauth2/commit/033cdfea0021f420dac3f077c5ee5eda9acb0bb4)), closes [#105](https://github.com/udibo/oauth2/issues/105) [#105](https://github.com/udibo/oauth2/issues/105) [#109](https://github.com/udibo/oauth2/issues/109) [#110](https://github.com/udibo/oauth2/issues/110) [#111](https://github.com/udibo/oauth2/issues/111) [#116](https://github.com/udibo/oauth2/issues/116) [#118](https://github.com/udibo/oauth2/issues/118) [#117](https://github.com/udibo/oauth2/issues/117)

## [0.23.0](https://github.com/udibo/oauth2/compare/0.22.0...0.23.0) (2026-10-14)

### ⚠ BREAKING CHANGES

* **server:** /revoke given a refresh token that rotation already
replaced now revokes its whole rotation family, including the live
successor and its access tokens, when the token service stamps rotatedAt
in revokeRotated and implements getRevokedRefreshToken and revokeFamily
(as MemoryTokenService does). A client that revokes its previous refresh
token after a successful refresh now ends the session it just renewed:
revoke only the current token, at sign-out. A token service that does
not stamp rotatedAt keeps the earlier behavior, and also loses
replayGraceSeconds.
🤖 Generated with [Claude Code](https://claude.com/claude-code)

### Features

* **server:** revoke the family of a rotated-out refresh token ([#116](https://github.com/udibo/oauth2/issues/116)) ([a49582d](https://github.com/udibo/oauth2/commit/a49582df6aef2146a85812032805b05d899030b5)), closes [#115](https://github.com/udibo/oauth2/issues/115)

## [0.22.0](https://github.com/udibo/oauth2/compare/0.21.3...0.22.0) (2026-10-14)

### Features

* **server:** add an opt-in replay grace to the refresh token grant ([#111](https://github.com/udibo/oauth2/issues/111)) ([e474207](https://github.com/udibo/oauth2/commit/e474207e3e7f90c1593996b6102c0c270c5617d7)), closes [#97](https://github.com/udibo/oauth2/issues/97) [#105](https://github.com/udibo/oauth2/issues/105)
* **bff:** answer a pre-refresh cookie with the session that replaced it ([#110](https://github.com/udibo/oauth2/issues/110)) ([6f6e730](https://github.com/udibo/oauth2/commit/6f6e7301936d0ccb478996a5c84e82dd37e1c414)), closes [#105](https://github.com/udibo/oauth2/issues/105) [#109](https://github.com/udibo/oauth2/issues/109) [#97](https://github.com/udibo/oauth2/issues/97) [#105](https://github.com/udibo/oauth2/issues/105)

## [0.21.3](https://github.com/udibo/oauth2/compare/0.21.2...0.21.3) (2026-10-14)

### Bug Fixes

* **bff:** keep the session Set-Cookie on auth error responses ([#109](https://github.com/udibo/oauth2/issues/109)) ([5ea3693](https://github.com/udibo/oauth2/commit/5ea36934cafddcf38d47c5ce96487bb0d4621ff9)), closes [#108](https://github.com/udibo/oauth2/issues/108)

## [0.21.2](https://github.com/udibo/oauth2/compare/0.21.1...0.21.2) (2026-10-14)

### Bug Fixes

* put a deadline on the connectors' provider reads ([#112](https://github.com/udibo/oauth2/issues/112)) ([ccd445e](https://github.com/udibo/oauth2/commit/ccd445e41f2d7a11be8fde2348babafddc96f9d7)), closes [#106](https://github.com/udibo/oauth2/issues/106) [#107](https://github.com/udibo/oauth2/issues/107)

## [0.21.1](https://github.com/udibo/oauth2/compare/0.21.0...0.21.1) (2026-10-14)

### Bug Fixes

* **bff:** refresh a session once across instances sharing a store ([#105](https://github.com/udibo/oauth2/issues/105)) ([33e90de](https://github.com/udibo/oauth2/commit/33e90de9265c7bdb9b9ae315078dfeb81cb38b8b)), closes [#97](https://github.com/udibo/oauth2/issues/97)

## [0.21.0](https://github.com/udibo/oauth2/compare/0.20.0...0.21.0) (2026-10-14)

### ⚠ BREAKING CHANGES

* `JwksTokenReader` refuses a discovery document or JWKS
over 256 KiB, `IntrospectionTokenReader` refuses an introspection
response over 64 KiB, and `breachedPasswordValidator` treats a range
response over 1 MiB as unavailable. Set `maxResponseBytes` to raise any
of these caps. The external connectors refuse profile, UserInfo and
Apple JWKS responses over 64 KiB, and `udibo-oauth2 idp dev` answers 413
to a body over 64 KiB.

## Tradeoffs

- The connectors get no option. Their token exchange already uses a
fixed 64 KiB cap, and an option for profile reads alone would be
inconsistent with it.
- No separate key-count limit on the JWKS. The byte cap bounds the
count, and keys are imported lazily.

## Closes

### Bug Fixes

* cap the responses the package reads from servers it calls ([#106](https://github.com/udibo/oauth2/issues/106)) ([7892c47](https://github.com/udibo/oauth2/commit/7892c47d91a420aceb356b433946039ef1af480c)), closes [#90](https://github.com/udibo/oauth2/issues/90) [#52](https://github.com/udibo/oauth2/issues/52)

## [0.20.0](https://github.com/udibo/oauth2/compare/0.19.0...0.20.0) (2026-10-14)

### ⚠ BREAKING CHANGES

* **server:** `realm` must be printable ASCII. A realm with any other
character, including Latin-1 letters such as `"Café"` that the header
used to carry, now makes the `ResourceServer` / `AuthorizationServer`
constructor (and the `realm` setter) throw a `TypeError`. Pass an ASCII
form of the name instead. `realm` is now an accessor, so a subclass that
redeclares it as a field must use an accessor too.

## Verification

- New tests in `src/server/resource-server.test.ts`,
`src/adapters/hono/resource-server.test.ts` and
`src/server/endpoint-error-format.test.ts`, run against `main` first: 26
failed. Hono `protect()` with a reader message outside Latin-1 answered
`500` (expected `401`); core `handleAuthError` threw `TypeError: Cannot
convert argument to a ByteString … value of 321`; non-ASCII realms
constructed without error; the `Basic` challenge came out as `Basic
realm="Acme "Prod" \ API"`.
- With the fix those pass; each asserts `401`, the exact challenge, and
the full message in the oauth2 and problem-details bodies.
- Review follow-up tests, red at the previous head (6 failed):
`handleAuthError(new InvalidTokenError("db row 42 for tenant acme-secret
missing", { expose: false }))` put that text in the header while the
body was generic; `{ exposedMessage: "token rejected" }` and an
`error_description` extension were ignored by the header; `files:wrïte
files:read` advertised `scope="files:read"`. All pass now.
- Seeded mutation: dropping the `u` flag from the description pattern
(an emoji becomes `??`) fails 3 tests.
- `pnpm check` and `pnpm test` (132 files, 3375 tests) pass on Node 26.

## Risk

**Door:** one-way once released (published package, breaking for
non-ASCII realms). The change touches only how the challenge header is
built and what `realm` accepts; bodies, status codes and error codes are
unchanged. The header now discloses no more than the body does.

## Tradeoffs

- Sanitizing the realm too, instead of rejecting it, was rejected: a
silently rewritten realm is a configuration surprise, and a startup
error points at the line to fix.
- Latin-1 (obs-text) realms were not kept: RFC 9110 treats obs-text as
opaque and clients decode it inconsistently.

## Closes

### Bug Fixes

* **server:** keep WWW-Authenticate challenges in the header charset ([#103](https://github.com/udibo/oauth2/issues/103)) ([b2de5cf](https://github.com/udibo/oauth2/commit/b2de5cfa06fb38208391cf60b138f743b3fda045)), closes [#54](https://github.com/udibo/oauth2/issues/54)

## [0.19.0](https://github.com/udibo/oauth2/compare/0.18.0...0.19.0) (2026-10-13)

### ⚠ BREAKING CHANGES

* **server:** `errorFormat` now governs only protected-resource
refusals (`protect()`, `handleAuthError`, `createErrorResponse` and
UserInfo). An authorization server's OAuth endpoints always answer
errors as RFC 6749 §5.2 JSON (`{ error, error_description, error_uri }`
as `application/json`), even with `errorFormat: "problem-details"`. A
client that parsed problem details (`status`, `title`, `detail`) from
those endpoints reads `error` and `error_description` instead.
`toOAuth2Error` no longer copies an error's `type` into
`extensions.error_uri`, so a problem-details body carries the URI in
`type` alone; read `type` there. The RFC 6749 format still emits
`error_uri` from `type`. Servers that used the default `"oauth2"` format
see no change.

## Changes

- `src/server/_error-response.ts` (internal): the RFC 6749 serializer
that was `ResourceServer`'s private `#createOAuth2ErrorResponse`, plus
the header copy. Both servers now share it.
- `ResourceServer.createErrorResponse` produces the same output as
before.
- `AuthorizationServer`: the ten endpoint error sites go through a
private `#handleEndpointError`. It normalizes the error, runs the
endpoint's prepare callback (`Cache-Control: no-store`, `Pragma:
no-cache`, and `WWW-Authenticate: Basic realm=…` on a client-auth 401),
honours `throwOnError`, and serializes in the RFC format. UserInfo still
uses `handleAuthError`.
- `errorFormat` JSDoc, the provider guide (new _Error responses_
section), protect-an-api and known limitations now describe the narrower
scope. `llms-full.txt` is regenerated.
- They also correct the description of the problem-details body for
protected-resource refusals. The old JSDoc said
`detail`/`error_description` and `type`/`error_uri` carry the same
values. The body holds `status`, `title`, `detail`, `type` when set,
`error` and extensions such as `requiredScope`. The `WWW-Authenticate`
challenge carries `error` and `error_description`.
- `toOAuth2Error` keeps mirroring `extensions.error_uri` into `type`,
but no longer mirrors `type` into `extensions.error_uri`. Its JSDoc is
updated. Two existing `resource-server.test.ts` cases pinned that
mirror: one asserted the error was mutated, one asserted `error_uri` in
a problem body. I changed both deliberately to the new contract and
renamed them for the rule they now pin.
- `protocol-parameters.test.ts`: the "keeps problem details … on
malformed forms" cases asserted the old contract. They now assert the
RFC format with the no-store headers under `errorFormat:
"problem-details"`.

## Testing

- `src/server/endpoint-error-format.test.ts` runs on the core and Hono
transports. Every endpoint error is tested under both `errorFormat`
values, for `application/json;charset=UTF-8`, status, `error`,
`error_description`, no problem members, and the expected headers. The
response is also asserted identical across the two values.
- It includes a metadata error (resolve throws), a JWKS key-provider
failure, and wrong-`Basic` cases on token and revocation that assert
`WWW-Authenticate: Basic realm="Service"`.
  - Neither 500 leaks its internal message.
- The UserInfo and `handleAuthError` cases assert
`application/problem+json` under `problem-details` and RFC JSON under
`oauth2`.
- Red on `main`: all 24 problem-details endpoint cases failed with
`expected 'application/problem+json' to be
'application/json;charset=UTF-8'`. All 24 "identical under either
errorFormat" cases failed too. The 32 oauth2-format and bearer cases
passed.
- Seeded mutations, each restored afterwards:
- Metadata site back to `handleError`: only the 4 metadata cases failed.
- JWKS provider-failure site back to `handleError`: only the 4
JWKS-failure cases failed.
- Token or revocation prepare removed: that endpoint's 8 cases failed on
`no-store`.
- Basic challenge header renamed: the 8 wrong-`Basic` cases failed on
`WWW-Authenticate`.
- Protected-resource refusal bodies are pinned per format. Under
problem-details, `invalid_token`, `insufficient_scope` (plus
`requiredScope`) and missing-credentials refusals carry exactly
`status`, `title`, `detail` and `error`. Under oauth2 they carry exactly
`error` and `error_description`. `error_description` and `error_uri`
appear only when set as extensions. The challenge carries
`error_description` under both formats. A refusal with `type` set keeps
the URI in `type` alone, with no `error_uri` and no mutation. That case
was red before the `toOAuth2Error` change, with `"error_uri" in body`
true. A typed endpoint error still answers `{ error, error_description,
error_uri }`, with `error_uri` taken from `type`. Making the
problem-details path copy the message into `error_description` turned
the three member-set cases red.
- `pnpm check` passed. `pnpm test` passed: 132 files, 3338 tests.

## Related Issues

None.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-authored-by: Claude Opus 5.5 <noreply@anthropic.com>

### Features

* **server:** answer OAuth endpoint errors in the RFC 6749 format ([#102](https://github.com/udibo/oauth2/issues/102)) ([c1e8bd5](https://github.com/udibo/oauth2/commit/c1e8bd5240a9e513c22fc453c867274271b61465))

## [0.18.0](https://github.com/udibo/oauth2/compare/0.17.1...0.18.0) (2026-10-13)

### ⚠ BREAKING CHANGES

* `AccountLockout` and `RateLimiter` require `store`.
Pass a `LockoutStore` and a `RateLimitStore` every instance shares, or
`new MemoryLockoutStore()` and `new MemoryRateLimitStore()` for the old
single-process behavior. `MemoryLockoutStore` now forgets an account's
failures 24 hours after the last one (`ttlMs`) and holds at most 10,000
records (`maxEntries`). Outside a browser, a `DirectClient` that signs
users in or runs the device flow requires `authRequestStorage` (on the
client or per call) and `refreshTokenStorage`; pass `new
MemoryAuthRequestStorage()` and `new MemoryRefreshTokenStorage()` for
the old single-process behavior. Client-credentials use needs neither.
Web and service workers have no `document`, so they count as outside a
browser and must pass these stores too.

### Features

* require the lockout, rate-limit and server-side client stores ([#101](https://github.com/udibo/oauth2/issues/101)) ([6494148](https://github.com/udibo/oauth2/commit/6494148a1e8960fa020ffe2e360def15ad868072)), closes [#94](https://github.com/udibo/oauth2/issues/94) [#94](https://github.com/udibo/oauth2/issues/94) [#95](https://github.com/udibo/oauth2/issues/95) [#96](https://github.com/udibo/oauth2/issues/96) [#96](https://github.com/udibo/oauth2/issues/96) [#99](https://github.com/udibo/oauth2/issues/99) [#97](https://github.com/udibo/oauth2/issues/97) [#94](https://github.com/udibo/oauth2/issues/94) [#95](https://github.com/udibo/oauth2/issues/95) [#96](https://github.com/udibo/oauth2/issues/96)

## [0.17.1](https://github.com/udibo/oauth2/compare/0.17.0...0.17.1) (2026-10-13)

### Bug Fixes

* use the RFC 7638 thumbprint as the kid of a kid-less signing key ([#100](https://github.com/udibo/oauth2/issues/100)) ([f5b5f88](https://github.com/udibo/oauth2/commit/f5b5f88c7a27a3404879900b04988f63d98e9668)), closes [#99](https://github.com/udibo/oauth2/issues/99) [#98](https://github.com/udibo/oauth2/issues/98)

## [0.17.0](https://github.com/udibo/oauth2/compare/0.16.0...0.17.0) (2026-10-12)

### ⚠ BREAKING CHANGES

* `HonoBffOptions.sessionStore` and
`HonoBffOptions.authRequestStorage` are required, and `HonoBff` no
longer falls back to the client's `authRequestStorage`. For the old
single-process behavior pass `sessionStore: new MemorySessionStore()`
and `authRequestStorage: new MemoryAuthRequestStorageFactory()`. With
more than one instance pass `EncryptedCookieSessionStore` and
`EncryptedCookieAuthRequestStorage` with a secret every instance shares
(sign-out cannot invalidate a copied session cookie before its
`maxAgeMs`), or stores over shared storage when you need revocation. A
`forRequest` that returns no storage now fails the sign-in instead of
falling back. If the `DirectClient` was given its own
`authRequestStorage`, pass it to the BFF as `authRequestStorage: {
forRequest: () => storage }`.

### Features

* require HonoBff's session and auth-request stores ([#99](https://github.com/udibo/oauth2/issues/99)) ([6bcb570](https://github.com/udibo/oauth2/commit/6bcb5709ee6252458c6facb7729fc2f21f22c403)), closes [#94](https://github.com/udibo/oauth2/issues/94) [#95](https://github.com/udibo/oauth2/issues/95) [#96](https://github.com/udibo/oauth2/issues/96) [#97](https://github.com/udibo/oauth2/issues/97) [#98](https://github.com/udibo/oauth2/issues/98) [#93](https://github.com/udibo/oauth2/issues/93)

## [0.16.0](https://github.com/udibo/oauth2/compare/0.15.2...0.16.0) (2026-10-12)

### ⚠ BREAKING CHANGES

* `safeReturnTo`, `HonoBff` and `loginContinuation` cap
`return_to` at 2048 UTF-16 code units by default (`maxReturnToLength` /
`maxLength` to change it); `MemoryAuthRequestStorage` holds at most 1000
records (`maxEntries`); `EncryptedCookieAuthRequestStorage` rejects a
`maxPending` that is not a positive integer; with `rpInitiatedLogout`, a
configured `redirectUri` and no `resolveOrigin`,
`post_logout_redirect_uri` uses the `redirectUri`'s origin instead of
the request's, so a BFF serving several hosts needs `resolveOrigin` or
`deriveRedirectUri`.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

### Bug Fixes

* bound pending sign-ins and use the app origin behind TLS proxies ([#92](https://github.com/udibo/oauth2/issues/92)) ([5ec0376](https://github.com/udibo/oauth2/commit/5ec0376e385e3400a4e302d0304704b79a4293d6)), closes [#91](https://github.com/udibo/oauth2/issues/91)

## [0.15.2](https://github.com/udibo/oauth2/compare/0.15.1...0.15.2) (2026-10-12)

### Bug Fixes

* cap the body reads the resource server and identity routes make before authenticating ([#90](https://github.com/udibo/oauth2/issues/90)) ([050c345](https://github.com/udibo/oauth2/commit/050c34585ff468c8254c70c3f915753c6cc5fb5d))

## [0.15.1](https://github.com/udibo/oauth2/compare/0.15.0...0.15.1) (2026-10-12)

### Bug Fixes

* rebuild the request attachToken hands on from its parts ([#89](https://github.com/udibo/oauth2/issues/89)) ([f44d48c](https://github.com/udibo/oauth2/commit/f44d48c10f0ee1a3d71a8077a26f9676b285405c))

## [0.15.0](https://github.com/udibo/oauth2/compare/0.14.1...0.15.0) (2026-10-10)

### Features

* run on Node and publish to npm and JSR from one TypeScript source ([ec64cc5](https://github.com/udibo/oauth2/commit/ec64cc546f3e093c1fe1b5d87fd24c0e8614144f))

### Bug Fixes

* **release:** push the release commit over the deploy key's SSH remote ([#88](https://github.com/udibo/oauth2/issues/88)) ([1744d2f](https://github.com/udibo/oauth2/commit/1744d2fce3a007a0502edc20c653fbebc57b3b4f))

## [0.14.1](https://github.com/udibo/oauth2/compare/0.14.0...0.14.1) (2026-10-09)

### Bug Fixes

- **bff:** destroy the session a new sign-in replaces
  ([#85](https://github.com/udibo/oauth2/issues/85))
  ([224995c](https://github.com/udibo/oauth2/commit/224995cd0b324c6601a0f8b025018747e4ae0a01))

## [0.14.0](https://github.com/udibo/oauth2/compare/0.13.0...0.14.0) (2026-10-07)

### ⚠ BREAKING CHANGES

- Login sessions follow the browser, not `signInAs`. Repeated authorization
  requests after one `signInAs` no longer share a session; each starts its own
  unless it sends back the session cookie the tenant set, so a test that relied
  on a second sign-in revoking the first credential must carry that cookie.
  Conversely, calling `signInAs` again no longer starts a new browser: a browser
  that carries the cookie continues its session for the same person, so a test
  modelling two devices needs two cookie jars (browser contexts). Revoking
  someone's last accepted role in an organization through
  `DELETE
…/members/:userId/:role` now also withdraws their pending memberships
  and unaccepted invitations there and drops the permissions `addMember` seeded,
  so a later accept of such an offer answers `invalid` and rejoining restores
  nothing. `TenantContractFixture` requires a new `addRole(permissions)` hook
  that defines a tenant-wide role and returns its id.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

### Features

- mirror member roles and per-sign-in sessions in the fake tenant
  ([#84](https://github.com/udibo/oauth2/issues/84))
  ([e94a8d7](https://github.com/udibo/oauth2/commit/e94a8d7e1cc602e0c0b85edee3cc6eae9c27f472))

## [0.13.0](https://github.com/udibo/oauth2/compare/0.12.2...0.13.0) (2026-10-07)

### ⚠ BREAKING CHANGES

- **server:** `ClientCredentialsGrant` refuses a token request that presents no
  client secret with 401 `invalid_client`. Register machine clients as
  confidential and authenticate them with their client secret, by HTTP Basic or
  `client_secret` in the body. A client service written before 0.9.2 must pass
  `runClientServiceContractTests`, or `client_credentials` is not limited to
  confidential clients.

### Bug Fixes

- **server:** admit only confidential clients to client_credentials
  ([#83](https://github.com/udibo/oauth2/issues/83))
  ([638123e](https://github.com/udibo/oauth2/commit/638123eb53de8e3024428a777489a283996b66c1))

## [0.12.2](https://github.com/udibo/oauth2/compare/0.12.1...0.12.2) (2026-10-03)

### Bug Fixes

- use placeholders in example commands
  ([#80](https://github.com/udibo/oauth2/issues/80))
  ([d359857](https://github.com/udibo/oauth2/commit/d3598576b54121428f8763f584895b98334d8576)),
  closes [#79](https://github.com/udibo/oauth2/issues/79)

## [0.12.1](https://github.com/udibo/oauth2/compare/0.12.0...0.12.1) (2026-10-03)

### Bug Fixes

- reject duplicate singleton form parameters
  ([#70](https://github.com/udibo/oauth2/issues/70))
  ([5b0a05f](https://github.com/udibo/oauth2/commit/5b0a05f72c904909cf3c6e42246bbe484e5c453b)),
  closes [#69](https://github.com/udibo/oauth2/issues/69)

# [0.12.0](https://github.com/udibo/oauth2/compare/0.11.1...0.12.0) (2026-10-03)

- fix!: validate finite clock skew
  ([#68](https://github.com/udibo/oauth2/issues/68))
  ([a817697](https://github.com/udibo/oauth2/commit/a817697306f5a0d686334c86ec92dbfa1796d2b0)),
  closes [#66](https://github.com/udibo/oauth2/issues/66)

### BREAKING CHANGES

- `ResourceServer.clockSkewSeconds` is now an accessor. Subclasses must
  configure it through constructor options or assignment rather than redeclaring
  a class field; reflection that expects an own property must read it directly.
  Non-finite, negative, or millisecond-overflowing skew is rejected at
  construction and on reassignment.

## Closes

## [0.11.1](https://github.com/udibo/oauth2/compare/0.11.0...0.11.1) (2026-10-03)

### Bug Fixes

- **ci:** reject private release references
  ([#67](https://github.com/udibo/oauth2/issues/67))
  ([b0cbbb9](https://github.com/udibo/oauth2/commit/b0cbbb9ec050e335b8a049bd779a8f68e2fa63ae)),
  closes [#24](https://github.com/udibo/oauth2/issues/24)

# [0.11.0](https://github.com/udibo/oauth2/compare/0.10.0...0.11.0) (2026-10-02)

### Features

- **testing:** add identity store contracts
  ([#65](https://github.com/udibo/oauth2/issues/65))
  ([4d9d7ad](https://github.com/udibo/oauth2/commit/4d9d7ade9a5ec28989e6708b42ac0805a0632e15))

# [0.10.0](https://github.com/udibo/oauth2/compare/0.9.2...0.10.0) (2026-10-02)

- feat!: add machine clients to the fake tenant
  ([#60](https://github.com/udibo/oauth2/issues/60))
  ([5c01bfe](https://github.com/udibo/oauth2/commit/5c01bfe86a9ad7795575f594d874f15edc383c5b))

### BREAKING CHANGES

- the fake tenant's introspection endpoint answers `{
active: false }` to a
  public client, and to a confidential client asking about a token issued to
  another client. A `client_credentials` request from a client registered
  without a secret answers 401 `invalid_client`. Fixtures passed to
  `runTenantContractTests` must implement
  `TenantContractFixture.addMachineClient`, which registers a
  `client_credentials` application with a scopes allowlist,
  administrator-assigned permissions and an optional `confidential` flag. It
  returns the application's id and, when confidential, its secret;
  `TenantContractClient.secret` is optional.

## [0.9.2](https://github.com/udibo/oauth2/compare/0.9.1...0.9.2) (2026-10-02)

### Bug Fixes

- **server:** resolve discovery scopes per request
  ([#63](https://github.com/udibo/oauth2/issues/63))
  ([3dde4b8](https://github.com/udibo/oauth2/commit/3dde4b8066bafd9bb64b846a5ea3368eb9758531))

## [0.9.1](https://github.com/udibo/oauth2/compare/0.9.0...0.9.1) (2026-10-01)

### Bug Fixes

- stop reusing a stalled HTTP/2 connection
  ([#61](https://github.com/udibo/oauth2/issues/61))
  ([3c80f93](https://github.com/udibo/oauth2/commit/3c80f9300aeb76d4d6d1ecbee8dd8c5d56502684))

# [0.9.0](https://github.com/udibo/oauth2/compare/0.8.0...0.9.0) (2026-09-27)

### Features

- **server:** let apps refuse logout redirects
  ([#57](https://github.com/udibo/oauth2/issues/57))
  ([5e1a1df](https://github.com/udibo/oauth2/commit/5e1a1dfc741b530f6f396be964e769e09e0870b0))

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
