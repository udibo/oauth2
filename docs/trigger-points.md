# Extension reference: callbacks and storage contracts

Use this reference when adapting the package to your application's data and
policy. It lists constructor callbacks and storage interfaces, when the package
calls them, and whether their return value or failure can stop a flow. The
exported symbol is the stable API name; the descriptive label is only a
navigation aid.

## How to read the reference

Two properties decide how a trigger point behaves, and every row states both.

- **Control** — what the seam can do to the flow:
  - **blocks** — the seam runs _inside_ the flow and can stop it. It denies by
    return value (`null`, `false`, `{ approved: false }`, an issue string) or by
    throwing; either way the flow does not continue as if nothing happened.
  - **fire-and-forget** — the seam is for a side effect (audit, notification,
    re-render). Its throw is caught and logged, never rethrown, so it _cannot_
    affect the outcome. Use it when you need observability, not a gate.
- **On throw** — what a thrown error actually does at the call site, traced to
  the code, because this is where accidental and deliberate behaviour diverge. A
  **blocks** seam usually surfaces the throw as a specific protocol error; a
  **fire-and-forget** seam swallows it. Rows call out the cases where a throw
  does something surprising.

**Stability.** A trigger-point's export name is public API under
[stability.md](stability.md) — renaming one is a breaking change, and its throw
contract is part of the wire behaviour the servers promise. The **Symbol**
column names the exact export; that name, not the informal trigger-point label,
is the stable identifier.

## Authorization server — `@udibo/oauth2/server`

Seams on `AuthorizationServer` and its grants. Unless noted, a throw from a seam
reached through an endpoint is caught by that endpoint and converted to an RFC
6749 §5.2 error response (or, on the authorize path once the redirect URI is
validated, a redirect to the client with `error=…`).

| Trigger point               | Symbol                                                               | Fires                                                                                      | Required                                               | Control         | On throw                                                                                                                             |
| --------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------ | --------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| introspection-authorization | `canIntrospectToken` (`AuthorizationServerOptions`)                  | After client authentication and live-token lookup, before claims enrichment                | no (omit → all admitted clients may inspect any token) | blocks          | false → inactive response; throw → error response                                                                                    |
| services-resolver           | `resolve` (`AuthorizationServerOptions`)                             | Top of every endpoint, to resolve per-request services                                     | yes                                                    | blocks          | Converted to an error response on token/authorize/revoke/introspect/device, and on the metadata and JWKS discovery endpoints         |
| authenticate                | `AuthenticateUserFn` (`handleAuthorizeRequest` arg)                  | `GET /authorize`, after client/PKCE validation                                             | yes                                                    | blocks          | `null` → `access_denied`; a `Response` short-circuits; an OAuth2 error redirects to the client, other throws → direct error response |
| consent                     | `HandleConsentFn` (`handleAuthorizeRequest` arg)                     | `GET /authorize`, only when the requested scope needs consent                              | no (omit → auto-grant)                                 | blocks          | `{ approved: false }` denies; same redirect/error conversion as authenticate                                                         |
| token-claims                | `userClaims` (`AuthorizationServerOptions`)                          | Assembling id_token and UserInfo claims (never the access token)                           | no                                                     | blocks          | Converted to a token-endpoint / UserInfo error response                                                                              |
| subject                     | `subjectOf` (`AuthorizationServerOptions`)                           | Assembling the `sub` for id_token and UserInfo                                             | no (defaults to `user.id`)                             | blocks          | Converted to a token-endpoint / UserInfo error response                                                                              |
| signing-key                 | `SigningKeyProvider` (`signingKeys`)                                 | `mintIdToken` (`getSigningKey`) and `GET /jwks` (`getPublicJwks`)                          | no (unset → OIDC surface off)                          | blocks          | `getSigningKey` throw → token-endpoint `server_error`; `getPublicJwks` throw → JWKS-endpoint error response                          |
| redirect-guard              | `IsPublicSuffix` (`isPublicSuffix`)                                  | `GET /authorize`, validating a wildcard `redirect_uri`                                     | no (unset → wildcards refused)                         | blocks          | Caught before a redirect URI is chosen → direct error response (bundled impl never throws). Must be sync, no I/O                     |
| challenge-method            | `ChallengeMethods` (`challengeMethods`)                              | PKCE verification during the code→token exchange                                           | no (defaults to `S256`)                                | blocks          | Converted to a token-endpoint error response                                                                                         |
| client-store                | `ClientServiceInterface` (`clientService`)                           | Client lookup/auth on every token/revoke/introspect/device call                            | yes                                                    | blocks          | `undefined` → `invalid_client`; other throws converted to an error response                                                          |
| token-store                 | `TokenServiceInterface` (`tokenService`)                             | Token issuance, refresh, revoke, introspect                                                | yes                                                    | blocks          | Converted to a token-endpoint error response                                                                                         |
| token-reuse                 | `onTokenReuse` (`RefreshTokenGrantOptions`)                          | A rotated-out refresh token is replayed, after the family is revoked                       | no                                                     | fire-and-forget | Isolated: caught and logged, never rethrown, so a throw can't change the `invalid_grant` a replayed token yields                     |
| refresh-cap                 | `refreshTokenFamilyExpiresAt` (`TokenServiceInterface`)              | Refresh-token issuance and rotation                                                        | no (absent → uncapped)                                 | blocks          | A past cap → `invalid_grant`; other throws → token-endpoint error response                                                           |
| accepted-scope              | `acceptedScope` (`TokenServiceInterface`)                            | Scope narrowing during issuance                                                            | yes (on the interface)                                 | blocks          | `false` → `invalid_scope`; other throws converted                                                                                    |
| authorization-code-store    | `AuthorizationCodeServiceInterface` (`authorizationCodeService`)     | Authorize (mint code) and code→token exchange                                              | with the code grant                                    | blocks          | Missing/expired → `invalid_grant`; other throws converted                                                                            |
| device-code-store           | `DeviceAuthorizationServiceInterface` (`deviceAuthorizationService`) | Device-authorization request and polling                                                   | with the device grant                                  | blocks          | RFC 8628 codes (`authorization_pending`, `slow_down`, `expired_token`, …); other throws converted                                    |
| user-authenticator          | `UserServiceInterface` (`userService`)                               | `PasswordGrant.token` — the only MFA-enforcement point for the (deprecated) password grant | with the password grant                                | blocks          | `undefined` → `invalid_grant`; a thrown OAuth2 error surfaces verbatim, other throws → `server_error`                                |
| scope-constructor           | `ScopeConstructor` (`Scope`)                                         | Parsing/comparing scope strings                                                            | no (defaults to `BasicScope`)                          | blocks          | Follows its host flow's conversion path                                                                                              |

## Resource server — `@udibo/oauth2/server/resource`

`authenticate()` does not try/catch its seams; the adapter boundary
(`handleAuthError`) converts what they throw. The readers deliberately keep a
down issuer (`temporarily_unavailable`) distinct from an invalid token
(`invalid_token`).

| Trigger point     | Symbol                                          | Fires                                                  | Required                      | Control | On throw                                                                                   |
| ----------------- | ----------------------------------------------- | ------------------------------------------------------ | ----------------------------- | ------- | ------------------------------------------------------------------------------------------ |
| services-resolver | `resolve` (`ResourceServerOptions`)             | Top of `authenticate()`, after the bearer is extracted | yes                           | blocks  | Propagates to the handler boundary; a non-OAuth2 throw → `server_error`                    |
| token-reader      | `TokenReaderInterface` (`tokenService`)         | `authenticate()` validates the access token            | yes                           | blocks  | `undefined` → `invalid_token`; a reader may throw `temporarily_unavailable`/`server_error` |
| token-owner       | `getClient` / `getUser` (both readers' options) | After a token validates, to resolve client/user        | `getClient` yes, `getUser` no | blocks  | **Not wrapped — a throw propagates out of `getToken` raw** (surfaces as `server_error`)    |
| reader-fetch      | `fetch` (both readers' options)                 | Introspection POST / JWKS + discovery fetch            | no                            | blocks  | Wrapped: transport/5xx → `temporarily_unavailable`, 4xx / bad body → `server_error`        |

## Identity — `@udibo/oauth2/identity`

The identity protections are **opt-in**: `rateLimiter` and `lockout` do nothing
unless you pass them. `passwordPolicy` is not — the policy check runs on every
`signUp` and `resetPassword`, at its 8–256 character defaults when you pass
nothing; the option only tightens it. A throw from a store or hook here
propagates out of the `IdentityService` method you called and up to your route,
unless the row says otherwise.

| Trigger point      | Symbol                                                    | Fires                                                                                | Required                                  | Control                  | On throw                                                                                                                                                                                                                                                                                                                                 |
| ------------------ | --------------------------------------------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| user-store         | `IdentityUserStore<User>` (`users`)                       | Every flow (`create` in `signUp`, `findByIdentifier`/`getCredential` in `signIn`, …) | yes                                       | blocks                   | Propagates and aborts the flow. **Throwing from `create` is today's only pre-registration veto** (see Gaps). `markEmailVerified` runs _before_ the token is consumed, so a throw leaves the verification link retryable                                                                                                                  |
| credential-import  | `LegacyPasswordVerifier` (`legacyVerifiers`)              | `signIn`, when a user has an imported hash but no native credential                  | no                                        | blocks                   | **Fail-closed:** `canVerify`/`verify` throws are caught → verifier skipped / returns `false`; never authenticates, never aborts                                                                                                                                                                                                          |
| delivery           | `DeliveryHooks` (`delivery`)                              | After a verify/reset/unlock/sign-in token or code is minted                          | no (omit a hook → that message disabled)  | blocks (side-effect)     | A throw is caught for every hook, code included: the minted token or code is invalidated (that exact one) and the flow still resolves with its uniform result — no orphaned credential, no mailer-outage enumeration oracle. Emits `delivery.failed`; `invalidated: false` means the cleanup failed too and the credential is still live |
| event              | `IdentityEventHook` (`onEvent`)                           | After every flow outcome                                                             | no                                        | fire-and-forget          | Caught and logged, never rethrown — cannot break the flow (deliberate)                                                                                                                                                                                                                                                                   |
| password-policy    | `PasswordPolicy.validators` (`passwordPolicy`)            | `signUp` and `resetPassword`, before hashing (defaults apply when unset)             | no                                        | blocks                   | Return an issue string to reject (→ `weak_password`); a validator that _throws_ is trapped to `weak_password` too                                                                                                                                                                                                                        |
| rate-limiter       | `RateLimiterLike` (`rateLimiter` / `rateLimiters`)        | Start of each throttled flow (`check`); reset on success                             | no (opt-in)                               | blocks                   | A limit _hit_ under `enforce` → `rate_limited`; a limiter that _throws_ → `rate_limited` under `enforce` (fail closed), logged-and-allowed under `log-only`                                                                                                                                                                              |
| rate-limit-store   | `RateLimitStore`                                          | Backs the built-in `RateLimiter`                                                     | no                                        | blocks                   | Propagates through `RateLimiter.check`/`reset`                                                                                                                                                                                                                                                                                           |
| lockout            | `AccountLockoutLike` (`lockout`)                          | `signIn` (`status`/`recordFailure`), reset on success/reset/unlock                   | no (opt-in)                               | blocks                   | Propagates and aborts the flow; enforcement itself is uniform-`null` (no lockout oracle)                                                                                                                                                                                                                                                 |
| lockout-store      | `LockoutStore`                                            | Backs the built-in `AccountLockout`                                                  | no                                        | blocks                   | Propagates through the `AccountLockoutLike` call sites                                                                                                                                                                                                                                                                                   |
| token-flow-store   | `TokenFlowStore` (via `tokens`)                           | All `request*` / `verify*` / `reset*` / `unlock*` / `consume*` flows                 | required for those flows                  | blocks                   | Propagates and aborts the flow                                                                                                                                                                                                                                                                                                           |
| otp-store          | `OtpStore` (`otp.store`)                                  | `requestSignInCode` / `verifySignInCode`                                             | required for the code flow                | blocks                   | Propagates and aborts the flow                                                                                                                                                                                                                                                                                                           |
| session-revocation | `RevocableSessionService` (`sessions`)                    | `resetPassword`, after the new credential is set                                     | no                                        | blocks (side-effect)     | A throw (after the password change) emits `password_reset.failed` (`session_revocation_failed`), suppresses `password_reset.completed`, and rethrows — the reset is reported failed/retryable, not silently half-complete                                                                                                                |
| session-listing    | `ListableSessionService`                                  | App-driven (a "where you're signed in" screen)                                       | no                                        | n/a (app calls it)       | Propagates to your caller                                                                                                                                                                                                                                                                                                                |
| captcha            | `CaptchaProvider` (via `verifyCaptcha`)                   | App-driven, in your route before `signUp` / `signIn` / the email-sending requests    | no (no provider → unchallenged pass)      | blocks (you enforce it)  | **Never propagates.** `verifyCaptcha` traps a provider throw and returns a decision: `failOpen: true` (default) → `"pass"`, `false` → `"fail"`, both with `degraded: true`. A `{ success: false }` return is a real rejection (`"fail"`, `degraded: false`); reject it with `IdentityError` `captcha_failed` (403)                       |
| identifier-lookup  | `IdentifierLookups<User>` (`createIdentifierResolver`)    | When you call the resolver to classify + look up an identifier                       | each kind optional                        | blocks                   | Propagates to your caller                                                                                                                                                                                                                                                                                                                |
| otp-deliver        | `RequestOtpOptions.onDeliver` (`EmailOtpService.request`) | After the OTP hash is stored, to hand the raw code to transport                      | required for direct `EmailOtpService` use | blocks (side-effect)     | Propagates out of `request`, after the code is stored                                                                                                                                                                                                                                                                                    |
| breach-check       | `breachedPasswordValidator` (`fetch` / `onEvent`)         | The HIBP range lookup a `passwordPolicy` validator runs                              | both optional                             | blocks / fire-and-forget | `fetch` failure caught → fail-open (default) or fail-closed; `onEvent` swallowed. Safe under the no-catch validator call site                                                                                                                                                                                                            |

## External providers — `@udibo/oauth2/identity/external`

`ExternalAuthFlow` is deliberately storage-free and has **no** callback hooks of
its own: `finish()` returns a verified `ExternalProfile` and your app does
find-or-create-user, session start, and rejection _outside_ the flow, in its own
`try`/`catch`. The seams below live on the provider connectors.

| Trigger point     | Symbol                                      | Fires                                                                  | Required                              | Control | On throw                                                                                                         |
| ----------------- | ------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------- |
| external-provider | `ExternalProvider` (`provider`)             | External start (`buildAuthorizationUrl`) and callback (`fetchProfile`) | yes                                   | blocks  | Propagates and aborts start/callback; built-ins throw `ExternalAuthError`                                        |
| profile-mapper    | `OAuth2ProfileMapper` (`mapProfile`)        | External callback, mapping the raw profile                             | with `oauth2Provider`                 | blocks  | A missing/empty `subject` in the _return_ → `provider_error`; a mapper that _throws_ surfaces raw (see Findings) |
| client-secret     | `AppleClientSecretFactory` (`clientSecret`) | Apple callback, signing a fresh client-secret JWT                      | no (defaults to the built-in factory) | blocks  | Not wrapped — a custom factory's throw propagates raw; the default throws `configuration`                        |
| provider-fetch    | `fetch` (every connector config)            | Discovery, token exchange, UserInfo, JWKS                              | no (defaults to `globalThis.fetch`)   | blocks  | Wrapped → `provider_error`; OIDC UserInfo failure is non-fatal (swallowed → `null`)                              |

## MFA — `@udibo/oauth2/identity/mfa`

`MfaService` decides nothing about _when_ to demand a factor — that stays your
app's sign-in policy. It exposes read methods (`enrollmentStatus`, `isEnrolled`)
and a `verify` you call; there is no app-supplied challenge hook to veto (see
Gaps). The app implements one required interface plus the two shared optional
seams.

| Trigger point | Symbol                            | Fires                                              | Required | Control         | On throw                                                                                                                                                    |
| ------------- | --------------------------------- | -------------------------------------------------- | -------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| mfa-store     | `MfaStore` (`store`)              | Enroll, verify, disable, regenerate                | yes      | blocks          | Propagates; `confirmEnrollment` specially rolls back (`clearTotp`) and rethrows if recovery-code persistence fails                                          |
| rate-limiter  | `RateLimiterLike` (`rateLimiter`) | Start of each `verify` (`check`); reset on success | no       | blocks          | A limit _hit_ under `enforce` → `rate_limited`; a limiter that _throws_ → `rate_limited` under `enforce` (fail closed), logged-and-allowed under `log-only` |
| event         | `IdentityEventHook` (`onEvent`)   | `mfa.*` outcomes                                   | no       | fire-and-forget | Swallowed and logged                                                                                                                                        |

## Hono BFF — `@udibo/oauth2/hono/bff`

| Trigger point            | Symbol                                        | Fires                                             | Required                 | Control | On throw                                                                                                 |
| ------------------------ | --------------------------------------------- | ------------------------------------------------- | ------------------------ | ------- | -------------------------------------------------------------------------------------------------------- |
| session-store            | `SessionStore` (`sessionStore`)               | Callback, refresh, session read, logout           | no (defaults to memory)  | blocks  | In `/auth/callback` → `invalid_grant`; in refresh/logout/session paths → propagates to Hono              |
| backchannel-logout-store | `destroyByLogout` (`SessionStore` capability) | `POST /auth/backchannel`                          | with `backchannelLogout` | blocks  | Propagates to Hono (500)                                                                                 |
| resolve-user             | `resolveUser` (`HonoBffOptions`)              | `/auth/callback`, enriching session user claims   | no                       | blocks  | **Relabeled as `invalid_grant` "code exchange failed"** even though it runs post-exchange (see Findings) |
| callback-error           | `onCallbackError` (`HonoBffOptions`)          | `/auth/callback` cannot complete                  | no (default 400 JSON)    | blocks  | **Invoked with no guard — its own throw propagates to Hono (500)** (see Findings)                        |
| resolve-origin           | `resolveOrigin` (`HonoBffOptions`)            | Login/callback/logout, to pick the trusted origin | no                       | blocks  | Login/logout → propagates to Hono; callback → relabeled as `invalid_grant` "code exchange failed"        |
| auth-request-storage     | `authRequestStorage` (`HonoBffOptions`)       | `/auth/login` and `/auth/callback`, per request   | no                       | blocks  | Login → propagates; callback → `invalid_grant`                                                           |
| logout-token-verifier    | `verifyLogoutToken` (`backchannelLogout`)     | `POST /auth/backchannel`, verifying the JWT       | with `backchannelLogout` | blocks  | Throw or `null` → `400 invalid_request` (deliberate "throw-or-null to reject" contract)                  |
| proxy-fetch              | `fetch` (`HonoBffProxyOptions`)               | The upstream call in `bff.proxy`                  | no                       | blocks  | Wrapped → `502` `temporarily_unavailable`                                                                |

## Hono adapters — authorization server & identity

| Trigger point       | Symbol                                        | Fires                                         | Required                                                       | Control | On throw                                                                                 |
| ------------------- | --------------------------------------------- | --------------------------------------------- | -------------------------------------------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| authenticate        | `HonoAuthenticateUserFn` (`authenticateUser`) | `GET /authorize` (Hono adapter)               | yes                                                            | blocks  | Passed through to the core server, which converts it (same contract as the core seam)    |
| consent             | `HonoHandleConsentFn` (`handleConsent`)       | `GET /authorize` after auth (Hono adapter)    | no (omit → auto-grant)                                         | blocks  | Passed through to the core server                                                        |
| post-authentication | `onAuthenticated` (`HonoIdentityOptions`)     | After `signUp`/`signIn`, to mint your session | no, but **required to mount the `/signup` + `/signin` routes** | blocks  | A thrown `IdentityError` → JSON error response; any other throw propagates to Hono (500) |

## Client — `@udibo/oauth2/client`

| Trigger point         | Symbol                                        | Fires                                                                                                                                                                                                                                                                                                 | Required                                                                                    | Control         | On throw                                                                                                           |
| --------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------ |
| event-listener        | `OAuth2ClientEventListener` (`subscribe`)     | Every client state change                                                                                                                                                                                                                                                                             | no                                                                                          | fire-and-forget | **Swallowed** — a synchronous listener throw is isolated so other subscribers still receive the event (deliberate) |
| token-storage         | `TokenStorage` (`tokenStorage`)               | Token read/persist/clear                                                                                                                                                                                                                                                                              | no (defaults to memory)                                                                     | blocks          | Propagates and aborts the calling method                                                                           |
| refresh-token-storage | `RefreshTokenStorage` (`refreshTokenStorage`) | Refresh-token read/persist/clear                                                                                                                                                                                                                                                                      | no (defaults to memory)                                                                     | blocks          | Propagates and aborts the calling method                                                                           |
| auth-request-storage  | `AuthRequestStorage` (`authRequestStorage`)   | `DirectClient.login` / `exchangeAuthorizationCode`                                                                                                                                                                                                                                                    | no (defaults to `SessionStorageAuthRequestStorage` in a browser document, memory elsewhere) | blocks          | Propagates and aborts the calling method                                                                           |
| discovery-cache       | `DiscoveryCache` (`discoveryCache`)           | Every endpoint use of an `issuer` client whose held copy has expired. The client keeps a copy either way: until the `expiresAt` its `resolve` reports when a cache is supplied, or `DEFAULT_DISCOVERY_TTL_MS` (1 h) when one is not — so a cache is read once per entry lifetime, not once per lookup | no                                                                                          | blocks          | Propagates to `discover()`; a rejected load is deliberately not cached                                             |
| client-fetch          | `fetch` (`BaseOptions`)                       | Every outbound HTTP call                                                                                                                                                                                                                                                                              | no (defaults to `globalThis.fetch`)                                                         | blocks          | Mostly propagates; `#fetchMetadata` retries both well-known paths before rethrowing                                |

## React auth forms — `@udibo/oauth2/react/components`

Seams on the headless `useAuthForm` hook and the prebuilt components.

| Trigger point | Symbol                                                   | Fires                                 | Required | Control         | On throw                                                          |
| ------------- | -------------------------------------------------------- | ------------------------------------- | -------- | --------------- | ----------------------------------------------------------------- |
| form-submit   | `AuthSubmitHandler` (`onSubmit`)                         | Form submit, after `validate` passes  | yes      | blocks          | Caught → form-level error (`status: "error"`); does not propagate |
| form-validate | `validate` (`UseAuthFormOptions`)                        | Synchronously at the start of submit  | no       | blocks          | Caught → form-level error (`status: "error"`), like `onSubmit`    |
| form-success  | `onSuccess` (`UseAuthFormOptions`)                       | After a submit with no errors         | no       | fire-and-forget | Caught → `console.error`; deliberately isolated                   |
| social-select | `onSocialSelect` / `socialHref` (`SocialProvidersProps`) | A social button is clicked / rendered | no       | blocks          | Surfaces through React's event/render path                        |

## Known gaps

These responsibilities stay in the application or use a separate API.

- **No dedicated pre-registration veto.** The only way to reject a sign-up on
  something other than the password is to throw from `IdentityUserStore.create`
  (or reject the password with a `passwordPolicy` validator). There is no
  `beforeCreate`/allowlist/domain-restriction seam.
- **No service-layer post-authentication hook.** After `signIn` verifies a
  credential, nothing app-supplied can inspect or veto the success (e.g. force
  MFA, reject a disabled user) — that gating lives in your route.
- **Access-token claims use a separate API.** The authorization server's
  `userClaims` reaches ID tokens and UserInfo. Use
  `createJwtAccessTokenGenerator` and its claims options when your app issues
  JWT access tokens.
- **No MFA-challenge seam in `IdentityService`.** `IdentityService` has zero MFA
  integration; MFA is the separate `@udibo/oauth2/identity/mfa` module, and
  _when_ to demand a factor is your app's decision.

## Failure behavior to account for

- **A signing failure surfaces after the token row is persisted.**
  `tokenService.save` runs before `mintIdToken` / JWT-access-token generation,
  so a signing-key outage returns `server_error` for a token that already
  exists.
- **Inconsistent legacy-credential contract.** A `getLegacyCredential` throw
  aborts sign-in, but a `clearLegacyCredential` throw is swallowed — even though
  the docs tell implementers to provide both together.
- **BFF `resolveUser` / `resolveOrigin` throws are misclassified.** Failures in
  these post-exchange app hooks are relabeled `invalid_grant` "code exchange
  failed" because they sit inside the exchange `try`/`catch`.
- **BFF `onCallbackError` is unguarded.** A throw from the error handler itself
  propagates to Hono (500).
