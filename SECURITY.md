# Security Policy

`@udibo/oauth2` is security-critical software: it implements the OAuth 2.0 /
OpenID Connect protocol surface and password-based identity flows. We take
reports seriously and value the time of security researchers.

> **Status note:** the package is not yet published to a public registry. Until
> it is, the disclosure channel below is drafted and monitored, but the package
> has no external users; the process activates fully at publish.

## Supported versions

| Version        | Supported                        |
| -------------- | -------------------------------- |
| latest `0.x`   | ✅ security fixes                |
| older releases | ❌ upgrade to the latest release |

Pre-1.0, security fixes land on the latest release only. From 1.0 on, the latest
minor of the current major receives fixes, and the final minor of the previous
major receives critical fixes for 6 months after a new major ships.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Email **security@udibo.com** with:

- A description of the vulnerability and the affected module/subpath (e.g.
  `@udibo/oauth2/server`, `@udibo/oauth2/identity`).
- Reproduction steps or a proof of concept.
- The impact you believe it has (what an attacker gains).
- Any suggested remediation, if you have one.

You will receive an acknowledgment within **72 hours** and a substantive
assessment within **7 days**. We ask that you give us **90 days** to remediate
before public disclosure; we will credit you in the release notes unless you
prefer otherwise. We do not operate a paid bounty program.

## Scope

In scope:

- Protocol vulnerabilities (token leakage, redirect validation, PKCE bypass,
  replay, open redirects, header trust).
- Identity-flow vulnerabilities (enumeration oracles, timing oracles, throttle
  or lockout bypass, token-flow weaknesses).
- Cryptographic mistakes (signing, comparison, randomness).

Out of scope:

- Vulnerabilities in example apps' third-party dependencies (report upstream).
- Misconfiguration of an app that consumes the library contrary to documented
  guidance (though we welcome reports that the safe path is unclear — unclear
  docs around a security control are treated as a docs bug with priority).

## Design commitments

- **The protocol defaults are the strict ones.** PKCE is required at both the
  authorize and token endpoints (`requirePKCE: true`), `state` is required,
  identity flows are enumeration-safe and timing-equalized, and the built-in
  password policy runs whether or not you configure one. Relaxing any of these
  is an explicit option you pass.
- **The identity protections are opt-in objects, not defaults.** Rate limiting
  and account lockout do **nothing** unless you construct and pass them:
  `IdentityService` takes `rateLimiter` (and optional per-flow `rateLimiters`),
  `lockout`, and — at the route layer — a `CaptchaProvider` you verify through
  `verifyCaptcha`. An `IdentityService` built without them has no throttling and
  no lockout. This is the single most consequential default in the identity
  layer; treat wiring `rateLimiter` and `lockout` as part of deploying, not as
  hardening you get to later. See
  [Rate limiting, lockout, and password policy](docs/guides/production-deployment.md#rate-limiting-lockout-and-password-policy)
  and the [hardening checklist](docs/guides/hardening-checklist.md).
- **Honest gaps:** deviations from the specs, and defaults that trade safety for
  compatibility, are documented in
  [docs/known-limitations.md](docs/known-limitations.md), not hidden.
- **No silent fixes:** security-relevant fixes are called out in the changelog
  and release notes.
