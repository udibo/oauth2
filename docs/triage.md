# Issue Triage Process

How incoming issues are handled once the package has a public tracker. Until
then the same process runs on the internal tracker, so opening up is a switch
flip, not a scramble.

## Intake

Every new issue gets, within **3 business days**:

1. A **type** label: `bug`, `security` (see below), `feature`, `docs`,
   `question`.
2. A **module** label when clear: `server`, `client`, `identity`, `bff`,
   `react`, `examples`.
3. A first response — even if only "reproduced, looking into it" or a request
   for a minimal reproduction.

**Security reports opened publicly** are acknowledged, minimally scrubbed
(details edited out if actively dangerous), and redirected to the
[SECURITY.md](../SECURITY.md) channel. The reporter is thanked, not scolded.

## Priority

| Label | Meaning                                                            | Target                   |
| ----- | ------------------------------------------------------------------ | ------------------------ |
| `p0`  | Security vulnerability or data-loss/auth-bypass bug                | fix ASAP, patch release  |
| `p1`  | Broken documented behavior with no workaround                      | next release             |
| `p2`  | Broken documented behavior with a workaround; significant papercut | scheduled                |
| `p3`  | Nice-to-have, cosmetic, or speculative                             | backlog, may be declined |

## Bug bar

- A deviation from a documented behavior or an RFC MUST is a bug.
- A deviation listed in [known-limitations.md](known-limitations.md) is not a
  bug report — it converts to a feature request against that entry.
- "The safe path was unclear and I misconfigured it" is a **docs bug** and is
  taken seriously; unclear docs around security controls get `p1`.

## Feature requests

Measured against the library's positioning: it serves apps that consume an IdP
or own their single-app auth. Multi-tenancy, org SSO orchestration, plugin
frameworks, and hosted-service concerns are out of scope by design and are
declined with a pointer to that rationale — kindly, and only after understanding
the underlying need (the need may have an in-scope answer).

## Staleness

- `needs-repro` issues with no response for 30 days close with an invitation to
  reopen.
- Declined features close with the reasoning stated; "no" is said explicitly
  rather than by silence.
