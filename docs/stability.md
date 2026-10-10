# Stability & Breaking-Change Policy

How `@udibo/oauth2` versions, what counts as breaking, and what users can rely
on. Use this policy to decide when to upgrade and which migration notes to
review.

## Versioning

Releases follow [semantic versioning](https://semver.org/), cut automatically by
semantic-release from Conventional Commits (see
[CONTRIBUTING.md](../CONTRIBUTING.md)). Nobody hand-picks version numbers.

### While 0.x

- A **minor** (`0.X.0`) may contain breaking changes. Every breaking change is
  marked `feat!:`/`fix!:` in the commit, called out in the changelog with a
  migration note, and never lands silently.
- A **patch** (`0.x.Y`) preserves the public API, subject to the security-fix
  policy below.
- This is enforced, not just described: `.releaserc.json` maps
  `{ "breaking": true, "release": "minor" }`, so a `feat!:` commit cuts a minor
  rather than a major, and a packaging test pins that mapping. Moving to 1.0 is
  a deliberate decision, not a side effect of a breaking commit.

### From 1.0

- Breaking changes ship only in **majors**, batched rather than dribbled.
- Anything removed in a major must have been deprecated (documented + JSDoc
  `@deprecated` with the replacement named) for at least one minor beforehand.
- Minors and patches are additive or corrective only.

## Runtime support

The supported runtime is Node.js 22 and later. CI runs the complete test suite
on Node 22, 24, and 26, and smoke-tests the packed npm tarball from a clean
consumer: it type checks every entrypoint under NodeNext resolution and imports
each one. The testing exports (`/testing`, `/testing/contract`,
`/hono/bff/testing`, `/react/testing`) register tests through Vitest, an
optional peer dependency. The `udibo-oauth2` command is Node-only.

Client and React exports are intended for browser use. Server exports belong on
the backend, where client secrets and token storage can remain private. Deno and
Bun have not been verified. See the [runtime table](../README.md#runtime-support)
for the entrypoint groups.

The legacy-password symbols live in `/identity/migration`; `/identity` does not
re-export them. Narrowing a documented runtime target or removing an exported
subpath is a compatibility change.

## What is public API

- Every subpath export listed in `package.json` `exports` (and in `jsr.json`),
  and every symbol those modules export, including their documented types. The
  `udibo-oauth2` command and its subcommands (`oidc keygen`, `idp dev`) are
  public too.
- The **wire behavior** of the servers and adapters: endpoint request/response
  shapes, error codes, and challenge headers are API — a change that breaks a
  conforming OAuth2/OIDC client is a breaking change even if no TypeScript
  signature moved.
- The documented storage/service seams (`ClientServiceInterface`,
  `TokenServiceInterface`, `IdentityUserStore`, `RateLimitStore`, …): **adding a
  required member is breaking**; adding an optional member is not.

Not public API: anything under `src/` not reachable from an export, test
helpers' internals, and the example apps.

## Security exceptions

A security fix may tighten behavior in a patch (e.g. stricter validation of a
malformed input) when the previous behavior was a vulnerability. If a security
fix must break a documented API, it ships as the smallest honest semver bump
with a prominent changelog notice — we do not sit on a vulnerability to wait for
a major.

## What we promise not to do

- Remove or paywall a shipped capability (MFA and core auth stay free — standing
  product commitment).
- Rename exports without a deprecation window (post-1.0).
- Change defaults to something less secure. Defaults only ever tighten, and a
  tightening default is documented as breaking.
