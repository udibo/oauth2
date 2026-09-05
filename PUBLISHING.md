# Publishing @udibo/oauth2

The package is prepared for its first JSR release, **0.1.0**. Repository layout
and releases follow Juniper: a root Deno workspace, the published package in
`src/`, examples and templates alongside it, Conventional Commits, and
semantic-release on `main`.

Publishing is disabled until `OAUTH2_RELEASE_ENABLED` is set to `true` in the
standalone repository. Nothing in the preparation tasks publishes a package.

## Validate a release

From this directory, with Deno 2 installed:

```sh
deno ci
deno task check
deno task test:all
```

`check` includes type checking, formatting, lint, all 22 public entrypoints'
JSDoc, documentation examples, links, and a JSR dry run. It first copies the
README, license, security policy, contributor guide, guides and AI documentation
into `src/`. Generated copies are ignored by Git but explicitly included in the
publish manifest. Links in these copies point to the public repository so they
remain usable from the JSR package root.

Run these commands from a clean checkout. The standalone CI workflow also runs
package, script, example and template tests on Linux, macOS and Windows. The npm
artifact is built and consumed under Node in CI to check compatibility; npm
publication is separate and is not required for JSR.

## Configure the first release

1. Create the `oauth2` package in JSR's `@udibo` scope and link it to
   `udibo/oauth2` in the package settings. The release job uses GitHub OIDC; no
   JSR token is stored. See
   [JSR publishing](https://jsr.io/docs/publishing-packages).
2. Configure a `DEPLOY_KEY` with push access for semantic-release, as in
   Juniper. Ensure repository rules allow that identity to push the release
   commit and version tag. Keep ordinary changes behind pull requests.
3. Tag the initial package import `0.0.0` and push that tag. It is a version
   baseline, not a published package. semantic-release otherwise chooses `1.0.0`
   for a repository with no release tags, ignoring the version in
   `src/deno.json`.
4. Enable the repository variable `OAUTH2_RELEASE_ENABLED=true` only after the
   standalone CI passes, JSR linking is complete and push permissions are ready.
5. Merge a `feat:` commit to `main`. From the `0.0.0` baseline, this computes
   `0.1.0`; a `fix:` would compute `0.0.1`.

`scripts/verify-release.ts` rejects any first version other than `0.1.0` before
release preparation, tags or publication. The workflow prints a semantic-release
dry run first. Keep the release gate available as an off switch.

## What the release does

- Validates the proposed first version.
- Generates `CHANGELOG.md` and stamps `src/deno.json` and every example/template
  dependency pin with the release version.
- Stages the complete documentation payload using the same task exercised by the
  publish dry run.
- Commits release files and pushes the release commit/tag during
  semantic-release's prepare/tag phases, then publishes to JSR and creates a
  GitHub release.

A release is not a transaction across Git and JSR. If publication fails after
the release commit or tag was pushed, inspect both Git and JSR before retrying.
If the version already exists on JSR, do not try to overwrite it. If only Git
advanced, resolve that partial release state deliberately before rerunning.

While 0.x, breaking changes increment the minor version under
[the stability policy](docs/stability.md). This differs from Juniper's current
major-version mapping intentionally.

## Verify the published version

In a fresh directory outside either repository:

```sh
deno init
deno add jsr:@udibo/oauth2@0.1.0
```

Use `smoke-consumer/mod.tsx` and its compiler options as a consumer fixture, but
**omit its `links` field** so it resolves the registry package. Check every
subpath with `deno check`, inspect the JSR README and license, and confirm that
test source is absent from the file listing. Then copy a template from the
public repository, install its dependencies, and run its test task.

JSR's [package rules](https://jsr.io/docs/publishing-packages#jsr-package-rules)
and [immutable-version policy](https://jsr.io/docs/immutability) apply to the
uploaded artifact. The local dry run verifies packaging, not account settings,
repository permissions, or the eventual registry upload.
