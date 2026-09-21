# Publishing @udibo/oauth2

The package is prepared for its first release, **0.1.0**, published to both JSR
and npm from the same semantic-release run. Repository layout and releases
follow Juniper: a root Deno workspace, the published package in `src/`, examples
and templates alongside it, Conventional Commits, and semantic-release on
`main`.

Publishing is disabled until `OAUTH2_RELEASE_ENABLED` is set to `true` in the
standalone repository. Nothing in the preparation tasks publishes a package.

## Validate a release

From this directory, with Deno 2 installed:

```sh
deno ci
deno task check
deno task test:all
```

`check` includes type checking, formatting, lint, all 23 public entrypoints'
JSDoc, documentation examples, links, and a JSR dry run. It first copies the
README, license, security policy, contributor guide, guides and AI documentation
into `src/`. Generated copies are ignored by Git but explicitly included in the
publish manifest. Links in these copies point to the public repository so they
remain usable from the JSR package root.

Run these commands from a clean checkout. The standalone CI workflow also runs
package, script, example and template tests on Linux, macOS and Windows. The npm
artifact is built and consumed under Node in CI on every run, which is what
keeps the published npm build honest: `deno task npm:build` then
`deno task npm:smoke` installs the packed tarball into `npm-smoke-consumer/` and
proves the Node claims in the README's runtime table.

## Configure the first release

1. Create the `oauth2` package in JSR's `@udibo` scope and link it to
   `udibo/oauth2` in the package settings. The release job uses GitHub OIDC; no
   JSR token is stored. See
   [JSR publishing](https://jsr.io/docs/publishing-packages).
1. Own the `@udibo` scope on npm. Nothing else is needed now that the package
   exists: releases authenticate by OIDC (see **npm trusted publishing** below).
   A first release into a _new_ scope is the exception — npm cannot configure a
   trusted publisher for a package that does not exist, so that one publish
   needs a granular access token in an `NPM_TOKEN` secret, removed afterwards.
1. Create the `DEPLOY_KEY` semantic-release pushes the release commit and tag
   with. GitHub does not issue one: a deploy key is an SSH keypair you generate,
   whose public half is registered on the repository and whose private half
   becomes a secret.

   ```sh
   ssh-keygen -t ed25519 -N "" -C "semantic-release@udibo/oauth2" -f ./deploy_key
   gh repo deploy-key add ./deploy_key.pub --repo udibo/oauth2 \
     --title semantic-release --allow-write
   gh secret set DEPLOY_KEY --repo udibo/oauth2 < ./deploy_key
   shred -u ./deploy_key ./deploy_key.pub
   ```

   Leave the passphrase empty: `actions/checkout` cannot unlock an encrypted
   key. Delete the local copies afterwards — the private half lives in the
   repository secret, and replacing a lost key means generating a new pair.

   The key is what lets the release push to a protected branch. `main`'s ruleset
   requires a pull request and lists `DeployKey` as an always-bypass actor, so
   semantic-release pushes as that identity while ordinary changes stay behind
   pull requests. Without the bypass the release cannot push at all; with a
   ruleset that requires no pull request, `GITHUB_TOKEN` would do and the key
   would be redundant.
1. Tag the initial package import `0.0.0` and push that tag. It is a version
   baseline, not a published package. semantic-release otherwise chooses `1.0.0`
   for a repository with no release tags, ignoring the version in
   `src/deno.json`.
1. Enable the repository variable `OAUTH2_RELEASE_ENABLED=true` only after the
   standalone CI passes, JSR linking is complete, the npm scope and `NPM_TOKEN`
   are in place, and push permissions are ready.
1. Merge a `feat:` commit to `main`. From the `0.0.0` baseline, this computes
   `0.1.0`; a `fix:` would compute `0.0.1`.
1. For a first release into a new scope only: once it lands, configure the
   trusted publisher and delete both the secret and any `NPM_TOKEN` line, so no
   long-lived npm credential outlives the bootstrap.

`scripts/verify-release.ts` rejects any first version other than `0.1.0` before
release preparation, tags or publication. The workflow prints a semantic-release
dry run first. Keep the release gate available as an off switch.

## npm trusted publishing

**In effect since 0.1.0.** This repository stores no npm credential: the release
job mints an OIDC token, `@semantic-release/npm` exchanges it with the registry
for publish rights, and npm attaches a provenance attestation automatically —
there is no `--provenance` flag to pass.

The trust relationship is configured on npmjs.com, under the package's **Trusted
Publisher** settings: organization `udibo`, repository `oauth2`, workflow
filename `ci-cd.yml`, environment empty. Moving the release job into a named
GitHub environment means naming it there too, or the exchange stops matching.

Two things follow from that, both enforced by
`smoke-consumer/packaging.test.ts`:

- The job needs `id-token: write`. Without it the runner cannot mint the token
  and the publish has nothing to fall back on.
- No `NPM_TOKEN` belongs in the workflow. A stored credential would silently
  take precedence over the OIDC exchange, reintroducing the long-lived publish
  secret it exists to remove.

The exchange fails with `404 ... package not found` for a package that does not
exist yet, which is why a first release into a new scope still needs a token.

## What the release does

- Validates the proposed first version.
- Generates `CHANGELOG.md` and stamps `src/deno.json` and every example/template
  dependency pin with the release version.
- Stages the complete documentation payload using the same task exercised by the
  publish dry run.
- Builds the npm artifact from `src/` with dnt, stamped with the version being
  released, and publishes it to npm alongside the JSR upload.
- Commits release files and pushes the release commit/tag during
  semantic-release's prepare/tag phases, then publishes to JSR and creates a
  GitHub release.

A release is not a transaction across Git, JSR and npm. If publication fails
after the release commit or tag was pushed, inspect all three before retrying.
If the version already exists on JSR, do not try to overwrite it — JSR versions
are immutable, and so are npm versions in practice. If only Git advanced, or if
JSR published and npm did not, resolve that partial release state deliberately
before rerunning.

Registry credentials are verified before anything is pushed: the release job
builds `npm/` before semantic-release starts, so `@semantic-release/npm` checks
npm authentication during `verifyConditions` rather than after the release
commit exists.

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
