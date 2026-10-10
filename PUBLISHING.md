# Publishing @udibo/oauth2

The package is published to both [npm](https://www.npmjs.com/package/@udibo/oauth2)
and [JSR](https://jsr.io/@udibo/oauth2) from the same semantic-release run. npm
gets the `tsc` build in `dist/`; JSR gets the TypeScript sources in `src/` as
`jsr.json` lists them. The first release was **0.1.0**, and the first release
from the Node toolchain is **0.15.0** (`0.14.1` is the last Deno-built tag).

Every push to `main` whose [Conventional Commits](https://www.conventionalcommits.org)
call for a release publishes one, as long as the repository variable
`OAUTH2_RELEASE_ENABLED` is `true`. Setting it to anything else is the off
switch. Nothing in the validation commands below publishes a package.

## Release configuration in place

The release job depends on these:

1. The `oauth2` package in JSR's `@udibo` scope, linked to `udibo/oauth2` in the
   package settings. The release job uses GitHub OIDC; no JSR token is stored.
   See [JSR publishing](https://jsr.io/docs/publishing-packages).
1. The `@udibo/oauth2` package on npm, with this repository configured as its
   trusted publisher (see **npm trusted publishing** below). No npm token is
   stored.
1. The `DEPLOY_KEY` semantic-release pushes the release commit and tag with.
   GitHub does not issue one: a deploy key is an SSH keypair you generate, whose
   public half is registered on the repository and whose private half becomes a
   secret. To replace it:

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
1. The repository variable `OAUTH2_RELEASE_ENABLED=true`.
1. Optional: a `CODECOV_TOKEN` repository secret. The coverage upload from the
   Node 24 job does not fail the build without it, but a token keeps uploads
   from pull requests reliable.

The `0.0.0` tag on the initial package import is a version baseline, not a
published package. `scripts/verify-release.ts` rejects commits since
semantic-release's last release head that reference the private application
repository, before notes are generated, release files are prepared, or packages
are published. With no previous release, it checks all commits. Pull-request CI
applies the same check to commits since the base head and the proposed squash
title and body, including edits to that text. Keep commit footers and URLs
public; these guards do not remove references from Git history or rewrite
published release notes. The workflow prints a semantic-release dry run before
the real run.

## Validate a release

From this directory, with Node.js 22.18 or later and pnpm:

```sh
pnpm install --frozen-lockfile
pnpm check
pnpm test:coverage
pnpm test:browser
pnpm build
pnpm smoke
pnpm jsr:dry-run
```

`pnpm check` runs the type-aware lint, formatting check, and `tsc`, then the
documentation gates: `doc:lint` (JSDoc on every exported symbol and public
member), `doc:check` (type-checks the fenced snippets in the Markdown and every
JSDoc `@example`), `doc:links` (local links and headings), and `llms:check`
(`llms-full.txt` matches `llms.txt`; regenerate with `pnpm llms:generate`).
`pnpm smoke` packs the package, installs the tarball into an empty project, type
checks a consumer of every subpath under NodeNext resolution, runs the
`udibo-oauth2` command from the installed package, and imports each subpath on
Node.

The workflow in [`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml)
runs `pnpm check` and `pnpm test` on Node 22, 24, and 26 on Linux and on Node 26
on Windows and macOS; builds, smoke-tests, and dry-runs the JSR publish for the
package on Node 22, 24, and 26; and runs `pnpm test:browser` in headless
Chromium, installed with `playwright install --with-deps chromium`, so a missing
browser fails instead of skipping the suite. The release job requires every one
of those jobs to succeed; a failed or skipped prerequisite prevents publication.

## Release configuration

`.releaserc.json` runs, in order: the commit analyzer and release-notes
generator (the `conventionalcommits` preset, so `feat!:` and `fix(scope)!:` are
read as breaking), `@semantic-release/changelog` for `CHANGELOG.md`, the
`verifyReleaseCmd` guard above, `@sebbo2002/semantic-release-jsr` (rewrites
`jsr.json` and publishes to JSR over OIDC), `@semantic-release/npm` (rewrites
`package.json` and publishes the repository root to npm over OIDC, with a
provenance attestation), `@semantic-release/github`, and `@semantic-release/git`,
which commits `CHANGELOG.md`, `package.json`, and `jsr.json`. `semantic-release`,
each plugin, and the `conventional-changelog-conventionalcommits` preset are
exact-pinned devDependencies, so the release job runs the versions in the
lockfile. The preset stays on 9.x: 10.x needs `conventional-changelog-writer` 9,
and the commit analyzer and notes generator bundled with semantic-release 25
load writer 8.

`pnpm build` runs before semantic-release because `@semantic-release/npm`
verifies registry authentication during `verifyConditions`, which needs `dist/`
to exist. That makes a credential problem fail before a release commit or tag
exists.

## npm trusted publishing

**In effect since 0.2.0.** 0.1.0 predates it and carries no provenance
attestation: npm cannot configure a trusted publisher for a package that does
not exist yet. This repository stores no npm credential: the release job mints
an OIDC token, `@semantic-release/npm` exchanges it with the registry for
publish rights, and npm attaches a provenance attestation automatically.

The trust relationship is configured on npmjs.com, under the package's **Trusted
Publisher** settings: organization `udibo`, repository `oauth2`, workflow
filename `ci-cd.yml`, environment empty. The workflow file keeps that name for
this reason; renaming it, or moving the release job into a named GitHub
environment, means updating the trusted publisher to match, or the exchange
stops matching.

Two things follow from that, both enforced by `scripts/release-config.test.ts`:

- The job needs `id-token: write`. Without it the runner cannot mint the token
  and the publish has nothing to fall back on.
- No `NPM_TOKEN` belongs in the workflow. A stored credential would silently
  take precedence over the OIDC exchange, reintroducing the long-lived publish
  secret it exists to remove. The release job also takes no dependency cache
  and does not set `registry-url` on `actions/setup-node`, which would write an
  `.npmrc` with a placeholder token.

OIDC publishing needs npm 11.5.1 or later, so the release job upgrades npm
before it runs.

## What the release does

- Checks the unreleased commit references and the dependency rules above.
- Generates `CHANGELOG.md` and stamps `package.json` and `jsr.json` with the
  release version.
- Publishes the TypeScript sources to JSR and `dist/` to npm.
- Commits the release files, pushes the commit and tag with the deploy key, and
  creates a GitHub release.

A release is not a transaction across Git, JSR and npm. If publication fails
after the release commit or tag was pushed, inspect all three before retrying.
If the version already exists on JSR, do not try to overwrite it — JSR versions
are immutable, and so are npm versions in practice. If only Git advanced, or if
JSR published and npm did not, resolve that partial release state deliberately
before rerunning.

While 0.x, breaking changes increment the minor version under
[the stability policy](docs/stability.md).

## Verify the published version

In a fresh directory outside this repository:

```sh
npm init -y
npm install @udibo/oauth2@<version>
npx udibo-oauth2 --help
```

Import a few subpaths from a Node ESM script and from a TypeScript file checked
under `moduleResolution: NodeNext`; `pnpm smoke` does the same for every
subpath against the local tarball. Then confirm on npm that the version shows a
provenance badge and that the package file listing holds `dist/`, `README.md`,
`LICENSE`, and `SECURITY.md` but no test source.

For JSR, run `npx jsr add @udibo/oauth2@<version>`, check every subpath type
checks, and inspect the JSR page's README, license, and file listing, again
confirming that test source is absent. JSR's
[package rules](https://jsr.io/docs/publishing-packages#jsr-package-rules) and
[immutable-version policy](https://jsr.io/docs/immutability) apply to the
uploaded artifact. The local dry run verifies packaging, not account settings,
repository permissions, or the eventual registry upload. It also cannot show how
JSR renders the README's relative links.

## The command name on npm

The package's `bin` is `udibo-oauth2`. No npm package has that bare name, so
`npx udibo-oauth2` run where `@udibo/oauth2` is not installed offers to download
whatever package someone later registers under it. The guides tell readers to
install `@udibo/oauth2` first or to use
`npx --package @udibo/oauth2 udibo-oauth2`. Registering the unscoped name for
Udibo, or deprecating a placeholder package that points at `@udibo/oauth2`,
closes that gap.
