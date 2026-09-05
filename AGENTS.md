# OAuth2 agent instructions

This repository is the public `@udibo/oauth2` package. Its layout follows
Juniper: root Deno workspace, published library in `src/`, and standalone
examples and templates alongside it.

- Run `deno task test --parallel --reporter=dot` from the repository root for
  package tests. Paths passed to that task are relative to `src/`.
- Run `deno task test:all` for package, script, example and template suites.
- Run `deno task check` for types, lint, formatting, documentation and
  packaging. Run `deno fmt` from the repository root to format changes.
- Use explicit exported return types, `@std/assert` assertions and
  contract-level JSDoc for public APIs. Never disable test sanitizers.
- Reproduce behavioral bugs with failing tests before fixing them. Keep
  security-sensitive storage operations atomic and test concurrent callers.
- Public docs serve developers and coding agents integrating an application with
  Udibo or hosting authorization for their own app. Keep hosted-platform
  internals and business operations out of the package docs. Udibo is currently
  in private beta with a waitlist; do not imply public signup is available.
- Public docs explain package usage. Do not add per-document changelogs or
  internal-business frontmatter; release history belongs in `CHANGELOG.md`.
- Follow Conventional Commits and the PR template. Do not publish, enable the
  release gate, or change repository visibility without an explicit request.
- See `CONTRIBUTING.md` for development and `PUBLISHING.md` for release setup.
