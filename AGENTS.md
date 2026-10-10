# OAuth2 agent instructions

This repository is the public `@udibo/oauth2` package: a pnpm package on Node
22 or later, published library in `src/`, and standalone examples and templates
alongside it. Source is erasable TypeScript with explicit `.ts` import
extensions; `tsc` builds the npm package and the same files publish to JSR.

- Run `pnpm test` for the package tests (Vitest) and `pnpm test:coverage` for
  coverage. Pass a path to run one file, for example
  `pnpm test src/utils/crypto.test.ts`.
- Run `pnpm test:browser` after changing the React form components. It drives
  them in headless Chromium through Playwright (`pnpm exec playwright install
  chromium` once); jsdom cannot show where focus goes while a submit is pending.
- Run `pnpm check` for lint (oxlint, type-aware), formatting (oxfmt) and types.
  Run `pnpm fmt` to format changes.
- Run `pnpm build` then `pnpm smoke` to pack the package and prove it from a
  clean Node consumer. Run `pnpm jsr:dry-run` to check the JSR publish.
- Use explicit exported return types, `expect` assertions from Vitest and
  contract-level JSDoc for public APIs. Leave no open handles after a suite.
- Reproduce behavioral bugs with failing tests before fixing them. Keep
  security-sensitive storage operations atomic and test concurrent callers.
- Public docs serve developers and coding agents integrating an application with
  Udibo or hosting authorization for their own app. Keep hosted-platform
  internals and business operations out of the package docs. Do not label
  Udibo's hosted service or its pricing as beta, preview, provisional or new;
  point readers to https://www.udibo.com/ for getting an account, and do not
  imply self-serve signup is available.
- Public docs explain package usage. Do not add per-document changelogs or
  internal-business frontmatter; release history belongs in `CHANGELOG.md`.
- Follow Conventional Commits and the PR template. Do not publish, enable the
  release gate, or change repository visibility without an explicit request.
- See `CONTRIBUTING.md` for development and `PUBLISHING.md` for release setup.
