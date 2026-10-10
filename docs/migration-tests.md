# Test migration ledger

Per-file verdict for the Deno to Vitest port of `@udibo/oauth2`. `keep` is a codemod plus fixes with every assertion retained, `rewrite` means the behavior is retained and the test changed shape, `drop` means the file existed only for Deno plumbing. `pending` files belong to slice 4b.

Totals: 69 keep, 5 rewrite, 5 drop, 29 pending (4b); 10 new files.

| file | verdict | reason | ported-to |
| --- | --- | --- | --- |
| src/adapters/hono/authorization-server.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/adapters/hono/bff/auth-request-store.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/adapters/hono/bff/bff.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/adapters/hono/bff/cookie-prefix.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/adapters/hono/bff/proxy.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/adapters/hono/bff/session-store.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/adapters/hono/bff/testing.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/adapters/hono/identity.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/adapters/hono/log.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/adapters/hono/resource-server.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/cli/idp/config.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/cli/idp/server.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/cli/mod.test.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/client/_test_check_stalled_connection.ts | drop | Child-process script for the Deno HTTP/2 rig. | replaced by the 'new connection' test in src/client/check.test.ts |
| src/client/_test_interrupted_body.ts | rewrite | Servers rebuilt on node:http (stalled body, no headers, body cut short); each helper now resolves once listening. | src/client/_test_interrupted_body.ts |
| src/client/bff-client.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/client/bff-client.test.ts |
| src/client/browser-storage.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/client/browser-storage.test.ts |
| src/client/check.test.ts | keep | Codemod plus fixes. The stalled-body test waited the real timeout; the Deno HTTP/2 reconnect test runs on the fake Deno runtime. | src/client/check.test.ts |
| src/client/direct-client.test.ts | keep | Codemod plus fixes. Three tests waited the real 10 s request timeout (20 s for discovery's two paths); the deadline is now expired by the test and asserted to be the request timeout. | src/client/direct-client.test.ts |
| src/client/discovery-cache.test.ts | keep | Codemod. Two `delay(5)` sleeps that held a load open are deferred promises. | src/client/discovery-cache.test.ts |
| src/client/storage.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/client/storage.test.ts |
| src/errors.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/errors.test.ts |
| src/identity/captcha.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/captcha.test.ts |
| src/identity/delivery.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/delivery.test.ts |
| src/identity/errors.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/errors.test.ts |
| src/identity/external/_shared.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/external/_shared.test.ts |
| src/identity/external/_token-exchange.test.ts | keep | Codemod; test server moved to node:http. The drip-feed deadline test expires the deadline itself instead of racing a 100 ms timeout. | src/identity/external/_token-exchange.test.ts |
| src/identity/external/apple-client-secret.test.ts | rewrite | The cache test passed on Deno only because its ECDSA signatures are deterministic, so two fresh signings compared equal; it now asserts reuse by identity and the renew boundary to the second, and a second test covers the always-renew window. | src/identity/external/apple-client-secret.test.ts |
| src/identity/external/apple.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/external/apple.test.ts |
| src/identity/external/discord.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/external/discord.test.ts |
| src/identity/external/flow.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/external/flow.test.ts |
| src/identity/external/github.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/external/github.test.ts |
| src/identity/external/google.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/external/google.test.ts |
| src/identity/external/oauth2.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/external/oauth2.test.ts |
| src/identity/external/oidc.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/external/oidc.test.ts |
| src/identity/hibp.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/hibp.test.ts |
| src/identity/identifier.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/identifier.test.ts |
| src/identity/lockout.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/lockout.test.ts |
| src/identity/mfa/recovery-codes.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/mfa/recovery-codes.test.ts |
| src/identity/mfa/service.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/mfa/service.test.ts |
| src/identity/mfa/totp.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/mfa/totp.test.ts |
| src/identity/migration.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/migration.test.ts |
| src/identity/otp.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/otp.test.ts |
| src/identity/password-policy.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/password-policy.test.ts |
| src/identity/password.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/password.test.ts |
| src/identity/rate-limit.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/rate-limit.test.ts |
| src/identity/service.test.ts | keep | Codemod plus fixes. The failed sign-in timing group measured wall-clock medians and ratios (flaky under load); it now runs on fake `performance`/timers and asserts every branch lands exactly on the floor. The concurrent-reset race window is fake-timer driven instead of a 200 ms sleep. | src/identity/service.test.ts |
| src/identity/session.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/session.test.ts |
| src/identity/token-flow.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/identity/token-flow.test.ts |
| src/models/authorization.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/models/authorization.test.ts |
| src/models/scope.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/models/scope.test.ts |
| src/react/_test_cdp.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/_test_setup.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/_test_pending_submit_page.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/a11y.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/class-names.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/host-integration.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/mfa.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/password-reset.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/pending-submit.e2e.ts | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/pending-submit.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/sign-in-form.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/sign-up-form.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/use-auth-form.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/components/user-menu.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/error-sinks.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/react/react.test.tsx | pending | Ported by slice 4b (adapters, React and CLI), which owns these suites. | - |
| src/release-regressions.test.ts | keep | Codemod; `stub` becomes `vi.spyOn`. | src/release-regressions.test.ts |
| src/server/_test_introspection_stalled_connection.ts | drop | Child-process script for the Deno HTTP/2 rig. | replaced by the 'new connection' test in src/server/introspection-token-reader.test.ts |
| src/server/_test_jwks_stalled_connection.ts | drop | Child-process script for the Deno HTTP/2 rig. | replaced by the 'new connection' test in src/server/jwks-token-reader.test.ts |
| src/server/authentication-context.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/authentication-context.test.ts |
| src/server/authorization-server.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/authorization-server.test.ts |
| src/server/grants/authorization-code.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/grants/authorization-code.test.ts |
| src/server/grants/client-credentials.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/grants/client-credentials.test.ts |
| src/server/grants/device-authorization.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/grants/device-authorization.test.ts |
| src/server/grants/grant.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/grants/grant.test.ts |
| src/server/grants/password.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/grants/password.test.ts |
| src/server/grants/refresh-token.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/grants/refresh-token.test.ts |
| src/server/introspection-token-reader.test.ts | keep | Codemod; test server moved to node:http. The Deno HTTP/2 reconnect test runs on the fake Deno runtime with fake timers. | src/server/introspection-token-reader.test.ts |
| src/server/jwks-token-reader.test.ts | keep | Codemod. The Deno HTTP/2 reconnect test runs on the fake Deno runtime with fake timers. | src/server/jwks-token-reader.test.ts |
| src/server/oidc.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/oidc.test.ts |
| src/server/protocol-parameters.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/protocol-parameters.test.ts |
| src/server/public-suffix/mod.test.ts | keep | Codemod. | src/server/public-suffix/mod.test.ts |
| src/server/redirect-uri.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/redirect-uri.test.ts |
| src/server/request-body-limit.test.ts | keep | Codemod; test server on node:http. Node requires `duplex: "half"` for streamed request bodies. | src/server/request-body-limit.test.ts |
| src/server/resource-server.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/resource-server.test.ts |
| src/server/services/token.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/services/token.test.ts |
| src/server/services/user.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/services/user.test.ts |
| src/server/signing-keys.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/signing-keys.test.ts |
| src/server/utils/hash.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/server/utils/hash.test.ts |
| src/testing/_test_fixtures.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/testing/_test_fixtures.ts |
| src/testing/contract/_test_identity_contract_faults.ts | keep | Reads the fault from `process.env`. | src/testing/contract/_test_identity_contract_faults.ts |
| src/testing/contract/_test_identity_contract_fixtures.ts | keep | Unchanged fixtures. | same path |
| src/testing/contract/_test_scoped_clear_wipes_live.ts | keep | Unchanged fixture run in a child Vitest. | same path |
| src/testing/contract/auth-request-storage.test.ts | rewrite | Ran `deno test` in a child and parsed its output; now runs the faulty suite in a child Vitest and reads its JSON report. | src/testing/contract/auth-request-storage.test.ts, _test_child.ts |
| src/testing/contract/contract.test.ts | keep | Codemod; fake tenant served from node:http. | src/testing/contract/contract.test.ts |
| src/testing/contract/identity-contracts.test.ts | rewrite | Ran `deno task test` per injected fault; now one child Vitest per fault, asserting the failing test and message. | src/testing/contract/identity-contracts.test.ts, _test_child.ts |
| src/testing/server.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/testing/server.test.ts |
| src/testing/services.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/testing/services.test.ts |
| src/testing/tenant.concurrent.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/testing/tenant.concurrent.test.ts |
| src/testing/tenant.test.ts | keep | Codemod; fake tenant served from node:http. | src/testing/tenant.test.ts |
| src/utils/_default-fetch.test.ts | rewrite | Real TLS + HTTP/2 stall tests ran child Deno processes and only prove Deno's pool; the module's logic is now driven in-process with a fake `Deno.createHttpClient` and fetch, one test per rule. The status-999 case becomes `Response.error()` (a `Response` cannot carry 999). The two source scans stay as `node:fs` scans. | src/utils/_default-fetch.test.ts, src/_test_deno-runtime.ts |
| src/utils/_test_default_fetch_plan.ts | drop | Child-process script for the Deno HTTP/2 rig above. | replaced by src/utils/_default-fetch.test.ts |
| src/utils/_test_tls.ts | drop | Deno-only rig (self-signed cert, `Deno.listenTls`, `deno test --cert` child) for Deno's HTTP/2 connection pooling; nothing on Node to run it against. | replaced by src/_test_deno-runtime.ts |
| src/utils/basic-auth.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/utils/basic-auth.test.ts |
| src/utils/crypto.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/utils/crypto.test.ts |
| src/utils/pkce.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/utils/pkce.test.ts |
| src/utils/url.test.ts | keep | Codemod to Vitest (`expect`, `describe`/`it`, `vi`); assertions kept one for one. | src/utils/url.test.ts |
| src/_test_assert.ts | new | Replaces `assertThrows`/`assertRejects`: runs the action, checks class and message, returns the error. | src/_test_assert.ts |
| src/_test_deno-runtime.ts | new | Fake `Deno.createHttpClient` plus global fetch for the Deno-only default-fetch behavior. | src/_test_deno-runtime.ts |
| src/_test_fake-time.ts | new | Replaces `@std/testing/time` `FakeTime` on `vi.useFakeTimers`; `settle` ticks until a promise settles. | src/_test_fake-time.ts |
| src/_test_server.ts | new | Replaces `Deno.serve({ port: 0 })`; ephemeral loopback port, closes every connection on dispose. | src/_test_server.ts |
| src/_test_timeouts.ts | new | Lets a test decide when `AbortSignal.timeout` deadlines pass. | src/_test_timeouts.ts |
| src/testing/contract/_test_child.ts | new | Runs a suite in a child Vitest and returns its JSON report. | src/testing/contract/_test_child.ts |
| src/testing/contract/_test_child.config.ts | new | Vitest config for the child run. | src/testing/contract/_test_child.config.ts |
| src/utils/_encoding.test.ts | new | New. The internal codecs replace `@std/encoding`; RFC 4648 vectors, Buffer agreement and error types. A one-off differential run against `@std/encoding` over 291,453 inputs matched on every result and error type. | src/utils/_encoding.test.ts |
| src/utils/_constant-time.test.ts | new | New. Covers the internal constant-time comparison that replaces `@std/crypto/timing-safe-equal`. | src/utils/_constant-time.test.ts |
| src/utils/_delay.test.ts | new | New. Covers the internal abortable delay that replaces `@std/async/delay`. | src/utils/_delay.test.ts |
