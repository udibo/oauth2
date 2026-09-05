/**
 * Testing helpers for apps that use `@udibo/oauth2`.
 *
 * Two layers ship:
 *
 * - **Testing surface for the OAuth2 protocol.** The recommended pattern
 *   for testing apps that use the resource server is to expose your
 *   `IntrospectionTokenReader` instance from your app's OAuth2 wiring module
 *   and stub `tokenReader.getToken` directly with `@std/testing/mock`'s
 *   `stub` —
 *   one method on one object, no `fetch` indirection, no wire format to
 *   fake. For tests that need the OAuth2 protocol end-to-end (BFF flows,
 *   SPA integration), build a real in-process authorization server with
 *   {@link createMemoryAuthorizationServer} and pass its `fetch` to your
 *   `DirectClient` via the constructor's `fetch` option. Both patterns
 *   are constructor- or method-scoped — they never touch
 *   `globalThis.fetch`, which silently captures every other outbound
 *   request the app makes.
 *
 * - **In-memory service implementations.** `MemoryUserService`,
 *   `MemoryClientService`, `MemoryTokenService`,
 *   `MemoryAuthorizationCodeService`, and `MemoryDeviceAuthorizationService`
 *   satisfy every server-side service contract, generic over the consumer's
 *   user / client / scope types. Suitable for tests, examples, and
 *   prototypes — never for production.
 *
 * Nothing in this module is an OAuth2 primitive — only testing support.
 * Production code should never import from here.
 *
 * @module
 */

export {
  MemoryAuthorizationCodeService,
  type MemoryAuthorizationCodeServiceOptions,
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  type MemoryDeviceAuthorizationServiceOptions,
  MemoryTokenService,
  type MemoryTokenServiceOptions,
  MemoryUserService,
  type MemoryUserServiceOptions,
  type MemoryUserShape,
} from "./services.ts";

export {
  createMemoryAuthorizationServer,
  type CreateMemoryAuthorizationServerOptions,
  type MemoryAuthorizationServerClientSeed,
  type MemoryAuthorizationServerGrants,
  type MemoryAuthorizationServerHarness,
  type MemoryAuthorizationServerUserSeed,
} from "./server.ts";
