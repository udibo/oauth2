/**
 * OAuth2 clients for browsers, CLIs, servers, and framework adapters.
 *
 * Pick by who holds the tokens:
 *
 * - {@link BffClient} — a Backend-for-Frontend holds them. The browser only
 *   talks to the BFF's `/auth/*` routes with the session cookie, and never
 *   sees a token.
 * - {@link DirectClient} — this process holds them. Drives the standard
 *   grants (authorization code + PKCE, refresh, client credentials, device
 *   authorization, introspection, revocation) against any RFC 6749-compliant
 *   authorization server.
 *
 * Both extend {@link OAuth2ClientBase}, which is what code that shouldn't
 * care — the React adapter's `<OAuth2Provider>`, a shared UI helper — should
 * accept.
 *
 * Storage interfaces (token / refresh-token / auth-request) default to
 * in-memory implementations suitable for servers and tests; browser
 * applications should substitute the appropriate persistent variants.
 *
 * @module
 */

export {
  type BaseLoginOptions,
  type BaseOptions,
  type LoginRedirect,
  type LogoutOptions,
  type LogoutRedirect,
  OAuth2ClientBase,
  type SessionState,
  SIGNED_OUT,
  type UserInfoClaims,
} from "./base.ts";
export {
  BffClient,
  type BffClientOptions,
  type BffEndpoints,
} from "./bff-client.ts";
export {
  type AuthorizationCallbackResult,
  type AuthorizationRedirect,
  type AuthorizationServerEndpoints,
  type DeviceAuthorizationOptions,
  DirectClient,
  type DirectClientOptions,
  type ExchangeOptions,
  type ExchangeResult,
  type IntrospectionResult,
  type LoginOptions,
  type PollDeviceTokenOptions,
} from "./direct-client.ts";
export {
  DEFAULT_DISCOVERY_CACHE_MAX_ENTRIES,
  DEFAULT_DISCOVERY_TTL_MS,
  type DiscoveryCache,
  type DiscoveryCacheEntry,
  MemoryDiscoveryCache,
  type MemoryDiscoveryCacheOptions,
} from "./discovery-cache.ts";
export {
  type AuthenticatedEvent,
  type ErrorEvent,
  type LoggedOutEvent,
  type OAuth2ClientEvent,
  type OAuth2ClientEventListener,
  type TokenRefreshedEvent,
} from "./events.ts";
export {
  type AuthRequestRecord,
  type AuthRequestStorage,
  MemoryAuthRequestStorage,
  MemoryRefreshTokenStorage,
  MemoryTokenStorage,
  type RefreshTokenStorage,
  type TokenBundle,
  type TokenStorage,
} from "./storage.ts";
export {
  checkPermissions,
  type CheckPermissionsOptions,
  type CheckPermissionsResult,
  type CheckResource,
} from "./check.ts";
export {
  Authorization,
  authorizationFromClaims,
} from "../models/authorization.ts";
export type { OrganizationContext } from "../models/authorization.ts";
export { isOAuth2Error, OAuth2Error } from "../errors.ts";
export {
  IndexedDBRefreshTokenStorage,
  type IndexedDBRefreshTokenStorageOptions,
  SessionStorageAuthRequestStorage,
  type SessionStorageAuthRequestStorageOptions,
} from "./browser-storage.ts";
