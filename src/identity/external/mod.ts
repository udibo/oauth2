/**
 * External-provider (social login) connectors: a storage-free flow that turns
 * "Sign in with Google/GitHub/any OIDC provider" into a verified, normalized
 * {@link ExternalProfile}.
 *
 * The library's job ends at the profile. It stores nothing — the only state
 * is the JSON-serializable {@link ExternalAuthTransient} the caller keeps in a
 * cookie or session between {@link ExternalAuthFlow.start} and
 * {@link ExternalAuthFlow.finish} — and it takes no position on what the app
 * does with the profile (create a user, link an account, reject): key
 * identities by `(provider, subject)` in your own storage.
 *
 * - {@link ExternalAuthFlow} — the two-step redirect flow (start → finish)
 *   with CSRF state, PKCE, nonce, and transient-expiry handling built in.
 * - {@link oidcProvider} — generic OpenID Connect connector via discovery.
 * - {@link oauth2Provider} — generic plain-OAuth2 connector (no discovery / no
 *   id_token) for providers {@link oidcProvider} cannot cover.
 * - {@link googleProvider} / {@link githubProvider} / {@link discordProvider} /
 *   {@link appleProvider} — presets for the most common providers.
 * - {@link ExternalProvider} — the small interface to implement for any
 *   provider the built-ins don't cover.
 * - {@link ExternalAuthError} — diagnosable failures; every message names the
 *   provider, what failed, and the likely fix.
 * - {@link MemoryDiscoveryCache} — hand one to every OIDC connector a server
 *   rebuilds per request so they share a discovery fetch instead of each
 *   making their own.
 *
 * @example
 * ```ts
 * import {
 *   ExternalAuthFlow,
 *   googleProvider,
 * } from "@udibo/oauth2/identity/external";
 *
 * const google = new ExternalAuthFlow({
 *   provider: googleProvider({ clientId, clientSecret }),
 * });
 *
 * // Route 1: redirect the user out.
 * const { url, transient } = await google.start({ redirectUri });
 * // …persist `transient` in a sealed cookie, redirect to `url`.
 *
 * // Route 2: the callback.
 * const profile = await google.finish({ params: callbackUrl, transient });
 * // …app code: find-or-create the user for (profile.provider,
 * // profile.subject) and start a session.
 * ```
 *
 * @module
 */

export {
  ExternalAuthError,
  type ExternalAuthErrorCode,
  isExternalAuthError,
} from "./errors.ts";
export type {
  ExternalAuthorizationUrlInput,
  ExternalAuthTransient,
  ExternalProfile,
  ExternalProfileInput,
  ExternalProvider,
} from "./provider.ts";
export {
  DEFAULT_MAX_TRANSIENT_AGE_MS,
  type ExternalAuthFinishInput,
  ExternalAuthFlow,
  type ExternalAuthFlowOptions,
  type ExternalAuthStartInput,
  type ExternalAuthStartResult,
} from "./flow.ts";
export { oidcProvider, type OidcProviderOptions } from "./oidc.ts";
export type { AzpPolicy } from "./_shared.ts";
export {
  DEFAULT_DISCOVERY_CACHE_MAX_ENTRIES,
  DEFAULT_DISCOVERY_TTL_MS,
  type DiscoveryCache,
  type DiscoveryCacheEntry,
  MemoryDiscoveryCache,
  type MemoryDiscoveryCacheOptions,
} from "../../client/discovery-cache.ts";
export { googleProvider, type GoogleProviderOptions } from "./google.ts";
export { githubProvider, type GithubProviderOptions } from "./github.ts";
export {
  type OAuth2ProfileMapper,
  type OAuth2ProfileMapping,
  oauth2Provider,
  type OAuth2ProviderOptions,
  type OAuth2TokenResult,
} from "./oauth2.ts";
export { discordProvider, type DiscordProviderOptions } from "./discord.ts";
export { appleProvider, type AppleProviderOptions } from "./apple.ts";
export {
  APPLE_AUDIENCE,
  APPLE_CLIENT_SECRET_MAX_TTL_SECONDS,
  type AppleClientSecretFactory,
  type AppleClientSecretOptions,
  createAppleClientSecretFactory,
  DEFAULT_APPLE_CLIENT_SECRET_TTL_SECONDS,
  generateAppleClientSecret,
} from "./apple-client-secret.ts";
