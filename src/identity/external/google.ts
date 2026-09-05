/**
 * Google sign-in preset over the generic {@link oidcProvider} connector.
 *
 * @module
 */

import type { DiscoveryCache } from "../../client/discovery-cache.ts";
import type { AzpPolicy } from "./_shared.ts";
import { oidcProvider } from "./oidc.ts";
import type { ExternalProvider } from "./provider.ts";

/** Options for {@link googleProvider}. */
export interface GoogleProviderOptions {
  /** OAuth client ID from the Google Cloud console ("Web application" type). */
  clientId: string;
  /** The matching OAuth client secret. */
  clientSecret: string;
  /** Scopes requested by default. Defaults to `["openid", "email", "profile"]`. */
  scopes?: string[];
  /**
   * How the id_token's `azp` claim is checked. Defaults to `"conditional"`.
   * Google's cross-client identity is the case for `"ignore"`: a token minted
   * for another client of the same project reports that client in `azp` while
   * `aud` is this one. See {@link AzpPolicy}.
   */
  azp?: AzpPolicy;
  /** Fetch implementation for all provider traffic. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /**
   * Cache Google's discovery document is read from and written to, shared with
   * any other connector given the same instance. Supply one when the connector
   * is rebuilt per request. See {@link OidcProviderOptions.discoveryCache}.
   */
  discoveryCache?: DiscoveryCache;
}

/**
 * Creates a Google connector: the generic OIDC connector pinned to issuer
 * `https://accounts.google.com` with id `"google"`.
 *
 * Claim mapping follows the OIDC normalization: `emailVerified` is `true`
 * only when Google asserts `email_verified: true`, and Google-specific claims
 * such as `hd` (the Workspace domain) stay available on
 * {@link ExternalProfile.raw}.
 *
 * @example
 * ```ts
 * const flow = new ExternalAuthFlow({
 *   provider: googleProvider({
 *     clientId: Deno.env.get("GOOGLE_CLIENT_ID")!,
 *     clientSecret: Deno.env.get("GOOGLE_CLIENT_SECRET")!,
 *   }),
 * });
 * ```
 */
export function googleProvider(
  options: GoogleProviderOptions,
): ExternalProvider {
  return oidcProvider({
    id: "google",
    displayName: "Google",
    issuer: "https://accounts.google.com",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    scopes: options.scopes,
    azp: options.azp,
    fetch: options.fetch,
    discoveryCache: options.discoveryCache,
  });
}
