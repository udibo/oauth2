/**
 * OAuth2 client configuration — the minimum surface the framework reads.
 *
 * Only includes fields the framework actually inspects. Users are expected
 * to extend this interface (or the class that implements it) with
 * application-specific fields: display name, client secret hashes, token
 * lifetimes, scope vocabulary, confidentiality flags, rate limits, etc.
 *
 * @example
 * ```ts
 * interface MyClient extends ClientInterface {
 *   name: string;
 *   confidential: boolean;
 *   tenantId: string;
 * }
 * ```
 */
export interface ClientInterface {
  /** Unique client identifier. */
  id: string;
  /**
   * OAuth2 grant type identifiers this client is allowed to use (e.g.
   * `"authorization_code"`, `"client_credentials"`,
   * `"urn:ietf:params:oauth:grant-type:device_code"`). The framework
   * rejects grant-type requests where the identifier is not in this list.
   * When omitted, the client cannot use any grant type.
   */
  grants?: string[];
  /**
   * Allowed redirect URIs for the authorization code flow. An authorization
   * request's `redirect_uri` is authorized by `matchRedirectUri` from
   * `@udibo/oauth2/server`, which compares it against these entries and rejects
   * the request when none authorizes it.
   *
   * An ordinary entry is a **literal**, compared by exact string match (RFC
   * 6749 §3.1.2.3), and an exact match always wins. An entry may instead be a
   * **pattern** — one `*` in the leftmost host label, `https` only, over a
   * single registrable domain (`https://myapp-*.myorg.deno.net/cb`) — so one
   * registration covers the per-deploy hostnames a preview environment
   * produces. `matchRedirectUri` needs `isPublicSuffix` (from
   * `@udibo/oauth2/server/public-suffix`) to decide that last rule: without it
   * every pattern entry is **inert** and only literals match. The list proves
   * the domain is registrable, not that *this* client registered it, so
   * deciding which clients may hold a pattern stays your policy — see
   * `matchRedirectUri` and `checkRedirectUriPattern` for the full rules.
   *
   * An authorization request that omits `redirect_uri` falls back to the first
   * **literal** entry, so order the array with that default first. When omitted
   * or empty, no redirect URI is authorized at all.
   *
   * A legacy literal entry containing a `*` (registrable before patterns
   * existed) now matches **nothing** — the value reads as a pattern and fails
   * the rules. That fails closed, but silently: re-register such a client.
   */
  redirectUris?: string[];
  /**
   * Where the authorization server may send the browser after an RP-initiated
   * logout (OpenID Connect RP-Initiated Logout 1.0 §2). A logout request's
   * `post_logout_redirect_uri` is authorized against this list by **exact
   * string match only** — no patterns, no prefix matching. Unlike
   * {@link ClientInterface.redirectUris}, a logout redirect carries no
   * credential and so has no code to steal, but it is still an open redirect
   * wearing your domain, which is a phishing primitive.
   *
   * When omitted or empty, no post-logout redirect is authorized: the logout
   * still ends the session, it just answers directly instead of bouncing the
   * browser onward. That is the safe failure, so a client that never registers
   * one is not broken, only less convenient.
   */
  postLogoutRedirectUris?: string[];
}

/** Client credentials from a request. */
export interface ClientCredentials {
  /** Client identifier presented by the request. */
  clientId: string;
  /** Client secret, present only for confidential clients. */
  clientSecret?: string;
}
