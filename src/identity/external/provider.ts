/**
 * The contract between {@link ExternalAuthFlow} and a concrete external
 * provider connector ({@link oidcProvider}, {@link googleProvider},
 * {@link githubProvider}, or your own).
 *
 * A provider's job ends at returning a verified, normalized
 * {@link ExternalProfile}. What the app does with it — create a user, link an
 * account, reject — is app code; the library deliberately stores nothing.
 *
 * @module
 */

/**
 * A verified, normalized profile returned by an external provider after a
 * successful sign-in. This is the connector layer's entire output — account
 * creation/linking is the app's job.
 */
export interface ExternalProfile {
  /** The provider id the profile came from (e.g. `"google"`). */
  provider: string;
  /**
   * The provider's stable unique id for the user (OIDC `sub`, GitHub user
   * id). Key identities by `(provider, subject)` — never by email, which can
   * change or be reassigned.
   */
  subject: string;
  /** The user's email address, when the provider shared one. */
  email?: string;
  /**
   * `true` only when the provider positively asserted the email is verified
   * (OIDC `email_verified: true`, GitHub verified primary email). Defaults to
   * `false` — treat unverified emails as attacker-controllable input and do
   * not auto-link accounts on them.
   */
  emailVerified: boolean;
  /** Display name, when shared. */
  name?: string;
  /** Given (first) name, when shared. */
  givenName?: string;
  /** Family (last) name, when shared. */
  familyName?: string;
  /** Avatar/profile picture URL, when shared. */
  picture?: string;
  /**
   * The provider's raw claims/profile payload, for app-specific fields the
   * normalized shape omits (e.g. Google's `hd`, GitHub's `login`).
   */
  raw: Record<string, unknown>;
}

/**
 * The per-authorization transient state {@link ExternalAuthFlow.start}
 * returns. JSON-serializable by construction — put it in a sealed cookie or
 * your session store and hand it back to {@link ExternalAuthFlow.finish} on
 * the callback. It is the only state the flow needs; the library stores
 * nothing.
 */
export interface ExternalAuthTransient {
  /** CSRF token echoed back by the provider as the callback `state` param. */
  state: string;
  /** PKCE code verifier, present when the provider uses PKCE. */
  codeVerifier?: string;
  /** OIDC replay-protection nonce, present when the provider uses one. */
  nonce?: string;
  /** The id of the provider the attempt was started with. */
  provider: string;
  /** The redirect URI the authorization request was built with. */
  redirectUri: string;
  /** Unix ms when the attempt started; bounds the callback window. */
  createdAt: number;
}

/** Input to {@link ExternalProvider.buildAuthorizationUrl}. */
export interface ExternalAuthorizationUrlInput {
  /** The callback URL registered with the provider for this app. */
  redirectUri: string;
  /** CSRF token to send as the `state` parameter. */
  state: string;
  /** PKCE code verifier to derive the S256 challenge from, when PKCE is on. */
  codeVerifier?: string;
  /** OIDC nonce to bind into the id_token, when the provider uses one. */
  nonce?: string;
  /** Scopes to request (already defaulted by the flow). */
  scopes: string[];
  /** OIDC `prompt` parameter (e.g. `"select_account"`), when requested. */
  prompt?: string;
}

/** Input to {@link ExternalProvider.fetchProfile}. */
export interface ExternalProfileInput {
  /** The authorization code from the callback. */
  code: string;
  /** The redirect URI the flow was started with (must match the exchange). */
  redirectUri: string;
  /** The PKCE code verifier from the transient, when PKCE was used. */
  codeVerifier?: string;
  /** The expected id_token `nonce` from the transient, when one was sent. */
  nonce?: string;
}

/**
 * What a connector must provide for {@link ExternalAuthFlow} to drive it.
 *
 * The flow owns the cross-provider policy (state generation and timing-safe
 * verification, transient expiry, callback error surfacing); the provider
 * owns the wire protocol (authorize URL shape, code exchange, id_token nonce
 * validation, profile normalization). Implement this only for providers the
 * built-in {@link oidcProvider} / {@link githubProvider} cannot cover.
 */
export interface ExternalProvider {
  /** Stable id used in {@link ExternalProfile.provider} and error messages. */
  readonly id: string;
  /** Human-readable name for buttons and logs (e.g. `"Google"`). */
  readonly displayName: string;
  /** Scopes requested when the caller passes none. */
  readonly defaultScopes: string[];
  /** Whether the flow should generate a PKCE code verifier for this provider. */
  readonly usesPkce: boolean;
  /** Whether the flow should generate an OIDC nonce for this provider. */
  readonly usesNonce: boolean;
  /**
   * Builds the provider's authorization URL for the given per-attempt values.
   *
   * @throws {ExternalAuthError} `configuration` when the provider cannot
   *   resolve its authorization endpoint (e.g. OIDC discovery failed).
   */
  buildAuthorizationUrl(input: ExternalAuthorizationUrlInput): Promise<string>;
  /**
   * Exchanges the authorization code and returns the verified, normalized
   * profile. Implementations must validate the id_token `nonce` against
   * `input.nonce` when one was sent.
   *
   * @throws {ExternalAuthError} `provider_error` when the exchange or profile
   *   fetch fails, `nonce_mismatch` when the id_token nonce does not match.
   */
  fetchProfile(input: ExternalProfileInput): Promise<ExternalProfile>;
}
