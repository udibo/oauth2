/**
 * The provider-agnostic two-step flow for external (social) sign-in:
 * {@link ExternalAuthFlow.start} builds the redirect and hands back a
 * serializable transient; {@link ExternalAuthFlow.finish} verifies the
 * callback and returns the normalized profile.
 *
 * @module
 */

import { timingSafeEqualString } from "../../utils/crypto.ts";
import { generateCodeVerifier, generateState } from "../../utils/pkce.ts";
import { ExternalAuthError } from "./errors.ts";
import type {
  ExternalAuthTransient,
  ExternalProfile,
  ExternalProvider,
} from "./provider.ts";

/** Default {@link ExternalAuthFlowOptions.maxTransientAgeMs}: 10 minutes. */
export const DEFAULT_MAX_TRANSIENT_AGE_MS = 10 * 60 * 1000;

/** Options for {@link ExternalAuthFlow}. */
export interface ExternalAuthFlowOptions {
  /** The connector to drive (e.g. `googleProvider(…)`). */
  provider: ExternalProvider;
  /**
   * Max age of a transient before {@link ExternalAuthFlow.finish} rejects the
   * attempt as expired, in ms. Bounds the window in which a stolen transient
   * or callback URL stays usable. Defaults to
   * {@link DEFAULT_MAX_TRANSIENT_AGE_MS}.
   */
  maxTransientAgeMs?: number;
}

/** Input to {@link ExternalAuthFlow.start}. */
export interface ExternalAuthStartInput {
  /** The callback URL registered with the provider for this app. */
  redirectUri: string;
  /** Override the provider's default scopes. */
  scopes?: string[];
  /** OIDC `prompt` parameter (e.g. `"select_account"`). */
  prompt?: string;
}

/** Result of {@link ExternalAuthFlow.start}. */
export interface ExternalAuthStartResult {
  /** The provider authorization URL to redirect the user's browser to. */
  url: string;
  /**
   * Per-attempt state to persist in a cookie/session and hand back to
   * {@link ExternalAuthFlow.finish}. JSON-serializable; contains no tokens.
   */
  transient: ExternalAuthTransient;
}

/** Input to {@link ExternalAuthFlow.finish}. */
export interface ExternalAuthFinishInput {
  /** The callback URL's search params (or the full URL / query string). */
  params: URL | URLSearchParams | string;
  /** The transient produced by the matching {@link ExternalAuthFlow.start}. */
  transient: ExternalAuthTransient;
}

/**
 * Drives one external provider through the authorization-code redirect dance
 * without the library storing anything: {@link start} returns the redirect URL
 * plus a JSON-serializable {@link ExternalAuthTransient} for the caller to keep
 * (sealed cookie or session), and {@link finish} takes the callback params and
 * that transient back and returns the verified {@link ExternalProfile}.
 *
 * The flow itself performs no network I/O — inject `fetch` on the provider to
 * stub the network in tests. Create one flow per configured provider.
 *
 * @example
 * ```ts
 * const flow = new ExternalAuthFlow({
 *   provider: googleProvider({ clientId, clientSecret }),
 * });
 *
 * // GET /auth/social/google — redirect to Google, transient into a cookie.
 * const { url, transient } = await flow.start({
 *   redirectUri: "https://app.example.com/auth/social/google/callback",
 * });
 *
 * // GET /auth/social/google/callback — verify and normalize.
 * const profile = await flow.finish({
 *   params: new URL(request.url).searchParams,
 *   transient,
 * });
 * // App code decides: look up (profile.provider, profile.subject), create
 * // or link a user, then start your own session.
 * ```
 */
export class ExternalAuthFlow {
  /** The connector this flow drives. */
  readonly provider: ExternalProvider;
  readonly #maxTransientAgeMs: number;

  /** Creates a flow for one configured provider. */
  constructor(options: ExternalAuthFlowOptions) {
    this.provider = options.provider;
    this.#maxTransientAgeMs = options.maxTransientAgeMs ??
      DEFAULT_MAX_TRANSIENT_AGE_MS;
  }

  /**
   * Begins a sign-in attempt: generates the per-attempt `state` (plus a PKCE
   * verifier and OIDC nonce when the provider uses them), builds the
   * provider's authorization URL, and returns both. Persist the transient
   * (e.g. sealed cookie) and redirect the browser to `url`.
   *
   * @throws {ExternalAuthError} `configuration` when the provider cannot
   *   resolve its endpoints (e.g. OIDC discovery failed).
   */
  async start(input: ExternalAuthStartInput): Promise<ExternalAuthStartResult> {
    const state = generateState();
    const codeVerifier = this.provider.usesPkce
      ? generateCodeVerifier()
      : undefined;
    const nonce = this.provider.usesNonce ? generateState() : undefined;
    const scopes = input.scopes ?? this.provider.defaultScopes;
    const url = await this.provider.buildAuthorizationUrl({
      redirectUri: input.redirectUri,
      state,
      codeVerifier,
      nonce,
      scopes,
      prompt: input.prompt,
    });
    return {
      url,
      transient: {
        state,
        codeVerifier,
        nonce,
        provider: this.provider.id,
        redirectUri: input.redirectUri,
        createdAt: Date.now(),
      },
    };
  }

  /**
   * Completes a sign-in attempt from the provider callback: enforces the max
   * transient age, surfaces provider `error` callback params, verifies
   * `state` with a timing-safe compare, exchanges the code, and (for OIDC
   * providers) validates the id_token nonce — then returns the normalized
   * profile.
   *
   * @throws {ExternalAuthError} with a code describing the failure — see
   *   {@link ExternalAuthErrorCode} for how app code should respond to each.
   */
  async finish(input: ExternalAuthFinishInput): Promise<ExternalProfile> {
    const { transient } = input;
    const providerId = this.provider.id;
    if (transient.provider !== providerId) {
      throw new ExternalAuthError(
        providerId,
        "configuration",
        `callback was given a transient started for provider ` +
          `"${transient.provider}" — the app routed the callback to the ` +
          `wrong flow. Route each provider's callback to the flow built ` +
          `with that provider.`,
      );
    }
    if (Date.now() - transient.createdAt > this.#maxTransientAgeMs) {
      throw new ExternalAuthError(
        providerId,
        "transient_expired",
        `sign-in attempt expired (older than ${this.#maxTransientAgeMs}ms). ` +
          `Ask the user to start signing in again.`,
      );
    }

    const params = toSearchParams(input.params);
    const state = params.get("state");
    if (!state) {
      throw new ExternalAuthError(
        providerId,
        "invalid_callback",
        `callback is missing the "state" parameter — the URL is not a ` +
          `provider callback, or the provider dropped the state.`,
      );
    }
    if (!timingSafeEqualString(state, transient.state)) {
      throw new ExternalAuthError(
        providerId,
        "state_mismatch",
        `callback "state" does not match this sign-in attempt — possible ` +
          `CSRF, or a stale/mixed-up attempt. Ask the user to start again.`,
      );
    }

    const providerError = params.get("error");
    if (providerError) {
      const description = params.get("error_description");
      throw new ExternalAuthError(
        providerId,
        "provider_error",
        `provider returned an error on the callback: "${providerError}"` +
          (description ? ` (${description})` : "") +
          `. "access_denied" means the user cancelled; ` +
          `"redirect_uri_mismatch" means the redirectUri is not registered ` +
          `with the provider exactly as sent.`,
      );
    }

    const code = params.get("code");
    if (!code) {
      throw new ExternalAuthError(
        providerId,
        "invalid_callback",
        `callback is missing the "code" parameter.`,
      );
    }

    return await this.provider.fetchProfile({
      code,
      redirectUri: transient.redirectUri,
      codeVerifier: transient.codeVerifier,
      nonce: transient.nonce,
    });
  }
}

function toSearchParams(
  input: URL | URLSearchParams | string,
): URLSearchParams {
  if (input instanceof URLSearchParams) return input;
  if (input instanceof URL) return input.searchParams;
  try {
    return new URL(input).searchParams;
  } catch {
    const queryStart = input.indexOf("?");
    const query = queryStart === -1 ? input : input.slice(queryStart + 1);
    const hashStart = query.indexOf("#");
    return new URLSearchParams(
      hashStart === -1 ? query : query.slice(0, hashStart),
    );
  }
}
