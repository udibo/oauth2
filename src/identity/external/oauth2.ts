/**
 * Generic plain-OAuth2 connector: fixed authorize/token endpoints, an optional
 * UserInfo endpoint, and a caller-supplied profile mapper. The connector for
 * providers that speak OAuth2 but publish no OpenID Connect discovery document
 * and issue no `id_token` — where {@link oidcProvider} does not apply and
 * hand-rolling a full {@link ExternalProvider} would be repetitive.
 *
 * @module
 */

import { generateCodeChallenge } from "../../utils/pkce.ts";
import { describeError, readErrorBody } from "./_shared.ts";
import { runTokenExchange } from "./_token-exchange.ts";
import { ExternalAuthError } from "./errors.ts";
import type {
  ExternalAuthorizationUrlInput,
  ExternalProfile,
  ExternalProfileInput,
  ExternalProvider,
} from "./provider.ts";

/** The token-endpoint response fields the mapper may read. */
export interface OAuth2TokenResult {
  /** The bearer access token issued by the token endpoint. */
  accessToken: string;
  /** The token endpoint's full JSON body, for provider-specific fields. */
  raw: Record<string, unknown>;
}

/** The normalized fields a {@link OAuth2ProfileMapper} returns. */
export interface OAuth2ProfileMapping {
  /** The provider's stable unique id for the user. Required and non-empty. */
  subject: string;
  /** The user's email, when the provider shared one. */
  email?: string;
  /**
   * `true` only when the provider positively asserted the email is verified.
   * Defaults to `false` — never auto-link on an unverified email.
   */
  emailVerified?: boolean;
  /** Display name, when shared. */
  name?: string;
  /** Given (first) name, when shared. */
  givenName?: string;
  /** Family (last) name, when shared. */
  familyName?: string;
  /** Avatar/profile picture URL, when shared. */
  picture?: string;
}

/**
 * Maps a provider's raw profile (the UserInfo body, or the token response when
 * no UserInfo endpoint is configured) to the normalized {@link ExternalProfile}
 * fields. Throw {@link ExternalAuthError} `provider_error` when a required field
 * (typically the subject) is absent.
 */
export type OAuth2ProfileMapper = (context: {
  /** The UserInfo JSON, or the token response body when no UserInfo endpoint. */
  profile: Record<string, unknown>;
  /** The token-endpoint result, for providers that carry claims in it. */
  tokens: OAuth2TokenResult;
}) => OAuth2ProfileMapping;

/** Options for {@link oauth2Provider}. */
export interface OAuth2ProviderOptions {
  /** Provider id used in {@link ExternalProfile.provider} and error messages. */
  id: string;
  /** Human-readable name for buttons and logs (e.g. `"Discord"`). */
  displayName: string;
  /** The provider's authorization endpoint (browser redirect target). */
  authorizationEndpoint: string;
  /** The provider's token endpoint (server-to-server code exchange). */
  tokenEndpoint: string;
  /**
   * The provider's UserInfo endpoint, called with the bearer token to build the
   * profile. Omit when the profile is carried in the token response itself.
   */
  userInfoEndpoint?: string;
  /** The client id registered with the provider. */
  clientId: string;
  /** The matching client secret (sent as `client_secret` in the token body). */
  clientSecret: string;
  /** Turns the raw profile into normalized fields. */
  mapProfile: OAuth2ProfileMapper;
  /** Scopes requested when the caller passes none. */
  defaultScopes: string[];
  /** Scopes override; falls back to `defaultScopes`. */
  scopes?: string[];
  /** Separator joining scopes in the authorize URL. Defaults to a space. */
  scopeSeparator?: string;
  /** Whether to run PKCE (S256). Defaults to `false`. */
  usesPkce?: boolean;
  /** Extra fixed query params to add to the authorize URL. */
  authorizationParams?: Record<string, string>;
  /** Fetch implementation for all provider traffic. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

/**
 * Creates a connector for a plain-OAuth2 provider from its fixed endpoints and
 * a profile mapper.
 *
 * The exchange posts `authorization_code` to `tokenEndpoint` with the client
 * credentials in the body (`client_secret_post`); the profile is read from
 * `userInfoEndpoint` with the bearer token when set, else from the token
 * response, and handed to `mapProfile`. Presets like {@link discordProvider}
 * are thin wrappers over this.
 *
 * @example
 * ```ts
 * const provider = oauth2Provider({
 *   id: "discord",
 *   displayName: "Discord",
 *   authorizationEndpoint: "https://discord.com/oauth2/authorize",
 *   tokenEndpoint: "https://discord.com/api/oauth2/token",
 *   userInfoEndpoint: "https://discord.com/api/users/@me",
 *   clientId,
 *   clientSecret,
 *   defaultScopes: ["identify", "email"],
 *   mapProfile: ({ profile }) => ({ subject: String(profile.id) }),
 * });
 * const flow = new ExternalAuthFlow({ provider });
 * ```
 */
export function oauth2Provider(
  options: OAuth2ProviderOptions,
): ExternalProvider {
  const id = options.id;
  const fetchImpl: typeof fetch = (input, init) =>
    (options.fetch ?? globalThis.fetch)(input, init);
  const scopeSeparator = options.scopeSeparator ?? " ";

  async function exchangeCode(
    input: ExternalProfileInput,
  ): Promise<OAuth2TokenResult> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: input.code,
      redirect_uri: input.redirectUri,
      client_id: options.clientId,
      client_secret: options.clientSecret,
    });
    if (input.codeVerifier) body.set("code_verifier", input.codeVerifier);

    const { value, raw } = await runTokenExchange({
      provider: id,
      displayName: options.displayName,
      endpoint: options.tokenEndpoint,
      body,
      requiredField: "access_token",
      fetch: fetchImpl,
      httpErrorHint: `Check that clientId/clientSecret and the redirect URI ` +
        `match the ${options.displayName} app registration, then try again.`,
      tokenErrorHint: oauth2TokenErrorHint,
    });
    return { accessToken: value, raw };
  }

  async function fetchUserInfo(accessToken: string): Promise<
    Record<string, unknown>
  > {
    let res: Response;
    try {
      res = await fetchImpl(options.userInfoEndpoint!, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
        },
      });
    } catch (error) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `could not reach the ${options.displayName} profile endpoint ` +
          `(${describeError(error)}). Try again.`,
        { cause: error },
      );
    }
    if (!res.ok) {
      const detail = await readErrorBody(res);
      throw new ExternalAuthError(
        id,
        "provider_error",
        `profile endpoint responded with HTTP ${res.status}${detail}. The ` +
          `access token was issued but lacks profile access — ensure the ` +
          `identity scope is requested.`,
      );
    }
    try {
      return (await res.json()) as Record<string, unknown>;
    } catch (error) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `the ${options.displayName} profile endpoint returned a response ` +
          `that was not valid JSON (${describeError(error)}).`,
        { cause: error },
      );
    }
  }

  return {
    id,
    displayName: options.displayName,
    defaultScopes: options.scopes ?? options.defaultScopes,
    usesPkce: options.usesPkce ?? false,
    usesNonce: false,
    async buildAuthorizationUrl(
      input: ExternalAuthorizationUrlInput,
    ): Promise<string> {
      const url = new URL(options.authorizationEndpoint);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", options.clientId);
      url.searchParams.set("redirect_uri", input.redirectUri);
      url.searchParams.set("scope", input.scopes.join(scopeSeparator));
      url.searchParams.set("state", input.state);
      for (
        const [key, value] of Object.entries(options.authorizationParams ?? {})
      ) {
        url.searchParams.set(key, value);
      }
      if (input.codeVerifier) {
        url.searchParams.set(
          "code_challenge",
          await generateCodeChallenge(input.codeVerifier),
        );
        url.searchParams.set("code_challenge_method", "S256");
      }
      if (input.prompt) url.searchParams.set("prompt", input.prompt);
      return url.toString();
    },
    async fetchProfile(input: ExternalProfileInput): Promise<ExternalProfile> {
      const tokens = await exchangeCode(input);
      const profile = options.userInfoEndpoint
        ? await fetchUserInfo(tokens.accessToken)
        : tokens.raw;
      const mapped = options.mapProfile({ profile, tokens });
      if (typeof mapped.subject !== "string" || mapped.subject.length === 0) {
        throw new ExternalAuthError(
          id,
          "provider_error",
          `the ${options.displayName} profile is missing a stable subject id.`,
        );
      }
      return {
        provider: id,
        subject: mapped.subject,
        email: mapped.email,
        emailVerified: mapped.emailVerified === true,
        name: mapped.name,
        givenName: mapped.givenName,
        familyName: mapped.familyName,
        picture: mapped.picture,
        raw: profile,
      };
    },
  };
}

function oauth2TokenErrorHint(error: string | undefined): string {
  if (error === "invalid_client" || error === "unauthorized_client") {
    return `The provider rejected the client credentials — check clientId ` +
      `and clientSecret against the app registration.`;
  }
  if (error === "invalid_grant") {
    return `The provider rejected the code — it expired, was already used, ` +
      `or the redirect URI does not match the registered one. Ask the user ` +
      `to start again.`;
  }
  if (error === "invalid_scope") {
    return `The provider rejected the requested scopes — check the ` +
      `connector's scopes against what the app registration allows.`;
  }
  return `The code may have expired or already been used — ask the user to ` +
    `start again.`;
}
