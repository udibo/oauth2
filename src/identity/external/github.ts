/**
 * GitHub connector: plain OAuth2 (GitHub is not an OIDC provider), with the
 * profile assembled from the REST API's `/user` and `/user/emails` endpoints.
 *
 * @module
 */

import { describeError } from "./_shared.ts";
import { runTokenExchange } from "./_token-exchange.ts";
import { ExternalAuthError } from "./errors.ts";
import type {
  ExternalAuthorizationUrlInput,
  ExternalProfile,
  ExternalProfileInput,
  ExternalProvider,
} from "./provider.ts";

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL = "https://api.github.com/user";
const GITHUB_EMAILS_URL = "https://api.github.com/user/emails";

/** Options for {@link githubProvider}. */
export interface GithubProviderOptions {
  /** Client ID of the GitHub OAuth App (or GitHub App). */
  clientId: string;
  /** The matching client secret. */
  clientSecret: string;
  /** Scopes requested by default. Defaults to `["read:user", "user:email"]`. */
  scopes?: string[];
  /** Fetch implementation for all provider traffic. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

interface GithubEmailEntry {
  email: string;
  primary: boolean;
  verified: boolean;
}

/**
 * Creates a GitHub connector with id `"github"`.
 *
 * GitHub speaks plain OAuth2 (no discovery, no id_token, no PKCE for OAuth
 * Apps), so the connector uses GitHub's fixed endpoints and builds the
 * profile from `GET /user` plus `GET /user/emails`: the primary email is used
 * (falling back to the first verified, then the first listed), and
 * `emailVerified` reflects GitHub's flag for whichever email was chosen. When
 * `/user/emails` is unavailable (e.g. the `user:email` scope was not granted),
 * the public profile email is used with `emailVerified: false`. The `/user`
 * payload (plus an `emails` array when fetched) is available on
 * {@link ExternalProfile.raw}.
 *
 * @example
 * ```ts
 * const flow = new ExternalAuthFlow({
 *   provider: githubProvider({
 *     clientId: Deno.env.get("GITHUB_CLIENT_ID")!,
 *     clientSecret: Deno.env.get("GITHUB_CLIENT_SECRET")!,
 *   }),
 * });
 * ```
 */
export function githubProvider(
  options: GithubProviderOptions,
): ExternalProvider {
  const id = "github";
  const fetchImpl: typeof fetch = (input, init) =>
    (options.fetch ?? globalThis.fetch)(input, init);

  async function exchangeCode(input: ExternalProfileInput): Promise<string> {
    const { value } = await runTokenExchange({
      provider: id,
      displayName: "GitHub",
      endpoint: GITHUB_TOKEN_URL,
      body: new URLSearchParams({
        client_id: options.clientId,
        client_secret: options.clientSecret,
        code: input.code,
        redirect_uri: input.redirectUri,
      }),
      requiredField: "access_token",
      fetch: fetchImpl,
      httpErrorHint: `Check that clientId/clientSecret match the GitHub ` +
        `OAuth App and try again.`,
      tokenErrorHint: githubTokenErrorHint,
    });
    return value;
  }

  async function getJson(
    url: string,
    accessToken: string,
  ): Promise<unknown | null> {
    let res: Response;
    try {
      res = await fetchImpl(url, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
        },
      });
    } catch (error) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `could not reach ${url} (${describeError(error)}). Try again.`,
        { cause: error },
      );
    }
    if (!res.ok) {
      await res.body?.cancel();
      return null;
    }
    try {
      return await res.json();
    } catch (error) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `${url} returned a response that was not valid JSON ` +
          `(${describeError(error)}).`,
        { cause: error },
      );
    }
  }

  return {
    id,
    displayName: "GitHub",
    defaultScopes: options.scopes ?? ["read:user", "user:email"],
    usesPkce: false,
    usesNonce: false,
    buildAuthorizationUrl(input: ExternalAuthorizationUrlInput) {
      const url = new URL(GITHUB_AUTHORIZE_URL);
      url.searchParams.set("client_id", options.clientId);
      url.searchParams.set("redirect_uri", input.redirectUri);
      url.searchParams.set("scope", input.scopes.join(" "));
      url.searchParams.set("state", input.state);
      if (input.prompt) url.searchParams.set("prompt", input.prompt);
      return Promise.resolve(url.toString());
    },
    async fetchProfile(input: ExternalProfileInput): Promise<ExternalProfile> {
      const accessToken = await exchangeCode(input);
      const [user, emailsRaw] = await Promise.all([
        getJson(GITHUB_USER_URL, accessToken) as Promise<
          Record<string, unknown> | null
        >,
        getJson(GITHUB_EMAILS_URL, accessToken),
      ]);
      if (!user || user.id === undefined || user.id === null) {
        throw new ExternalAuthError(
          id,
          "provider_error",
          `could not load the user profile from ${GITHUB_USER_URL}. The ` +
            `access token was issued but lacks profile access — ensure the ` +
            `"read:user" scope is requested.`,
        );
      }
      const emails = parseGithubEmails(emailsRaw);
      const chosen = emails?.find((entry) => entry.primary) ??
        emails?.find((entry) => entry.verified) ?? emails?.[0];
      const publicEmail = typeof user.email === "string"
        ? user.email
        : undefined;
      return {
        provider: id,
        subject: String(user.id),
        email: chosen?.email ?? publicEmail,
        emailVerified: chosen?.verified === true,
        name: typeof user.name === "string" ? user.name : undefined,
        picture: typeof user.avatar_url === "string"
          ? user.avatar_url
          : undefined,
        raw: Array.isArray(emailsRaw) ? { ...user, emails: emailsRaw } : user,
      };
    },
  };
}

function parseGithubEmails(raw: unknown): GithubEmailEntry[] | null {
  if (!Array.isArray(raw)) return null;
  const entries: GithubEmailEntry[] = [];
  for (const entry of raw) {
    if (typeof entry !== "object" || entry === null) continue;
    const { email, primary, verified } = entry as Record<string, unknown>;
    if (typeof email !== "string" || email.length === 0) continue;
    entries.push({
      email,
      primary: primary === true,
      verified: verified === true,
    });
  }
  return entries;
}

function githubTokenErrorHint(error: string | undefined): string {
  if (error === "incorrect_client_credentials") {
    return `Check clientId/clientSecret against the GitHub OAuth App ` +
      `settings.`;
  }
  if (error === "redirect_uri_mismatch") {
    return `The redirectUri must exactly match the "Authorization callback ` +
      `URL" configured on the GitHub OAuth App.`;
  }
  if (error === "bad_verification_code") {
    return `The code expired or was already used — ask the user to start ` +
      `signing in again.`;
  }
  return `See https://docs.github.com/apps/oauth-apps for the error's ` +
    `meaning.`;
}
