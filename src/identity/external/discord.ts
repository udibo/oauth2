/**
 * Discord sign-in preset over the generic {@link oauth2Provider} connector.
 *
 * @module
 */

import { oauth2Provider } from "./oauth2.ts";
import type { ExternalProvider } from "./provider.ts";

const DISCORD_AUTHORIZE_URL = "https://discord.com/oauth2/authorize";
const DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token";
const DISCORD_USER_URL = "https://discord.com/api/users/@me";

/** Options for {@link discordProvider}. */
export interface DiscordProviderOptions {
  /** Client ID of the Discord application (OAuth2 tab). */
  clientId: string;
  /** The matching client secret. */
  clientSecret: string;
  /** Scopes requested by default. Defaults to `["identify", "email"]`. */
  scopes?: string[];
  /** Fetch implementation for all provider traffic. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

function avatarUrl(
  user: Record<string, unknown>,
): string | undefined {
  const id = user.id;
  const avatar = user.avatar;
  if (typeof id === "string" && typeof avatar === "string" && avatar) {
    const ext = avatar.startsWith("a_") ? "gif" : "png";
    return `https://cdn.discordapp.com/avatars/${id}/${avatar}.${ext}`;
  }
  return undefined;
}

/**
 * Creates a Discord connector with id `"discord"`.
 *
 * Discord speaks plain OAuth2 (no discovery, no id_token), so this is a preset
 * over {@link oauth2Provider} pinned to Discord's fixed endpoints. The profile
 * is read from `GET /users/@me`: the subject is the Discord user id,
 * `emailVerified` reflects Discord's `verified` flag for the account email, and
 * the display name prefers the global display name over the legacy username.
 * The `/users/@me` payload is available on {@link ExternalProfile.raw}.
 *
 * @example
 * ```ts
 * const flow = new ExternalAuthFlow({
 *   provider: discordProvider({
 *     clientId: Deno.env.get("DISCORD_CLIENT_ID")!,
 *     clientSecret: Deno.env.get("DISCORD_CLIENT_SECRET")!,
 *   }),
 * });
 * ```
 */
export function discordProvider(
  options: DiscordProviderOptions,
): ExternalProvider {
  return oauth2Provider({
    id: "discord",
    displayName: "Discord",
    authorizationEndpoint: DISCORD_AUTHORIZE_URL,
    tokenEndpoint: DISCORD_TOKEN_URL,
    userInfoEndpoint: DISCORD_USER_URL,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    defaultScopes: options.scopes ?? ["identify", "email"],
    fetch: options.fetch,
    mapProfile: ({ profile }) => ({
      subject: typeof profile.id === "string" ? profile.id : "",
      email: typeof profile.email === "string" ? profile.email : undefined,
      emailVerified: profile.verified === true,
      name: typeof profile.global_name === "string" && profile.global_name
        ? profile.global_name
        : typeof profile.username === "string"
        ? profile.username
        : undefined,
      picture: avatarUrl(profile),
    }),
  });
}
