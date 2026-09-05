/**
 * Generic OpenID Connect connector: discovery-driven endpoints, PKCE + nonce,
 * profile from id_token claims merged with the UserInfo response.
 *
 * @module
 */

import { DirectClient } from "../../client/direct-client.ts";
import type { DiscoveryCache } from "../../client/discovery-cache.ts";
import { MemoryAuthRequestStorage } from "../../client/storage.ts";
import { isOAuth2Error } from "../../errors.ts";
import type { AuthorizationServerMetadata } from "../../models/responses.ts";
import type { TokenResponse } from "../../models/token.ts";
import { generateCodeChallenge } from "../../utils/pkce.ts";
import {
  assertIdTokenClaims,
  type AzpPolicy,
  describeError,
  stripTrailingSlash,
} from "./_shared.ts";
import { ExternalAuthError } from "./errors.ts";
import type {
  ExternalAuthorizationUrlInput,
  ExternalProfile,
  ExternalProfileInput,
  ExternalProvider,
} from "./provider.ts";

/** Options for {@link oidcProvider}. */
export interface OidcProviderOptions {
  /** Provider id used in profiles and error messages. Defaults to `"oidc"`. */
  id?: string;
  /** Human-readable name for buttons and logs. Defaults to `"OpenID Connect"`. */
  displayName?: string;
  /**
   * The provider's issuer URL. Endpoints are resolved from
   * `${issuer}/.well-known/openid-configuration` (with an RFC 8414 fallback)
   * on first use and cached.
   */
  issuer: string;
  /** The client id registered with the provider. */
  clientId: string;
  /**
   * The client secret, for providers that registered this app as a
   * confidential client (sent via HTTP Basic auth on the token exchange).
   * Omit for public clients — PKCE is always used either way.
   */
  clientSecret?: string;
  /** Scopes requested by default. Defaults to `["openid", "email", "profile"]`. */
  scopes?: string[];
  /**
   * How the id_token's `azp` claim is checked. Defaults to `"conditional"`
   * (OpenID Connect Core §3.1.3.7). Set `"ignore"` only for a provider that
   * reports a different authorized party than the client doing the exchange —
   * see {@link AzpPolicy}.
   */
  azp?: AzpPolicy;
  /** Fetch implementation for all provider traffic. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /**
   * Cache the discovery document is read from and written to, shared with any
   * other connector given the same instance. Supply one when the connector is
   * rebuilt per request (a server resolving provider config from a database),
   * or discovery is re-fetched on every sign-in leg. `MemoryDiscoveryCache`
   * from `@udibo/oauth2/client` is the ready-made implementation.
   */
  discoveryCache?: DiscoveryCache;
}

/**
 * Creates a connector for any spec-compliant OpenID Connect provider.
 *
 * The exchange reuses the package's `DirectClient` (discovery caching with
 * both well-known paths, Basic client auth, RFC 6749 error mapping) with PKCE
 * always on. The profile is built from the id_token claims, merged with the
 * UserInfo response when the provider advertises a `userinfo_endpoint` (the
 * UserInfo `sub` must match the id_token `sub` per OIDC Core §5.3.2, and a
 * UserInfo failure is non-fatal — the id_token claims already suffice).
 *
 * **id_token validation:** the `iss`, `aud`, `azp` (when the token has multiple
 * audiences or an `azp` claim, unless `azp: "ignore"` is configured), `exp`,
 * and `nonce` claims are checked per OpenID Connect Core §3.1.3.7. The
 * signature is deliberately **not** verified: the token arrives directly from
 * the token endpoint over TLS, where §3.1.3.7 permits relying on TLS server
 * validation instead of signature checks (rule 6). Every other rule —
 * including expiry (rule 9) — still applies. Do not feed this connector
 * id_tokens obtained out-of-band.
 *
 * @example
 * ```ts
 * const provider = oidcProvider({
 *   id: "acme",
 *   displayName: "Acme SSO",
 *   issuer: "https://sso.acme.example",
 *   clientId: "my-app",
 *   clientSecret: Deno.env.get("ACME_CLIENT_SECRET")!,
 * });
 * const flow = new ExternalAuthFlow({ provider });
 * ```
 */
export function oidcProvider(options: OidcProviderOptions): ExternalProvider {
  const id = options.id ?? "oidc";
  assertSecureIssuer(id, options.issuer);
  const displayName = options.displayName ?? "OpenID Connect";
  const defaultScopes = options.scopes ?? ["openid", "email", "profile"];
  const fetchImpl: typeof fetch = (input, init) => {
    assertSecureIssuer(
      id,
      input instanceof Request ? input.url : String(input),
    );
    return (options.fetch ?? globalThis.fetch)(input, {
      ...init,
      redirect: "error",
    });
  };
  const authRequestStorage = new MemoryAuthRequestStorage();
  const client = new DirectClient({
    clientId: options.clientId,
    ...(options.clientSecret === undefined
      ? {}
      : { clientSecret: options.clientSecret }),
    issuer: options.issuer,
    fetch: fetchImpl,
    authRequestStorage,
    discoveryCache: options.discoveryCache,
  });

  async function discover(): Promise<AuthorizationServerMetadata> {
    let meta: AuthorizationServerMetadata;
    try {
      meta = await client.discover();
    } catch (error) {
      throw new ExternalAuthError(
        id,
        "configuration",
        `OIDC discovery failed for issuer "${options.issuer}" ` +
          `(${describeError(error)}). Check that the issuer URL is correct ` +
          `and serves "${wellKnownUrl(options.issuer)}".`,
        { cause: error },
      );
    }
    if (normalizeIssuer(meta.issuer) !== normalizeIssuer(options.issuer)) {
      throw new ExternalAuthError(
        id,
        "configuration",
        `discovery document "issuer" is "${
          String(meta.issuer)
        }" but the configured issuer is "${options.issuer}" — OpenID Connect ` +
          `Discovery §4.3 / RFC 8414 §3.3 require them to be identical. The ` +
          `configured issuer likely points at a proxy or the wrong tenant.`,
      );
    }
    for (
      const endpoint of [
        meta.authorization_endpoint,
        meta.token_endpoint,
        meta.userinfo_endpoint,
      ]
    ) {
      if (endpoint !== undefined) assertSecureIssuer(id, endpoint);
    }
    return meta;
  }

  async function exchangeCode(
    input: ExternalProfileInput,
  ): Promise<TokenResponse> {
    const exchangeKey = crypto.randomUUID();
    await authRequestStorage.set(exchangeKey, {
      codeVerifier: input.codeVerifier ?? "",
      createdAt: Date.now(),
    });
    try {
      const { raw } = await client.exchangeAuthorizationCode(
        input.code,
        exchangeKey,
        { redirectUri: input.redirectUri },
      );
      return raw;
    } catch (error) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `token exchange failed (${describeError(error)}). ` +
          tokenExchangeHint(error),
        { cause: error },
      );
    } finally {
      await authRequestStorage.delete(exchangeKey);
    }
  }

  function decodeAndValidateIdToken(
    response: TokenResponse,
    meta: AuthorizationServerMetadata,
    expectedNonce: string | undefined,
  ): Record<string, unknown> {
    const idToken = response.id_token;
    if (!idToken) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `token response contained no id_token. Ensure the "openid" scope ` +
          `is requested and that issuer "${options.issuer}" is an OpenID ` +
          `Connect provider (for plain OAuth2 providers, implement ` +
          `ExternalProvider directly).`,
      );
    }
    let claims: Record<string, unknown>;
    try {
      claims = client.decodeIdToken(idToken);
    } catch (error) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `token endpoint returned a malformed id_token ` +
          `(${describeError(error)}).`,
        { cause: error },
      );
    }
    assertIdTokenClaims({
      provider: id,
      claims,
      issuer: meta.issuer,
      clientId: options.clientId,
      expectedNonce,
      azp: options.azp,
    });
    return claims;
  }

  async function fetchUserInfoClaims(
    meta: AuthorizationServerMetadata,
    accessToken: string,
    idTokenSub: unknown,
  ): Promise<Record<string, unknown> | null> {
    if (!meta.userinfo_endpoint) return null;
    try {
      const res = await fetchImpl(meta.userinfo_endpoint, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
        },
      });
      if (!res.ok) {
        await res.body?.cancel();
        return null;
      }
      const info = (await res.json()) as Record<string, unknown>;
      return info.sub === idTokenSub ? info : null;
    } catch {
      return null;
    }
  }

  return {
    id,
    displayName,
    defaultScopes,
    usesPkce: true,
    usesNonce: true,
    async buildAuthorizationUrl(
      input: ExternalAuthorizationUrlInput,
    ): Promise<string> {
      const meta = await discover();
      if (!meta.authorization_endpoint) {
        throw new ExternalAuthError(
          id,
          "configuration",
          `issuer "${options.issuer}" metadata does not advertise an ` +
            `authorization_endpoint — it cannot drive a browser sign-in.`,
        );
      }
      const url = new URL(meta.authorization_endpoint);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", options.clientId);
      url.searchParams.set("redirect_uri", input.redirectUri);
      url.searchParams.set("scope", input.scopes.join(" "));
      url.searchParams.set("state", input.state);
      if (input.nonce) url.searchParams.set("nonce", input.nonce);
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
      const meta = await discover();
      const response = await exchangeCode(input);
      const claims = decodeAndValidateIdToken(response, meta, input.nonce);
      const userInfo = await fetchUserInfoClaims(
        meta,
        response.access_token,
        claims.sub,
      );
      return profileFromOidcClaims(id, { ...claims, ...userInfo });
    },
  };
}

function profileFromOidcClaims(
  provider: string,
  claims: Record<string, unknown>,
): ExternalProfile {
  const subject = claims.sub;
  if (typeof subject !== "string" || subject.length === 0) {
    throw new ExternalAuthError(
      provider,
      "provider_error",
      `id_token is missing the required "sub" claim.`,
    );
  }
  return {
    provider,
    subject,
    email: asString(claims.email),
    emailVerified: claims.email_verified === true,
    name: asString(claims.name),
    givenName: asString(claims.given_name),
    familyName: asString(claims.family_name),
    picture: asString(claims.picture),
    raw: claims,
  };
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function wellKnownUrl(issuer: string): string {
  return `${stripTrailingSlash(issuer)}/.well-known/openid-configuration`;
}

function normalizeIssuer(value: unknown): string {
  return stripTrailingSlash(typeof value === "string" ? value : "");
}

function assertSecureIssuer(id: string, issuer: string): void {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    throw new ExternalAuthError(
      id,
      "configuration",
      `issuer "${issuer}" is not a valid absolute URL.`,
    );
  }
  const loopback = url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new ExternalAuthError(
      id,
      "configuration",
      `issuer "${issuer}" must use https — this connector trusts the ` +
        `id_token because it arrives directly from the token endpoint over ` +
        `TLS, so a non-TLS issuer removes that guarantee. Only localhost may ` +
        `use http, for development.`,
    );
  }
}

function tokenExchangeHint(error: unknown): string {
  const code = isOAuth2Error(error) ? error.extensions.error : undefined;
  if (code === "invalid_client") {
    return `The provider rejected the client credentials — check clientId ` +
      `and clientSecret against the provider's app registration.`;
  }
  if (code === "invalid_grant") {
    return `The provider rejected the code — most often the redirectUri ` +
      `does not exactly match the URI registered with the provider, or the ` +
      `code expired or was already used.`;
  }
  return `Check the provider's app registration (client credentials and ` +
    `redirect URI) if this persists.`;
}
