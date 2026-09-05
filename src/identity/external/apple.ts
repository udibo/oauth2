/**
 * Sign in with Apple connector. Apple is OpenID-Connect-shaped but does not fit
 * {@link oidcProvider}: its client secret is a signed ES256 JWT rather than a
 * static string (see {@link generateAppleClientSecret}), it authenticates the
 * client in the token body (`client_secret_post`), and it requires
 * `response_mode=form_post` whenever profile scopes are requested. This is a
 * dedicated {@link ExternalProvider} that exchanges the code, then verifies the
 * `id_token` signature against Apple's JWKS.
 *
 * The user's name is returned by Apple **only** on the first authorization, in
 * the `form_post` body's `user` field — never in the `id_token`. This connector
 * returns what the `id_token` carries (stable subject, email); capturing the
 * first-authorization name is the callback route's responsibility, since only
 * it sees the form body.
 *
 * @module
 */

import { toArrayBuffer } from "../../utils/_buffer.ts";
import { base64urlDecode } from "../../utils/crypto.ts";
import { assertIdTokenClaims, describeError } from "./_shared.ts";
import { runTokenExchange } from "./_token-exchange.ts";
import {
  type AppleClientSecretFactory,
  type AppleClientSecretOptions,
  createAppleClientSecretFactory,
} from "./apple-client-secret.ts";
import { ExternalAuthError } from "./errors.ts";
import type {
  ExternalAuthorizationUrlInput,
  ExternalProfile,
  ExternalProfileInput,
  ExternalProvider,
} from "./provider.ts";

const APPLE_ISSUER = "https://appleid.apple.com";
const APPLE_AUTHORIZE_URL = "https://appleid.apple.com/auth/authorize";
const APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token";
const APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const JWKS_CACHE_TTL_MS = 60 * 60 * 1000;

const SIGNATURE_NOT_VERIFIED =
  `Apple id_token signature did not verify against Apple's JWKS — the ` +
  `token is forged, corrupted, or signed by an unpublished key.`;

/** Options for {@link appleProvider}. */
export interface AppleProviderOptions
  extends Pick<AppleClientSecretOptions, "teamId" | "keyId" | "privateKey"> {
  /** The Services ID configured for web Sign in with Apple (the `client_id`). */
  clientId: string;
  /** Scopes requested by default. Defaults to `["name", "email"]`. */
  scopes?: string[];
  /**
   * Client-secret lifetime in seconds. Defaults to Apple's practical maximum;
   * see {@link AppleClientSecretOptions.expiresInSeconds}.
   */
  expiresInSeconds?: number;
  /**
   * Override the client-secret source — inject a stub in tests instead of real
   * `.p8` key material. Defaults to a cached factory over the key material.
   */
  clientSecret?: AppleClientSecretFactory;
  /** Fetch implementation for all provider traffic. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

interface JwkWithKid extends JsonWebKey {
  kid?: string;
}

/**
 * Creates a Sign in with Apple connector with id `"apple"`.
 *
 * The flow requests `response_mode=form_post` (Apple's requirement when `name`
 * or `email` scope is present), exchanges the code at Apple's token endpoint
 * with a freshly-signed client-secret JWT, and verifies the returned
 * `id_token`'s RS256 signature against Apple's published keys before trusting
 * its claims (`iss`, `aud`, `azp`, `exp`, and the `nonce` when one was sent,
 * checked exactly as {@link oidcProvider} checks them). Apple's
 * private-relay addresses (`@privaterelay.appleid.com`) are ordinary verified
 * emails and are returned as-is. The raw `id_token` claims — including
 * `is_private_email` — stay on {@link ExternalProfile.raw}.
 *
 * @example
 * ```ts
 * const flow = new ExternalAuthFlow({
 *   provider: appleProvider({
 *     clientId: "com.example.web",
 *     teamId: Deno.env.get("APPLE_TEAM_ID")!,
 *     keyId: Deno.env.get("APPLE_KEY_ID")!,
 *     privateKey: Deno.env.get("APPLE_PRIVATE_KEY")!,
 *   }),
 * });
 * ```
 */
export function appleProvider(options: AppleProviderOptions): ExternalProvider {
  const id = "apple";
  const fetchImpl: typeof fetch = (input, init) =>
    (options.fetch ?? globalThis.fetch)(input, init);
  const clientSecretFactory = options.clientSecret ??
    createAppleClientSecretFactory({
      providerId: id,
      teamId: options.teamId,
      keyId: options.keyId,
      clientId: options.clientId,
      privateKey: options.privateKey,
      expiresInSeconds: options.expiresInSeconds,
    });
  let jwksCache: { keys: JwkWithKid[]; fetchedAt: number } | null = null;

  async function exchangeCode(input: ExternalProfileInput): Promise<string> {
    const clientSecret = await clientSecretFactory();
    const { value } = await runTokenExchange({
      provider: id,
      displayName: "Apple",
      endpoint: APPLE_TOKEN_URL,
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: input.code,
        redirect_uri: input.redirectUri,
        client_id: options.clientId,
        client_secret: clientSecret,
      }),
      requiredField: "id_token",
      fetch: fetchImpl,
      httpErrorHint: `An "invalid_client" here means the client-secret JWT ` +
        `is wrong — check the team id, key id, and Services ID (client id).`,
      tokenErrorHint: appleTokenErrorHint,
    });
    return value;
  }

  async function loadJwks(): Promise<JwkWithKid[]> {
    if (jwksCache && Date.now() - jwksCache.fetchedAt < JWKS_CACHE_TTL_MS) {
      return jwksCache.keys;
    }
    let res: Response;
    try {
      res = await fetchImpl(APPLE_JWKS_URL, {
        headers: { Accept: "application/json" },
      });
    } catch (error) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `could not reach Apple's JWKS endpoint (${describeError(error)}).`,
        { cause: error },
      );
    }
    if (!res.ok) {
      await res.body?.cancel();
      throw new ExternalAuthError(
        id,
        "provider_error",
        `Apple's JWKS endpoint responded with HTTP ${res.status}.`,
      );
    }
    let doc: { keys?: unknown };
    try {
      doc = (await res.json()) as { keys?: unknown };
    } catch (error) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `Apple's JWKS endpoint returned invalid JSON (${
          describeError(error)
        }).`,
        { cause: error },
      );
    }
    if (!Array.isArray(doc.keys)) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `Apple's JWKS endpoint returned no "keys" array.`,
      );
    }
    const keys = doc.keys as JwkWithKid[];
    jwksCache = { keys, fetchedAt: Date.now() };
    return keys;
  }

  async function verifyIdToken(
    idToken: string,
    expectedNonce: string | undefined,
  ): Promise<Record<string, unknown>> {
    const parts = idToken.split(".");
    if (parts.length !== 3) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `Apple returned a malformed id_token (expected three segments).`,
      );
    }
    const header = decodeJson(id, parts[0], "id_token header");
    const kid = typeof header.kid === "string" ? header.kid : undefined;
    if (header.alg !== "RS256") {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `Apple id_token is signed with "${String(header.alg)}", expected ` +
          `RS256.`,
      );
    }
    if (!kid) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `Apple id_token header has no "kid" — refusing to bind it to an ` +
          `arbitrary JWKS key. Apple always sets "kid" on a real token.`,
      );
    }
    const jwk = await resolveVerificationKey(kid);
    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
    } catch (error) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `Apple's signing key could not be imported (${describeError(error)}).`,
        { cause: error },
      );
    }
    let signature: Uint8Array;
    try {
      signature = base64urlDecode(parts[2]);
    } catch (error) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        SIGNATURE_NOT_VERIFIED,
        {
          cause: error,
        },
      );
    }
    const valid = await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      key,
      toArrayBuffer(signature),
      encoder.encode(`${parts[0]}.${parts[1]}`),
    );
    if (!valid) {
      throw new ExternalAuthError(id, "provider_error", SIGNATURE_NOT_VERIFIED);
    }
    const claims = decodeJson(id, parts[1], "id_token payload");
    assertIdTokenClaims({
      provider: id,
      claims,
      issuer: APPLE_ISSUER,
      clientId: options.clientId,
      expectedNonce,
    });
    return claims;
  }

  async function resolveVerificationKey(kid: string): Promise<JwkWithKid> {
    const pick = (keys: JwkWithKid[]): JwkWithKid | undefined =>
      keys.find((key) => key.kid === kid);
    let match = pick(await loadJwks());
    if (!match) {
      jwksCache = null;
      match = pick(await loadJwks());
    }
    if (!match) {
      throw new ExternalAuthError(
        id,
        "provider_error",
        `Apple's JWKS has no key with kid "${
          String(kid)
        }" — the id_token was ` +
          `signed by a key Apple no longer publishes.`,
      );
    }
    return match;
  }

  return {
    id,
    displayName: "Apple",
    defaultScopes: options.scopes ?? ["name", "email"],
    usesPkce: false,
    usesNonce: true,
    buildAuthorizationUrl(
      input: ExternalAuthorizationUrlInput,
    ): Promise<string> {
      const url = new URL(APPLE_AUTHORIZE_URL);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", options.clientId);
      url.searchParams.set("redirect_uri", input.redirectUri);
      url.searchParams.set("scope", input.scopes.join(" "));
      url.searchParams.set("state", input.state);
      if (input.nonce) url.searchParams.set("nonce", input.nonce);
      if (input.scopes.length > 0) {
        url.searchParams.set("response_mode", "form_post");
      }
      return Promise.resolve(url.toString());
    },
    async fetchProfile(input: ExternalProfileInput): Promise<ExternalProfile> {
      const idToken = await exchangeCode(input);
      const claims = await verifyIdToken(idToken, input.nonce);
      return profileFromClaims(claims);
    },
  };
}

function profileFromClaims(
  claims: Record<string, unknown>,
): ExternalProfile {
  const subject = claims.sub;
  if (typeof subject !== "string" || subject.length === 0) {
    throw new ExternalAuthError(
      "apple",
      "provider_error",
      `Apple id_token is missing the required "sub" claim.`,
    );
  }
  return {
    provider: "apple",
    subject,
    email: typeof claims.email === "string" ? claims.email : undefined,
    emailVerified: isAppleTrue(claims.email_verified),
    raw: claims,
  };
}

function isAppleTrue(value: unknown): boolean {
  return value === true || value === "true";
}

function appleTokenErrorHint(error: string | undefined): string {
  if (error === undefined) {
    return `Ensure the sign-in requested the "openid" flow scopes.`;
  }
  if (error === "invalid_client") {
    return `The client-secret JWT is wrong — check the team id, key id, and ` +
      `Services ID (client id).`;
  }
  if (error === "invalid_grant") {
    return `Apple rejected the code — it expired, was already used, or the ` +
      `redirect URI does not match the Services ID configuration. Ask the ` +
      `user to start again.`;
  }
  return `See Apple's "Generate and validate tokens" documentation for the ` +
    `error's meaning.`;
}

function decodeJson(
  providerId: string,
  segment: string,
  what: string,
): Record<string, unknown> {
  try {
    return JSON.parse(
      decoder.decode(base64urlDecode(segment)),
    ) as Record<string, unknown>;
  } catch (error) {
    throw new ExternalAuthError(
      providerId,
      "provider_error",
      `Apple ${what} was not valid base64url JSON (${describeError(error)}).`,
      { cause: error },
    );
  }
}
