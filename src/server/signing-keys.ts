/**
 * OIDC signing keys and compact JWS signing — Web Crypto only, no
 * dependencies. Backs id_token issuance, the JWKS endpoint, and the optional
 * signed (JWT) access-token generator.
 *
 * Keys are ES256 (the OIDC-recommended default with broad library support).
 * Generate once with {@link generateSigningKey}, persist via
 * {@link exportSigningKeyJwk}, and load on boot with {@link importSigningKeyJwk}
 * so every instance of a multi-instance deploy signs with the same key (an
 * ephemeral per-instance key would fail verification across instances).
 *
 * @module
 */

import { base64urlDecode, base64urlEncode } from "../utils/crypto.ts";

/** A ready-to-use signing key: private half signs, public JWK is published. */
export interface SigningKey {
  /** Key id, stamped into JWS headers and the JWKS entry. */
  kid: string;
  /** JWS algorithm. Always `ES256` today. */
  alg: "ES256";
  /** The private key used to sign. */
  privateKey: CryptoKey;
  /** The public JWK (no private material) served from the JWKS endpoint. */
  publicJwk: JsonWebKey & { kid: string; alg: string; use: string };
}

/**
 * Provides the server's current signing key. A provider seam so key storage
 * and rotation stay app-owned; {@link StaticSigningKeyProvider} covers the
 * single-key case.
 */
export interface SigningKeyProvider {
  /** The key new tokens are signed with. */
  getSigningKey(): Promise<SigningKey>;
  /** Every public key a verifier may need (current + not-yet-expired old). */
  getPublicJwks(): Promise<{ keys: JsonWebKey[] }>;
}

/** A {@link SigningKeyProvider} over one fixed key. */
export class StaticSigningKeyProvider implements SigningKeyProvider {
  readonly #key: SigningKey;

  /** Fixes the single key this provider signs with and publishes. */
  constructor(key: SigningKey) {
    this.#key = key;
  }

  /** The fixed key passed at construction. */
  getSigningKey(): Promise<SigningKey> {
    return Promise.resolve(this.#key);
  }

  /** A JWKS containing only the fixed key's public JWK. */
  getPublicJwks(): Promise<{ keys: JsonWebKey[] }> {
    return Promise.resolve({ keys: [this.#key.publicJwk] });
  }
}

/** Options for {@link RotatingSigningKeyProvider}. */
export interface RotatingSigningKeyProviderOptions {
  /** The key new tokens are signed with. Its `kid` is stamped into every JWS. */
  current: SigningKey;
  /**
   * Keys retired from signing but still published in JWKS so tokens minted
   * before the rotation keep verifying. Omit (or pass `[]`) for the single-key
   * steady state, where this provider behaves exactly like
   * {@link StaticSigningKeyProvider}.
   */
  previous?: SigningKey[];
}

/**
 * A {@link SigningKeyProvider} for rotating the signing key through a JWKS
 * grace window: sign with {@link RotatingSigningKeyProviderOptions.current}
 * only, while {@link RotatingSigningKeyProviderOptions.previous} keys stay
 * published so outstanding tokens keep validating until they expire and every
 * consumer has refetched JWKS.
 *
 * Rotation is: promote the new key to `current`, move the old one into
 * `previous`, and hold that grace window for at least the longest token
 * lifetime before dropping the old key from `previous`. Because
 * {@link signJwt} stamps the current key's `kid` into every JWS header and each
 * published JWK carries its own `kid`, verifiers select the right key by `kid`
 * across the window. Keys are published current-first and de-duplicated by
 * `kid`.
 *
 * A single-key configuration (`previous` empty or omitted) publishes exactly
 * the one key and is behaviourally identical to
 * {@link StaticSigningKeyProvider} — adopting this provider does not change a
 * deployment that has not started a rotation.
 *
 * @example
 * ```ts
 * const provider = new RotatingSigningKeyProvider({
 *   current: await importSigningKeyJwk(JSON.parse(currentJwk)),
 *   previous: [await importSigningKeyJwk(JSON.parse(oldJwk))],
 * });
 * ```
 */
export class RotatingSigningKeyProvider implements SigningKeyProvider {
  readonly #current: SigningKey;
  readonly #publicJwks: { keys: JsonWebKey[] };

  /** Fixes the current signing key and the published set (current + previous). */
  constructor(options: RotatingSigningKeyProviderOptions) {
    this.#current = options.current;
    const seen = new Set<string>();
    const keys: JsonWebKey[] = [];
    for (const key of [options.current, ...(options.previous ?? [])]) {
      if (seen.has(key.kid)) continue;
      seen.add(key.kid);
      keys.push(key.publicJwk);
    }
    this.#publicJwks = { keys };
  }

  /** The current key — the only key new tokens are ever signed with. */
  getSigningKey(): Promise<SigningKey> {
    return Promise.resolve(this.#current);
  }

  /** Public JWKs for the current key and every still-published previous key. */
  getPublicJwks(): Promise<{ keys: JsonWebKey[] }> {
    return Promise.resolve({ keys: [...this.#publicJwks.keys] });
  }
}

const ES256_PARAMS = { name: "ECDSA", namedCurve: "P-256" } as const;
const ES256_SIGN_PARAMS = { name: "ECDSA", hash: "SHA-256" } as const;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function encodeSegment(value: unknown): string {
  return base64urlEncode(encoder.encode(JSON.stringify(value)));
}

/** Maps a user to a JWT `sub` claim: the user's `id` property, else the user itself. */
export function defaultSubjectOf(user: unknown): string {
  return String((user as { id?: unknown })?.id ?? user);
}

function publicJwkOf(
  jwk: JsonWebKey,
  kid: string,
): SigningKey["publicJwk"] {
  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    kid,
    alg: "ES256",
    use: "sig",
  };
}

/** Generate a fresh ES256 signing key with a random `kid`. */
export async function generateSigningKey(): Promise<SigningKey> {
  const pair = await crypto.subtle.generateKey(ES256_PARAMS, true, [
    "sign",
    "verify",
  ]);
  const kid = crypto.randomUUID();
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    kid,
    alg: "ES256",
    privateKey: pair.privateKey,
    publicJwk: publicJwkOf(jwk, kid),
  };
}

/**
 * Export a signing key (including private material) as a JWK for persistence
 * — e.g. into a secret-manager entry the app loads on boot. Guard it like any
 * credential.
 */
export async function exportSigningKeyJwk(
  key: SigningKey,
): Promise<JsonWebKey & { kid: string }> {
  const jwk = await crypto.subtle.exportKey("jwk", key.privateKey);
  return { ...jwk, kid: key.kid, alg: key.alg };
}

/** Import a signing key previously exported with {@link exportSigningKeyJwk}. */
export async function importSigningKeyJwk(
  jwk: JsonWebKey & { kid?: string },
): Promise<SigningKey> {
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    ES256_PARAMS,
    true,
    ["sign"],
  );
  const kid = jwk.kid ?? crypto.randomUUID();
  return {
    kid,
    alg: "ES256",
    privateKey,
    publicJwk: publicJwkOf(jwk, kid),
  };
}

/**
 * Sign a compact JWS (`header.payload.signature`) with the given key —
 * the primitive behind id_tokens and JWT access tokens.
 */
export async function signJwt(
  key: SigningKey,
  payload: Record<string, unknown>,
  header: Record<string, unknown> = {},
): Promise<string> {
  const signingInput = `${
    encodeSegment({ alg: key.alg, typ: "JWT", kid: key.kid, ...header })
  }.${encodeSegment(payload)}`;
  const signature = await crypto.subtle.sign(
    ES256_SIGN_PARAMS,
    key.privateKey,
    encoder.encode(signingInput),
  );
  return `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
}

/** Options for {@link verifyJwt}. */
export interface VerifyJwtOptions {
  /**
   * Accept a payload whose `exp` has passed. Only for a token used as a
   * **hint** rather than as authority — OIDC RP-Initiated Logout's
   * `id_token_hint` is the case this exists for, since the id_token naming the
   * session to end has usually outlived its own lifetime by the time anyone
   * logs out. Never set it for a token that authorizes something.
   *
   * @default false
   */
  ignoreExpiration?: boolean;
}

/**
 * Verify a compact JWS against a public JWK and return its payload, or
 * `undefined` when the signature (or shape) is invalid or the payload's `exp`
 * is in the past. Exported for tests and lightweight in-process verification;
 * production resource servers should verify against the JWKS endpoint with
 * their JOSE library of choice.
 */
export async function verifyJwt(
  jwt: string,
  publicJwk: JsonWebKey,
  options: VerifyJwtOptions = {},
): Promise<Record<string, unknown> | undefined> {
  const parts = jwt.split(".");
  if (parts.length !== 3) return undefined;
  const [headerPart, payloadPart, signaturePart] = parts;
  try {
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      publicJwk,
      ES256_PARAMS,
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify(
      ES256_SIGN_PARAMS,
      publicKey,
      new Uint8Array(base64urlDecode(signaturePart)),
      encoder.encode(`${headerPart}.${payloadPart}`),
    );
    if (!valid) return undefined;
    const payload: Record<string, unknown> = JSON.parse(
      decoder.decode(base64urlDecode(payloadPart)),
    );
    if (
      !options.ignoreExpiration &&
      typeof payload.exp === "number" && payload.exp * 1000 <= Date.now()
    ) {
      return undefined;
    }
    return payload;
  } catch {
    return undefined;
  }
}

/**
 * Build a `generateAccessToken` implementation that issues **signed JWT
 * access tokens** (RFC 9068 `at+jwt`) instead of opaque strings — the
 * "verifiable signed-token option": resource servers can validate offline
 * against the JWKS endpoint. Wire it into your token service:
 *
 * ```ts
 * class JwtTokenService extends MyTokenService {
 *   override generateAccessToken = createJwtAccessTokenGenerator({
 *     signingKeys, issuer: "https://auth.example.com",
 *   });
 * }
 * ```
 *
 * The token store still persists the (hashed) JWT string, so revocation and
 * introspection keep working exactly as with opaque tokens.
 */
export function createJwtAccessTokenGenerator(options: {
  /** Keys the tokens are signed with (also served from JWKS). */
  signingKeys: SigningKeyProvider;
  /** The `iss` claim — must match the advertised issuer. */
  issuer: string;
  /**
   * The `aud` claim — per RFC 9068 an identifier of the resource server(s)
   * the token is intended for (e.g. `https://api.example.com`). Defaults to
   * the client id, which single-resource validators must then accept.
   */
  audience?: string;
  /** Token lifetime in seconds for the `exp` claim. Defaults to 3600. */
  lifetimeSeconds?: number;
  /** Maps a user to the `sub` claim. Defaults to the user's `id` property. */
  subjectOf?: (user: unknown) => string;
  /**
   * Extra claims for the resource owner's tokens — the same seam
   * `AuthorizationServer`'s `userClaims` option gives the id_token, so one
   * claims computation can feed both. Called only when a user is present: a
   * client-credentials token has no resource owner, so it never carries user
   * claims. The protocol claims (`iss`, `sub`, `aud`, `client_id`, `iat`,
   * `exp`, `jti`, `scope`) always win — a returned claim under one of those
   * names is discarded, never merged.
   */
  userClaims?: (
    user: unknown,
    scope?: { toString(): string } | null,
    client?: { id: string },
  ) => Record<string, unknown> | Promise<Record<string, unknown>>;
}): (
  client: { id: string },
  user: unknown,
  scope?: { toString(): string } | null,
) => Promise<string> {
  const lifetime = options.lifetimeSeconds ?? 3600;
  const subjectOf = options.subjectOf ?? defaultSubjectOf;
  return async (client, user, scope) => {
    const key = await options.signingKeys.getSigningKey();
    const now = Math.floor(Date.now() / 1000);
    const extraClaims = user && options.userClaims
      ? await options.userClaims(user, scope, client)
      : undefined;
    const payload: Record<string, unknown> = {
      ...extraClaims,
      iss: options.issuer,
      sub: user ? subjectOf(user) : client.id,
      client_id: client.id,
      aud: options.audience ?? client.id,
      iat: now,
      exp: now + lifetime,
      jti: crypto.randomUUID(),
    };
    const scopeText = scope?.toString();
    if (scopeText) payload.scope = scopeText;
    else delete payload.scope;
    return await signJwt(key, payload, { typ: "at+jwt" });
  };
}
