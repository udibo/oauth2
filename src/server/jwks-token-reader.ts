/**
 * Token reader that validates JWT access tokens locally against the
 * issuer's published JWKS, with no per-request network hop.
 *
 * This is the validating half of RFC 9068 (`at+jwt`): the authorization
 * server signs access tokens and publishes its public keys at a `jwks_uri`;
 * the resource server fetches those keys once, caches them, and verifies
 * every subsequent token in-process. Signature verification uses Web Crypto
 * only — the package takes no JOSE dependency.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9068
 * @see https://datatracker.ietf.org/doc/html/rfc7517
 * @module
 */

import { ServerError, TemporarilyUnavailableError } from "../errors.ts";
import type { ClientInterface } from "../models/client.ts";
import type { AbstractScope, ScopeConstructor } from "../models/scope.ts";
import { BasicScope } from "../models/scope.ts";
import type { Token } from "../models/token.ts";
import { toArrayBuffer } from "../utils/_buffer.ts";
import { base64urlDecode } from "../utils/crypto.ts";
import type { TokenReaderInterface } from "./services/token.ts";

/**
 * Claims of a validated JWT access token, as defined by RFC 9068 §2.2.
 *
 * Passed to the {@linkcode JwksTokenReaderOptions.getClient} and
 * {@linkcode JwksTokenReaderOptions.getUser} mappers. Issuers routinely add
 * their own claims (roles, tenant, email); the index signature exposes them.
 */
export interface JwtAccessTokenClaims {
  /** Issuer that signed the token. Verified against the configured issuer. */
  iss: string;
  /** Subject — the end user, or the client itself for client-credentials tokens. */
  sub?: string;
  /** Audience(s) the token is intended for. Verified against the configured audience. */
  aud: string | string[];
  /** Expiration time, seconds since the epoch. */
  exp: number;
  /** Issued-at time, seconds since the epoch. */
  iat?: number;
  /** Not-before time, seconds since the epoch. */
  nbf?: number;
  /** Unique token identifier. */
  jti?: string;
  /** Client the token was issued to. */
  client_id?: string;
  /** Space-delimited granted scopes. */
  scope?: string;
  /** Granted scopes as an array or string — the variant some issuers emit instead of `scope`. */
  scp?: string | string[];
  /** Extension claims. Issuers may add anything. */
  [claim: string]: unknown;
}

/**
 * Options for configuring the JWKS token reader.
 *
 * {@linkcode issuer} and {@linkcode audience} are required because RFC 9068
 * §4 requires a resource server to reject tokens minted for a different
 * issuer or a different audience — with local validation there is no
 * authorization server in the request path to do it for you.
 */
export interface JwksTokenReaderOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> {
  /**
   * Expected `iss` claim. Also the discovery base when
   * {@linkcode jwksUri} is omitted.
   */
  issuer: string;
  /**
   * Accepted `aud` claim value(s) — this resource server's identifier. A
   * token passes when its `aud` (string or array) includes at least one of
   * these. Authorization servers that default `aud` to the client id
   * require listing the client ids you accept.
   */
  audience: string | string[];
  /**
   * URL of the issuer's JWKS. Omit to discover it from `issuer`, trying
   * `/.well-known/oauth-authorization-server` then
   * `/.well-known/openid-configuration` inserted before the issuer's path
   * component (RFC 8414 §3.1), then the OIDC Core form with
   * `/.well-known/openid-configuration` appended. For a path-less issuer the
   * last two are the same URL and only one request is made.
   */
  jwksUri?: string;
  /**
   * JWS algorithms accepted from the token header, intersected with what the
   * matched key supports. Defaults to every asymmetric algorithm Web Crypto
   * covers: `ES256`/`ES384`/`ES512`, `RS256`/`RS384`/`RS512`, and
   * `PS256`/`PS384`/`PS512`. Pin it to what your issuer actually signs with
   * when you can. Symmetric (`HS*`) and `none` are never accepted.
   */
  algorithms?: string[];
  /**
   * Accepted `typ` header values, compared case-insensitively with an
   * optional `application/` prefix. Defaults to `["at+jwt"]` per RFC 9068 §4.
   *
   * This is the first line of defense against another JWT the same issuer
   * signs — an OIDC `id_token` above all — being replayed as an access
   * token. Prefer configuring your issuer to stamp `at+jwt` over widening
   * this. If you must widen it (`["at+jwt", "jwt"]`) or disable it (`[]`),
   * give this API an {@linkcode audience} that is **not** one of your client
   * ids, since an `id_token`'s `aud` is a client id. The
   * {@linkcode clientIdClaim} requirement and the rejection of
   * `id_token`-only claims still apply either way.
   */
  types?: string[];
  /**
   * Claim carrying the client id, required on every accepted token (RFC 9068
   * §2.2 makes `client_id` REQUIRED, and its absence is what tells an
   * `id_token` apart from an access token). Defaults to `"client_id"`; point
   * it at the vendor claim for issuers that deviate — Okta's `cid`, Azure
   * AD v1's `appid`. There is deliberately no way to drop the requirement.
   */
  clientIdClaim?: string;
  /**
   * Leeway in seconds applied to `exp` and `nbf` to absorb clock drift
   * between the issuer and this server. Defaults to 30.
   *
   * This governs this reader's own claim checks. The token it returns carries
   * the issuer's `exp` verbatim, and {@linkcode ResourceServer} re-checks that
   * against its own {@linkcode ResourceServerOptions.clockSkewSeconds}, which
   * defaults to no leeway — so set that one too for a resource server that
   * must tolerate an about-to-expire token.
   */
  clockSkewSeconds?: number;
  /**
   * How long a fetched JWKS is served before the next validation refreshes
   * it. Defaults to 600000 (10 minutes). A refresh that fails keeps serving
   * the cached keys. Zero or negative makes every read refresh — supported,
   * and the deterministic setting for tests, but it leans on
   * {@link JwksTokenReaderOptions.minFetchIntervalMs} alone for rate limiting.
   */
  cacheMaxAgeMs?: number;
  /**
   * Minimum interval between JWKS fetches. Defaults to 30000 (30 seconds).
   * This is the guard that stops a flood of tokens bearing unknown `kid`s
   * from turning this reader into a JWKS-endpoint DoS amplifier; the cost is
   * that a key rotation is picked up at most one interval late. Zero or
   * negative removes the throttle entirely — a test-only setting, never
   * appropriate against a real endpoint.
   */
  minFetchIntervalMs?: number;
  /**
   * Deadline in milliseconds for a JWKS or discovery request. Defaults to
   * 5000. Without it a blackholed endpoint (dropped packets rather than a
   * refused connection) would hang the refresh — and with it every request
   * that joins the shared in-flight fetch. Ignored by an injected
   * {@linkcode fetch} that doesn't honour `AbortSignal`.
   */
  fetchTimeoutMs?: number;
  /** Optional scope constructor for parsing scope strings. Defaults to BasicScope. */
  Scope?: ScopeConstructor<S>;
  /**
   * Projects a validated token's claims into a typed `Client`. Required
   * because the client shape is app-specific; `client_id` (RFC 9068) is the
   * usual key.
   *
   * May be async — return a promise to enrich from a DB lookup.
   */
  getClient: (claims: JwtAccessTokenClaims) => Client | Promise<Client>;
  /**
   * Projects a validated token's claims into a typed `User`. Return
   * `undefined` when the token doesn't represent a user (e.g.
   * client-credentials tokens). Omit entirely if your app never reads user
   * info off the token.
   *
   * May be async — return a promise to enrich from a DB lookup or the
   * issuer's UserInfo endpoint, using `claims.sub` as the lookup key.
   */
  getUser?: (
    claims: JwtAccessTokenClaims,
  ) => User | undefined | Promise<User | undefined>;
  /**
   * `fetch` implementation used for JWKS and discovery requests. Defaults to
   * the global `fetch`. Inject it to route through a custom client (mTLS,
   * timeouts, retries) or to stub the network in tests.
   */
  fetch?: typeof fetch;
}

interface AlgorithmSpec {
  kty: string;
  crv?: string;
  importParams: EcKeyImportParams | RsaHashedImportParams;
  verifyParams: AlgorithmIdentifier | EcdsaParams | RsaPssParams;
}

const ALGORITHMS: Record<string, AlgorithmSpec> = {
  ES256: {
    kty: "EC",
    crv: "P-256",
    importParams: { name: "ECDSA", namedCurve: "P-256" },
    verifyParams: { name: "ECDSA", hash: "SHA-256" },
  },
  ES384: {
    kty: "EC",
    crv: "P-384",
    importParams: { name: "ECDSA", namedCurve: "P-384" },
    verifyParams: { name: "ECDSA", hash: "SHA-384" },
  },
  ES512: {
    kty: "EC",
    crv: "P-521",
    importParams: { name: "ECDSA", namedCurve: "P-521" },
    verifyParams: { name: "ECDSA", hash: "SHA-512" },
  },
  RS256: {
    kty: "RSA",
    importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    verifyParams: { name: "RSASSA-PKCS1-v1_5" },
  },
  RS384: {
    kty: "RSA",
    importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
    verifyParams: { name: "RSASSA-PKCS1-v1_5" },
  },
  RS512: {
    kty: "RSA",
    importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
    verifyParams: { name: "RSASSA-PKCS1-v1_5" },
  },
  PS256: {
    kty: "RSA",
    importParams: { name: "RSA-PSS", hash: "SHA-256" },
    verifyParams: { name: "RSA-PSS", saltLength: 32 },
  },
  PS384: {
    kty: "RSA",
    importParams: { name: "RSA-PSS", hash: "SHA-384" },
    verifyParams: { name: "RSA-PSS", saltLength: 48 },
  },
  PS512: {
    kty: "RSA",
    importParams: { name: "RSA-PSS", hash: "SHA-512" },
    verifyParams: { name: "RSA-PSS", saltLength: 64 },
  },
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type PublishedJwk = JsonWebKey & { kid?: string };

interface JwksEntry {
  jwk: PublishedJwk;
  kid?: string;
  alg?: string;
  imported: Map<string, CryptoKey>;
}

interface ParsedJws {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: ArrayBuffer;
  signature: ArrayBuffer;
}

function parseJws(jwt: string): ParsedJws | undefined {
  const parts = jwt.split(".");
  if (parts.length !== 3) return undefined;
  const [headerPart, payloadPart, signaturePart] = parts;
  try {
    const header = JSON.parse(decoder.decode(base64urlDecode(headerPart)));
    const payload = JSON.parse(decoder.decode(base64urlDecode(payloadPart)));
    if (!isRecord(header) || !isRecord(payload)) return undefined;
    return {
      header,
      payload,
      signingInput: toArrayBuffer(
        encoder.encode(`${headerPart}.${payloadPart}`),
      ),
      signature: toArrayBuffer(base64urlDecode(signaturePart)),
    };
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const MEDIA_TYPE_PREFIX = "application/";

function normalizeType(value: string): string {
  const lowered = value.toLowerCase();
  return lowered.startsWith(MEDIA_TYPE_PREFIX)
    ? lowered.slice(MEDIA_TYPE_PREFIX.length)
    : lowered;
}

function verifyJwkOf(jwk: PublishedJwk): JsonWebKey {
  return jwk.kty === "EC"
    ? { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true }
    : { kty: jwk.kty, n: jwk.n, e: jwk.e, ext: true };
}

function usableForVerification(jwk: PublishedJwk): boolean {
  if (jwk.kty !== "EC" && jwk.kty !== "RSA") return false;
  if (jwk.use !== undefined && jwk.use !== "sig") return false;
  if (jwk.key_ops !== undefined) {
    if (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes("verify")) {
      return false;
    }
  }
  if (jwk.alg !== undefined) {
    if (typeof jwk.alg !== "string" || !(jwk.alg in ALGORITHMS)) return false;
  }
  return true;
}

const ID_TOKEN_ONLY_CLAIMS = ["nonce", "at_hash", "c_hash", "s_hash"];

function metadataUrlsFor(issuer: string): string[] {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    throw new TypeError("`issuer` must be an absolute URL");
  }
  const path = url.pathname.replace(/\/$/, "");
  return [
    ...new Set([
      `${url.origin}/.well-known/oauth-authorization-server${path}`,
      `${url.origin}/.well-known/openid-configuration${path}`,
      `${url.origin}${path}/.well-known/openid-configuration`,
    ]),
  ];
}

function scopeTextOf(claims: JwtAccessTokenClaims): string | undefined {
  if (typeof claims.scope === "string" && claims.scope) return claims.scope;
  if (Array.isArray(claims.scp)) return claims.scp.join(" ") || undefined;
  if (typeof claims.scp === "string" && claims.scp) return claims.scp;
  return undefined;
}

/**
 * Validates JWT access tokens (RFC 9068) against the issuer's remote JWKS.
 *
 * Use this with {@linkcode ResourceServer} when the authorization server
 * issues **signed** access tokens: keys are fetched once and cached on the
 * instance, so validation costs no network round-trip per request — the
 * trade-off against {@linkcode IntrospectionTokenReader}, which sees
 * revocation immediately but calls the authorization server every time. A
 * revoked JWT stays valid here until it expires, so keep access-token
 * lifetimes short, or introspect on the endpoints where revocation latency
 * matters.
 *
 * A token is accepted only when its signature verifies against a published
 * key whose algorithm the header matches, and its `typ`, `iss`, `aud`, `exp`
 * and `nbf` all satisfy the configuration. Anything else is `undefined` —
 * the same `invalid_token` surface as an unknown opaque token. Unreachable
 * key material throws instead, so a down issuer is never reported as a bad
 * token.
 *
 * **Token substitution.** An access token must never be confused with
 * another JWT the same issuer signs. Three checks enforce that
 * independently: `typ` must be `at+jwt`
 * ({@linkcode JwksTokenReaderOptions.types}), the client-id claim must be
 * present ({@linkcode JwksTokenReaderOptions.clientIdClaim}, REQUIRED by
 * RFC 9068 §2.2 and absent from an `id_token`), and `id_token`-only claims
 * (`nonce`, `at_hash`, `c_hash`, `s_hash`) are rejected outright.
 * `auth_time`, `acr` and `amr` are **not** in that list — RFC 9068 §2.2.1
 * permits them on an access token. A `crit` header is rejected per RFC 7515
 * §4.1.11, since this reader understands no JWS extensions.
 *
 * The cache lives on the instance: construct one reader and reuse it.
 *
 * @example
 * ```ts
 * import { JwksTokenReader, ResourceServer } from "@udibo/oauth2/server/resource";
 *
 * interface MyClient { id: string }
 * interface MyUser { id: string }
 *
 * const tokenReader = new JwksTokenReader<MyClient, MyUser>({
 *   issuer: "https://auth.example.com",
 *   audience: "https://api.example.com",
 *   getClient: (claims) => ({ id: String(claims.client_id) }),
 *   getUser: (claims) => claims.sub ? { id: claims.sub } : undefined,
 * });
 *
 * const resourceServer = new ResourceServer<MyClient, MyUser>({
 *   resolve: () => ({ services: { tokenService: tokenReader } }),
 * });
 * ```
 */
export class JwksTokenReader<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> implements TokenReaderInterface<Client, User, S> {
  readonly #issuer: string;
  readonly #audience: string[];
  readonly #algorithms: string[];
  readonly #types: string[];
  readonly #clientIdClaim: string;
  readonly #clockSkewSeconds: number;
  readonly #cacheMaxAgeMs: number;
  readonly #minFetchIntervalMs: number;
  readonly #fetchTimeoutMs: number;
  readonly #metadataUrls: string[];
  readonly #Scope: ScopeConstructor<S>;
  readonly #getClient: (
    claims: JwtAccessTokenClaims,
  ) => Client | Promise<Client>;
  readonly #getUser?: (
    claims: JwtAccessTokenClaims,
  ) => User | undefined | Promise<User | undefined>;
  readonly #customFetch?: typeof fetch;

  #jwksUri?: string;
  #entries: JwksEntry[] = [];
  #fetchedAt = 0;
  #lastAttemptAt = 0;
  #inFlight?: Promise<void>;

  /**
   * Defaults: every Web Crypto asymmetric algorithm accepted, `at+jwt`
   * required as `typ`, `client_id` as the required client-id claim, 30
   * seconds of clock skew, a 10-minute cache with a 30-second minimum
   * between fetches, a 5-second request deadline, {@linkcode BasicScope},
   * and the global `fetch`.
   *
   * @throws {TypeError} If `issuer` is not an absolute URL, `audience` is
   *   empty, or `algorithms` names an algorithm this package cannot verify
   *   (a silently ignored entry would read as a policy that isn't enforced).
   */
  constructor(options: JwksTokenReaderOptions<Client, User, S>) {
    this.#issuer = options.issuer;
    this.#metadataUrls = metadataUrlsFor(options.issuer);
    this.#audience = Array.isArray(options.audience)
      ? [...options.audience]
      : [options.audience];
    if (this.#audience.length === 0) {
      throw new TypeError("`audience` must name at least one value");
    }
    this.#algorithms = options.algorithms ?? Object.keys(ALGORITHMS);
    for (const algorithm of this.#algorithms) {
      if (!(algorithm in ALGORITHMS)) {
        throw new TypeError(`unsupported algorithm: ${algorithm}`);
      }
    }
    this.#types = (options.types ?? ["at+jwt"]).map(normalizeType);
    this.#clientIdClaim = options.clientIdClaim ?? "client_id";
    this.#clockSkewSeconds = options.clockSkewSeconds ?? 30;
    this.#cacheMaxAgeMs = options.cacheMaxAgeMs ?? 600_000;
    this.#minFetchIntervalMs = options.minFetchIntervalMs ?? 30_000;
    this.#fetchTimeoutMs = options.fetchTimeoutMs ?? 5_000;
    this.#Scope = options.Scope ??
      (BasicScope as unknown as ScopeConstructor<S>);
    this.#getClient = options.getClient;
    this.#getUser = options.getUser;
    this.#customFetch = options.fetch;
    this.#jwksUri = options.jwksUri;
  }

  /**
   * Validates a JWT access token against the cached JWKS.
   *
   * Refreshes the keys when no published key verifies the signature — at
   * most one fetch per {@linkcode
   * JwksTokenReaderOptions.minFetchIntervalMs}, shared by concurrent
   * callers. A token whose `kid` matched a cached key and still failed
   * verification is a forgery, not a rotation, and provokes no fetch. A
   * stale cache refreshes in the background: requests are served from the
   * cached keys rather than blocked on the issuer.
   *
   * @returns The token with client/user/scope info, or `undefined` when the
   *   token is malformed, signed by an unknown or unaccepted key, or fails
   *   any claim check.
   * @throws {TemporarilyUnavailableError} If the JWKS (or discovery
   *   document) is unreachable or returns a 5xx **and** no cached keys are
   *   available — a down issuer must be distinguishable from a genuinely
   *   invalid token, not collapsed into it. Once keys are cached, a failed
   *   refresh is absorbed and the cached keys keep serving.
   * @throws {ServerError} If the JWKS endpoint returns a 4xx or a body that
   *   is not a JWKS, or discovery reports no `jwks_uri` — a
   *   misconfiguration, not a verdict on the caller's token.
   */
  async getToken(
    accessToken: string,
  ): Promise<Token<Client, User, S> | undefined> {
    const parsed = parseJws(accessToken);
    if (!parsed) return undefined;

    const { alg, kid, typ, crit } = parsed.header;
    if (crit !== undefined) return undefined;
    if (typeof alg !== "string" || !this.#algorithms.includes(alg)) {
      return undefined;
    }
    if (!this.#acceptsType(typ)) return undefined;

    const verified = await this.#verified(
      parsed,
      alg,
      typeof kid === "string" ? kid : undefined,
    );
    if (!verified) return undefined;

    const claims = parsed.payload as unknown as JwtAccessTokenClaims;
    if (!this.#validClaims(claims)) return undefined;

    const [client, user] = await Promise.all([
      this.#getClient(claims),
      this.#getUser?.(claims),
    ]);
    const scopeText = scopeTextOf(claims);

    return {
      accessToken,
      accessTokenExpiresAt: new Date(claims.exp * 1000),
      client,
      user,
      scope: scopeText ? new this.#Scope(scopeText) as S : undefined,
      claims: claims as Record<string, unknown>,
    };
  }

  #acceptsType(typ: unknown): boolean {
    if (this.#types.length === 0) return true;
    if (typeof typ !== "string") return false;
    return this.#types.includes(normalizeType(typ));
  }

  #validClaims(claims: JwtAccessTokenClaims): boolean {
    if (claims.iss !== this.#issuer) return false;

    const clientId = claims[this.#clientIdClaim];
    if (typeof clientId !== "string" || !clientId) return false;
    for (const claim of ID_TOKEN_ONLY_CLAIMS) {
      if (claims[claim] !== undefined) return false;
    }

    const audience = Array.isArray(claims.aud)
      ? claims.aud
      : typeof claims.aud === "string"
      ? [claims.aud]
      : [];
    if (!audience.some((value) => this.#audience.includes(value))) return false;

    const now = Math.floor(Date.now() / 1000);
    if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp)) {
      return false;
    }
    if (now >= claims.exp + this.#clockSkewSeconds) return false;
    if (claims.nbf !== undefined) {
      if (typeof claims.nbf !== "number" || !Number.isFinite(claims.nbf)) {
        return false;
      }
      if (claims.nbf - this.#clockSkewSeconds > now) return false;
    }
    return true;
  }

  async #verifySignature(
    candidates: JwksEntry[],
    alg: string,
    parsed: ParsedJws,
  ): Promise<boolean> {
    const { verifyParams } = ALGORITHMS[alg];
    for (const entry of candidates) {
      const key = await this.#importKey(entry, alg);
      if (!key) continue;
      const valid = await crypto.subtle.verify(
        verifyParams,
        key,
        parsed.signature,
        parsed.signingInput,
      );
      if (valid) return true;
    }
    return false;
  }

  async #importKey(
    entry: JwksEntry,
    alg: string,
  ): Promise<CryptoKey | undefined> {
    const cached = entry.imported.get(alg);
    if (cached) return cached;
    try {
      const key = await crypto.subtle.importKey(
        "jwk",
        verifyJwkOf(entry.jwk),
        ALGORITHMS[alg].importParams,
        false,
        ["verify"],
      );
      entry.imported.set(alg, key);
      return key;
    } catch {
      return undefined;
    }
  }

  #match(kid: string | undefined, alg: string): JwksEntry[] {
    const spec = ALGORITHMS[alg];
    return this.#entries.filter((entry) => {
      if (kid !== undefined && entry.kid !== kid) return false;
      if (entry.alg !== undefined && entry.alg !== alg) return false;
      if (entry.jwk.kty !== spec.kty) return false;
      if (spec.crv !== undefined && entry.jwk.crv !== spec.crv) return false;
      return true;
    });
  }

  async #verified(
    parsed: ParsedJws,
    alg: string,
    kid: string | undefined,
  ): Promise<boolean> {
    await this.#ensureKeys();

    const candidates = this.#match(kid, alg);
    if (await this.#verifySignature(candidates, alg, parsed)) return true;
    if (kid !== undefined && candidates.length > 0) return false;

    await this.#refreshQuietly();
    return await this.#verifySignature(this.#match(kid, alg), alg, parsed);
  }

  async #ensureKeys(): Promise<void> {
    if (this.#entries.length === 0) {
      await this.#refresh();
      return;
    }
    if (Date.now() - this.#fetchedAt > this.#cacheMaxAgeMs) {
      void this.#refreshQuietly();
    }
  }

  async #refreshQuietly(): Promise<void> {
    await this.#refresh().catch(() => {});
  }

  async #refresh(): Promise<void> {
    if (this.#inFlight) return await this.#inFlight;
    if (Date.now() - this.#lastAttemptAt < this.#minFetchIntervalMs) {
      if (this.#entries.length === 0) {
        throw new TemporarilyUnavailableError("jwks is unavailable");
      }
      return;
    }
    const promise = this.#load();
    this.#inFlight = promise;
    try {
      await promise;
    } finally {
      this.#inFlight = undefined;
      this.#lastAttemptAt = Date.now();
    }
  }

  async #load(): Promise<void> {
    const jwksUri = this.#jwksUri ?? await this.#discoverJwksUri();
    const body = await this.#fetchJson(jwksUri, "jwks");
    if (!isRecord(body) || !Array.isArray(body.keys)) {
      throw new ServerError("jwks response has no `keys` array");
    }
    this.#entries = body.keys
      .filter((jwk): jwk is PublishedJwk => isRecord(jwk))
      .filter(usableForVerification)
      .map((jwk) => ({
        jwk,
        kid: typeof jwk.kid === "string" ? jwk.kid : undefined,
        alg: typeof jwk.alg === "string" ? jwk.alg : undefined,
        imported: new Map<string, CryptoKey>(),
      }));
    this.#fetchedAt = Date.now();
  }

  async #discoverJwksUri(): Promise<string> {
    let transientError: unknown;
    let lastError: unknown;
    for (const url of this.#metadataUrls) {
      try {
        const metadata = await this.#fetchJson(url, "discovery");
        const jwksUri = isRecord(metadata) ? metadata.jwks_uri : undefined;
        if (typeof jwksUri !== "string") {
          throw new ServerError("discovery metadata has no `jwks_uri`");
        }
        this.#jwksUri = jwksUri;
        return jwksUri;
      } catch (error) {
        if (
          error instanceof TemporarilyUnavailableError &&
          transientError === undefined
        ) {
          transientError = error;
        }
        lastError = error;
      }
    }
    throw transientError ?? lastError ?? new ServerError("discovery failed");
  }

  async #fetchJson(url: string, label: string): Promise<unknown> {
    const fetchImpl = this.#customFetch ?? globalThis.fetch;
    const controller = new AbortController();
    const deadline = setTimeout(
      () => controller.abort(),
      this.#fetchTimeoutMs,
    );
    try {
      let response: Response;
      try {
        response = await fetchImpl(url, {
          headers: { "Accept": "application/json" },
          signal: controller.signal,
        });
      } catch (cause) {
        throw new TemporarilyUnavailableError(`${label} request failed`, {
          cause,
        });
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw response.status >= 500
          ? new TemporarilyUnavailableError(
            `${label} request failed (HTTP ${response.status})`,
          )
          : new ServerError(
            `${label} request failed (HTTP ${response.status})`,
          );
      }
      try {
        return await response.json();
      } catch (cause) {
        throw new ServerError(`${label} response was not JSON`, { cause });
      }
    } finally {
      clearTimeout(deadline);
    }
  }
}
