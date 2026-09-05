/**
 * In-memory implementations of every OAuth2 service interface.
 *
 * The `Memory*Service` family is the public, generic version of the fixtures
 * the library uses for its own tests. They satisfy the
 * `UserServiceInterface`, `ClientServiceInterface`, `TokenServiceInterface`,
 * `AuthorizationCodeServiceInterface`, and `DeviceAuthorizationServiceInterface`
 * contracts using `Map`-backed storage that lives only for the process /
 * test lifetime.
 *
 * They are deliberately **not** for production: tokens and codes vanish on
 * restart, there is no concurrency control, and nothing is ever reclaimed — an
 * expired record stays in its `Map` until something revokes it, and the
 * revoked-refresh-token tombstones that reuse detection reads are kept for the
 * process lifetime, so memory grows with every token issued. Port the shape to
 * a database and it needs the expiry sweep or row TTL these fixtures skip. Use
 * them to:
 *
 * - Spin up a stand-in authorization server in tests of consumer apps.
 * - Prototype an OAuth2 integration before the database schema lands.
 * - Drive examples that need realistic data without DB infrastructure.
 *
 * Pair with `createMemoryAuthorizationServer` for the one-shot factory
 * variant, or compose directly when you need finer control.
 *
 * @module
 */

import type { ClientInterface } from "../models/client.ts";
import type { AuthorizationCode } from "../models/authorization-code.ts";
import type { RefreshToken, Token } from "../models/token.ts";
import type { DeviceAuthorization } from "../models/device-authorization.ts";
import type { AbstractScope, BasicScope } from "../models/scope.ts";
import type { AuthorizationCodeServiceInterface } from "../server/services/authorization-code.ts";
import type { ClientServiceInterface } from "../server/services/client.ts";
import type { DeviceAuthorizationServiceInterface } from "../server/services/device-authorization.ts";
import type { TokenServiceInterface } from "../server/services/token.ts";
import type { UserServiceInterface } from "../server/services/user.ts";
import {
  type PasswordCredential,
  type PasswordHasherLike,
  PasswordIdentityService,
} from "../identity/password.ts";

import { sha256Hash } from "../server/utils/hash.ts";

const FIXTURE_PBKDF2_ITERATIONS = 1_000;

/** Options for {@link MemoryUserService}. */
export interface MemoryUserServiceOptions {
  /**
   * Hasher used to mint and check credentials. Defaults to
   * {@link PasswordIdentityService} at a deliberately low iteration count:
   * these credentials live in a `Map` that dies with the process, so a
   * production work factor defends nothing here and only slows a test suite
   * down. Credentials still record their `params`, so one minted by a
   * production-strength hasher and handed to {@link
   * MemoryUserService.setCredential} verifies unchanged. Pass your own hasher
   * to exercise the real cost.
   */
  passwords?: PasswordHasherLike;
}

/** Minimal user shape the default `MemoryUserService` knows how to index. */
export interface MemoryUserShape {
  /** Stable identifier the service indexes users by. */
  id: string;
  /** Login name used by the resource-owner password and credential lookups. */
  username: string;
}

/**
 * In-memory `UserServiceInterface` implementation.
 *
 * Generic over the user type — supply your real app's `User` interface
 * (extending {@link MemoryUserShape}) so fixtures match production data.
 */
export class MemoryUserService<U extends MemoryUserShape>
  implements UserServiceInterface<U> {
  #usersById = new Map<string, U>();
  #usersByUsername = new Map<string, U>();
  #credentialsByUserId = new Map<string, PasswordCredential>();
  readonly #passwords: PasswordHasherLike;

  /** Applies the password-hasher default; construct with no arguments for it. */
  constructor(options: MemoryUserServiceOptions = {}) {
    this.#passwords = options.passwords ??
      new PasswordIdentityService({ iterations: FIXTURE_PBKDF2_ITERATIONS });
  }

  /** Adds a user with the given password. Throws on duplicate id or username. */
  async add(user: U, password: string): Promise<void> {
    if (this.#usersById.has(user.id)) {
      throw new Error(`User with id "${user.id}" already exists`);
    }
    if (this.#usersByUsername.has(user.username)) {
      throw new Error(`User with username "${user.username}" already exists`);
    }
    this.#usersById.set(user.id, user);
    this.#usersByUsername.set(user.username, user);
    this.#credentialsByUserId.set(
      user.id,
      await this.#passwords.hash(password),
    );
  }

  /** Looks up a user by id, or resolves `undefined` when none is stored. */
  get(id: string): Promise<U | undefined> {
    return Promise.resolve(this.#usersById.get(id));
  }

  /**
   * Resolves the user when the username exists and the password verifies
   * against its stored salt/hash, otherwise `undefined`. Backs the
   * resource-owner password-credentials grant.
   */
  async getAuthenticated(
    username: string,
    password: string,
  ): Promise<U | undefined> {
    const user = this.#usersByUsername.get(username);
    if (!user) return undefined;
    const credential = this.#credentialsByUserId.get(user.id);
    if (!credential) return undefined;
    return await this.#passwords.verify(password, credential)
      ? user
      : undefined;
  }

  /** Looks up a user by username without a password check, or `undefined`. */
  findByUsername(username: string): Promise<U | undefined> {
    return Promise.resolve(this.#usersByUsername.get(username));
  }

  /**
   * The user's stored password credential, or `undefined`. Shape-compatible
   * with the identity layer's `IdentityUserStore.getCredential`, so a
   * memory-backed store can drive the own-auth flows (sign-in, password
   * reset) in examples and tests.
   */
  getCredential(userId: string): Promise<PasswordCredential | undefined> {
    return Promise.resolve(this.#credentialsByUserId.get(userId));
  }

  /**
   * Replace the user's stored password credential (e.g. after a password
   * reset). Matches `IdentityUserStore.setCredential`.
   * @throws Error when no user with `userId` exists.
   */
  setCredential(userId: string, credential: PasswordCredential): Promise<void> {
    if (!this.#usersById.has(userId)) {
      throw new Error(`User with id "${userId}" does not exist`);
    }
    this.#credentialsByUserId.set(userId, credential);
    return Promise.resolve();
  }
}

/**
 * In-memory `ClientServiceInterface` implementation.
 *
 * A client is treated as confidential when {@link add} is called with a
 * secret, and public when it is not — there is no separate flag to
 * remember. `getAuthenticated` requires the secret for confidential
 * clients and accepts a missing secret for public clients.
 */
export class MemoryClientService<C extends ClientInterface, U>
  implements ClientServiceInterface<C, U> {
  #clientsById = new Map<string, C>();
  #secretHashByClientId = new Map<string, string>();
  #ownerUserIdByClientId = new Map<string, string>();
  #userService: UserServiceInterface<U>;

  /**
   * Creates an empty client store backed by the given user service.
   *
   * @param userService Resolves the owner returned by {@linkcode getUser}
   * for the client-credentials grant.
   */
  constructor(userService: UserServiceInterface<U>) {
    this.#userService = userService;
  }

  /**
   * Registers a client. Pass `secret` to make it confidential; omit for a
   * public client. `ownerUserId` is the user returned by {@link getUser},
   * used by the client-credentials grant.
   * @throws Error when a client with the same id is already registered.
   */
  async add(
    client: C,
    secret?: string,
    ownerUserId?: string,
  ): Promise<void> {
    if (this.#clientsById.has(client.id)) {
      throw new Error(`Client with id "${client.id}" already exists`);
    }
    this.#clientsById.set(client.id, client);
    if (secret) {
      this.#secretHashByClientId.set(client.id, await sha256Hash(secret));
    }
    if (ownerUserId) {
      this.#ownerUserIdByClientId.set(client.id, ownerUserId);
    }
  }

  /** Looks up a client by id, or resolves `undefined` when none is stored. */
  get(id: string): Promise<C | undefined> {
    return Promise.resolve(this.#clientsById.get(id));
  }

  /**
   * Resolves the client when authentication succeeds, otherwise `undefined`.
   * Confidential clients (registered with a secret) require a matching
   * `secret`; public clients (registered without one) ignore it.
   */
  async getAuthenticated(
    id: string,
    secret?: string,
  ): Promise<C | undefined> {
    const client = this.#clientsById.get(id);
    if (!client) return undefined;
    const storedHash = this.#secretHashByClientId.get(id);
    if (storedHash) {
      if (!secret) return undefined;
      if (await sha256Hash(secret) !== storedHash) return undefined;
    }
    return client;
  }

  /**
   * Resolves the user registered as the client's owner via the `ownerUserId`
   * passed to {@linkcode add}, or `undefined` when none was set. Accepts the
   * client or its id.
   */
  getUser(client: C | string): Promise<U | undefined> {
    const id = typeof client === "string" ? client : client.id;
    const userId = this.#ownerUserIdByClientId.get(id);
    if (!userId) return Promise.resolve(undefined);
    return this.#userService.get(userId);
  }
}

/** Options for {@link MemoryTokenService}. */
export interface MemoryTokenServiceOptions<
  C extends ClientInterface,
  U extends MemoryUserShape,
> {
  /** Resolves clients when hydrating stored tokens back into full records. */
  clientService: ClientServiceInterface<C, U>;
  /** Resolves users when hydrating stored tokens back into full records. */
  userService: UserServiceInterface<U>;
  /** Default access-token lifetime in seconds. Defaults to 1 hour. */
  accessTokenLifetime?: number;
  /** Default refresh-token lifetime in seconds. Defaults to 14 days. */
  refreshTokenLifetime?: number;
  /**
   * Default absolute lifetime of a refresh-token family in seconds. Omit to
   * leave rotation uncapped.
   */
  refreshTokenMaxLifetime?: number;
}

interface StoredToken<S extends AbstractScope> {
  accessTokenHash: string;
  accessTokenExpiresAt?: Date;
  clientId: string;
  userId?: string;
  scope?: S | null;
  refreshTokenHash?: string;
  refreshTokenExpiresAt?: Date;
  codeHash?: string;
  familyId?: string;
  familyCreatedAt?: Date;
}

/**
 * In-memory `TokenServiceInterface` implementation. Tokens are hashed on
 * write and looked up by hash, mirroring how a real database-backed token
 * service would store them.
 *
 * Per-client lifetime overrides are supported via three optional fields the
 * client may declare: `accessTokenLifetime`, `refreshTokenLifetime`, and
 * `refreshTokenMaxLifetime`. Each takes precedence over the service-wide
 * default when present.
 */
export class MemoryTokenService<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> implements TokenServiceInterface<C, U, S> {
  /** Service-wide access-token lifetime in seconds when a client sets none. */
  accessTokenLifetime: number;
  /** Service-wide refresh-token lifetime in seconds when a client sets none. */
  refreshTokenLifetime: number;
  /**
   * Service-wide absolute refresh-token family lifetime in seconds when a
   * client sets none. Undefined leaves families uncapped.
   */
  refreshTokenMaxLifetime?: number;
  #clientService: ClientServiceInterface<C, U>;
  #userService: UserServiceInterface<U>;
  #tokensByAccessHash = new Map<string, StoredToken<S>>();
  #tokensByRefreshHash = new Map<string, StoredToken<S>>();
  #tokensByCodeHash = new Map<string, Set<string>>();
  #revokedByRefreshHash = new Map<string, StoredToken<S>>();

  /**
   * Creates an empty token store.
   *
   * @param options Backing client/user services and optional default token
   * lifetimes.
   */
  constructor(options: MemoryTokenServiceOptions<C, U>) {
    this.#clientService = options.clientService;
    this.#userService = options.userService;
    this.accessTokenLifetime = options.accessTokenLifetime ?? 60 * 60;
    this.refreshTokenLifetime = options.refreshTokenLifetime ??
      14 * 24 * 60 * 60;
    this.refreshTokenMaxLifetime = options.refreshTokenMaxLifetime;
  }

  /**
   * Accepts the requested scope verbatim; the stub performs no scope
   * narrowing. Return `false` from a subclass to reject a request.
   */
  acceptedScope(
    _client: C,
    _user: U,
    scope?: S | null,
  ): Promise<S | null | undefined | false> {
    return Promise.resolve(scope);
  }

  /** Mints a random opaque access token. */
  generateAccessToken(
    _client: C,
    _user: U,
    _scope?: S | null,
  ): Promise<string> {
    return Promise.resolve(crypto.randomUUID());
  }

  /** Mints a random opaque refresh token. */
  generateRefreshToken(
    _client: C,
    _user: U,
    _scope?: S | null,
  ): Promise<string | undefined> {
    return Promise.resolve(crypto.randomUUID());
  }

  /**
   * Returns now plus the client's `accessTokenLifetime` override, falling back
   * to {@linkcode accessTokenLifetime}.
   */
  accessTokenExpiresAt(
    client: C,
    _user: U,
    _scope?: S | null,
  ): Promise<Date | undefined> {
    const lifetime =
      (client as { accessTokenLifetime?: number }).accessTokenLifetime ??
        this.accessTokenLifetime;
    return Promise.resolve(new Date(Date.now() + lifetime * 1000));
  }

  /**
   * Returns now plus the client's `refreshTokenLifetime` override, falling
   * back to {@linkcode refreshTokenLifetime}.
   */
  refreshTokenExpiresAt(
    client: C,
    _user: U,
    _scope?: S | null,
  ): Promise<Date | undefined> {
    const lifetime =
      (client as { refreshTokenLifetime?: number }).refreshTokenLifetime ??
        this.refreshTokenLifetime;
    return Promise.resolve(new Date(Date.now() + lifetime * 1000));
  }

  /**
   * Returns the family anchor plus the client's `refreshTokenMaxLifetime`
   * override, falling back to {@linkcode refreshTokenMaxLifetime}, or
   * `undefined` when neither caps the family.
   */
  refreshTokenFamilyExpiresAt(
    client: C,
    _user: U,
    familyCreatedAt: Date,
    _scope?: S | null,
  ): Promise<Date | undefined> {
    const maxLifetime = (client as { refreshTokenMaxLifetime?: number })
      .refreshTokenMaxLifetime ??
      this.refreshTokenMaxLifetime;
    return Promise.resolve(
      maxLifetime == null
        ? undefined
        : new Date(familyCreatedAt.getTime() + maxLifetime * 1000),
    );
  }

  async #hydrate(
    stored: StoredToken<S>,
    accessToken: string,
    refreshToken?: string,
  ): Promise<Token<C, U, S> | undefined> {
    const client = await this.#clientService.get(stored.clientId);
    if (!client) return undefined;
    const user = stored.userId
      ? await this.#userService.get(stored.userId)
      : undefined;
    if (stored.userId && !user) return undefined;
    const token: Token<C, U, S> = {
      accessToken,
      accessTokenExpiresAt: stored.accessTokenExpiresAt,
      client,
      user,
      scope: stored.scope,
    };
    if (stored.refreshTokenHash) {
      return {
        ...token,
        refreshToken: refreshToken ?? "",
        refreshTokenExpiresAt: stored.refreshTokenExpiresAt,
        familyId: stored.familyId,
        familyCreatedAt: stored.familyCreatedAt,
      } as RefreshToken<C, U, S>;
    }
    return token;
  }

  /**
   * Resolves the token whose access token hashes to the given value, with its
   * client and user rehydrated, or `undefined` when not found.
   */
  async getToken(accessToken: string): Promise<Token<C, U, S> | undefined> {
    const stored = this.#tokensByAccessHash.get(await sha256Hash(accessToken));
    if (!stored) return undefined;
    return this.#hydrate(stored, accessToken);
  }

  /**
   * Resolves the refresh token whose value hashes to the given input, with its
   * client and user rehydrated, or `undefined` when not found.
   */
  async getRefreshToken(
    refreshToken: string,
  ): Promise<RefreshToken<C, U, S> | undefined> {
    const stored = this.#tokensByRefreshHash.get(
      await sha256Hash(refreshToken),
    );
    if (!stored) return undefined;
    return this.#hydrate(stored, "", refreshToken) as Promise<
      RefreshToken<C, U, S> | undefined
    >;
  }

  /**
   * Persists a token, indexing it by hashed access token (and hashed refresh
   * token, plus authorization-code hash when a `code` is present so
   * {@linkcode revokeCode} can find it). Returns the input unchanged.
   */
  save(
    token: RefreshToken<C, U, S>,
  ): Promise<RefreshToken<C, U, S>>;
  /**
   * Persists a token, indexing it by hashed access token (and authorization-code
   * hash when a `code` is present). Returns the input unchanged.
   */
  save(token: Token<C, U, S>): Promise<Token<C, U, S>>;
  async save(
    token: Token<C, U, S> | RefreshToken<C, U, S>,
  ): Promise<Token<C, U, S> | RefreshToken<C, U, S>> {
    const accessTokenHash = await sha256Hash(token.accessToken);
    const stored: StoredToken<S> = {
      accessTokenHash,
      accessTokenExpiresAt: token.accessTokenExpiresAt,
      clientId: token.client.id,
      userId: token.user?.id,
      scope: token.scope,
    };
    if (token.code) {
      stored.codeHash = await sha256Hash(token.code);
      let bucket = this.#tokensByCodeHash.get(stored.codeHash);
      if (!bucket) {
        bucket = new Set();
        this.#tokensByCodeHash.set(stored.codeHash, bucket);
      }
      bucket.add(accessTokenHash);
    }
    if ("refreshToken" in token) {
      const rt = token as RefreshToken<C, U, S>;
      stored.refreshTokenHash = await sha256Hash(rt.refreshToken);
      stored.refreshTokenExpiresAt = rt.refreshTokenExpiresAt;
      stored.familyId = rt.familyId;
      stored.familyCreatedAt = rt.familyCreatedAt;
      this.#tokensByRefreshHash.set(stored.refreshTokenHash, stored);
    }
    this.#tokensByAccessHash.set(accessTokenHash, stored);
    return token;
  }

  /**
   * Removes the given token and its paired access/refresh entry. Resolves
   * `true` when something was removed, `false` otherwise.
   */
  revoke(token: Token<C, U, S>): Promise<boolean>;
  /**
   * Removes the given refresh token and its paired access entry. Resolves
   * `true` when something was removed, `false` otherwise.
   */
  revoke(token: RefreshToken<C, U, S>): Promise<boolean>;
  /**
   * Removes a token by its raw string value. Pass `hint` of `"refresh_token"`
   * to look it up as a refresh token; any other value treats it as an access
   * token. Resolves `true` when something was removed.
   */
  revoke(token: string, hint?: string | null): Promise<boolean>;
  async revoke(
    token: Token<C, U, S> | RefreshToken<C, U, S> | string,
    hint?: string | null,
  ): Promise<boolean> {
    if (typeof token !== "string") {
      if ("refreshToken" in token && token.refreshToken) {
        hint = "refresh_token";
        token = token.refreshToken;
      } else {
        token = token.accessToken;
      }
    }
    const hashed = await sha256Hash(token);
    const stored = hint === "refresh_token"
      ? this.#tokensByRefreshHash.get(hashed)
      : this.#tokensByAccessHash.get(hashed);
    if (!stored) return false;
    this.#tokensByAccessHash.delete(stored.accessTokenHash);
    if (stored.refreshTokenHash) {
      this.#tombstone(stored.refreshTokenHash, stored);
      this.#tokensByRefreshHash.delete(stored.refreshTokenHash);
    }
    return true;
  }

  #tombstone(refreshTokenHash: string, stored: StoredToken<S>): void {
    this.#revokedByRefreshHash.set(refreshTokenHash, stored);
  }

  /**
   * Looks up a revoked/rotated-out refresh token for the refresh grant's
   * reuse detection: revoked refresh records are kept as tombstones instead
   * of deleted.
   */
  async getRevokedRefreshToken(
    refreshToken: string,
  ): Promise<RefreshToken<C, U, S> | undefined> {
    const stored = this.#revokedByRefreshHash.get(
      await sha256Hash(refreshToken),
    );
    if (!stored) return undefined;
    return this.#hydrate(stored, "", refreshToken) as Promise<
      RefreshToken<C, U, S> | undefined
    >;
  }

  /**
   * Revokes every live token in a rotation family (reuse detection response).
   * Resolves `true` when at least one live token was removed.
   */
  revokeFamily(familyId: string): Promise<boolean> {
    let revoked = false;
    for (const [hash, stored] of this.#tokensByRefreshHash) {
      if (stored.familyId === familyId) {
        this.#tombstone(hash, stored);
        this.#tokensByRefreshHash.delete(hash);
        this.#tokensByAccessHash.delete(stored.accessTokenHash);
        revoked = true;
      }
    }
    for (const [hash, stored] of this.#tokensByAccessHash) {
      if (stored.familyId === familyId) {
        this.#tokensByAccessHash.delete(hash);
        revoked = true;
      }
    }
    return Promise.resolve(revoked);
  }

  /**
   * Removes every token issued from the given authorization code, used when a
   * code is replayed. Resolves `true` when at least one token was removed.
   */
  async revokeCode(code: string): Promise<boolean> {
    const codeHash = await sha256Hash(code);
    const tokenHashes = this.#tokensByCodeHash.get(codeHash);
    if (!tokenHashes || tokenHashes.size === 0) return false;
    for (const accessTokenHash of tokenHashes) {
      const stored = this.#tokensByAccessHash.get(accessTokenHash);
      if (stored) {
        this.#tokensByAccessHash.delete(accessTokenHash);
        if (stored.refreshTokenHash) {
          this.#tokensByRefreshHash.delete(stored.refreshTokenHash);
        }
      }
    }
    this.#tokensByCodeHash.delete(codeHash);
    return true;
  }
}

/** Options for {@link MemoryAuthorizationCodeService}. */
export interface MemoryAuthorizationCodeServiceOptions<
  C extends ClientInterface,
  U extends MemoryUserShape,
> {
  /** Resolves clients when hydrating stored codes back into full records. */
  clientService: ClientServiceInterface<C, U>;
  /** Resolves users when hydrating stored codes back into full records. */
  userService: UserServiceInterface<U>;
  /** Lifetime in seconds. Defaults to 10 minutes. */
  lifetime?: number;
}

interface StoredAuthorizationCode<S extends AbstractScope> {
  codeHash: string;
  expiresAt: Date;
  clientId: string;
  userId: string;
  scope?: S | null;
  redirectUri?: string;
  challenge?: string;
  challengeMethod?: string;
  nonce?: string;
}

/** In-memory `AuthorizationCodeServiceInterface` implementation. */
export class MemoryAuthorizationCodeService<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> implements AuthorizationCodeServiceInterface<C, U, S> {
  /** Authorization-code lifetime in seconds applied by {@linkcode expiresAt}. */
  lifetime: number;
  #clientService: ClientServiceInterface<C, U>;
  #userService: UserServiceInterface<U>;
  #codes = new Map<string, StoredAuthorizationCode<S>>();

  /**
   * Creates an empty authorization-code store.
   *
   * @param options Backing client/user services and optional code lifetime.
   */
  constructor(options: MemoryAuthorizationCodeServiceOptions<C, U>) {
    this.#clientService = options.clientService;
    this.#userService = options.userService;
    this.lifetime = options.lifetime ?? 600;
  }

  /** Mints a random opaque authorization code. */
  generateCode(
    _client: C,
    _user: U,
    _scope?: S | null,
  ): Promise<string> {
    return Promise.resolve(crypto.randomUUID());
  }

  /** Returns now plus {@linkcode lifetime}. */
  expiresAt(
    _client: C,
    _user: U,
    _scope?: S | null,
  ): Promise<Date> {
    return Promise.resolve(new Date(Date.now() + this.lifetime * 1000));
  }

  /**
   * Resolves the code whose value hashes to the given input, with its client
   * and user rehydrated, or `undefined` when not found or either is missing.
   */
  async get(code: string): Promise<AuthorizationCode<C, U, S> | undefined> {
    const stored = this.#codes.get(await sha256Hash(code));
    if (!stored) return undefined;
    const client = await this.#clientService.get(stored.clientId);
    const user = await this.#userService.get(stored.userId);
    if (!client || !user) return undefined;
    return {
      code,
      expiresAt: stored.expiresAt,
      client,
      user,
      scope: stored.scope,
      redirectUri: stored.redirectUri,
      challenge: stored.challenge,
      challengeMethod: stored.challengeMethod,
      nonce: stored.nonce,
    };
  }

  /**
   * Persists an authorization code indexed by its hash, including the PKCE
   * challenge and redirect URI. Returns the input unchanged.
   */
  async save(
    authorizationCode: AuthorizationCode<C, U, S>,
  ): Promise<AuthorizationCode<C, U, S>> {
    const hashed = await sha256Hash(authorizationCode.code);
    this.#codes.set(hashed, {
      codeHash: hashed,
      expiresAt: authorizationCode.expiresAt,
      clientId: authorizationCode.client.id,
      userId: authorizationCode.user.id,
      scope: authorizationCode.scope,
      redirectUri: authorizationCode.redirectUri,
      challenge: authorizationCode.challenge,
      challengeMethod: authorizationCode.challengeMethod,
      nonce: authorizationCode.nonce,
    });
    return authorizationCode;
  }

  /**
   * Removes a code, accepting the record or its raw string. Resolves `true`
   * when a code was removed, `false` otherwise.
   */
  async revoke(
    authorizationCode: AuthorizationCode<C, U, S> | string,
  ): Promise<boolean> {
    const code = typeof authorizationCode === "string"
      ? authorizationCode
      : authorizationCode.code;
    return this.#codes.delete(await sha256Hash(code));
  }
}

/** Options for {@link MemoryDeviceAuthorizationService}. */
export interface MemoryDeviceAuthorizationServiceOptions<
  C extends ClientInterface,
  U extends MemoryUserShape,
> {
  /** Resolves clients when hydrating stored authorizations into full records. */
  clientService: ClientServiceInterface<C, U>;
  /** Resolves users when hydrating stored authorizations into full records. */
  userService: UserServiceInterface<U>;
  /** Lifetime in seconds. Defaults to 30 minutes. */
  lifetime?: number;
  /** Polling interval floor in seconds. Defaults to 5. */
  interval?: number;
}

interface StoredDeviceAuthorization<S extends AbstractScope> {
  deviceCodeHash: string;
  userCodeHash: string;
  expiresAt: Date;
  clientId: string;
  scope?: S | null;
  interval: number;
  authorized?: boolean;
  userId?: string;
  denied?: boolean;
  lastPolled?: Date;
}

/** In-memory `DeviceAuthorizationServiceInterface` implementation. */
export class MemoryDeviceAuthorizationService<
  C extends ClientInterface,
  U extends MemoryUserShape,
  S extends AbstractScope = BasicScope,
> implements DeviceAuthorizationServiceInterface<C, U, S> {
  /** Device-authorization lifetime in seconds applied by {@linkcode expiresAt}. */
  lifetime: number;
  /** Minimum seconds clients must wait between token-endpoint polls. */
  interval: number;
  #clientService: ClientServiceInterface<C, U>;
  #userService: UserServiceInterface<U>;
  #byDeviceCode = new Map<string, StoredDeviceAuthorization<S>>();
  #byUserCode = new Map<string, StoredDeviceAuthorization<S>>();

  /**
   * Creates an empty device-authorization store.
   *
   * @param options Backing client/user services and optional lifetime and
   * polling interval.
   */
  constructor(options: MemoryDeviceAuthorizationServiceOptions<C, U>) {
    this.#clientService = options.clientService;
    this.#userService = options.userService;
    this.lifetime = options.lifetime ?? 1800;
    this.interval = options.interval ?? 5;
  }

  /** Mints a random opaque device code (polled by the device). */
  generateDeviceCode(
    _client: C,
    _scope?: S | null,
  ): Promise<string> {
    return Promise.resolve(crypto.randomUUID());
  }

  /**
   * Mints a short, human-enterable user code in `XXXX-XXXX` form drawn from an
   * unambiguous alphabet (no vowels or look-alike digits).
   */
  generateUserCode(
    _client: C,
    _scope?: S | null,
  ): Promise<string> {
    const chars = "BCDFGHJKLMNPQRSTVWXYZ23456789";
    let code = "";
    const array = new Uint8Array(8);
    crypto.getRandomValues(array);
    for (let i = 0; i < 8; i++) {
      code += chars[array[i] % chars.length];
      if (i === 3) code += "-";
    }
    return Promise.resolve(code);
  }

  /** Returns now plus {@linkcode lifetime}. */
  expiresAt(_client: C, _scope?: S | null): Promise<Date> {
    return Promise.resolve(new Date(Date.now() + this.lifetime * 1000));
  }

  async #hydrate(
    stored: StoredDeviceAuthorization<S>,
    deviceCode: string,
    userCode: string,
  ): Promise<DeviceAuthorization<C, U, S> | undefined> {
    const client = await this.#clientService.get(stored.clientId);
    if (!client) return undefined;
    const user = stored.userId
      ? await this.#userService.get(stored.userId)
      : undefined;
    if (stored.userId && !user) return undefined;
    return {
      deviceCode,
      userCode,
      expiresAt: stored.expiresAt,
      client,
      scope: stored.scope,
      interval: stored.interval,
      authorized: stored.authorized,
      user,
      denied: stored.denied,
      lastPolled: stored.lastPolled,
    };
  }

  /**
   * Persists a device authorization indexed by both its hashed device code and
   * hashed user code. Returns the input unchanged.
   */
  async save(
    authorization: DeviceAuthorization<C, U, S>,
  ): Promise<DeviceAuthorization<C, U, S>> {
    const deviceCodeHash = await sha256Hash(authorization.deviceCode);
    const userCodeHash = await sha256Hash(authorization.userCode);
    const stored: StoredDeviceAuthorization<S> = {
      deviceCodeHash,
      userCodeHash,
      expiresAt: authorization.expiresAt,
      clientId: authorization.client.id,
      scope: authorization.scope,
      interval: authorization.interval,
      authorized: authorization.authorized,
      userId: authorization.user?.id,
      denied: authorization.denied,
      lastPolled: authorization.lastPolled,
    };
    this.#byDeviceCode.set(deviceCodeHash, stored);
    this.#byUserCode.set(userCodeHash, stored);
    return authorization;
  }

  /**
   * Resolves the authorization for a device code (the value the device polls
   * with), client and user rehydrated, or `undefined` when not found.
   */
  async getByDeviceCode(
    deviceCode: string,
  ): Promise<DeviceAuthorization<C, U, S> | undefined> {
    const stored = this.#byDeviceCode.get(await sha256Hash(deviceCode));
    if (!stored) return undefined;
    return this.#hydrate(stored, deviceCode, "");
  }

  /**
   * Resolves the authorization for a user code (the value the user enters in a
   * browser), client and user rehydrated, or `undefined` when not found.
   */
  async getByUserCode(
    userCode: string,
  ): Promise<DeviceAuthorization<C, U, S> | undefined> {
    const stored = this.#byUserCode.get(await sha256Hash(userCode));
    if (!stored) return undefined;
    return this.#hydrate(stored, "", userCode);
  }

  async #findStored(
    authorization: DeviceAuthorization<C, U, S>,
  ): Promise<StoredDeviceAuthorization<S> | undefined> {
    if (authorization.deviceCode) {
      const stored = this.#byDeviceCode.get(
        await sha256Hash(authorization.deviceCode),
      );
      if (stored) return stored;
    }
    if (authorization.userCode) {
      const stored = this.#byUserCode.get(
        await sha256Hash(authorization.userCode),
      );
      if (stored) return stored;
    }
    return undefined;
  }

  /**
   * Marks the authorization granted by `user`, optionally narrowing `scope`,
   * so a subsequent device-code poll can exchange it for a token. Returns the
   * updated record. Throws when the authorization is not stored.
   */
  async approve(
    authorization: DeviceAuthorization<C, U, S>,
    user: U,
    scope?: S | null,
  ): Promise<DeviceAuthorization<C, U, S>> {
    const stored = await this.#findStored(authorization);
    if (!stored) {
      throw new Error("approve: device authorization not found");
    }
    stored.authorized = true;
    stored.userId = user.id;
    if (scope !== undefined) stored.scope = scope;
    return {
      ...authorization,
      authorized: true,
      user,
      scope: stored.scope,
    };
  }

  /**
   * Marks the authorization denied so a subsequent poll is rejected. Returns
   * the updated record. Throws when the authorization is not stored.
   */
  async deny(
    authorization: DeviceAuthorization<C, U, S>,
  ): Promise<DeviceAuthorization<C, U, S>> {
    const stored = await this.#findStored(authorization);
    if (!stored) {
      throw new Error("deny: device authorization not found");
    }
    stored.denied = true;
    return { ...authorization, denied: true };
  }

  /**
   * Records that the device just polled (and stores its current interval) so
   * `slow_down` rate limiting can be enforced. Returns the updated record.
   * Throws when the authorization is not stored.
   */
  async updateLastPolled(
    authorization: DeviceAuthorization<C, U, S>,
  ): Promise<DeviceAuthorization<C, U, S>> {
    const stored = await this.#findStored(authorization);
    if (!stored) {
      throw new Error("updateLastPolled: device authorization not found");
    }
    stored.lastPolled = new Date();
    stored.interval = authorization.interval;
    return { ...authorization, lastPolled: stored.lastPolled };
  }

  /**
   * Removes a device authorization, accepting a raw device code or any record
   * this store returns — including the partially hydrated ones from
   * {@linkcode getByDeviceCode} and {@linkcode getByUserCode}, which are
   * resolved back to the stored entry so both its device-code and user-code
   * index entries are dropped. Resolves `true` only for the call that removed
   * a live authorization, `false` otherwise.
   */
  async revoke(
    authorization: DeviceAuthorization<C, U, S> | string,
  ): Promise<boolean> {
    if (typeof authorization === "string") {
      const hashed = await sha256Hash(authorization);
      const stored = this.#byDeviceCode.get(hashed);
      if (!stored) return false;
      this.#byDeviceCode.delete(hashed);
      this.#byUserCode.delete(stored.userCodeHash);
      return true;
    }
    const stored = await this.#findStored(authorization);
    if (!stored) return false;
    const deleted = this.#byDeviceCode.delete(stored.deviceCodeHash);
    this.#byUserCode.delete(stored.userCodeHash);
    return deleted;
  }
}
