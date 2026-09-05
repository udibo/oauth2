/**
 * Authorization code service interface and abstract implementation.
 * @module
 */

import type { AuthorizationCode } from "../../models/authorization-code.ts";
import type { ClientInterface } from "../../models/client.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import type { ClientServiceInterface } from "./client.ts";
import type { UserServiceInterface } from "./user.ts";

/**
 * Service interface for authorization code management.
 */
export interface AuthorizationCodeServiceInterface<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> {
  /** Lifetime of authorization codes in seconds. */
  lifetime: number;

  /** Generates an authorization code string. */
  generateCode(
    client: Client,
    user: User,
    scope?: Scope | null,
  ): Promise<string>;

  /** Gets the date that a new authorization code would expire at. */
  expiresAt(
    client: Client,
    user: User,
    scope?: Scope | null,
  ): Promise<Date>;

  /** Retrieves an existing authorization code. */
  get(
    code: string,
  ): Promise<AuthorizationCode<Client, User, Scope> | undefined>;

  /** Saves an authorization code. */
  save(
    authorizationCode: AuthorizationCode<Client, User, Scope>,
  ): Promise<AuthorizationCode<Client, User, Scope>>;

  /**
   * Revokes an authorization code, accepting the record or its raw string.
   *
   * **Implementations must compare and delete atomically.** The authorization
   * code grant claims a code by revoking it and issues a token only to the
   * caller whose revoke resolved `true`, so this boolean is the single-use
   * guarantee (RFC 6749 §4.1.2): resolve `true` only for the call that removed
   * a live code, and `false` for every other call — a code already revoked,
   * expired, or never stored. An implementation that reads then deletes in two
   * steps, or that returns `true` unconditionally, lets two concurrent
   * exchanges of one code both mint tokens. In SQL this is a
   * `DELETE ... WHERE code = $1` whose affected-row count is the answer.
   */
  revoke(
    authorizationCode: AuthorizationCode<Client, User, Scope> | string,
  ): Promise<boolean>;
}

/** Options for configuring an abstract authorization code service. */
export interface AbstractAuthorizationCodeServiceOptions<
  Client extends ClientInterface,
  User,
> {
  /** Lifetime of authorization codes in seconds. Defaults to 600 (10 minutes). */
  lifetime?: number;
  /** Client service for hydrating authorization codes. */
  clientService?: ClientServiceInterface<Client, User>;
  /** User service for hydrating authorization codes. */
  userService?: UserServiceInterface<User>;
}

/**
 * Abstract authorization code service with sensible defaults.
 *
 * Provides default implementations for:
 * - `generateCode` — crypto.randomUUID()
 * - `expiresAt` — based on lifetime setting
 *
 * Subclasses must implement the storage methods: `get`, `save`, `revoke`
 */
export abstract class AbstractAuthorizationCodeService<
  Client extends ClientInterface,
  User,
  Scope extends AbstractScope = BasicScope,
> implements AuthorizationCodeServiceInterface<Client, User, Scope> {
  /** Lifetime of authorization codes in seconds. */
  lifetime: number;
  /** Client service used by subclasses to hydrate authorization codes. */
  protected clientService?: ClientServiceInterface<Client, User>;
  /** User service used by subclasses to hydrate authorization codes. */
  protected userService?: UserServiceInterface<User>;

  /** Lifetime defaults to 600 seconds (10 minutes) when not supplied. */
  constructor(options?: AbstractAuthorizationCodeServiceOptions<Client, User>) {
    this.lifetime = options?.lifetime ?? 600;
    this.clientService = options?.clientService;
    this.userService = options?.userService;
  }

  /** Generates an opaque authorization code string via `crypto.randomUUID()`. */
  generateCode(
    _client: Client,
    _user: User,
    _scope?: Scope | null,
  ): Promise<string> {
    return Promise.resolve(crypto.randomUUID());
  }

  /** Computes the code expiry as now plus {@linkcode lifetime}. */
  expiresAt(
    _client: Client,
    _user: User,
    _scope?: Scope | null,
  ): Promise<Date> {
    return Promise.resolve(new Date(Date.now() + this.lifetime * 1000));
  }

  /** Retrieves a persisted authorization code by its string value. */
  abstract get(
    code: string,
  ): Promise<AuthorizationCode<Client, User, Scope> | undefined>;

  /** Persists an authorization code and returns the saved record. */
  abstract save(
    authorizationCode: AuthorizationCode<Client, User, Scope>,
  ): Promise<AuthorizationCode<Client, User, Scope>>;

  /**
   * Revokes an authorization code given as a record or string. Resolves `true`
   * only for the call that removed a live code, and `false` for every other
   * call; the compare and delete must be atomic, since the authorization code
   * grant relies on this boolean for single use.
   */
  abstract revoke(
    authorizationCode: AuthorizationCode<Client, User, Scope> | string,
  ): Promise<boolean>;
}
