/**
 * Token reader that validates tokens via an OAuth2 introspection endpoint.
 *
 * This is the standard way for resource servers to validate tokens when
 * they are separate from the authorization server. The reader calls the
 * authorization server's introspection endpoint (RFC 7662) to check
 * whether a token is active and retrieve its metadata.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662
 * @module
 */

import { ServerError, TemporarilyUnavailableError } from "../errors.ts";
import type { ClientInterface } from "../models/client.ts";
import type { AbstractScope, ScopeConstructor } from "../models/scope.ts";
import { BasicScope } from "../models/scope.ts";
import type { IntrospectionResponse, Token } from "../models/token.ts";
import type { TokenReaderInterface } from "./services/token.ts";
import { encodeBasicAuth } from "../utils/basic-auth.ts";

/**
 * Options for configuring the introspection token reader.
 *
 * The {@linkcode getClient} and {@linkcode getUser} mappers project the
 * introspection response into the resource server's `Client` / `User`
 * types — RFC 7662 only fixes a minimal set of fields, and most
 * authorization servers carry app-specific claims as extension fields.
 */
export interface IntrospectionTokenReaderOptions<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> {
  /** URL of the authorization server's introspection endpoint. */
  introspectionEndpoint: string;
  /** Client ID used to authenticate introspection requests. */
  clientId: string;
  /** Client secret used to authenticate introspection requests. */
  clientSecret: string;
  /** Optional scope constructor for parsing scope strings. Defaults to BasicScope. */
  Scope?: ScopeConstructor<S>;
  /**
   * Projects an active introspection response into a typed `Client`.
   * Required because the client shape is app-specific: RFC 7662 only
   * guarantees `client_id` may be present, and authorization servers may
   * include extension fields.
   *
   * May be async — return a promise to enrich from a DB lookup or a
   * downstream API call (e.g. fetching a client record by `client_id`).
   */
  getClient: (data: IntrospectionResponse) => Client | Promise<Client>;
  /**
   * Projects an active introspection response into a typed `User`. Return
   * `undefined` when the token doesn't represent a user. Omit entirely if
   * your app never reads user info off the token.
   *
   * A machine token (client credentials) carries no `sub`, so `data.sub` is
   * present only when there is a resource owner — `data.sub ? {…} : undefined`
   * is the whole discriminator, and a client-credentials caller resolves to no
   * user.
   *
   * May be async — return a promise to enrich from a DB lookup or the
   * authorization server's OIDC UserInfo endpoint, using `data.sub` as
   * the lookup key.
   */
  getUser?: (
    data: IntrospectionResponse,
  ) => User | undefined | Promise<User | undefined>;
  /**
   * Deadline in milliseconds for an introspection request. Defaults to 5000.
   * Without it an authorization server that accepts the connection and then
   * stops answering hangs every request this resource server is serving, since
   * introspection sits on the hot path of each one. Ignored by an injected
   * {@linkcode fetch} that doesn't honour `AbortSignal`.
   */
  fetchTimeoutMs?: number;
  /**
   * `fetch` implementation used to call the introspection endpoint. Defaults
   * to the global `fetch`. Inject it to route through a custom client (mTLS,
   * timeouts, retries) or to stub the network in tests.
   */
  fetch?: typeof fetch;
}

/**
 * Validates tokens by calling an OAuth2 introspection endpoint (RFC 7662).
 *
 * Use this with {@linkcode ResourceServer} when your resource server is
 * separate from the authorization server. The reader authenticates with
 * the introspection endpoint using client credentials (HTTP Basic Auth)
 * and projects the response into the resource server's `Client` / `User`
 * types via the {@linkcode IntrospectionTokenReaderOptions.getClient} and
 * {@linkcode IntrospectionTokenReaderOptions.getUser} mappers.
 *
 * @example
 * ```ts
 * import {
 *   IntrospectionTokenReader,
 *   ResourceServer,
 * } from "@udibo/oauth2/server/resource";
 *
 * interface MyClient { id: string }
 * interface MyUser { id: string; email?: string }
 *
 * const tokenReader = new IntrospectionTokenReader<MyClient, MyUser>({
 *   introspectionEndpoint: "https://auth.example.com/introspect",
 *   clientId: "my-api",
 *   clientSecret: "my-secret",
 *   getClient: (data) => ({ id: data.client_id! }),
 *   getUser: (data) =>
 *     data.sub
 *       ? { id: data.sub, email: data.email as string | undefined }
 *       : undefined,
 * });
 *
 * const resourceServer = new ResourceServer<MyClient, MyUser>({
 *   resolve: () => ({ services: { tokenService: tokenReader } }),
 * });
 * ```
 */
export class IntrospectionTokenReader<
  Client extends ClientInterface,
  User,
  S extends AbstractScope = BasicScope,
> implements TokenReaderInterface<Client, User, S> {
  private introspectionEndpoint: string;
  private clientId: string;
  private clientSecret: string;
  private Scope: ScopeConstructor<S>;
  private getClient: (data: IntrospectionResponse) => Client | Promise<Client>;
  private getUser?: (
    data: IntrospectionResponse,
  ) => User | undefined | Promise<User | undefined>;
  private fetchTimeoutMs: number;
  private customFetch?: typeof fetch;

  /**
   * `Scope` defaults to {@linkcode BasicScope}, `fetchTimeoutMs` to 5000, and
   * `fetch` to the global `fetch` when omitted from `options`.
   */
  constructor(options: IntrospectionTokenReaderOptions<Client, User, S>) {
    this.introspectionEndpoint = options.introspectionEndpoint;
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.Scope = options.Scope ??
      (BasicScope as unknown as ScopeConstructor<S>);
    this.getClient = options.getClient;
    this.getUser = options.getUser;
    this.fetchTimeoutMs = options.fetchTimeoutMs ?? 5_000;
    this.customFetch = options.fetch;
  }

  /**
   * Validates an access token by calling the introspection endpoint.
   *
   * Sends a POST request with the token to the configured introspection
   * endpoint, authenticated with client credentials via HTTP Basic Auth.
   *
   * @returns The token with client/user/scope info, or `undefined` when the
   *   endpoint reports the token inactive (RFC 7662 `{ active: false }`) or
   *   does not identify it as a bearer access token.
   * @throws {TemporarilyUnavailableError} If the introspection endpoint is
   *   unreachable, takes longer than
   *   {@linkcode IntrospectionTokenReaderOptions.fetchTimeoutMs} to answer, or
   *   returns a 5xx — a down authorization server must be distinguishable from
   *   a genuinely invalid token (which is `undefined` → `invalid_token`), not
   *   collapsed into it.
   * @throws {ServerError} If the endpoint returns a 4xx (e.g. the reader's own
   *   introspection credentials are rejected) — a misconfiguration, not a
   *   verdict on the caller's token.
   *
   * An active response is only accepted when its `token_type` names a bearer
   * token. RFC 7662 answers for refresh tokens too, and a refresh token's
   * response is otherwise indistinguishable from an access token's — without
   * this check a refresh token presented as `Authorization: Bearer …` would
   * authenticate at the resource server, bypassing rotation and reuse
   * detection. An authorization server that omits `token_type` from an active
   * response cannot be read by this reader.
   */
  async getToken(
    accessToken: string,
  ): Promise<Token<Client, User, S> | undefined> {
    const data = await this.#introspect(accessToken);
    if (!data.active) return undefined;
    if (data.token_type?.toLowerCase() !== "bearer") return undefined;

    const [client, user] = await Promise.all([
      this.getClient(data),
      this.getUser?.(data),
    ]);

    return {
      accessToken,
      accessTokenExpiresAt: data.exp ? new Date(data.exp * 1000) : undefined,
      client,
      user,
      scope: data.scope
        ? new this.Scope(data.scope) as S | undefined
        : undefined,
      claims: data as Record<string, unknown>,
    };
  }

  async #introspect(accessToken: string): Promise<IntrospectionResponse> {
    const fetchImpl = this.customFetch ?? globalThis.fetch;
    const controller = new AbortController();
    const deadline = setTimeout(
      () => controller.abort(),
      this.fetchTimeoutMs,
    );
    try {
      let response: Response;
      try {
        response = await fetchImpl(this.introspectionEndpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": encodeBasicAuth(this.clientId, this.clientSecret),
          },
          body: new URLSearchParams({ token: accessToken }),
          signal: controller.signal,
        });
      } catch (cause) {
        throw new TemporarilyUnavailableError(
          "token introspection request failed",
          { cause },
        );
      }

      if (!response.ok) {
        await response.body?.cancel();
        throw response.status >= 500
          ? new TemporarilyUnavailableError(
            `token introspection failed (HTTP ${response.status})`,
          )
          : new ServerError(
            `token introspection failed (HTTP ${response.status})`,
          );
      }

      try {
        return await response.json() as IntrospectionResponse;
      } catch (cause) {
        throw controller.signal.aborted
          ? new TemporarilyUnavailableError(
            "token introspection request failed",
            { cause },
          )
          : new ServerError("token introspection response was not JSON", {
            cause,
          });
      }
    } finally {
      clearTimeout(deadline);
    }
  }
}
