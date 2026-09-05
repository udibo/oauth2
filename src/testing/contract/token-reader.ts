/**
 * Contract test suite for {@link TokenReaderInterface} implementations.
 *
 * A resource server only ever calls `getToken`, so the contract is small
 * and strict: an accepted token comes back with the same access-token
 * string and a projected client, and anything the reader cannot validate
 * resolves to `undefined` rather than throwing — `undefined` is what the
 * resource server turns into `invalid_token`. Thrown errors are reserved
 * for transport and misconfiguration.
 *
 * Run it against the shipped readers, or against your own reader when your
 * API validates tokens out of a shared database.
 *
 * @example
 * ```ts
 * import { runTokenReaderContractTests } from "@udibo/oauth2/testing/contract";
 * import type { ClientInterface, TokenReaderInterface } from "@udibo/oauth2/server";
 *
 * interface AppUser {
 *   id: string;
 *   username: string;
 * }
 * declare function freshTokenReader(): Promise<
 *   TokenReaderInterface<ClientInterface, AppUser>
 * >;
 *
 * runTokenReaderContractTests<ClientInterface, AppUser>({
 *   setup: async () => ({
 *     reader: await freshTokenReader(),
 *     validAccessToken: "seeded-token",
 *     expected: { clientId: "my-client", userId: "u1", scope: "read" },
 *     invalidAccessTokens: ["unknown-token", "revoked-token"],
 *   }),
 * });
 * ```
 *
 * @module
 */

import { assert, assertStrictEquals } from "@std/assert";
import { afterEach, beforeEach, describe, it } from "@std/testing/bdd";

import type { ClientInterface } from "../../models/client.ts";
import type { AbstractScope, BasicScope } from "../../models/scope.ts";
import type { TokenReaderInterface } from "../../server/services/token.ts";

/** The reader under test plus the tokens the suite exercises it with. */
export interface TokenReaderContractFixture<
  C extends ClientInterface,
  U,
  S extends AbstractScope = BasicScope,
> {
  /** The reader under test. */
  reader: TokenReaderInterface<C, U, S>;
  /** An access token the reader must accept. */
  validAccessToken: string;
  /** What the accepted token must project. */
  expected: {
    /** `client.id` the reader must report for {@linkcode validAccessToken}. */
    clientId: string;
    /** `user.id` the reader must report, when the token represents a user. */
    userId?: string;
    /** Granted scope, as its string form, when the token carries one. */
    scope?: string;
  };
  /**
   * Access tokens the reader must reject with `undefined` — at minimum one
   * it has never seen. Add the rejection paths specific to your reader
   * (revoked, expired, wrong audience) to widen the coverage.
   */
  invalidAccessTokens: string[];
  /** Releases anything `setup` allocated (a mock server, a database). */
  cleanup?(): Promise<void> | void;
}

/** Options for {@link runTokenReaderContractTests}. */
export interface TokenReaderContractOptions<
  C extends ClientInterface,
  U,
  S extends AbstractScope = BasicScope,
> {
  /**
   * Builds a fresh fixture for each test. Must be isolated — one test
   * leaking state into another defeats the contract guarantees.
   */
  setup():
    | Promise<TokenReaderContractFixture<C, U, S>>
    | TokenReaderContractFixture<C, U, S>;
  /** Overrides the name passed to the outer `describe` block. */
  describeName?: string;
}

/** Runs the {@link TokenReaderInterface} contract suite. */
export function runTokenReaderContractTests<
  C extends ClientInterface,
  U,
  S extends AbstractScope = BasicScope,
>(options: TokenReaderContractOptions<C, U, S>): void {
  describe(
    options.describeName ?? "TokenReaderInterface contract",
    () => {
      let fixture: TokenReaderContractFixture<C, U, S>;

      beforeEach(async () => {
        fixture = await options.setup();
      });

      afterEach(async () => {
        await fixture.cleanup?.();
      });

      it("echoes back the access token it was given", async () => {
        const token = await fixture.reader.getToken(fixture.validAccessToken);
        assertStrictEquals(token?.accessToken, fixture.validAccessToken);
      });

      it("projects the client the token was issued to", async () => {
        const token = await fixture.reader.getToken(fixture.validAccessToken);
        assertStrictEquals(token?.client.id, fixture.expected.clientId);
      });

      it("projects the user the token was issued for", async () => {
        const token = await fixture.reader.getToken(fixture.validAccessToken);
        assertStrictEquals(
          (token?.user as { id?: string } | undefined)?.id,
          fixture.expected.userId,
        );
      });

      it("exposes the granted scope", async () => {
        const token = await fixture.reader.getToken(fixture.validAccessToken);
        assertStrictEquals(token?.scope?.toString(), fixture.expected.scope);
      });

      it("exposes an expiry as a Date when the token carries one", async () => {
        const token = await fixture.reader.getToken(fixture.validAccessToken);
        assert(
          token?.accessTokenExpiresAt === undefined ||
            token.accessTokenExpiresAt instanceof Date,
        );
      });

      it("resolves undefined for tokens it cannot validate", async () => {
        for (const accessToken of fixture.invalidAccessTokens) {
          assertStrictEquals(
            await fixture.reader.getToken(accessToken),
            undefined,
            `expected ${accessToken} to be rejected with undefined`,
          );
        }
      });
    },
  );
}
