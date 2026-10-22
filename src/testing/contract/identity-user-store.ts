/**
 * Reusable checks for app-owned identity users and password credentials.
 * Optional capabilities are selected explicitly so an omitted implementation
 * cannot silently pass a capability the application intends to provide.
 * @module
 */

import { afterEach, assert, beforeEach, describe, expect, it } from "vitest";
import type {
  IdentityUser,
  IdentityUserStore,
} from "../../identity/service.ts";
import type { PasswordCredential } from "../../identity/password.ts";

/** App-specific profile and lookup keys for one fresh test user. */
export interface IdentityUserContractProfile {
  /** Valid sign-up fields for your application. */
  profile: Record<string, unknown>;
  /** Identifier that findByIdentifier must resolve for this profile. */
  identifier: string;
  /** Email that findByEmail must resolve for this profile. */
  email: string;
}

/** Isolated store and app-owned setup helpers for one test. */
export interface IdentityUserStoreContractFixture<User extends IdentityUser> {
  /** Fresh, empty implementation being verified. */
  store: IdentityUserStore<User>;
  /** Valid app-shaped user id that is absent from this fixture. */
  unknownUserId: string;
  /** Distinct valid profiles; return the same profile for the same sequence (1 or 2). */
  makeProfile(sequence: number): IdentityUserContractProfile;
  /** Remove a native credential to exercise compare-and-set from undefined. */
  removeCredential?(userId: string): Promise<void>;
  /** Change the current email without verifying it. Required for emailVerification. */
  setEmail?(userId: string, email: string): Promise<void>;
  /** Read the persisted verification flag. Required for emailVerification. */
  isEmailVerified?(userId: string): Promise<boolean>;
  /** Seed an imported hash. Required for legacyCredentials. */
  setLegacyCredential?(userId: string, hash: string): Promise<void>;
  /** Start a live session for the user and return its id. Required for resetCredential. */
  startSession?(userId: string): Promise<string>;
  /** Whether the application would still accept the session. Required for resetCredential. */
  isSessionLive?(sessionId: string): Promise<boolean>;
  /**
   * Make the next resetCredential call throw at `step`, after the other
   * step has had its chance to write. Required for resetCredential: the suite
   * calls it once for each step to prove that neither write survives the other
   * failing, whichever order your transaction runs them in.
   */
  failNextReset?(step: "credential" | "sessions"): Promise<void> | void;
  /** Release resources and remove this test's records after all calls finish. */
  dispose?(): Promise<void> | void;
}

/** Options for runIdentityUserStoreContractTests. */
export interface IdentityUserStoreContractOptions<User extends IdentityUser> {
  /** Create an isolated fixture for each test. */
  makeFixture():
    | IdentityUserStoreContractFixture<User>
    | Promise<IdentityUserStoreContractFixture<User>>;
  /** Override the outer suite's name. */
  describeName?: string;
  /** Require the optional atomic credential-replacement capability and its setup helper. */
  replaceCredential?: boolean;
  /** Require guarded, idempotent email verification and its observation helpers. */
  emailVerification?: boolean;
  /** Require imported credential lookup and clearing, plus its setup helper. */
  legacyCredentials?: boolean;
  /**
   * Require the transactional password-reset capability and its session and
   * fault-injection helpers. With legacyCredentials, also checks that the
   * reset drops the imported hash.
   */
  resetCredential?: boolean;
}

const ORIGINAL: PasswordCredential = {
  hash: "11".repeat(32),
  salt: "22".repeat(16),
  params: { algorithm: "pbkdf2-sha256", iterations: 600_000 },
};
const REPLACEMENT: PasswordCredential = {
  hash: "33".repeat(32),
  salt: "44".repeat(16),
  params: { algorithm: "pbkdf2-sha256", iterations: 700_000 },
};

async function drain<T>(calls: Promise<T>[]): Promise<T[]> {
  const results = await Promise.allSettled(calls);
  return results.map((result) => {
    if (result.status === "rejected") throw result.reason;
    return result.value;
  });
}

/**
 * Register the IdentityUserStore suite in a Vitest test file. Credential fixtures
 * are serialized values, not real passwords: these checks verify persistence,
 * lookup, and conditional writes, rather than password hashing. Concurrent
 * checks can expose read-then-write races but cannot prove every interleaving.
 * Enable each optional capability your application uses; disabled capabilities
 * are not verified. Application validation and identifier normalization remain
 * app-owned and are outside this suite.
 */
export function runIdentityUserStoreContractTests<User extends IdentityUser>(
  options: IdentityUserStoreContractOptions<User>,
): void {
  describe(options.describeName ?? "IdentityUserStore contract", () => {
    let fixture: IdentityUserStoreContractFixture<User>;
    let store: IdentityUserStore<User>;
    beforeEach(async () => {
      fixture = await options.makeFixture();
      store = fixture.store;
    });
    afterEach(async () => {
      await fixture?.dispose?.();
    });

    async function create(sequence = 1): Promise<User> {
      return await store.create(
        fixture.makeProfile(sequence).profile,
        structuredClone(ORIGINAL),
      );
    }

    it("returns undefined for unknown lookup keys and credentials", async () => {
      expect(
        await store.findByIdentifier(
          "missing-identity-contract@example.invalid",
        ),
      ).toBe(undefined);
      expect(
        await store.findByEmail("missing-identity-contract@example.invalid"),
      ).toBe(undefined);
      expect(await store.getCredential(fixture.unknownUserId)).toBe(undefined);
    });
    it("creates distinct users and resolves each profile's lookup keys", async () => {
      const first = await create();
      const second = await create(2);
      assert(first.id.length > 0);
      assert(second.id.length > 0);
      assert(first.id !== second.id, "distinct users must have distinct ids");
      for (const [sequence, user] of [
        [1, first],
        [2, second],
      ] as const) {
        const profile = fixture.makeProfile(sequence);
        expect(
          (await store.findByIdentifier(profile.identifier))?.id,
        ).toStrictEqual(user.id);
        expect((await store.findByEmail(profile.email))?.id).toStrictEqual(
          user.id,
        );
        expect(await store.getCredential(user.id)).toStrictEqual(ORIGINAL);
      }
    });
    it("replaces every credential field without changing another user", async () => {
      const first = await create();
      const second = await create(2);
      await store.setCredential(first.id, structuredClone(REPLACEMENT));
      expect(await store.getCredential(first.id)).toStrictEqual(REPLACEMENT);
      expect(await store.getCredential(second.id)).toStrictEqual(ORIGINAL);
      await store.setCredential(first.id, {
        hash: ORIGINAL.hash,
        salt: ORIGINAL.salt,
      });
      expect(await store.getCredential(first.id)).toStrictEqual({
        hash: ORIGINAL.hash,
        salt: ORIGINAL.salt,
      });
    });

    if (options.replaceCredential) {
      it("compares credential values, including every parameter and absent params", async () => {
        const user = await create();
        assert.exists(
          store.replaceCredential,
          "replaceCredential capability is required",
        );
        const mismatches: PasswordCredential[] = [
          { ...ORIGINAL, hash: REPLACEMENT.hash },
          { ...ORIGINAL, salt: REPLACEMENT.salt },
          { ...ORIGINAL, params: { algorithm: "other", iterations: 600_000 } },
          {
            ...ORIGINAL,
            params: { algorithm: "pbkdf2-sha256", iterations: 600_001 },
          },
          { hash: ORIGINAL.hash, salt: ORIGINAL.salt },
        ];
        for (const expected of mismatches) {
          expect(
            await store.replaceCredential(user.id, expected, REPLACEMENT),
          ).toBe(false);
          expect(
            await store.getCredential(user.id),
            "a failed compare-and-set must preserve the winner",
          ).toStrictEqual(ORIGINAL);
        }
        expect(
          await store.replaceCredential(
            user.id,
            structuredClone(ORIGINAL),
            REPLACEMENT,
          ),
        ).toBe(true);
        expect(await store.getCredential(user.id)).toStrictEqual(REPLACEMENT);
        expect(await store.replaceCredential(user.id, ORIGINAL, ORIGINAL)).toBe(
          false,
        );
        expect(
          await store.getCredential(user.id),
          "read after a lost compare-and-set must see the committed credential",
        ).toStrictEqual(REPLACEMENT);
        await store.setCredential(user.id, {
          hash: ORIGINAL.hash,
          salt: ORIGINAL.salt,
        });
        expect(
          await store.replaceCredential(
            user.id,
            {
              hash: ORIGINAL.hash,
              salt: ORIGINAL.salt,
            },
            REPLACEMENT,
          ),
        ).toBe(true);
      });
      it("upgrades an absent credential only once", async () => {
        const user = await create();
        assert.exists(store.replaceCredential);
        assert.exists(
          fixture.removeCredential,
          "removeCredential setup helper is required",
        );
        await fixture.removeCredential(user.id);
        expect(await store.getCredential(user.id)).toBe(undefined);
        const results = await drain(
          Array.from({ length: 8 }, () =>
            store.replaceCredential!(
              user.id,
              undefined,
              structuredClone(REPLACEMENT),
            ),
          ),
        );
        expect(
          results.filter(Boolean).length,
          "exactly one concurrent imported upgrade may win",
        ).toStrictEqual(1);
        expect(await store.getCredential(user.id)).toStrictEqual(REPLACEMENT);
      });
      it("allows exactly one concurrent replacement of the same credential", async () => {
        const user = await create();
        const other = await create(2);
        assert.exists(store.replaceCredential);
        const candidates = Array.from({ length: 8 }, (_, index) => ({
          ...REPLACEMENT,
          hash: (index + 5).toString(16).padStart(2, "0").repeat(32),
        }));
        const results = await drain(
          candidates.map((credential) =>
            store.replaceCredential!(
              user.id,
              structuredClone(ORIGINAL),
              credential,
            ),
          ),
        );
        expect(
          results.filter(Boolean).length,
          "exactly one concurrent replacement may win",
        ).toStrictEqual(1);
        expect(await store.getCredential(user.id)).toStrictEqual(
          candidates[results.indexOf(true)],
        );
        expect(await store.getCredential(other.id)).toStrictEqual(ORIGINAL);
      });
    }
    if (options.resetCredential) {
      async function resetSetup(): Promise<{
        user: User;
        other: User;
        sessions: string[];
        otherSession: string;
      }> {
        assert.exists(
          store.resetCredential,
          "resetCredential capability is required",
        );
        assert.exists(
          fixture.startSession,
          "startSession setup helper is required",
        );
        assert.exists(
          fixture.isSessionLive,
          "isSessionLive setup helper is required",
        );
        const user = await create();
        const other = await create(2);
        if (options.legacyCredentials) {
          assert.exists(fixture.setLegacyCredential);
          await fixture.setLegacyCredential(user.id, "imported-hash-one");
        }
        return {
          user,
          other,
          sessions: [
            await fixture.startSession(user.id),
            await fixture.startSession(user.id),
          ],
          otherSession: await fixture.startSession(other.id),
        };
      }
      async function liveness(ids: string[]): Promise<boolean[]> {
        return await Promise.all(ids.map((id) => fixture.isSessionLive!(id)));
      }

      it("resets the credential and revokes every session of the user, and only that user", async () => {
        const { user, other, sessions, otherSession } = await resetSetup();
        expect(
          await store.resetCredential!(user.id, structuredClone(REPLACEMENT)),
          "resetCredential must report the sessions it revoked",
        ).toStrictEqual(2);
        expect(await store.getCredential(user.id)).toStrictEqual(REPLACEMENT);
        expect(
          await liveness(sessions),
          "resetCredential revokes every session of the user",
        ).toStrictEqual([false, false]);
        if (options.legacyCredentials) {
          expect(
            await store.getLegacyCredential!(user.id),
            "resetCredential drops the imported hash",
          ).toBe(null);
        }
        expect(await store.getCredential(other.id)).toStrictEqual(ORIGINAL);
        expect(
          await fixture.isSessionLive!(otherSession),
          "resetCredential must not revoke another user's sessions",
        ).toBe(true);
        expect(
          await store.resetCredential!(user.id, structuredClone(REPLACEMENT)),
        ).toStrictEqual(0);
      });
      for (const step of ["credential", "sessions"] as const) {
        it(`changes nothing when the reset fails at the ${step} step`, async () => {
          const { user, sessions } = await resetSetup();
          assert.exists(
            fixture.failNextReset,
            "failNextReset fault-injection helper is required",
          );
          await fixture.failNextReset(step);
          const outcome = await store.resetCredential!(
            user.id,
            structuredClone(REPLACEMENT),
          ).then(
            () => "resolved",
            () => "rejected",
          );
          expect(
            outcome,
            "resetCredential must reject when failNextReset injected a failure",
          ).toStrictEqual("rejected");
          const unchanged =
            "a failed reset must leave the credential, imported hash and sessions unchanged";
          expect(await store.getCredential(user.id), unchanged).toStrictEqual(
            ORIGINAL,
          );
          expect(await liveness(sessions), unchanged).toStrictEqual([
            true,
            true,
          ]);
          if (options.legacyCredentials) {
            expect(
              await store.getLegacyCredential!(user.id),
              unchanged,
            ).toStrictEqual("imported-hash-one");
          }
        });
      }
    }
    if (options.emailVerification) {
      it("verifies only the issued-for email and is idempotent", async () => {
        const user = await create();
        const other = await create(2);
        assert.exists(
          store.markEmailVerified,
          "email verification capability is required",
        );
        assert.exists(fixture.setEmail);
        assert.exists(fixture.isEmailVerified);
        const originalEmail = fixture.makeProfile(1).email;
        const changedEmail = "changed-identity-contract@example.invalid";
        expect(await fixture.isEmailVerified(user.id)).toBe(false);
        await fixture.setEmail(user.id, changedEmail);
        await store.markEmailVerified(user.id, originalEmail);
        expect(
          await fixture.isEmailVerified(user.id),
          "a token for an old email must not verify the new email",
        ).toBe(false);
        await store.markEmailVerified(user.id, changedEmail);
        await store.markEmailVerified(user.id, changedEmail);
        expect(await fixture.isEmailVerified(user.id)).toBe(true);
        expect(await fixture.isEmailVerified(other.id)).toBe(false);
      });
    }
    if (options.legacyCredentials) {
      it("clears the selected imported credential and is idempotent", async () => {
        const user = await create();
        const other = await create(2);
        assert.exists(
          store.getLegacyCredential,
          "legacy credential lookup capability is required",
        );
        assert.exists(
          store.clearLegacyCredential,
          "legacy credential clearing capability is required",
        );
        assert.exists(fixture.setLegacyCredential);
        expect(await store.getLegacyCredential(user.id)).toBe(null);
        await fixture.setLegacyCredential(user.id, "imported-hash-one");
        await fixture.setLegacyCredential(other.id, "imported-hash-two");
        expect(await store.getLegacyCredential(user.id)).toStrictEqual(
          "imported-hash-one",
        );
        await store.clearLegacyCredential(user.id);
        await store.clearLegacyCredential(user.id);
        expect(await store.getLegacyCredential(user.id)).toBe(null);
        expect(await store.getLegacyCredential(other.id)).toStrictEqual(
          "imported-hash-two",
        );
        expect(await store.getCredential(user.id)).toStrictEqual(ORIGINAL);
      });
    }
  });
}
