/**
 * Reusable checks for app-owned identity users and password credentials.
 * Optional capabilities are selected explicitly so an omitted implementation
 * cannot silently pass a capability the application intends to provide.
 * @module
 */
import {
  assert,
  assertEquals,
  assertExists,
  assertStrictEquals,
} from "@std/assert";
import { afterEach, beforeEach, describe, it } from "@std/testing/bdd";
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
 * Register the IdentityUserStore suite in a Deno test file. Credential fixtures
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
      assertStrictEquals(
        await store.findByIdentifier(
          "missing-identity-contract@example.invalid",
        ),
        undefined,
      );
      assertStrictEquals(
        await store.findByEmail("missing-identity-contract@example.invalid"),
        undefined,
      );
      assertStrictEquals(
        await store.getCredential("missing-identity-contract-user"),
        undefined,
      );
    });
    it("creates distinct users and resolves each profile's lookup keys", async () => {
      const first = await create();
      const second = await create(2);
      assert(first.id.length > 0);
      assert(second.id.length > 0);
      assert(first.id !== second.id, "distinct users must have distinct ids");
      for (const [sequence, user] of [[1, first], [2, second]] as const) {
        const profile = fixture.makeProfile(sequence);
        assertEquals(
          (await store.findByIdentifier(profile.identifier))?.id,
          user.id,
        );
        assertEquals((await store.findByEmail(profile.email))?.id, user.id);
        assertEquals(await store.getCredential(user.id), ORIGINAL);
      }
    });
    it("replaces every credential field without changing another user", async () => {
      const first = await create();
      const second = await create(2);
      await store.setCredential(first.id, structuredClone(REPLACEMENT));
      assertEquals(await store.getCredential(first.id), REPLACEMENT);
      assertEquals(await store.getCredential(second.id), ORIGINAL);
      await store.setCredential(first.id, {
        hash: ORIGINAL.hash,
        salt: ORIGINAL.salt,
      });
      assertEquals(await store.getCredential(first.id), {
        hash: ORIGINAL.hash,
        salt: ORIGINAL.salt,
      });
    });

    if (options.replaceCredential) {
      it("compares credential values, including every parameter and absent params", async () => {
        const user = await create();
        assertExists(
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
          assertStrictEquals(
            await store.replaceCredential(user.id, expected, REPLACEMENT),
            false,
          );
          assertEquals(
            await store.getCredential(user.id),
            ORIGINAL,
            "a failed compare-and-set must preserve the winner",
          );
        }
        assertStrictEquals(
          await store.replaceCredential(
            user.id,
            structuredClone(ORIGINAL),
            REPLACEMENT,
          ),
          true,
        );
        assertEquals(await store.getCredential(user.id), REPLACEMENT);
        assertStrictEquals(
          await store.replaceCredential(user.id, ORIGINAL, ORIGINAL),
          false,
        );
        assertEquals(
          await store.getCredential(user.id),
          REPLACEMENT,
          "read after a lost compare-and-set must see the committed credential",
        );
        await store.setCredential(user.id, {
          hash: ORIGINAL.hash,
          salt: ORIGINAL.salt,
        });
        assertStrictEquals(
          await store.replaceCredential(user.id, {
            hash: ORIGINAL.hash,
            salt: ORIGINAL.salt,
          }, REPLACEMENT),
          true,
        );
      });
      it("upgrades an absent credential only once", async () => {
        const user = await create();
        assertExists(store.replaceCredential);
        assertExists(
          fixture.removeCredential,
          "removeCredential setup helper is required",
        );
        await fixture.removeCredential(user.id);
        assertStrictEquals(await store.getCredential(user.id), undefined);
        const results = await drain(
          Array.from({ length: 8 }, () =>
            store.replaceCredential!(
              user.id,
              undefined,
              structuredClone(REPLACEMENT),
            )),
        );
        assertEquals(
          results.filter(Boolean).length,
          1,
          "exactly one concurrent imported upgrade may win",
        );
        assertEquals(await store.getCredential(user.id), REPLACEMENT);
      });
      it("allows exactly one concurrent replacement of the same credential", async () => {
        const user = await create();
        const other = await create(2);
        assertExists(store.replaceCredential);
        const candidates = Array.from(
          { length: 8 },
          (_, index) => ({
            ...REPLACEMENT,
            hash: (index + 5).toString(16).padStart(2, "0").repeat(32),
          }),
        );
        const results = await drain(
          candidates.map((credential) =>
            store.replaceCredential!(
              user.id,
              structuredClone(ORIGINAL),
              credential,
            )
          ),
        );
        assertEquals(
          results.filter(Boolean).length,
          1,
          "exactly one concurrent replacement may win",
        );
        assertEquals(
          await store.getCredential(user.id),
          candidates[results.indexOf(true)],
        );
        assertEquals(await store.getCredential(other.id), ORIGINAL);
      });
    }
    if (options.emailVerification) {
      it("verifies only the issued-for email and is idempotent", async () => {
        const user = await create();
        const other = await create(2);
        assertExists(
          store.markEmailVerified,
          "email verification capability is required",
        );
        assertExists(fixture.setEmail);
        assertExists(fixture.isEmailVerified);
        const originalEmail = fixture.makeProfile(1).email;
        const changedEmail = "changed-identity-contract@example.invalid";
        assertStrictEquals(await fixture.isEmailVerified(user.id), false);
        await fixture.setEmail(user.id, changedEmail);
        await store.markEmailVerified(user.id, originalEmail);
        assertStrictEquals(
          await fixture.isEmailVerified(user.id),
          false,
          "a token for an old email must not verify the new email",
        );
        await store.markEmailVerified(user.id, changedEmail);
        await store.markEmailVerified(user.id, changedEmail);
        assertStrictEquals(await fixture.isEmailVerified(user.id), true);
        assertStrictEquals(await fixture.isEmailVerified(other.id), false);
      });
    }
    if (options.legacyCredentials) {
      it("clears the selected imported credential and is idempotent", async () => {
        const user = await create();
        const other = await create(2);
        assertExists(
          store.getLegacyCredential,
          "legacy credential lookup capability is required",
        );
        assertExists(
          store.clearLegacyCredential,
          "legacy credential clearing capability is required",
        );
        assertExists(fixture.setLegacyCredential);
        assertStrictEquals(await store.getLegacyCredential(user.id), null);
        await fixture.setLegacyCredential(user.id, "imported-hash-one");
        await fixture.setLegacyCredential(other.id, "imported-hash-two");
        assertEquals(
          await store.getLegacyCredential(user.id),
          "imported-hash-one",
        );
        await store.clearLegacyCredential(user.id);
        await store.clearLegacyCredential(user.id);
        assertStrictEquals(await store.getLegacyCredential(user.id), null);
        assertEquals(
          await store.getLegacyCredential(other.id),
          "imported-hash-two",
        );
        assertEquals(await store.getCredential(user.id), ORIGINAL);
      });
    }
  });
}
