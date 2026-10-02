import type { IdentityUserStore } from "../../identity/service.ts";
import type { PasswordCredential } from "../../identity/password.ts";
import type { SessionSummary } from "../../identity/session.ts";
import type { IdentityUserStoreContractFixture } from "./identity-user-store.ts";
import type {
  IdentitySessionContractState,
  ListableSessionServiceContractFixture,
} from "./identity-session.ts";

function uuid(sequence: number): string {
  return `019b0000-0000-7000-8000-${sequence.toString().padStart(12, "0")}`;
}
function requireUuid(value: string): void {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
      value,
    )
  ) throw new TypeError("Fixture requires an app-valid UUID");
}
interface User {
  id: string;
  email: string;
}
export function userFixture(
  fault?: string,
): IdentityUserStoreContractFixture<User> {
  const users = new Map<string, User>();
  const credentials = new Map<string, PasswordCredential>();
  const verified = new Set<string>();
  const stale = new Map<string, PasswordCredential>();
  const legacy = new Map<string, string>();
  let sequence = 0;
  const store: IdentityUserStore<User> = {
    create(profile, credential) {
      const user = { id: uuid(++sequence), email: String(profile.email) };
      users.set(user.id, user);
      credentials.set(user.id, structuredClone(credential));
      return Promise.resolve(structuredClone(user));
    },
    findByEmail(email) {
      return Promise.resolve(
        structuredClone(
          [...users.values()].find((user) => user.email === email),
        ),
      );
    },
    findByIdentifier(identifier) {
      return this.findByEmail(identifier);
    },
    getCredential(id) {
      requireUuid(id);
      return Promise.resolve(
        structuredClone(stale.get(id) ?? credentials.get(id)),
      );
    },
    setCredential(id, credential) {
      credentials.set(id, structuredClone(credential));
      return Promise.resolve();
    },
    async replaceCredential(id, expected, credential) {
      const current = credentials.get(id);
      const same = expected === undefined
        ? current === undefined
        : current !== undefined && current.hash === expected.hash &&
          current.salt === expected.salt &&
          (fault === "cas-params" ||
            JSON.stringify(current.params) === JSON.stringify(expected.params));
      if (!same) {
        if (
          fault === "cas-stale" && expected?.hash === "11".repeat(32) &&
          current?.hash === "33".repeat(32)
        ) stale.set(id, structuredClone(expected));
        return false;
      }
      if (fault === "cas-race") await Promise.resolve();
      credentials.set(id, structuredClone(credential));
      return true;
    },
    markEmailVerified(id, email) {
      const user = users.get(id);
      if (
        user &&
        (fault === "email-guard" || email === undefined || user.email === email)
      ) verified.add(id);
      return Promise.resolve();
    },
    getLegacyCredential(id) {
      return Promise.resolve(legacy.get(id) ?? null);
    },
    clearLegacyCredential(id) {
      if (fault !== "legacy-clear") legacy.delete(id);
      return Promise.resolve();
    },
  };
  if (fault === "cas-missing") delete store.replaceCredential;
  return {
    store,
    unknownUserId: uuid(999),
    makeProfile(sequence) {
      const email = `user${sequence}@example.invalid`;
      return { profile: { email }, email, identifier: email };
    },
    removeCredential(id) {
      credentials.delete(id);
      return Promise.resolve();
    },
    setEmail(id, email) {
      users.get(id)!.email = email;
      verified.delete(id);
      return Promise.resolve();
    },
    isEmailVerified(id) {
      return Promise.resolve(verified.has(id));
    },
    setLegacyCredential(id, hash) {
      legacy.set(id, hash);
      return Promise.resolve();
    },
  };
}

export function sessionFixture(
  fault?: string,
): ListableSessionServiceContractFixture {
  const rows = new Map<
    string,
    {
      userId: string;
      summary: SessionSummary;
      state: IdentitySessionContractState;
      secret: string;
    }
  >();
  function revoke(userId: string, keep?: string): number {
    requireUuid(userId);
    if (keep !== undefined) requireUuid(keep);
    let count = 0;
    for (const row of rows.values()) {
      if (
        (fault === "revoke-owner" || row.userId === userId) &&
        row.summary.id !== keep && row.state === "live"
      ) {
        if (fault !== "revoke-advisory") row.state = "revoked";
        count++;
      }
    }
    return count;
  }
  return {
    userId: uuid(1),
    otherUserId: uuid(2),
    sessionId: (sequence) => uuid(sequence + 100),
    service: {
      revokeAllByUser(userId) {
        return Promise.resolve(revoke(userId));
      },
      revokeOthers(userId, keep) {
        return Promise.resolve(revoke(userId, keep));
      },
      listByUser(userId) {
        requireUuid(userId);
        const list = [...rows.values()].filter((row) =>
          row.userId === userId &&
          (fault === "list-ended" || row.state === "live")
        );
        if (fault !== "list-order") {
          list.sort((a, b) =>
            b.summary.lastSeenAt.getTime() - a.summary.lastSeenAt.getTime()
          );
        }
        return Promise.resolve(
          list.map((row) =>
            fault === "list-secret"
              ? { ...structuredClone(row.summary), secret: row.secret }
              : structuredClone(row.summary)
          ),
        );
      },
    },
    addSession(userId, summary, state) {
      requireUuid(userId);
      requireUuid(summary.id);
      rows.set(summary.id, {
        userId,
        summary: structuredClone(summary),
        state,
        secret: "private-session-material",
      });
      return Promise.resolve();
    },
    isLive(id) {
      return Promise.resolve(rows.get(id)?.state === "live");
    },
  };
}
