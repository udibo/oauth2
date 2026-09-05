/**
 * The app's own-auth flows — the credential half of `/login` and `/signup` —
 * built on the library's `IdentityService` over the same user store the
 * authorization server issues tokens for, so credentials live in one place.
 *
 * Reach for `IdentityService.signIn` rather than checking a password
 * yourself. It throttles per identifier *before* the account lookup, locks an
 * account after repeated wrong passwords, and hashes on every failure branch,
 * so an unknown username takes as long to reject as a known one with a wrong
 * password. A hand-rolled check that returns early on "no such user" answers
 * measurably faster for unknown names, which is a username-enumeration
 * oracle — and one that survives swapping the in-memory store for a database.
 *
 * Demo shortcuts a real store should not copy: `create` seeds `add` with a
 * throwaway password and immediately overwrites it via `setCredential`
 * (a database-backed store writes the credential in one statement), and the
 * rate-limit and lockout counters live in per-process memory, so they reset on
 * restart and are not shared across instances. Back them with your database or
 * Redis via the `RateLimitStore` / `LockoutStore` seams before running more
 * than one process.
 *
 * @module
 */

import {
  AccountLockout,
  IdentityError,
  IdentityService,
  type IdentityUserStore,
  RateLimiter,
} from "@udibo/oauth2/identity";

import { type AppUser, passwords, userService } from "@/oauth2/server.ts";

const store: IdentityUserStore<AppUser> = {
  async create(profile, credential) {
    const username = String(profile.username ?? "").trim();
    if (await userService.findByUsername(username)) {
      throw new IdentityError(
        "identifier_taken",
        "That username is already taken.",
      );
    }
    const user: AppUser = {
      id: crypto.randomUUID(),
      username,
      name: String(profile.name ?? "").trim() || username,
    };
    await userService.add(user, crypto.randomUUID());
    await userService.setCredential(user.id, credential);
    return user;
  },
  findByIdentifier(identifier) {
    return userService.findByUsername(identifier.trim());
  },
  findByEmail(email) {
    return userService.findByUsername(email.trim());
  },
  getCredential(userId) {
    return userService.getCredential(userId);
  },
  setCredential(userId, credential) {
    return userService.setCredential(userId, credential);
  },
};

/**
 * The own-auth orchestrator the `/login` and `/signup` actions call. Sign-in
 * is throttled to 10 attempts per identifier per 15 minutes and an account
 * locks for 15 minutes after 10 consecutive wrong passwords; both reset on a
 * successful sign-in.
 */
export const identity: IdentityService<AppUser> = new IdentityService<AppUser>({
  users: store,
  passwords,
  passwordPolicy: { minLength: 8 },
  rateLimiter: new RateLimiter({ limit: 10, windowMs: 15 * 60_000 }),
  lockout: new AccountLockout({
    maxAttempts: 10,
    lockDurationMs: 15 * 60_000,
  }),
});
