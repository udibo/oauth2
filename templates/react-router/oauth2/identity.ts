/**
 * Own-auth identity flows: sign-up, sign-in, password reset, and email
 * verification via the library's `IdentityService`. The SPA's `/login` and
 * `/signup` pages post to the routes `main.ts` mounts over this service.
 *
 * The user store adapts the same `MemoryUserService` the authorization server
 * authenticates against, so credentials live in exactly one place. The email
 * address doubles as the sign-in identifier (`AppUser.username`), normalized
 * case-insensitively.
 *
 * Two demo-store shortcuts a real store should not copy: `create` seeds `add`
 * with a throwaway password then overwrites it with `setCredential` (a real
 * store writes the credential in one step), and `markEmailVerified` mutates the
 * object `get` returns, which only persists because the in-memory store hands
 * back a live reference — a DB-backed store must issue an explicit write.
 *
 * There is no mailer — `delivery` logs each action link to the server console;
 * click it from there. Swap those two hooks for your email transport when you
 * have one (enqueue the send rather than awaiting your provider in-request, so
 * response timing stays enumeration-safe).
 *
 * @module
 */

import {
  type DeliveryHooks,
  IdentityError,
  IdentityService,
  type IdentityUserStore,
  MemoryTokenFlowStore,
  TokenFlowService,
} from "@udibo/oauth2/identity";

import { ORIGIN } from "@/config.ts";
import { revokeUserSessions } from "@/sessions.ts";
import { type AppUser, userService } from "./server.ts";

function emailKey(email: string): string {
  return email.trim().toLowerCase();
}

const store: IdentityUserStore<AppUser> = {
  async create(profile, credential) {
    const email = emailKey(String(profile.email ?? ""));
    if (await userService.findByUsername(email)) {
      throw new IdentityError(
        "identifier_taken",
        "That email is already registered.",
      );
    }
    const user: AppUser = {
      id: `user-${crypto.randomUUID()}`,
      username: email,
      name: String(profile.name ?? "") || email,
      email,
      emailVerified: false,
    };
    await userService.add(user, crypto.randomUUID());
    await userService.setCredential(user.id, credential);
    return user;
  },
  findByIdentifier(identifier) {
    return userService.findByUsername(emailKey(identifier));
  },
  findByEmail(email) {
    return userService.findByUsername(emailKey(email));
  },
  getCredential(userId) {
    return userService.getCredential(userId);
  },
  setCredential(userId, credential) {
    return userService.setCredential(userId, credential);
  },
  async markEmailVerified(userId, email) {
    const user = await userService.get(userId);
    if (!user) return;
    if (email !== undefined && emailKey(user.email) !== emailKey(email)) return;
    user.emailVerified = true;
  },
};

/**
 * Console "transport" for verification/reset links. Exported so tests stub
 * these methods on the instance to capture tokens instead of reading the
 * console. Replace with your mailer for real delivery.
 */
export const delivery: DeliveryHooks = {
  sendPasswordReset(message) {
    console.log(`[email] Password reset link for ${message.to}:`);
    console.log(`  ${message.url}`);
  },
  sendEmailVerification(message) {
    console.log(`[email] Verification link for ${message.to}:`);
    console.log(`  ${message.url}`);
  },
};

/** The own-auth orchestrator behind the `/identity/*` routes. */
export const identity = new IdentityService<AppUser>({
  users: store,
  tokens: new TokenFlowService(new MemoryTokenFlowStore()),
  sessions: {
    revokeAllByUser: (userId) => Promise.resolve(revokeUserSessions(userId)),
    revokeOthers: (userId, keepSessionId) =>
      Promise.resolve(revokeUserSessions(userId, keepSessionId)),
  },
  delivery,
  baseUrl: ORIGIN,
  passwordPolicy: { minLength: 8 },
});
