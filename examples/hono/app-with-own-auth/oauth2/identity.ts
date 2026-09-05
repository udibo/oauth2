/**
 * Own-auth identity flows for the embedded IDP: sign-up, password reset, and
 * email verification via the library's `IdentityService` orchestrator.
 *
 * The `IdentityUserStore` adapts the example's `MemoryUserService` (the same
 * store the login form and password grant authenticate against, so credentials
 * live in exactly one place) plus a local email index keyed case-insensitively.
 * Tokens are single-use and hashed at rest via `MemoryTokenFlowStore`; a
 * completed reset revokes the user's other IDP sessions.
 *
 * Two demo-store shortcuts a real store should not copy: `create` seeds
 * `MemoryUserService.add` with a throwaway password (its signature requires
 * one) and immediately replaces it with the identity layer's credential, and
 * the email index enforces no uniqueness — signing up with an email that is
 * already indexed repoints future resets at the newest account. A real store
 * writes the credential in one step and constrains email uniqueness.
 *
 * The example has no mailer, so `delivery` logs each action link to the server
 * console — click it from there. A real app replaces those two hooks with its
 * email transport; everything else stays the same. Responses stay
 * enumeration-safe: `requestPasswordReset` resolves identically whether or not
 * the email matches an account.
 *
 * @module
 */

import {
  type DeliveryHooks,
  IdentityService,
  type IdentityUserStore,
  MemoryTokenFlowStore,
  TokenFlowService,
} from "@udibo/oauth2/identity";

import { revokeUserSessions } from "../sessions.ts";
import {
  ADMIN_USER,
  type DemoUser,
  STANDARD_USER,
  userService,
} from "./server.ts";

function emailKey(email: string): string {
  return email.trim().toLowerCase();
}

const usersByEmail = new Map<string, DemoUser>();
for (const user of [ADMIN_USER, STANDARD_USER]) {
  if (user.email) usersByEmail.set(emailKey(user.email), user);
}

const store: IdentityUserStore<DemoUser> = {
  async create(profile, credential) {
    const user: DemoUser = {
      id: `user-${crypto.randomUUID()}`,
      username: String(profile.username),
      name: String(profile.name || profile.username),
      maxScope: "read write",
      email: profile.email ? String(profile.email) : undefined,
      emailVerified: false,
    };
    await userService.add(user, crypto.randomUUID());
    await userService.setCredential(user.id, credential);
    if (user.email) usersByEmail.set(emailKey(user.email), user);
    return user;
  },
  findByIdentifier(identifier) {
    return userService.findByUsername(identifier);
  },
  findByEmail(email) {
    return Promise.resolve(usersByEmail.get(emailKey(email)));
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
    if (email !== undefined && emailKey(user.email ?? "") !== emailKey(email)) {
      return;
    }
    user.emailVerified = true;
  },
};

/**
 * Console "transport" for verify/reset links. Exported so tests stub these
 * methods on the instance to capture tokens instead of reading the console.
 */
export const delivery: DeliveryHooks = {
  sendPasswordReset(message) {
    console.log(`[forgot-password] Reset link for ${message.to}:`);
    console.log(`  ${message.url}`);
  },
  sendEmailVerification(message) {
    console.log(`[verify-email] Verification link for ${message.to}:`);
    console.log(`  ${message.url}`);
  },
};

/** Token flow shared with routes that `validate()` without consuming. */
export const tokens = new TokenFlowService(new MemoryTokenFlowStore());

/** The example's own-auth orchestrator; routes call these flows directly. */
export const identity = new IdentityService<DemoUser>({
  users: store,
  tokens,
  sessions: {
    revokeAllByUser: (userId) => Promise.resolve(revokeUserSessions(userId)),
    revokeOthers: (userId, keepSessionId) =>
      Promise.resolve(revokeUserSessions(userId, keepSessionId)),
  },
  delivery,
  baseUrl: "http://localhost:8001",
  passwordPolicy: { minLength: 8 },
});
