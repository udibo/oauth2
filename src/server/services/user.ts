/**
 * Service interface for user management.
 * Provides user lookup and authentication.
 */
export interface UserServiceInterface<User> {
  /** Retrieves a user by their unique identifier. */
  get(id: string): Promise<User | undefined>;
  /**
   * Retrieves an authenticated user if the username/password combination is
   * correct.
   *
   * Only the password grant calls this, and the grant issues tokens for
   * whatever user this returns — it applies **no second-factor check of its
   * own**. This method is therefore the only place an MFA policy can be
   * enforced on that flow: return `undefined` or throw for a user who owes a
   * second factor, or accept that their password alone mints tokens.
   *
   * Throwing an OAuth2 error (e.g. `InvalidGrantError`) surfaces it on the
   * token response as that error; anything else becomes a `server_error`.
   */
  getAuthenticated(
    username: string,
    password: string,
  ): Promise<User | undefined>;
}

/**
 * The password hashing primitives, re-exported from the identity layer so a
 * credential minted through one entrypoint verifies through the other. See
 * `@udibo/oauth2/identity` for the work-factor constants and the
 * `PasswordIdentityService` that records them on the credential.
 */
export {
  generateSalt,
  hashPassword,
  verifyPassword,
} from "../../identity/password.ts";
