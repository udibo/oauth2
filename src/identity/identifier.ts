/**
 * Sign-in identifier classification + resolution.
 *
 * A sign-in form usually accepts "email or username" (sometimes phone), and
 * every app hand-rolls the `identifier.includes("@")` branch to decide which
 * lookup to run. This makes that a configured concern instead.
 *
 * @module
 */

/** How a sign-in identifier was classified. */
export type IdentifierKind = "email" | "username" | "phone";

/**
 * Classify a sign-in identifier as an email, phone number, or username.
 *
 * Heuristic: an `@` → `email`; otherwise a value made only of phone characters
 * (`+`, digits, spaces, `-`, `()`, `.`) with at least 7 digits → `phone`;
 * everything else → `username`. The value is trimmed first.
 */
export function classifyIdentifier(identifier: string): IdentifierKind {
  const value = identifier.trim();
  if (value.includes("@")) return "email";
  const digitCount = (value.match(/\d/g) ?? []).length;
  if (digitCount >= 7 && /^\+?[\d\s\-().]+$/.test(value)) return "phone";
  return "username";
}

/** Per-kind user lookups supplied by the app. Omit a kind to disallow it. */
export interface IdentifierLookups<User> {
  /** Resolve a user by email; omit to disallow signing in with an email. */
  email?: (email: string) => Promise<User | undefined> | User | undefined;
  /** Resolve a user by username; omit to disallow signing in with a username. */
  username?: (username: string) => Promise<User | undefined> | User | undefined;
  /** Resolve a user by phone number; omit to disallow signing in with a phone. */
  phone?: (phone: string) => Promise<User | undefined> | User | undefined;
}

/**
 * Build a resolver that classifies an identifier ({@link classifyIdentifier})
 * and dispatches to the matching app-supplied lookup. Returns `undefined` when
 * no lookup is configured for the classified kind, or the user isn't found —
 * callers should treat both as "invalid credentials" without revealing which.
 *
 * @example
 * ```ts
 * const resolve = createIdentifierResolver({
 *   email: (e) => userService.getByEmail(e),
 *   username: (u) => userService.getByUsername(u),
 * });
 * const user = await resolve(form.get("identifier"));
 * ```
 */
export function createIdentifierResolver<User>(
  lookups: IdentifierLookups<User>,
): (identifier: string) => Promise<User | undefined> {
  return async (identifier) => {
    const value = identifier.trim();
    const lookup = lookups[classifyIdentifier(value)];
    return lookup ? await lookup(value) : undefined;
  };
}
