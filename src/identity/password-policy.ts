/**
 * A small, configurable password policy. Defaults to a length floor (the NIST
 * guidance is "length over composition rules"); add your own `validators` for
 * extra checks (e.g. a breached-password list). Tenant-agnostic.
 *
 * @module
 */

import { IdentityError } from "./errors.ts";

/** Password policy configuration. */
export interface PasswordPolicy {
  /** Minimum length. Defaults to 8. */
  minLength?: number;
  /** Maximum length (a DoS guard on the hash input). Defaults to 256. */
  maxLength?: number;
  /**
   * Extra checks. Each returns an issue string to reject, or `undefined` to
   * pass, and may be async — e.g. {@link breachedPasswordValidator}, whose
   * k-anonymity range lookup needs the network.
   */
  validators?: Array<
    (password: string) => string | undefined | Promise<string | undefined>
  >;
}

/** The result of {@link checkPasswordPolicy}. */
export interface PasswordPolicyResult {
  /** Whether the password satisfied every policy check. */
  ok: boolean;
  /** Human-readable issues; empty when `ok`. */
  issues: string[];
}

/**
 * Check a password against a policy, collecting all issues.
 *
 * Fails closed on a non-string `password` — an untyped value off a JSON body
 * has no `length`, so the length checks would silently pass it through to a
 * hash function that then `String`-coerces it.
 */
export async function checkPasswordPolicy(
  password: string,
  policy: PasswordPolicy = {},
): Promise<PasswordPolicyResult> {
  if (typeof password !== "string") {
    return { ok: false, issues: ["Password must be a string."] };
  }
  const minLength = policy.minLength ?? 8;
  const maxLength = policy.maxLength ?? 256;
  const issues: string[] = [];

  if (password.length < minLength) {
    issues.push(`Password must be at least ${minLength} characters.`);
  }
  if (password.length > maxLength) {
    issues.push(`Password must be at most ${maxLength} characters.`);
  }
  for (const validate of policy.validators ?? []) {
    const issue = await validate(password);
    if (issue) issues.push(issue);
  }
  return { ok: issues.length === 0, issues };
}

/**
 * Throw {@link IdentityError} `weak_password` if the policy fails (the issues
 * are joined into the message). Convenient before {@link PasswordIdentityService.hash}.
 *
 * A custom `validators` entry that **throws** (rather than returning an issue
 * string) is trapped and surfaced as the same `weak_password` error, so a
 * misbehaving validator fails closed instead of leaking a raw error to the
 * caller. A validator that itself throws an {@link IdentityError} is preserved.
 */
export async function assertPasswordPolicy(
  password: string,
  policy?: PasswordPolicy,
): Promise<void> {
  let result: PasswordPolicyResult;
  try {
    result = await checkPasswordPolicy(password, policy);
  } catch (error) {
    if (error instanceof IdentityError) throw error;
    throw new IdentityError(
      "weak_password",
      "Password could not be validated.",
      {
        cause: error,
      },
    );
  }
  if (!result.ok) {
    throw new IdentityError("weak_password", result.issues.join(" "));
  }
}
