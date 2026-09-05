/**
 * Breached-password rejection via the Have I Been Pwned range API — the
 * privacy-preserving k-anonymity model: only the first five characters of the
 * password's SHA-1 hash ever leave the process; the full password and full
 * hash never do.
 *
 * {@link breachedPasswordValidator} returns an async validator for
 * {@link PasswordPolicy.validators}, so a policy rejects known-breached
 * passwords at sign-up and password reset. **Fail-open by default**: if the
 * range API is unreachable, the password is allowed —
 * availability of your sign-up flow shouldn't hinge on a third party. Set
 * `failOpen: false` to invert that.
 *
 * Pass `onEvent` so those fail-opens reach your audit store as
 * `password_policy.check_unavailable` events; an egress rule that blocks
 * `api.pwnedpasswords.com` disables this control silently otherwise.
 *
 * @module
 */

import { encodeHex } from "@std/encoding/hex";

import { dispatchIdentityEvent, type IdentityEventHook } from "./events.ts";

/** Options for {@link breachedPasswordValidator}. */
export interface BreachedPasswordOptions {
  /**
   * Reject when the password appears in at least this many breaches.
   * Defaults to 1.
   */
  threshold?: number;
  /**
   * Allow the password when the range API can't be reached (default `true`).
   * `false` rejects with a retry message instead.
   */
  failOpen?: boolean;
  /** Abort the range request after this many ms. Defaults to 3000. */
  timeoutMs?: number;
  /** Fetch implementation — inject for tests. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Range API base URL. Defaults to `https://api.pwnedpasswords.com/range/`. */
  baseUrl?: string;
  /**
   * Receives a `password_policy.check_unavailable` {@link IdentityEvent} every
   * time the range lookup fails, so a fail-open is answerable from the same
   * audit store as every other identity outcome ("was this check actually
   * running last month?"). Pass the hook you gave `IdentityService`'s
   * `onEvent`.
   *
   * Without it the failure is only a `console.warn` — greppable in container
   * logs, invisible to an audit query. The hook follows the
   * {@link IdentityEventHook} contract: awaited, and a rejection is logged
   * rather than rethrown, so the sign-up it observes still completes.
   */
  onEvent?: IdentityEventHook;
}

const DEFAULT_BASE_URL = "https://api.pwnedpasswords.com/range/";
const VALIDATOR_NAME = "breached_password";
const BREACHED_MESSAGE =
  "This password has appeared in a data breach; choose a different one.";
const UNAVAILABLE_MESSAGE =
  "The password couldn't be checked against known breaches; try again.";

/** Uppercase hex SHA-1, the digest format the HIBP range API keys on. */
export async function sha1Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-1",
    new TextEncoder().encode(input),
  );
  return encodeHex(digest).toUpperCase();
}

/**
 * Build a {@link PasswordPolicy} validator that rejects passwords found in the
 * HIBP breach corpus.
 *
 * @example
 * ```ts
 * const policy: PasswordPolicy = {
 *   minLength: 8,
 *   validators: [breachedPasswordValidator({ onEvent })],
 * };
 * ```
 */
export function breachedPasswordValidator(
  options: BreachedPasswordOptions = {},
): (password: string) => Promise<string | undefined> {
  const threshold = options.threshold ?? 1;
  const failOpen = options.failOpen ?? true;
  const timeoutMs = options.timeoutMs ?? 3000;
  const fetchImpl = options.fetch ?? fetch;
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  const onEvent = options.onEvent;

  return async (password: string): Promise<string | undefined> => {
    try {
      const hash = await sha1Hex(password);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      const response = await fetchImpl(`${baseUrl}${prefix}`, {
        headers: { "Add-Padding": "true" },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error(`range API responded ${response.status}`);
      }
      const body = await response.text();

      for (const line of body.split("\n")) {
        const [lineSuffix, countText] = line.trim().split(":");
        if (lineSuffix === suffix && Number(countText) >= threshold) {
          return BREACHED_MESSAGE;
        }
      }
      return undefined;
    } catch (error) {
      if (onEvent) {
        await dispatchIdentityEvent(onEvent, "breachedPasswordValidator", {
          type: "password_policy.check_unavailable",
          validator: VALIDATOR_NAME,
          failedOpen: failOpen,
          error: error instanceof Error ? error.message : String(error),
        });
      } else {
        console.warn("[@udibo/oauth2] breached-password check failed:", error);
      }
      return failOpen ? undefined : UNAVAILABLE_MESSAGE;
    }
  };
}
