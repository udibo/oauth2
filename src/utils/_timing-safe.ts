/**
 * Internal constant-time matching shared by the MFA and BFF code paths.
 *
 * @module
 */

import { timingSafeEqualString } from "./crypto.ts";

/**
 * Constant-time scan for `target` among `candidates`: every candidate is
 * compared (no early exit), so timing reveals neither whether nor where a
 * match occurred. Returns the index of the *last* matching candidate, or
 * `undefined` when none match — order candidates least- to most-preferred so
 * a duplicate resolves to the preferred entry.
 */
export function timingSafeMatchIndex(
  candidates: string[],
  target: string,
): number | undefined {
  let index: number | undefined;
  for (let i = 0; i < candidates.length; i++) {
    if (timingSafeEqualString(candidates[i], target)) {
      index = i;
    }
  }
  return index;
}
