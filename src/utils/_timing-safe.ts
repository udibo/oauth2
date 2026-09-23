/**
 * Internal timing-safe matching for secret candidates.
 *
 * @module
 */

import { timingSafeEqualString } from "./crypto.ts";

/**
 * Compares `target` against every candidate with no early exit, so the scan's
 * duration does not reveal where a match occurred. Each comparison is
 * {@link timingSafeEqualString}, which returns early on a byte-length mismatch,
 * so candidates of a different length than `target` are distinguishable by
 * timing. Returns the index of the *last* matching candidate, or `undefined`
 * when none match — order candidates least- to most-preferred so a duplicate
 * resolves to the preferred entry.
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
