/**
 * Internal constant-time byte comparison for modules that also run in
 * browsers, where `node:crypto` is unavailable.
 *
 * @module
 */

/**
 * Compares two byte arrays without an early exit on the first differing byte.
 * Returns `false` immediately when the lengths differ, so the length is not
 * secret.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let i = 0; i < a.byteLength; i++) difference |= a[i]! ^ b[i]!;
  return difference === 0;
}
