/**
 * Validates clock-skew configuration shared by token readers and resource
 * servers.
 *
 * @module
 */

/** Throws `RangeError` unless the leeway is non-negative, finite seconds whose millisecond conversion is finite. */
export function assertClockSkewSeconds(clockSkewSeconds: number): void {
  if (
    !Number.isFinite(clockSkewSeconds) ||
    clockSkewSeconds < 0 ||
    !Number.isFinite(clockSkewSeconds * 1000)
  ) {
    throw new RangeError(
      "clockSkewSeconds must be non-negative finite seconds with a finite millisecond conversion",
    );
  }
}
