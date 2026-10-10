/**
 * Internal cancellable sleep shared by the client and the identity service.
 *
 * @module
 */

/**
 * Resolves after `ms` milliseconds. When `signal` aborts first, rejects with
 * the signal's reason and clears the timer. Uses the global `setTimeout`, so
 * fake timers control it.
 */
export function delay(
  ms: number,
  options: { signal?: AbortSignal } = {},
): Promise<void> {
  const { signal } = options;
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
