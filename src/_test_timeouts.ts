import { vi } from "vitest";

/** Hands out `AbortSignal.timeout` signals that expire only on request. */
export interface ControlledTimeouts extends Disposable {
  /** The duration, in milliseconds, of every timeout signal requested. */
  requested: number[];
  /** Expires the most recently created timeout signal with a `TimeoutError`. */
  expireLatest(): void;
  /** Expires every timeout signal created so far. */
  expireAll(): void;
  /** Waits until `count` timeout signals exist, then expires them all. */
  expireOnceRequested(count: number): Promise<void>;
}

/**
 * Replaces `AbortSignal.timeout` so a test, not the clock, decides when a
 * package deadline passes. Declare it with `using`.
 */
export function controlTimeouts(): ControlledTimeouts {
  const controllers: AbortController[] = [];
  const requested: number[] = [];
  const spy = vi.spyOn(AbortSignal, "timeout").mockImplementation((ms) => {
    requested.push(ms);
    const controller = new AbortController();
    controllers.push(controller);
    return controller.signal;
  });
  const expire = (controller: AbortController | undefined): void =>
    controller?.abort(new DOMException("timed out", "TimeoutError"));
  return {
    requested,
    expireLatest: () => expire(controllers.at(-1)),
    expireAll: () => controllers.forEach(expire),
    async expireOnceRequested(count) {
      await vi.waitFor(() => {
        if (requested.length < count) {
          throw new Error(`${requested.length} of ${count} timeouts requested`);
        }
      });
      controllers.forEach(expire);
    },
    [Symbol.dispose]: () => spy.mockRestore(),
  };
}
