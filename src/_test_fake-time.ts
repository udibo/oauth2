import { vi } from "vitest";

/**
 * Fake timers for the clock the package reads: `Date`, `setTimeout`, and
 * `setInterval`, plus `performance.now` when `options.performance` is set. Declare it with `using` so the real clock returns when the
 * test ends.
 */
export class FakeTime implements Disposable {
  constructor(
    start: number | string | Date = Date.now(),
    options: { performance?: boolean } = {},
  ) {
    vi.useFakeTimers({
      now: new Date(start),
      toFake: [
        "Date",
        "setTimeout",
        "clearTimeout",
        "setInterval",
        "clearInterval",
        ...(options.performance ? (["performance"] as const) : []),
      ],
    });
  }

  get now(): number {
    return Date.now();
  }

  tick(ms = 0): void {
    vi.advanceTimersByTime(ms);
  }

  async tickAsync(ms = 0): Promise<void> {
    await vi.advanceTimersByTimeAsync(ms);
  }

  async settle<T>(promise: Promise<T>, stepMs = 1): Promise<T> {
    let settled = false;
    const watched = promise.finally(() => {
      settled = true;
    });
    watched.catch(() => {});
    while (!settled) await this.tickAsync(stepMs);
    return await promise;
  }

  async runAllAsync(): Promise<void> {
    await vi.runAllTimersAsync();
  }

  [Symbol.dispose](): void {
    vi.useRealTimers();
  }
}
