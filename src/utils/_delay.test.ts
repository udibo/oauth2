import { afterEach, describe, expect, it, vi } from "vitest";
import { FakeTime } from "../_test_fake-time.ts";
import { delay } from "./_delay.ts";

afterEach(() => {
  vi.useRealTimers();
});

describe("delay", () => {
  it("resolves once the time has passed and not before", async () => {
    using time = new FakeTime();
    let done = false;
    const pending = delay(100).then(() => {
      done = true;
    });

    await time.tickAsync(99);
    expect(done).toBe(false);
    await time.tickAsync(1);
    await pending;
    expect(done).toBe(true);
  });

  it("rejects with the signal's reason when it aborts first, and stops the timer", async () => {
    using time = new FakeTime();
    const controller = new AbortController();
    const reason = new Error("stop");
    const pending = delay(1_000, { signal: controller.signal });

    controller.abort(reason);

    await expect(pending).rejects.toBe(reason);
    expect(vi.getTimerCount()).toBe(0);
    await time.tickAsync(1_000);
  });

  it("rejects immediately when the signal is already aborted, without starting a timer", async () => {
    using _time = new FakeTime();

    await expect(
      delay(1_000, { signal: AbortSignal.abort(new Error("early")) }),
    ).rejects.toThrow("early");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not leave an abort listener behind after it resolves", async () => {
    using time = new FakeTime();
    const controller = new AbortController();
    const remove = vi.spyOn(controller.signal, "removeEventListener");
    const pending = delay(10, { signal: controller.signal });

    await time.tickAsync(10);
    await pending;

    expect(remove).toHaveBeenCalledWith("abort", expect.any(Function));
  });
});
