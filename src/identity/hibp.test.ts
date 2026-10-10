import { assert, describe, expect, it, vi } from "vitest";
import type { IdentityEvent } from "./events.ts";
import { breachedPasswordValidator, sha1Hex } from "./hibp.ts";

function rangeFetch(
  lines: string[],
  captured: { url?: string; padding?: string | null },
): typeof fetch {
  return ((input: URL | RequestInfo, init?: RequestInit) => {
    captured.url = String(input);
    captured.padding = new Headers(init?.headers).get("Add-Padding");
    return Promise.resolve(new Response(lines.join("\r\n"), { status: 200 }));
  }) as typeof fetch;
}

const rejectingFetch = (() =>
  Promise.reject(new Error("offline"))) as typeof fetch;

const respondingFetch = (status: number) =>
  (() => Promise.resolve(new Response("nope", { status }))) as typeof fetch;

/** Never settles on its own — only the caller's timeout signal ends it. */
const hangingFetch = ((_input: URL | RequestInfo, init?: RequestInit) =>
  new Promise((_resolve, reject) => {
    const signal = init?.signal;
    signal?.addEventListener("abort", () => reject(signal.reason));
  })) as typeof fetch;

type CheckUnavailable = Extract<
  IdentityEvent,
  { type: "password_policy.check_unavailable" }
>;

function eventCollector(): {
  events: IdentityEvent[];
  onEvent: (event: IdentityEvent) => void;
  unavailable: () => CheckUnavailable;
} {
  const events: IdentityEvent[] = [];
  return {
    events,
    onEvent: (event) => {
      events.push(event);
    },
    unavailable: () => {
      expect(events.length).toStrictEqual(1);
      const [event] = events;
      expect(event.type).toStrictEqual("password_policy.check_unavailable");
      return event as CheckUnavailable;
    },
  };
}

describe("breachedPasswordValidator", () => {
  it("rejects a password whose hash suffix appears in the range", async () => {
    const hash = await sha1Hex("password123");
    const captured: { url?: string; padding?: string | null } = {};
    const validate = breachedPasswordValidator({
      fetch: rangeFetch(
        ["00000AAAA:2", `${hash.slice(5)}:1050`, "FFFFFF:1"],
        captured,
      ),
    });

    const issue = await validate("password123");
    assert(issue?.includes("data breach"));
    expect(captured.url).toStrictEqual(
      `https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`,
    );
    expect(captured.padding).toStrictEqual("true");
  });

  it("allows a password not in the range", async () => {
    const validate = breachedPasswordValidator({
      fetch: rangeFetch(["00000AAAA:2"], {}),
    });
    expect(await validate("unique-enough-password")).toStrictEqual(undefined);
  });

  it("honors the breach-count threshold", async () => {
    const hash = await sha1Hex("borderline");
    const lines = [`${hash.slice(5)}:4`];
    const strict = breachedPasswordValidator({
      fetch: rangeFetch(lines, {}),
      threshold: 5,
    });
    expect(await strict("borderline")).toStrictEqual(undefined);

    const loose = breachedPasswordValidator({
      fetch: rangeFetch(lines, {}),
      threshold: 4,
    });
    assert(await loose("borderline"));
  });

  it("fails open on transport errors by default", async () => {
    using _warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const validate = breachedPasswordValidator({ fetch: rejectingFetch });
    expect(await validate("whatever-password")).toStrictEqual(undefined);
  });

  it("fails closed when configured", async () => {
    using _warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const validate = breachedPasswordValidator({
      fetch: rejectingFetch,
      failOpen: false,
    });
    assert((await validate("whatever-password"))?.includes("try again"));
  });

  it("treats a non-2xx range response as a transport failure", async () => {
    using _warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const validate = breachedPasswordValidator({
      fetch: respondingFetch(503),
      failOpen: false,
    });
    assert(await validate("whatever-password"));
  });

  it("warns to the console when no onEvent hook is wired", async () => {
    using warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const validate = breachedPasswordValidator({ fetch: rejectingFetch });
    expect(await validate("whatever-password")).toStrictEqual(undefined);
    expect(warn.mock.calls.length).toStrictEqual(1);
  });
});

describe("breachedPasswordValidator onEvent", () => {
  it("reports a network error as check_unavailable", async () => {
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: rejectingFetch,
      onEvent: collector.onEvent,
    });

    expect(await validate("whatever-password")).toStrictEqual(undefined);
    const event = collector.unavailable();
    expect(event.validator).toStrictEqual("breached_password");
    expect(event.failedOpen).toStrictEqual(true);
    expect(event.error).toStrictEqual("offline");
  });

  it("reports a non-2xx range response as check_unavailable", async () => {
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: respondingFetch(503),
      onEvent: collector.onEvent,
    });

    expect(await validate("whatever-password")).toStrictEqual(undefined);
    expect(collector.unavailable().error).toContain("503");
  });

  it("reports a timed-out range request as check_unavailable", async () => {
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: hangingFetch,
      timeoutMs: 5,
      onEvent: collector.onEvent,
    });

    expect(await validate("whatever-password")).toStrictEqual(undefined);
    expect(collector.unavailable().failedOpen).toStrictEqual(true);
  });

  it("reports failedOpen false when the password was rejected instead", async () => {
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: rejectingFetch,
      failOpen: false,
      onEvent: collector.onEvent,
    });

    assert((await validate("whatever-password"))?.includes("try again"));
    expect(collector.unavailable().failedOpen).toStrictEqual(false);
  });

  it("emits nothing when the range lookup succeeds", async () => {
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: rangeFetch(["00000AAAA:2"], {}),
      onEvent: collector.onEvent,
    });

    expect(await validate("unique-enough-password")).toStrictEqual(undefined);
    expect(collector.events.length).toStrictEqual(0);
  });

  it("replaces the console warning rather than doubling it", async () => {
    using warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: rejectingFetch,
      onEvent: collector.onEvent,
    });

    await validate("whatever-password");
    expect(collector.events.length).toStrictEqual(1);
    expect(warn.mock.calls.length).toStrictEqual(0);
  });

  it("keeps the password decision when the hook itself throws", async () => {
    using error = vi.spyOn(console, "error").mockImplementation(() => {});
    const validate = breachedPasswordValidator({
      fetch: rejectingFetch,
      onEvent: () => {
        throw new Error("audit sink down");
      },
    });

    expect(await validate("whatever-password")).toStrictEqual(undefined);
    expect(error.mock.calls.length).toStrictEqual(1);
  });
});
