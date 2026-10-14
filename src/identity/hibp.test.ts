import { assert, describe, expect, it, vi } from "vitest";
import { thrown } from "../_test_assert.ts";
import { type Reply, serveReplies } from "../_test_response-server.ts";
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

describe("breachedPasswordValidator response size limit", () => {
  const PASSWORD = "correct horse battery staple";
  const DEFAULT_LIMIT = 1024 * 1024;

  async function rangeEndingInMatch(bytes: number): Promise<string> {
    const line = `\r\n${(await sha1Hex(PASSWORD)).slice(5)}:3`;
    return `${"0".repeat(bytes - line.length)}${line}`;
  }

  async function check(
    reply: Reply,
    options: { maxResponseBytes?: number } = {},
  ): Promise<{ result: string | undefined; events: IdentityEvent[] }> {
    await using server = await serveReplies(() => reply);
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      baseUrl: `${server.origin}/range/`,
      failOpen: false,
      timeoutMs: 2_000,
      onEvent: collector.onEvent,
      ...options,
    });
    const result = await validate(PASSWORD);
    if (reply.transfer === "endless") await server.abandoned;
    return { result, events: collector.events };
  }

  it("reads a range response of exactly the default 1 MiB cap", async () => {
    const { result, events } = await check({
      contentType: "text/plain",
      body: await rangeEndingInMatch(DEFAULT_LIMIT),
      transfer: "chunked",
    });

    expect(result).toContain("appeared in a data breach");
    expect(events).toStrictEqual([]);
  });

  for (const transfer of ["length", "chunked"] as const) {
    it(`treats a range response over the cap as unavailable (${transfer})`, async () => {
      const { result, events } = await check({
        contentType: "text/plain",
        body: await rangeEndingInMatch(DEFAULT_LIMIT + 1),
        transfer,
      });

      expect(result).toContain("couldn't be checked");
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        type: "password_policy.check_unavailable",
        error: `range API response exceeded ${DEFAULT_LIMIT} bytes`,
      });
    });
  }

  it("stops reading an endless range response at the cap and cancels it", async () => {
    const { result, events } = await check({
      contentType: "text/plain",
      body: "0",
      transfer: "endless",
    });

    expect(result).toContain("couldn't be checked");
    expect(events[0]).toMatchObject({
      error: `range API response exceeded ${DEFAULT_LIMIT} bytes`,
    });
  });

  it("uses maxResponseBytes in place of the default", async () => {
    const body = await rangeEndingInMatch(2048);
    const reply: Reply = {
      contentType: "text/plain",
      body,
      transfer: "chunked",
    };

    expect((await check(reply, { maxResponseBytes: 2047 })).result).toContain(
      "couldn't be checked",
    );
    expect((await check(reply, { maxResponseBytes: 2048 })).result).toContain(
      "appeared in a data breach",
    );
  });

  it("rejects a maxResponseBytes that is not a positive integer", () => {
    for (const maxResponseBytes of [0, -1, 1.5, Number.NaN, Infinity]) {
      thrown(
        () => breachedPasswordValidator({ maxResponseBytes }),
        RangeError,
        "maxResponseBytes must be a positive integer",
      );
    }
  });
});
