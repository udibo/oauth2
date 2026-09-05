import { assert, assertEquals, assertStringIncludes } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { stub } from "@std/testing/mock";

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

const rejectingFetch =
  (() => Promise.reject(new Error("offline"))) as typeof fetch;

const respondingFetch = (status: number) =>
  (() => Promise.resolve(new Response("nope", { status }))) as typeof fetch;

/** Never settles on its own — only the caller's timeout signal ends it. */
const hangingFetch =
  ((_input: URL | RequestInfo, init?: RequestInit) =>
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
      assertEquals(events.length, 1);
      const [event] = events;
      assertEquals(event.type, "password_policy.check_unavailable");
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
    assertEquals(
      captured.url,
      `https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`,
    );
    assertEquals(captured.padding, "true");
  });

  it("allows a password not in the range", async () => {
    const validate = breachedPasswordValidator({
      fetch: rangeFetch(["00000AAAA:2"], {}),
    });
    assertEquals(await validate("unique-enough-password"), undefined);
  });

  it("honors the breach-count threshold", async () => {
    const hash = await sha1Hex("borderline");
    const lines = [`${hash.slice(5)}:4`];
    const strict = breachedPasswordValidator({
      fetch: rangeFetch(lines, {}),
      threshold: 5,
    });
    assertEquals(await strict("borderline"), undefined);

    const loose = breachedPasswordValidator({
      fetch: rangeFetch(lines, {}),
      threshold: 4,
    });
    assert(await loose("borderline"));
  });

  it("fails open on transport errors by default", async () => {
    using _warn = stub(console, "warn");
    const validate = breachedPasswordValidator({ fetch: rejectingFetch });
    assertEquals(await validate("whatever-password"), undefined);
  });

  it("fails closed when configured", async () => {
    using _warn = stub(console, "warn");
    const validate = breachedPasswordValidator({
      fetch: rejectingFetch,
      failOpen: false,
    });
    assert((await validate("whatever-password"))?.includes("try again"));
  });

  it("treats a non-2xx range response as a transport failure", async () => {
    using _warn = stub(console, "warn");
    const validate = breachedPasswordValidator({
      fetch: respondingFetch(503),
      failOpen: false,
    });
    assert(await validate("whatever-password"));
  });

  it("warns to the console when no onEvent hook is wired", async () => {
    using warn = stub(console, "warn");
    const validate = breachedPasswordValidator({ fetch: rejectingFetch });
    assertEquals(await validate("whatever-password"), undefined);
    assertEquals(warn.calls.length, 1);
  });
});

describe("breachedPasswordValidator onEvent", () => {
  it("reports a network error as check_unavailable", async () => {
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: rejectingFetch,
      onEvent: collector.onEvent,
    });

    assertEquals(await validate("whatever-password"), undefined);
    const event = collector.unavailable();
    assertEquals(event.validator, "breached_password");
    assertEquals(event.failedOpen, true);
    assertEquals(event.error, "offline");
  });

  it("reports a non-2xx range response as check_unavailable", async () => {
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: respondingFetch(503),
      onEvent: collector.onEvent,
    });

    assertEquals(await validate("whatever-password"), undefined);
    assertStringIncludes(collector.unavailable().error, "503");
  });

  it("reports a timed-out range request as check_unavailable", async () => {
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: hangingFetch,
      timeoutMs: 5,
      onEvent: collector.onEvent,
    });

    assertEquals(await validate("whatever-password"), undefined);
    assertEquals(collector.unavailable().failedOpen, true);
  });

  it("reports failedOpen false when the password was rejected instead", async () => {
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: rejectingFetch,
      failOpen: false,
      onEvent: collector.onEvent,
    });

    assert((await validate("whatever-password"))?.includes("try again"));
    assertEquals(collector.unavailable().failedOpen, false);
  });

  it("emits nothing when the range lookup succeeds", async () => {
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: rangeFetch(["00000AAAA:2"], {}),
      onEvent: collector.onEvent,
    });

    assertEquals(await validate("unique-enough-password"), undefined);
    assertEquals(collector.events.length, 0);
  });

  it("replaces the console warning rather than doubling it", async () => {
    using warn = stub(console, "warn");
    const collector = eventCollector();
    const validate = breachedPasswordValidator({
      fetch: rejectingFetch,
      onEvent: collector.onEvent,
    });

    await validate("whatever-password");
    assertEquals(collector.events.length, 1);
    assertEquals(warn.calls.length, 0);
  });

  it("keeps the password decision when the hook itself throws", async () => {
    using error = stub(console, "error");
    const validate = breachedPasswordValidator({
      fetch: rejectingFetch,
      onEvent: () => {
        throw new Error("audit sink down");
      },
    });

    assertEquals(await validate("whatever-password"), undefined);
    assertEquals(error.calls.length, 1);
  });
});
