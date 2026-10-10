import { assert, describe, expect, it, vi } from "vitest";
import { rejection } from "../_test_assert.ts";
import { ServerError, TemporarilyUnavailableError } from "../errors.ts";
import { MAX_RESPONSE_BYTES, REQUEST_TIMEOUT_MS } from "./_http.ts";
import { hangUntilAborted, stubDenoRuntime } from "../_test_deno-runtime.ts";
import { controlTimeouts } from "../_test_timeouts.ts";
import { checkPermissions } from "./check.ts";
import {
  serveDroppedBody,
  serveStalledBody,
} from "./_test_interrupted_body.ts";

function fetchAnswering(
  handler: (input: Request) => Response | Promise<Response>,
): typeof fetch {
  return ((input: RequestInfo | URL, init?: RequestInit) =>
    Promise.resolve(handler(new Request(input, init)))) as typeof fetch;
}

describe("checkPermissions", () => {
  const RESULT = {
    subject: "user-1",
    resource: { type: "organization", id: "org-2" },
    results: { "posts:write": true, "posts:delete": false },
  };

  it("posts the caller's question with their bearer token", async () => {
    let seen: Request | undefined;
    const result = await checkPermissions({
      endpoint: "https://tenant.example.com/api/check",
      accessToken: "token-1",
      permissions: ["posts:write", "posts:delete"],
      resource: { type: "organization", id: "org-2" },
      fetch: fetchAnswering((request) => {
        seen = request;
        return Response.json(RESULT);
      }),
    });

    expect(result).toStrictEqual(RESULT);
    expect(seen?.method).toStrictEqual("POST");
    expect(seen?.headers.get("authorization")).toStrictEqual("Bearer token-1");
    expect(await seen?.json()).toStrictEqual({
      permissions: ["posts:write", "posts:delete"],
      resource: { type: "organization", id: "org-2" },
    });
  });

  it("omits resource for the credential's own scope", async () => {
    let body: unknown;
    await checkPermissions({
      endpoint: "https://tenant.example.com/api/check",
      accessToken: "token-1",
      permissions: "posts:write",
      fetch: fetchAnswering(async (request) => {
        body = await request.json();
        return Response.json({
          subject: "user-1",
          resource: null,
          results: { "posts:write": true },
        });
      }),
    });
    expect(body).toStrictEqual({ permissions: "posts:write" });
  });

  it("reports an unreachable or failing endpoint as temporarily unavailable", async () => {
    const dnsFailure = new TypeError("dns failure");
    const unreachable = await rejection(
      () =>
        checkPermissions({
          endpoint: "https://tenant.example.com/api/check",
          accessToken: "token-1",
          permissions: "posts:write",
          fetch: (() => Promise.reject(dnsFailure)) as typeof fetch,
        }),
      TemporarilyUnavailableError,
    );
    expect(unreachable.cause).toBe(dnsFailure);
    await rejection(
      () =>
        checkPermissions({
          endpoint: "https://tenant.example.com/api/check",
          accessToken: "token-1",
          permissions: "posts:write",
          fetch: fetchAnswering(() => new Response("oops", { status: 503 })),
        }),
      TemporarilyUnavailableError,
    );
  });

  it("reports a refused request as a server error", async () => {
    await rejection(
      () =>
        checkPermissions({
          endpoint: "https://tenant.example.com/api/check",
          accessToken: "token-1",
          permissions: "posts:write",
          fetch: fetchAnswering(() => new Response("no", { status: 401 })),
        }),
      ServerError,
    );
  });

  it("refuses to follow a redirect while carrying the bearer token", async () => {
    const calls: string[] = [];
    const error = await rejection(
      () =>
        checkPermissions({
          endpoint: "https://tenant.example.com/api/check",
          accessToken: "token-1",
          permissions: "posts:write",
          fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
            const request = new Request(input, init);
            calls.push(request.url);
            if (request.redirect === "follow") {
              calls.push("https://attacker.example/check");
              return Promise.resolve(Response.json(RESULT));
            }
            return Promise.resolve(
              new Response(null, {
                status: 307,
                headers: { location: "https://attacker.example/check" },
              }),
            );
          }) as typeof fetch,
        }),
      ServerError,
    );
    expect(error.message).toContain("refuses to follow");
    expect(calls).toStrictEqual(["https://tenant.example.com/api/check"]);
  });

  it("sends the request with a deadline", async () => {
    let signal: AbortSignal | null | undefined;
    await checkPermissions({
      endpoint: "https://tenant.example.com/api/check",
      accessToken: "token-1",
      permissions: "posts:write",
      fetch: ((_input: RequestInfo | URL, init?: RequestInit) => {
        signal = init?.signal;
        return Promise.resolve(Response.json(RESULT));
      }) as typeof fetch,
    });
    assert(signal instanceof AbortSignal, "the check call needs a deadline");
  });

  it("reports a timed-out request as temporarily unavailable", async () => {
    await rejection(
      () =>
        checkPermissions({
          endpoint: "https://tenant.example.com/api/check",
          accessToken: "token-1",
          permissions: "posts:write",
          fetch: (() =>
            Promise.reject(
              new DOMException("signal timed out", "TimeoutError"),
            )) as typeof fetch,
        }),
      TemporarilyUnavailableError,
    );
  });

  it("reports a 2xx that is not JSON as a server error", async () => {
    const error = await rejection(() =>
      checkPermissions({
        endpoint: "https://tenant.example.com/api/check",
        accessToken: "token-1",
        permissions: "posts:write",
        fetch: fetchAnswering(
          () =>
            new Response("<!doctype html>", {
              headers: { "content-type": "text/html" },
            }),
        ),
      }),
    );
    assert(
      error instanceof ServerError,
      `expected a ServerError, got ${error}`,
    );
    expect(error.message).toContain("not valid JSON");
  });

  it("refuses a 2xx body larger than the response cap", async () => {
    const error = await rejection(
      () =>
        checkPermissions({
          endpoint: "https://tenant.example.com/api/check",
          accessToken: "token-1",
          permissions: "posts:write",
          fetch: fetchAnswering(() =>
            Response.json({
              ...RESULT,
              padding: "x".repeat(MAX_RESPONSE_BYTES),
            }),
          ),
        }),
      ServerError,
    );
    expect(error.message).toContain("exceeded");
  });

  it("reports a body that stalls past the deadline as temporarily unavailable", async () => {
    using timeouts = controlTimeouts();
    await using endpoint = await serveStalledBody('{"subject":"user-1",');
    let settled = false;
    const pending = rejection(() =>
      checkPermissions({
        endpoint: endpoint.url,
        accessToken: "token-1",
        permissions: "posts:write",
      }),
    ).finally(() => {
      settled = true;
    });
    await vi.waitFor(() => expect(endpoint.requests).toBe(1));
    expect(settled, "the call must not end before the deadline").toBe(false);
    await timeouts.expireOnceRequested(1);
    const error = await pending;

    expect(timeouts.requested).toStrictEqual([REQUEST_TIMEOUT_MS]);
    assert(
      error instanceof TemporarilyUnavailableError,
      `expected a TemporarilyUnavailableError, got ${error}`,
    );
  });

  it("reports a connection dropped mid-body as temporarily unavailable", async () => {
    await using endpoint = await serveDroppedBody('{"subject":"user-1",');
    const error = await rejection(() =>
      checkPermissions({
        endpoint: endpoint.url,
        accessToken: "token-1",
        permissions: "posts:write",
      }),
    );
    assert(
      error instanceof TemporarilyUnavailableError,
      `expected a TemporarilyUnavailableError, got ${error}`,
    );
  });

  it("refuses a body past the response cap even when the connection then drops", async () => {
    await using endpoint = await serveDroppedBody(
      `{"padding":"${"x".repeat(MAX_RESPONSE_BYTES)}"}`,
    );
    const error = await rejection(() =>
      checkPermissions({
        endpoint: endpoint.url,
        accessToken: "token-1",
        permissions: "posts:write",
      }),
    );
    assert(
      error instanceof ServerError,
      `expected a ServerError, got ${error}`,
    );
    expect(error.message).toContain("exceeded");
  });

  it("cancels the body of a refused response", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("denied"));
      },
      cancel() {
        cancelled = true;
      },
    });
    await rejection(
      () =>
        checkPermissions({
          endpoint: "https://tenant.example.com/api/check",
          accessToken: "token-1",
          permissions: "posts:write",
          fetch: fetchAnswering(() => new Response(body, { status: 403 })),
        }),
      ServerError,
    );
    assert(cancelled, "a refused response's body must be released");
  });

  it("sends the request after a timed-out one on a new connection", async () => {
    const endpoint = "https://check-reconnect.example.com/api/check";
    const check = () =>
      checkPermissions({
        endpoint,
        accessToken: "token-1",
        permissions: "posts:write",
      }).then(
        ({ results }) => (results["posts:write"] ? "allowed" : "denied"),
        (error: unknown) =>
          error instanceof TemporarilyUnavailableError
            ? "unavailable"
            : String(error),
      );
    using runtime = stubDenoRuntime((_input, init) =>
      runtime.requests.length === 2
        ? hangUntilAborted(init?.signal)
        : Promise.resolve(Response.json(RESULT)),
    );
    using timeouts = controlTimeouts();

    const outcomes = [await check()];
    const stalled = check();
    await vi.waitFor(() => expect(runtime.requests).toHaveLength(2));
    timeouts.expireLatest();
    outcomes.push(await stalled, await check());

    expect(outcomes).toStrictEqual(["allowed", "unavailable", "allowed"]);
    expect(runtime.clients).toHaveLength(1);
    expect(runtime.requests[2]?.init).toHaveProperty(
      "client",
      runtime.clients[0],
    );
  });
});
