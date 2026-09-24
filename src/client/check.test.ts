import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { ServerError, TemporarilyUnavailableError } from "../errors.ts";
import { MAX_RESPONSE_BYTES, REQUEST_TIMEOUT_MS } from "./_http.ts";
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

    assertEquals(result, RESULT);
    assertEquals(seen?.method, "POST");
    assertEquals(seen?.headers.get("authorization"), "Bearer token-1");
    assertEquals(await seen?.json(), {
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
    assertEquals(body, { permissions: "posts:write" });
  });

  it("reports an unreachable or failing endpoint as temporarily unavailable", async () => {
    await assertRejects(
      () =>
        checkPermissions({
          endpoint: "https://tenant.example.com/api/check",
          accessToken: "token-1",
          permissions: "posts:write",
          fetch: (() =>
            Promise.reject(new TypeError("dns failure"))) as typeof fetch,
        }),
      TemporarilyUnavailableError,
    );
    await assertRejects(
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
    await assertRejects(
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
    const error = await assertRejects(
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
    assertStringIncludes(error.message, "refuses to follow");
    assertEquals(calls, ["https://tenant.example.com/api/check"]);
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
    await assertRejects(
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
    const error = await assertRejects(
      () =>
        checkPermissions({
          endpoint: "https://tenant.example.com/api/check",
          accessToken: "token-1",
          permissions: "posts:write",
          fetch: fetchAnswering(() =>
            new Response("<!doctype html>", {
              headers: { "content-type": "text/html" },
            })
          ),
        }),
    );
    assert(
      error instanceof ServerError,
      `expected a ServerError, got ${error}`,
    );
    assertStringIncludes(error.message, "not valid JSON");
  });

  it("refuses a 2xx body larger than the response cap", async () => {
    const error = await assertRejects(
      () =>
        checkPermissions({
          endpoint: "https://tenant.example.com/api/check",
          accessToken: "token-1",
          permissions: "posts:write",
          fetch: fetchAnswering(() =>
            Response.json({
              ...RESULT,
              padding: "x".repeat(MAX_RESPONSE_BYTES),
            })
          ),
        }),
      ServerError,
    );
    assertStringIncludes(error.message, "exceeded");
  });

  it(
    "reports a body that stalls past the deadline as temporarily unavailable",
    async () => {
      await using endpoint = serveStalledBody('{"subject":"user-1",');
      const started = performance.now();
      const error = await assertRejects(
        () =>
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
      assert(
        performance.now() - started >= REQUEST_TIMEOUT_MS - 100,
        "the call must end at the deadline, not before it",
      );
    },
  );

  it(
    "reports a connection dropped mid-body as temporarily unavailable",
    async () => {
      await using endpoint = serveDroppedBody('{"subject":"user-1",');
      const error = await assertRejects(
        () =>
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
    },
  );

  it(
    "refuses a body past the response cap even when the connection then drops",
    async () => {
      await using endpoint = serveDroppedBody(
        `{"padding":"${"x".repeat(MAX_RESPONSE_BYTES)}"}`,
      );
      const error = await assertRejects(
        () =>
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
      assertStringIncludes(error.message, "exceeded");
    },
  );

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
    await assertRejects(
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
});
