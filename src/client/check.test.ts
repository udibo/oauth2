import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { ServerError, TemporarilyUnavailableError } from "../errors.ts";
import { checkPermissions } from "./check.ts";

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
});
