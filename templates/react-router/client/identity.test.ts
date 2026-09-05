import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { submitIdentityForm } from "./identity.ts";

interface Call {
  url: string;
  method?: string;
  contentType: string | null;
  body: unknown;
}

function stubFetch(
  respond: () => Response,
): { calls: Call[]; restore: () => void } {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    calls.push({
      url: String(url),
      method: init?.method,
      contentType: headers.get("content-type"),
      body: JSON.parse(String(init?.body ?? "null")),
    });
    return Promise.resolve(respond());
  }) as typeof fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

function stubAssign(): { assigned: string[]; restore: () => void } {
  const assigned: string[] = [];
  const original = globalThis.location;
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { assign: (to: string) => void assigned.push(to) },
  });
  return {
    assigned,
    restore: () => {
      Object.defineProperty(globalThis, "location", {
        configurable: true,
        value: original,
      });
    },
  };
}

describe("submitIdentityForm", () => {
  it("posts the form body as JSON to the endpoint it was given", async () => {
    const fetched = stubFetch(() => new Response(null, { status: 204 }));
    const nav = stubAssign();
    try {
      const error = await submitIdentityForm(
        "/identity/signin",
        { identifier: "user@example.com", password: "hunter2" },
        null,
      );
      assertEquals(error, null);
      assertEquals(fetched.calls.length, 1);
      assertEquals(fetched.calls[0].url, "/identity/signin");
      assertEquals(fetched.calls[0].method, "POST");
      assertEquals(fetched.calls[0].contentType, "application/json");
      assertEquals(fetched.calls[0].body, {
        identifier: "user@example.com",
        password: "hunter2",
      });
    } finally {
      nav.restore();
      fetched.restore();
    }
  });

  it("carries return_to so the server can resume an in-flight authorize URL", async () => {
    const fetched = stubFetch(() => new Response(null, { status: 204 }));
    const nav = stubAssign();
    try {
      await submitIdentityForm(
        "/identity/signup",
        { identifier: "a@b.co", password: "hunter2" },
        "/authorize?client_id=web&state=abc",
      );
      assertEquals(
        fetched.calls[0].url,
        "/identity/signup?return_to=" +
          encodeURIComponent("/authorize?client_id=web&state=abc"),
      );
    } finally {
      nav.restore();
      fetched.restore();
    }
  });

  it("follows the redirect chain the server landed on", async () => {
    const fetched = stubFetch(() => {
      const res = new Response(null, { status: 200 });
      Object.defineProperty(res, "redirected", { value: true });
      Object.defineProperty(res, "url", {
        value: "https://app.example/dashboard?welcome=1",
      });
      return res;
    });
    const nav = stubAssign();
    try {
      await submitIdentityForm("/identity/signin", { identifier: "a" }, null);
      assertEquals(nav.assigned, ["https://app.example/dashboard?welcome=1"]);
    } finally {
      nav.restore();
      fetched.restore();
    }
  });

  it("falls back to /dashboard when the response was not a redirect", async () => {
    const fetched = stubFetch(() => new Response(null, { status: 204 }));
    const nav = stubAssign();
    try {
      await submitIdentityForm("/identity/signin", { identifier: "a" }, null);
      assertEquals(nav.assigned, ["/dashboard"]);
    } finally {
      nav.restore();
      fetched.restore();
    }
  });

  it("maps each IdentityError code to its own message and navigates nowhere", async () => {
    const cases: [code: string, message: string][] = [
      ["invalid_credentials", "Invalid email or password."],
      ["identifier_taken", "That email is already registered."],
      ["weak_password", "Password must be at least 8 characters."],
      ["rate_limited", "Too many attempts. Try again shortly."],
      ["invalid_request", "Please fill in every field."],
    ];
    for (const [code, message] of cases) {
      const fetched = stubFetch(() =>
        Response.json({ error: code }, { status: 400 })
      );
      const nav = stubAssign();
      try {
        assertEquals(
          await submitIdentityForm(
            "/identity/signin",
            { identifier: "a" },
            null,
          ),
          message,
        );
        assertEquals(nav.assigned, []);
      } finally {
        nav.restore();
        fetched.restore();
      }
    }
  });

  it("reports a generic failure for an unmapped code, an empty body, and a 403 the CSRF guard raises", async () => {
    for (
      const respond of [
        () => Response.json({ error: "something_new" }, { status: 400 }),
        () => new Response("not json", { status: 500 }),
        () => Response.json({ error: "forbidden_origin" }, { status: 403 }),
      ]
    ) {
      const fetched = stubFetch(respond);
      const nav = stubAssign();
      try {
        assertEquals(
          await submitIdentityForm(
            "/identity/signin",
            { identifier: "a" },
            null,
          ),
          "Something went wrong. Try again.",
        );
        assertEquals(nav.assigned, []);
      } finally {
        nav.restore();
        fetched.restore();
      }
    }
  });
});
