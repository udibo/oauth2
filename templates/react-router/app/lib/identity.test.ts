import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useMockServer } from "../../test/server.ts";
import { submitIdentityForm } from "./identity.ts";

const server = useMockServer();

function captureNavigation(): string[] {
  const assigned: string[] = [];
  vi.stubGlobal("location", {
    href: window.location.href,
    assign: (to: string) => assigned.push(to),
  });
  return assigned;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("submitIdentityForm", () => {
  it("posts the form body as JSON to the endpoint it was given", async () => {
    const seen: { url: string; contentType: string | null; body: unknown }[] =
      [];
    server.use(
      http.post("*/identity/signin", async ({ request }) => {
        seen.push({
          url: new URL(request.url).pathname + new URL(request.url).search,
          contentType: request.headers.get("content-type"),
          body: await request.json(),
        });
        return new HttpResponse(null, { status: 204 });
      }),
    );
    captureNavigation();

    const error = await submitIdentityForm(
      "/identity/signin",
      { identifier: "user@example.com", password: "hunter2" },
      null,
    );

    expect(error).toBeNull();
    expect(seen).toEqual([
      {
        url: "/identity/signin",
        contentType: "application/json",
        body: { identifier: "user@example.com", password: "hunter2" },
      },
    ]);
  });

  it("carries return_to so the server can resume an in-flight authorize URL", async () => {
    const urls: string[] = [];
    server.use(
      http.post("*/identity/signup", ({ request }) => {
        const url = new URL(request.url);
        urls.push(url.pathname + url.search);
        return new HttpResponse(null, { status: 204 });
      }),
    );
    captureNavigation();

    await submitIdentityForm(
      "/identity/signup",
      { email: "a@b.co", password: "hunter2" },
      "/authorize?client_id=web&state=abc",
    );

    expect(urls).toEqual([
      "/identity/signup?return_to=" +
        encodeURIComponent("/authorize?client_id=web&state=abc"),
    ]);
  });

  it("navigates to wherever the server's redirect chain landed", async () => {
    server.use(
      http.post("*/identity/signin", () =>
        HttpResponse.redirect("http://localhost:3000/welcome?first=1", 302),
      ),
      http.get("http://localhost:3000/welcome", () => HttpResponse.text("hi")),
    );
    const assigned = captureNavigation();

    await submitIdentityForm("/identity/signin", { identifier: "a" }, null);

    expect(assigned).toEqual(["http://localhost:3000/welcome?first=1"]);
  });

  it("falls back to /dashboard when the response was not a redirect", async () => {
    server.use(
      http.post(
        "*/identity/signin",
        () => new HttpResponse(null, { status: 204 }),
      ),
    );
    const assigned = captureNavigation();

    await submitIdentityForm("/identity/signin", { identifier: "a" }, null);

    expect(assigned).toEqual(["/dashboard"]);
  });

  it.each([
    ["invalid_credentials", "Invalid email or password."],
    ["identifier_taken", "That email is already registered."],
    ["weak_password", "Password must be at least 8 characters."],
    ["rate_limited", "Too many attempts. Try again shortly."],
    ["invalid_request", "Please fill in every field."],
  ])(
    "maps the %s code to its own message and navigates nowhere",
    async (code, message) => {
      server.use(
        http.post("*/identity/signin", () =>
          HttpResponse.json({ error: code }, { status: 400 }),
        ),
      );
      const assigned = captureNavigation();

      expect(
        await submitIdentityForm("/identity/signin", { identifier: "a" }, null),
      ).toBe(message);
      expect(assigned).toEqual([]);
    },
  );

  it.each([
    [
      "an unmapped code",
      () => HttpResponse.json({ error: "something_new" }, { status: 400 }),
    ],
    [
      "a body that is not JSON",
      () => new HttpResponse("nope", { status: 500 }),
    ],
    [
      "a 403 the CSRF guard raises",
      () => HttpResponse.json({ error: "forbidden_origin" }, { status: 403 }),
    ],
  ])("reports a generic failure for %s", async (_name, respond) => {
    server.use(http.post("*/identity/signin", respond));
    const assigned = captureNavigation();

    expect(
      await submitIdentityForm("/identity/signin", { identifier: "a" }, null),
    ).toBe("Something went wrong. Try again.");
    expect(assigned).toEqual([]);
  });
});
