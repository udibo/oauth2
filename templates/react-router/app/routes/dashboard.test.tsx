import { RouterContextProvider } from "react-router";
import { screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import { requestContext } from "../context.ts";
import { renderUnderRoot, signedIn, signedOut } from "../../test/render.tsx";
import { useMockServer } from "../../test/server.ts";
import Dashboard, { loader } from "./dashboard.tsx";

const server = useMockServer();

function loaderArgs(
  session: typeof signedOut,
  url = "http://web.test/dashboard",
): Parameters<typeof loader>[0] {
  const context = new RouterContextProvider();
  context.set(requestContext, { session, demoAccount: true });
  return {
    request: new Request(url),
    url: new URL(url),
    pattern: "/dashboard",
    params: {},
    context,
  };
}

describe("Dashboard loader", () => {
  it("sends a signed-out request into the BFF login flow, returning to the page", () => {
    let thrown: unknown;
    try {
      loader(loaderArgs(signedOut, "http://web.test/dashboard?tab=billing"));
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(Response);
    const response = thrown as Response;
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/auth/login?return_to=" + encodeURIComponent("/dashboard?tab=billing"),
    );
    expect(response.headers.get("x-remix-reload-document")).toBe("true");
  });

  it("lets a signed-in request through", () => {
    expect(loader(loaderArgs(signedIn()))).toBeNull();
  });
});

describe("Dashboard route", () => {
  it("reads /api/me with the CSRF header the BFF requires, then shows the profile", async () => {
    const csrfHeaders: (string | null)[] = [];
    server.use(
      http.get("*/api/me", ({ request }) => {
        csrfHeaders.push(request.headers.get("x-csrf"));
        return HttpResponse.json({
          sub: "user-1",
          name: "Ada Lovelace",
          email: "ada@example.com",
          emailVerified: true,
        });
      }),
    );
    await renderUnderRoot([{ path: "dashboard", Component: Dashboard }], {
      entry: "/dashboard",
      session: signedIn(),
    });

    expect(
      await screen.findByText(/"emailVerified": true/),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Ada Lovelace", { selector: "strong" }),
    ).toBeInTheDocument();
    expect(csrfHeaders).toEqual(["1"]);
    expect(screen.queryByText(/isn't verified yet/)).toBeNull();
  });

  it("reminds an unverified user that the verification link is in the server console", async () => {
    server.use(
      http.get("*/api/me", () =>
        HttpResponse.json({
          sub: "user-2",
          name: "Grace",
          email: "grace@example.com",
          emailVerified: false,
        }),
      ),
    );
    await renderUnderRoot([{ path: "dashboard", Component: Dashboard }], {
      entry: "/dashboard",
      session: signedIn({ sub: "user-2", name: "Grace" }),
    });

    expect(await screen.findByText(/isn't verified yet/)).toBeInTheDocument();
  });

  it("keeps the loading message when the API does not answer", async () => {
    server.use(
      http.get("*/api/me", () => new HttpResponse(null, { status: 401 })),
    );
    await renderUnderRoot([{ path: "dashboard", Component: Dashboard }], {
      entry: "/dashboard",
      session: signedIn(),
    });

    expect(screen.getByText("Loading your profile…")).toBeInTheDocument();
  });
});
