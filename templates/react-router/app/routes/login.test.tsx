import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useMockServer } from "../../test/server.ts";
import { captureNavigation, renderUnderRoot } from "../../test/render.tsx";
import Login from "./login.tsx";

const server = useMockServer();

afterEach(() => {
  vi.unstubAllGlobals();
});

function renderLogin(entry = "/login", demoAccount = true) {
  return renderUnderRoot([{ path: "login", Component: Login }], {
    entry,
    demoAccount,
  });
}

async function fillAndSubmit(email: string, password: string) {
  await userEvent.type(screen.getByLabelText("Email"), email);
  await userEvent.type(screen.getByLabelText("Password"), password);
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("Login route", () => {
  it("posts the credentials to /identity/signin and follows the server's redirect", async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post("*/identity/signin", async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.redirect("http://localhost:3000/dashboard", 302);
      }),
      http.get("http://localhost:3000/dashboard", () => HttpResponse.text("")),
    );
    await renderLogin();
    const assigned = captureNavigation();

    await fillAndSubmit("demo@example.com", "password");

    await vi.waitFor(() =>
      expect(assigned).toEqual(["http://localhost:3000/dashboard"]),
    );
    expect(bodies).toEqual([
      { identifier: "demo@example.com", password: "password" },
    ]);
  });

  it("forwards return_to so an in-flight authorize request resumes", async () => {
    const urls: string[] = [];
    server.use(
      http.post("*/identity/signin", ({ request }) => {
        urls.push(new URL(request.url).search);
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await renderLogin(
      "/login?return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Dweb",
    );
    captureNavigation();

    await fillAndSubmit("demo@example.com", "password");

    await vi.waitFor(() =>
      expect(urls).toEqual([
        "?return_to=" + encodeURIComponent("/oauth2/authorize?client_id=web"),
      ]),
    );
  });

  it("shows the server's rejection and stays on the page", async () => {
    server.use(
      http.post("*/identity/signin", () =>
        HttpResponse.json({ error: "invalid_credentials" }, { status: 401 }),
      ),
    );
    await renderLogin();
    const assigned = captureNavigation();

    await fillAndSubmit("demo@example.com", "wrong-password");

    expect(
      await screen.findByText("Invalid email or password."),
    ).toBeInTheDocument();
    expect(assigned).toEqual([]);
  });

  it("keeps return_to on the link to sign-up", async () => {
    await renderLogin("/login?return_to=%2Fdashboard");

    expect(screen.getByRole("link", { name: "Create one" })).toHaveAttribute(
      "href",
      "/signup?return_to=%2Fdashboard",
    );
  });

  it("links to password reset", async () => {
    await renderLogin();

    expect(
      screen.getByRole("link", { name: "Forgot password?" }),
    ).toHaveAttribute("href", "/forgot-password");
  });

  it("shows the demo credentials only where the demo account exists", async () => {
    const { unmount } = await renderLogin("/login", true);
    expect(screen.getByText("password")).toBeInTheDocument();
    unmount();

    await renderLogin("/login", false);
    expect(screen.queryByText("demo@example.com")).toBeNull();
  });
});
