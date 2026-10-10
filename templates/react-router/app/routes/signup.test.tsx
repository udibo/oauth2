import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useMockServer } from "../../test/server.ts";
import { captureNavigation, renderUnderRoot } from "../../test/render.tsx";
import SignUp from "./signup.tsx";

const server = useMockServer();

afterEach(() => {
  vi.unstubAllGlobals();
});

function renderSignUp(entry = "/signup") {
  return renderUnderRoot([{ path: "signup", Component: SignUp }], { entry });
}

async function fillIn(password = "long-enough-1", confirm = password) {
  await userEvent.type(screen.getByLabelText("First name"), "Ada");
  await userEvent.type(screen.getByLabelText("Last name"), "Lovelace");
  await userEvent.type(screen.getByLabelText("Email"), "ada@example.com");
  await userEvent.type(screen.getByLabelText("Password"), password);
  await userEvent.type(screen.getByLabelText("Confirm password"), confirm);
  await userEvent.click(screen.getByRole("button", { name: "Create account" }));
}

describe("SignUp route", () => {
  it("posts the joined name, email and password to /identity/signup", async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post("*/identity/signup", async ({ request }) => {
        bodies.push(await request.json());
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await renderSignUp();
    const assigned = captureNavigation();

    await fillIn();

    await vi.waitFor(() => expect(assigned).toEqual(["/dashboard"]));
    expect(bodies).toEqual([
      {
        name: "Ada Lovelace",
        email: "ada@example.com",
        password: "long-enough-1",
      },
    ]);
  });

  it("blocks a mismatched confirmation before calling the server", async () => {
    await renderSignUp();
    const assigned = captureNavigation();

    await fillIn("long-enough-1", "something-else");

    expect(
      await screen.findByText("Passwords do not match."),
    ).toBeInTheDocument();
    expect(assigned).toEqual([]);
  });

  it("shows the server's rejection of an email that is already registered", async () => {
    server.use(
      http.post("*/identity/signup", () =>
        HttpResponse.json({ error: "identifier_taken" }, { status: 409 }),
      ),
    );
    await renderSignUp();
    captureNavigation();

    await fillIn();

    expect(
      await screen.findByText("That email is already registered."),
    ).toBeInTheDocument();
  });

  it("keeps return_to on the link back to sign-in", async () => {
    await renderSignUp("/signup?return_to=%2Fdashboard");

    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute(
      "href",
      "/login?return_to=%2Fdashboard",
    );
  });
});
