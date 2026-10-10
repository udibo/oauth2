import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import { renderUnderRoot } from "../../test/render.tsx";
import { useMockServer } from "../../test/server.ts";
import ForgotPassword from "./forgot-password.tsx";

const server = useMockServer();

function renderForgot() {
  return renderUnderRoot(
    [{ path: "forgot-password", Component: ForgotPassword }],
    { entry: "/forgot-password" },
  );
}

describe("ForgotPassword route", () => {
  it("requests a reset link and shows the neutral confirmation", async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post("*/identity/password/reset-request", async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({ ok: true });
      }),
    );
    await renderForgot();

    await userEvent.type(screen.getByLabelText("Email"), "ada@example.com");
    await userEvent.click(screen.getByRole("button", { name: /reset/i }));

    expect(
      await screen.findByText(/If that address has an account/),
    ).toBeInTheDocument();
    expect(bodies).toEqual([{ email: "ada@example.com" }]);
  });

  it("shows the same confirmation when the request fails, so nothing leaks", async () => {
    server.use(
      http.post("*/identity/password/reset-request", () =>
        HttpResponse.error(),
      ),
    );
    await renderForgot();

    await userEvent.type(screen.getByLabelText("Email"), "nobody@example.com");
    await userEvent.click(screen.getByRole("button", { name: /reset/i }));

    expect(
      await screen.findByText(/If that address has an account/),
    ).toBeInTheDocument();
  });

  it("links back to sign-in", async () => {
    await renderForgot();

    expect(
      screen.getByRole("link", { name: "Back to sign in" }),
    ).toHaveAttribute("href", "/login");
  });
});
