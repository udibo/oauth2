import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import { renderUnderRoot } from "../../test/render.tsx";
import { useMockServer } from "../../test/server.ts";
import ResetPassword from "./reset-password.tsx";

const server = useMockServer();

function renderReset(entry: string) {
  return renderUnderRoot(
    [{ path: "reset-password", Component: ResetPassword }],
    {
      entry,
    },
  );
}

async function chooseNewPassword(password: string, confirm = password) {
  await userEvent.type(screen.getByLabelText("New password"), password);
  await userEvent.type(screen.getByLabelText("Confirm new password"), confirm);
  await userEvent.click(screen.getByRole("button", { name: "Reset password" }));
}

describe("ResetPassword route", () => {
  it("sends the token and new password, then points at sign-in", async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post("*/identity/password/reset", async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({ ok: true });
      }),
    );
    await renderReset("/reset-password?token=reset-token");

    await chooseNewPassword("brand-new-secret");

    expect(await screen.findByText("Password updated")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute(
      "href",
      "/login",
    );
    expect(bodies).toEqual([
      { token: "reset-token", password: "brand-new-secret" },
    ]);
  });

  it.each([
    ["invalid_token", "That link is invalid or has already been used."],
    ["token_expired", "That link has expired. Request a new one."],
    ["weak_password", "Password must be at least 8 characters."],
  ])("explains a %s rejection", async (code, message) => {
    server.use(
      http.post("*/identity/password/reset", () =>
        HttpResponse.json({ error: code }, { status: 400 }),
      ),
    );
    await renderReset("/reset-password?token=reset-token");

    await chooseNewPassword("brand-new-secret");

    expect(await screen.findByText(message)).toBeInTheDocument();
  });

  it("asks for a fresh link when the token is missing", async () => {
    await renderReset("/reset-password");

    expect(screen.getByText(/missing its token/)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Request a reset link" }),
    ).toHaveAttribute("href", "/forgot-password");
  });
});
