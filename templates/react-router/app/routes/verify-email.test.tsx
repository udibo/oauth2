import { screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import { renderUnderRoot } from "../../test/render.tsx";
import { useMockServer } from "../../test/server.ts";
import VerifyEmail from "./verify-email.tsx";

const server = useMockServer();

function renderVerify(entry: string) {
  return renderUnderRoot([{ path: "verify-email", Component: VerifyEmail }], {
    entry,
  });
}

describe("VerifyEmail route", () => {
  it("consumes the token and confirms the address", async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post("*/identity/email/verify", async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({ ok: true });
      }),
    );
    await renderVerify("/verify-email?token=ok-token");

    expect(await screen.findByText(/Email verified/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "dashboard" })).toHaveAttribute(
      "href",
      "/dashboard",
    );
    expect(bodies).toEqual([{ token: "ok-token" }]);
  });

  it("tells the user an expired link has expired", async () => {
    server.use(
      http.post("*/identity/email/verify", () =>
        HttpResponse.json({ error: "token_expired" }, { status: 400 }),
      ),
    );
    await renderVerify("/verify-email?token=old-token");

    expect(
      await screen.findByText(/That link has expired/),
    ).toBeInTheDocument();
  });

  it("reports a used or unknown token as invalid", async () => {
    server.use(
      http.post("*/identity/email/verify", () =>
        HttpResponse.json({ error: "invalid_token" }, { status: 400 }),
      ),
    );
    await renderVerify("/verify-email?token=used-token");

    expect(
      await screen.findByText("That link is invalid or already used."),
    ).toBeInTheDocument();
  });

  it("asks a signed-out visitor to sign in and come back to the same link", async () => {
    server.use(
      http.post("*/identity/email/verify", () =>
        HttpResponse.json({ error: "sign_in_required" }, { status: 401 }),
      ),
    );
    await renderVerify("/verify-email?token=live-token");

    expect(
      await screen.findByText(/to finish verifying your email/),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute(
      "href",
      "/login?return_to=" +
        encodeURIComponent("/verify-email?token=live-token"),
    );
  });

  it("tells a visitor signed in as someone else that the link is for another account", async () => {
    server.use(
      http.post("*/identity/email/verify", () =>
        HttpResponse.json({ error: "wrong_account" }, { status: 403 }),
      ),
    );
    await renderVerify("/verify-email?token=other-token");

    expect(
      await screen.findByText(/sent for a different account/),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute(
      "href",
      "/login?return_to=" +
        encodeURIComponent("/verify-email?token=other-token"),
    );
  });

  it("reports a link without a token as invalid without calling the server", async () => {
    await renderVerify("/verify-email");

    expect(
      screen.getByText("That link is invalid or already used."),
    ).toBeInTheDocument();
  });
});
