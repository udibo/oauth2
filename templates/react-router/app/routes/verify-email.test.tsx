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

  it("reports a link without a token as invalid without calling the server", async () => {
    await renderVerify("/verify-email");

    expect(
      screen.getByText("That link is invalid or already used."),
    ).toBeInTheDocument();
  });
});
