import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  captureNavigation,
  renderUnderRoot,
  signedIn,
} from "../../test/render.tsx";
import Layout from "./layout.tsx";

afterEach(() => {
  vi.unstubAllGlobals();
});

const page = { index: true, Component: () => <p>page body</p> };

function renderLayout(
  session?: Parameters<typeof renderUnderRoot>[1]["session"],
) {
  return renderUnderRoot([{ Component: Layout, children: [page] }], {
    entry: "/",
    session,
  });
}

describe("Layout route", () => {
  it("offers sign-in and sign-up to a signed-out visitor", async () => {
    await renderLayout();

    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute(
      "href",
      "/login",
    );
    expect(
      screen.getByRole("link", { name: "Create account" }),
    ).toHaveAttribute("href", "/signup");
    expect(screen.queryByRole("button", { name: "Sign out" })).toBeNull();
    expect(screen.getByText("page body")).toBeInTheDocument();
  });

  it("shows the signed-in user's name and a sign-out button", async () => {
    await renderLayout(signedIn());

    expect(screen.getByText("Ada Lovelace")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Sign out" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Sign in" })).toBeNull();
  });

  it("falls back to the email when the user has no name", async () => {
    await renderLayout(signedIn({ sub: "user-1", email: "ada@example.com" }));

    expect(screen.getByText("ada@example.com")).toBeInTheDocument();
  });

  it("signs out through the BFF logout endpoint and returns home", async () => {
    await renderLayout(signedIn());
    const assigned = captureNavigation();

    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));

    expect(assigned).toEqual([
      `${window.location.origin}/auth/logout?return_to=%2F`,
    ]);
  });
});
