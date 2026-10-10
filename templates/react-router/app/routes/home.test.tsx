import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { renderUnderRoot, signedIn } from "../../test/render.tsx";
import Home, { meta } from "./home.tsx";

function renderHome(options: {
  demoAccount?: boolean;
  session?: Parameters<typeof renderUnderRoot>[1]["session"];
}) {
  return renderUnderRoot([{ index: true, Component: Home }], {
    entry: "/",
    ...options,
  });
}

describe("Home route", () => {
  it("points a signed-out visitor at the seeded demo account", async () => {
    await renderHome({ demoAccount: true });

    expect(
      screen.getByRole("heading", { name: "Welcome" }),
    ).toBeInTheDocument();
    expect(screen.getByText("demo@example.com")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "create an account" }),
    ).toHaveAttribute("href", "/signup");
  });

  it("mentions no demo credentials where none was seeded", async () => {
    await renderHome({ demoAccount: false });

    expect(screen.queryByText("demo@example.com")).toBeNull();
    expect(
      screen.getByRole("link", { name: "Create an account" }),
    ).toBeInTheDocument();
  });

  it("shows no sign-up prompt to a signed-in user", async () => {
    await renderHome({ session: signedIn() });

    expect(screen.queryByText("demo@example.com")).toBeNull();
    expect(
      screen.queryByRole("link", { name: /create an account/i }),
    ).toBeNull();
  });

  it("titles the page", async () => {
    expect(meta()).toEqual([{ title: "My App" }]);
  });
});
