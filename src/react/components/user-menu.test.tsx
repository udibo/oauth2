import { assert, describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { createMockOAuth2Client, MockOAuth2Provider } from "../testing.tsx";
import type { UserInfoClaims } from "../../client/mod.ts";
import { UserMenu } from "./user-menu.tsx";
import type { UserMenuProps } from "./user-menu.tsx";

function renderMenu(
  props: UserMenuProps,
  user: UserInfoClaims | null,
): ReturnType<typeof render> {
  const client = createMockOAuth2Client({
    user: user ?? undefined,
    isAuthenticated: user !== null,
  });
  return render(
    <MockOAuth2Provider
      client={client}
      state={{ user, isAuthenticated: user !== null }}
    >
      <UserMenu {...props} />
    </MockOAuth2Provider>,
  );
}

describe("UserMenu", () => {
  it("renders the user's display name from claims", () => {
    renderMenu({}, { sub: "u1", name: "Ada Lovelace" });
    assert(screen.getByText("Ada Lovelace"));
  });

  it("falls back to email then sub for the display name", () => {
    renderMenu({}, { sub: "u2", email: "ada@example.com" });
    assert(screen.getByText("ada@example.com"));
  });

  it("opens the menu and exposes a logout action", () => {
    const logouts: number[] = [];
    renderMenu(
      {
        items: <a href="/profile">Profile</a>,
        onLogout: () => {
          logouts.push(1);
        },
      },
      { sub: "u3", name: "Grace" },
    );
    const trigger = screen.getByRole("button", { name: "Grace" });
    expect(trigger.getAttribute("aria-expanded")).toStrictEqual("false");
    fireEvent.click(trigger);
    expect(trigger.getAttribute("aria-expanded")).toStrictEqual("true");
    assert(screen.getByText("Profile"));
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(logouts).toStrictEqual([1]);
  });

  it("uses a disclosure pattern, not ARIA menu roles", () => {
    renderMenu(
      { items: <a href="/profile">Profile</a> },
      { sub: "u3b", name: "Grace" },
    );
    fireEvent.click(screen.getByRole("button", { name: "Grace" }));
    expect(screen.queryByRole("menu")).toBeFalsy();
    expect(screen.queryByRole("menuitem")).toBeFalsy();
  });

  it("closes on Escape", () => {
    renderMenu(
      { items: <a href="/profile">Profile</a> },
      { sub: "u3c", name: "Grace" },
    );
    const trigger = screen.getByRole("button", { name: "Grace" });
    fireEvent.click(trigger);
    expect(trigger.getAttribute("aria-expanded")).toStrictEqual("true");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(trigger.getAttribute("aria-expanded")).toStrictEqual("false");
    expect(screen.queryByText("Profile")).toBeFalsy();
  });

  it("closes on outside pointerdown", () => {
    renderMenu(
      { items: <a href="/profile">Profile</a> },
      { sub: "u3d", name: "Grace" },
    );
    const trigger = screen.getByRole("button", { name: "Grace" });
    fireEvent.click(trigger);
    expect(trigger.getAttribute("aria-expanded")).toStrictEqual("true");
    fireEvent.pointerDown(document.body);
    expect(trigger.getAttribute("aria-expanded")).toStrictEqual("false");
    expect(screen.queryByText("Profile")).toBeFalsy();
  });

  it("renders the signedOut slot when unauthenticated", () => {
    renderMenu({ signedOut: <span>Sign in</span> }, null);
    assert(screen.getByText("Sign in"));
    expect(screen.queryByRole("button")).toBeFalsy();
  });

  it("ejects to a render prop with the user and logout callback", () => {
    renderMenu(
      {
        children: ({ user }) => <p data-testid="who">{String(user.sub)}</p>,
      },
      { sub: "u4" },
    );
    expect(screen.getByTestId("who").textContent).toStrictEqual("u4");
  });
});
