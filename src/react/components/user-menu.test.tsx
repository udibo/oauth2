import { cleanupAfterEach } from "../_test_setup.ts";

import { assert, assertEquals, assertFalse } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { fireEvent, render, screen } from "@testing-library/react";

import { createMockOAuth2Client, MockOAuth2Provider } from "../testing.tsx";
import type { UserInfoClaims } from "../../client/mod.ts";
import { UserMenu } from "./user-menu.tsx";
import type { UserMenuProps } from "./user-menu.tsx";

cleanupAfterEach();

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
    assertEquals(trigger.getAttribute("aria-expanded"), "false");
    fireEvent.click(trigger);
    assertEquals(trigger.getAttribute("aria-expanded"), "true");
    assert(screen.getByText("Profile"));
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    assertEquals(logouts, [1]);
  });

  it("uses a disclosure pattern, not ARIA menu roles", () => {
    renderMenu(
      { items: <a href="/profile">Profile</a> },
      { sub: "u3b", name: "Grace" },
    );
    fireEvent.click(screen.getByRole("button", { name: "Grace" }));
    assertFalse(screen.queryByRole("menu"));
    assertFalse(screen.queryByRole("menuitem"));
  });

  it("closes on Escape", () => {
    renderMenu(
      { items: <a href="/profile">Profile</a> },
      { sub: "u3c", name: "Grace" },
    );
    const trigger = screen.getByRole("button", { name: "Grace" });
    fireEvent.click(trigger);
    assertEquals(trigger.getAttribute("aria-expanded"), "true");
    fireEvent.keyDown(document, { key: "Escape" });
    assertEquals(trigger.getAttribute("aria-expanded"), "false");
    assertFalse(screen.queryByText("Profile"));
  });

  it("closes on outside pointerdown", () => {
    renderMenu(
      { items: <a href="/profile">Profile</a> },
      { sub: "u3d", name: "Grace" },
    );
    const trigger = screen.getByRole("button", { name: "Grace" });
    fireEvent.click(trigger);
    assertEquals(trigger.getAttribute("aria-expanded"), "true");
    fireEvent.pointerDown(document.body);
    assertEquals(trigger.getAttribute("aria-expanded"), "false");
    assertFalse(screen.queryByText("Profile"));
  });

  it("renders the signedOut slot when unauthenticated", () => {
    renderMenu({ signedOut: <span>Sign in</span> }, null);
    assert(screen.getByText("Sign in"));
    assertFalse(screen.queryByRole("button"));
  });

  it("ejects to a render prop with the user and logout callback", () => {
    renderMenu(
      {
        children: ({ user }) => <p data-testid="who">{String(user.sub)}</p>,
      },
      { sub: "u4" },
    );
    assertEquals(screen.getByTestId("who").textContent, "u4");
  });
});
