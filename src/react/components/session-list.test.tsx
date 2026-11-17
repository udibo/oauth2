import { assert, describe, expect, it } from "vitest";
import {
  act,
  createEvent,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";

import { SessionList } from "./session-list.tsx";
import type { SessionListItem, SessionListState } from "./session-list.tsx";
import type { AccountActionResult } from "./types.ts";

const SESSIONS: SessionListItem[] = [
  {
    id: "s-current",
    current: true,
    device: "Firefox on Linux",
    ipAddress: "203.0.113.7",
    createdAt: new Date("2026-01-02T03:04:05Z"),
    lastActiveAt: new Date("2026-01-03T03:04:05Z"),
  },
  {
    id: "s-phone",
    device: "Safari on iPhone",
    createdAt: new Date("2026-01-01T00:00:00Z"),
  },
  { id: "s-unknown" },
];

const isoDate = (date: Date): string => date.toISOString();

function held(): {
  promise: Promise<AccountActionResult | void>;
  release: () => void;
} {
  let release: () => void = () => {};
  const promise = new Promise<AccountActionResult | void>((resolve) => {
    release = () => resolve();
  });
  return { promise, release };
}

describe("SessionList", () => {
  it("lists each session's device, badge, IP and times", () => {
    const { container } = render(
      <SessionList sessions={SESSIONS} formatDate={isoDate} />,
    );
    const items = container.querySelectorAll("li[data-oauth2-session]");
    expect(items.length).toStrictEqual(3);
    expect(items[0]!.textContent).toStrictEqual(
      "Firefox on LinuxCurrent session203.0.113.7 · Signed in 2026-01-02T03:04:05.000Z · Last active 2026-01-03T03:04:05.000Z",
    );
    expect(items[1]!.textContent).toStrictEqual(
      "Safari on iPhoneSigned in 2026-01-01T00:00:00.000Z",
    );
    expect(items[2]!.textContent).toStrictEqual("Unknown device");
    assert(items[0]!.hasAttribute("data-oauth2-current-session"));
    assert(!items[1]!.hasAttribute("data-oauth2-current-session"));
  });

  it("is read-only without callbacks", () => {
    render(<SessionList sessions={SESSIONS} />);
    expect(screen.queryAllByRole("button")).toStrictEqual([]);
  });

  it("never offers to sign out the current session", () => {
    const { container } = render(
      <SessionList sessions={SESSIONS} onRevoke={() => {}} />,
    );
    const current = container.querySelector(
      '[data-oauth2-session="s-current"]',
    );
    assert(current);
    expect(current.querySelector("button")).toBeNull();
    expect(
      screen
        .getAllByRole("button")
        .map((button) => button.getAttribute("aria-label")),
    ).toStrictEqual(["Sign out Safari on iPhone", "Sign out Unknown device"]);
  });

  it("hands the chosen session to onRevoke", async () => {
    const revoked: string[] = [];
    render(
      <SessionList
        sessions={SESSIONS}
        onRevoke={(session) => {
          revoked.push(session.id);
        }}
      />,
    );
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Sign out Safari on iPhone" }),
      );
    });
    expect(revoked).toStrictEqual(["s-phone"]);
  });

  it("offers sign-out everywhere else only while another session is listed", async () => {
    let calls = 0;
    const onRevokeOthers = (): void => {
      calls++;
    };
    const { rerender } = render(
      <SessionList sessions={SESSIONS} onRevokeOthers={onRevokeOthers} />,
    );
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Sign out everywhere else" }),
      );
    });
    expect(calls).toStrictEqual(1);

    rerender(
      <SessionList sessions={[SESSIONS[0]!]} onRevokeOthers={onRevokeOthers} />,
    );
    expect(
      screen.queryByRole("button", { name: "Sign out everywhere else" }),
    ).toBeNull();
  });

  it("shows a pending label on the button that keeps focus, and ignores another action until it settles", async () => {
    const pending = held();
    const revoked: string[] = [];
    render(
      <SessionList
        sessions={SESSIONS}
        onRevoke={(session) => {
          revoked.push(session.id);
          return pending.promise;
        }}
        onRevokeOthers={() => {
          revoked.push("others");
        }}
      />,
    );
    const button = screen.getByRole("button", {
      name: "Sign out Safari on iPhone",
    });
    button.focus();
    await act(async () => {
      fireEvent.click(button);
    });

    expect(button.textContent).toStrictEqual("Signing out…");
    expect(button.getAttribute("aria-label")).toStrictEqual(
      "Signing out… Safari on iPhone",
    );
    expect(button.getAttribute("aria-disabled")).toStrictEqual("true");
    expect(button.hasAttribute("disabled")).toBeFalsy();
    expect(document.activeElement).toStrictEqual(button);

    const repeat = createEvent.click(button);
    await act(async () => {
      fireEvent(button, repeat);
      fireEvent.click(
        screen.getByRole("button", { name: "Sign out everywhere else" }),
      );
    });
    assert(repeat.defaultPrevented, "the pending button cancels activation");
    expect(revoked).toStrictEqual(["s-phone"]);

    await act(async () => pending.release());
    expect(button.textContent).toStrictEqual("Sign out");
    expect(button.hasAttribute("aria-disabled")).toBeFalsy();
  });

  it("shows a returned error in a focused alert", async () => {
    render(
      <SessionList
        sessions={SESSIONS}
        onRevoke={() => ({ error: "That session could not be signed out." })}
      />,
    );
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Sign out Safari on iPhone" }),
      );
    });
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toStrictEqual(
      "That session could not be signed out.",
    );
    expect(document.activeElement).toStrictEqual(
      alert.closest("[data-oauth2-error-summary]"),
    );
  });

  it("shows a thrown error's message, and clears it on the next attempt", async () => {
    let fail = true;
    render(
      <SessionList
        sessions={SESSIONS}
        onRevokeOthers={() => {
          if (fail) throw new Error("Network down.");
        }}
      />,
    );
    const button = screen.getByRole("button", {
      name: "Sign out everywhere else",
    });
    await act(async () => {
      fireEvent.click(button);
    });
    expect(screen.getByRole("alert").textContent).toStrictEqual(
      "Network down.",
    );
    fail = false;
    await act(async () => {
      fireEvent.click(button);
    });
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("posts intent and sessionId natively to action before JavaScript runs", () => {
    const { container } = render(
      <SessionList
        sessions={SESSIONS}
        action="/account/sessions"
        onRevoke={() => {}}
        onRevokeOthers={() => {}}
      />,
    );
    const forms = [...container.querySelectorAll("form")];
    expect(
      forms.map((form) => [
        form.getAttribute("action"),
        form.getAttribute("method"),
        Object.fromEntries(new FormData(form)),
      ]),
    ).toStrictEqual([
      [
        "/account/sessions",
        "post",
        { intent: "revoke-session", sessionId: "s-phone" },
      ],
      [
        "/account/sessions",
        "post",
        { intent: "revoke-session", sessionId: "s-unknown" },
      ],
      ["/account/sessions", "post", { intent: "revoke-other-sessions" }],
    ]);
  });

  it("suppresses the native post once React handles the submit", async () => {
    const { container } = render(
      <SessionList
        sessions={SESSIONS}
        action="/account/sessions"
        onRevoke={() => {}}
      />,
    );
    const form = container.querySelector("form");
    assert(form);
    const submit = createEvent.submit(form);
    await act(async () => {
      fireEvent(form, submit);
    });
    assert(submit.defaultPrevented);
  });

  it("renders the empty label for no sessions", () => {
    render(<SessionList sessions={[]} labels={{ empty: "Nothing here." }} />);
    assert(screen.getByText("Nothing here."));
  });

  it("applies per-slot classes", () => {
    const { container } = render(
      <SessionList
        sessions={SESSIONS}
        onRevoke={() => {}}
        onRevokeOthers={() => {}}
        className="outer"
        classNames={{
          root: "root",
          list: "list",
          item: "item",
          device: "device",
          badge: "badge",
          meta: "meta",
          revoke: "revoke",
          actions: "actions",
          revokeOthers: "others",
        }}
      />,
    );
    const classOf = (selector: string): string | null | undefined =>
      container.querySelector(selector)?.getAttribute("class");
    expect(classOf("[data-oauth2-session-list]")).toStrictEqual("outer root");
    expect(classOf("[data-oauth2-session-items]")).toStrictEqual("list");
    expect(classOf("[data-oauth2-session]")).toStrictEqual("item");
    expect(classOf("[data-oauth2-session-device]")).toStrictEqual("device");
    expect(classOf("[data-oauth2-session-badge]")).toStrictEqual("badge");
    expect(classOf("[data-oauth2-session-meta]")).toStrictEqual("meta");
    expect(classOf("[data-oauth2-revoke-session]")).toStrictEqual("revoke");
    expect(classOf("[data-oauth2-actions]")).toStrictEqual("actions");
    expect(classOf("[data-oauth2-revoke-other-sessions]")).toStrictEqual(
      "others",
    );
  });

  it("hands the live state to a render-prop child, guarding the current session", async () => {
    const pending = held();
    const revoked: string[] = [];
    let state: SessionListState | undefined;
    render(
      <SessionList
        sessions={SESSIONS}
        onRevoke={(session) => {
          revoked.push(session.id);
          return pending.promise;
        }}
      >
        {(live) => {
          state = live;
          return <p>custom</p>;
        }}
      </SessionList>,
    );
    assert(screen.getByText("custom"));
    assert(state);
    await act(async () => {
      await state!.revoke(SESSIONS[0]!);
    });
    expect(revoked, "the current session is never revoked").toStrictEqual([]);

    await act(async () => {
      void state!.revoke(SESSIONS[1]!);
    });
    expect(state.pendingSessionId).toStrictEqual("s-phone");
    expect(state.revokingOthers).toStrictEqual(false);
    await act(async () => pending.release());
    expect(state.pendingSessionId).toBeNull();
    expect(revoked).toStrictEqual(["s-phone"]);
  });
});
