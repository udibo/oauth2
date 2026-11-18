import { assert, describe, expect, it } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";

import { LinkedAccounts } from "./linked-accounts.tsx";
import type { LinkedAccount, LinkedAccountsState } from "./linked-accounts.tsx";
import type { AccountActionResult, SocialProvider } from "./types.ts";

const ACCOUNTS: LinkedAccount[] = [
  {
    id: "i-github",
    providerName: "GitHub",
    email: "ada@example.com",
    linkedAt: new Date("2026-02-03T00:00:00Z"),
  },
  { id: "i-google", providerName: "Google" },
];

const PROVIDERS: SocialProvider[] = [
  { id: "gitlab", name: "GitLab" },
  { id: "apple", name: "Apple" },
];

const isoDate = (date: Date): string => date.toISOString();

describe("LinkedAccounts", () => {
  it("lists each account's provider, email and linked date", () => {
    const { container } = render(
      <LinkedAccounts accounts={ACCOUNTS} formatDate={isoDate} />,
    );
    const items = [
      ...container.querySelectorAll("li[data-oauth2-linked-account]"),
    ].map((item) => item.textContent);
    expect(items).toStrictEqual([
      "GitHubada@example.com · Connected 2026-02-03T00:00:00.000Z",
      "Google",
    ]);
  });

  it("is read-only without callbacks", () => {
    render(<LinkedAccounts accounts={ACCOUNTS} providers={PROVIDERS} />);
    expect(screen.queryAllByRole("button")).toStrictEqual([]);
    expect(screen.queryAllByRole("link")).toStrictEqual([]);
  });

  it("hands the chosen account to onUnlink", async () => {
    const unlinked: string[] = [];
    render(
      <LinkedAccounts
        accounts={ACCOUNTS}
        onUnlink={(account) => {
          unlinked.push(account.id);
        }}
      />,
    );
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Disconnect Google" }),
      );
    });
    expect(unlinked).toStrictEqual(["i-google"]);
  });

  it("offers no Disconnect on an account that is the last way to sign in, and says why", async () => {
    const unlinked: string[] = [];
    let state: LinkedAccountsState | undefined;
    const accounts = [{ ...ACCOUNTS[0]!, canUnlink: false }];
    const { container, rerender } = render(
      <LinkedAccounts
        accounts={accounts}
        onUnlink={(account) => {
          unlinked.push(account.id);
        }}
      />,
    );
    expect(screen.queryByRole("button")).toBeNull();
    expect(
      container.querySelector("[data-oauth2-last-method]")?.textContent,
    ).toStrictEqual(
      "This is your only way to sign in, so it can't be disconnected.",
    );

    rerender(
      <LinkedAccounts
        accounts={accounts}
        onUnlink={(account) => {
          unlinked.push(account.id);
        }}
      >
        {(live) => {
          state = live;
          return null;
        }}
      </LinkedAccounts>,
    );
    assert(state);
    await act(async () => {
      await state!.unlink(accounts[0]!);
    });
    expect(unlinked, "the render-prop unlink keeps the guard").toStrictEqual(
      [],
    );
  });

  it("shows a pending label on Disconnect and ignores another action until it settles", async () => {
    let release: (result?: AccountActionResult) => void = () => {};
    const calls: string[] = [];
    render(
      <LinkedAccounts
        accounts={ACCOUNTS}
        providers={PROVIDERS}
        onUnlink={(account) => {
          calls.push(account.id);
          return new Promise<AccountActionResult | void>((resolve) => {
            release = resolve;
          });
        }}
        onLink={(provider) => {
          calls.push(provider.id);
        }}
      />,
    );
    const button = screen.getByRole("button", { name: "Disconnect GitHub" });
    button.focus();
    await act(async () => {
      fireEvent.click(button);
    });
    expect(button.textContent).toStrictEqual("Disconnecting…");
    expect(button.getAttribute("aria-disabled")).toStrictEqual("true");
    expect(document.activeElement).toStrictEqual(button);

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Connect GitLab" }));
      fireEvent.click(button);
    });
    expect(calls).toStrictEqual(["i-github"]);

    await act(async () =>
      release({ error: "Add another way to sign in first." }),
    );
    expect(button.textContent).toStrictEqual("Disconnect");
    expect(screen.getByRole("alert").textContent).toStrictEqual(
      "Add another way to sign in first.",
    );
    expect(document.activeElement).toStrictEqual(
      screen.getByRole("alert").closest("[data-oauth2-error-summary]"),
    );
  });

  it("renders connect buttons that call onLink with the provider", async () => {
    let release: () => void = () => {};
    const linked: string[] = [];
    let state: LinkedAccountsState | undefined;
    const props = {
      accounts: ACCOUNTS,
      providers: PROVIDERS,
      onLink: (provider: SocialProvider) => {
        linked.push(provider.id);
        return new Promise<void>((resolve) => {
          release = resolve;
        });
      },
    };
    render(<LinkedAccounts {...props} />);
    const connect = screen.getByRole("button", { name: "Connect Apple" });
    await act(async () => {
      fireEvent.click(connect);
    });
    expect(linked).toStrictEqual(["apple"]);
    expect(connect.getAttribute("aria-label")).toStrictEqual(
      "Connecting… Apple",
    );
    expect(connect.getAttribute("aria-disabled")).toStrictEqual("true");
    await act(async () => release());
    expect(connect.textContent).toStrictEqual("Connect Apple");

    render(
      <LinkedAccounts {...props}>
        {(live) => {
          state = live;
          return null;
        }}
      </LinkedAccounts>,
    );
    assert(state);
    await act(async () => {
      void state!.link(PROVIDERS[0]!);
    });
    expect(state.pendingProviderId).toStrictEqual("gitlab");
    expect(state.pendingAccountId).toBeNull();
    await act(async () => release());
  });

  it("renders connect links when linkHref is passed, even with onLink", () => {
    render(
      <LinkedAccounts
        accounts={[]}
        providers={PROVIDERS}
        onLink={() => {}}
        linkHref={(provider) => `/auth/link/${provider.id}`}
      />,
    );
    expect(
      screen
        .getAllByRole("link")
        .map((link) => [link.textContent, link.getAttribute("href")]),
    ).toStrictEqual([
      ["Connect GitLab", "/auth/link/gitlab"],
      ["Connect Apple", "/auth/link/apple"],
    ]);
    expect(screen.queryAllByRole("button")).toStrictEqual([]);
  });

  it("posts intent and identityId natively to action before JavaScript runs", () => {
    const { container } = render(
      <LinkedAccounts
        accounts={ACCOUNTS}
        action="/account/identities"
        onUnlink={() => {}}
      />,
    );
    expect(
      [...container.querySelectorAll("form")].map((form) => [
        form.getAttribute("action"),
        form.getAttribute("method"),
        Object.fromEntries(new FormData(form)),
      ]),
    ).toStrictEqual([
      [
        "/account/identities",
        "post",
        { intent: "unlink-identity", identityId: "i-github" },
      ],
      [
        "/account/identities",
        "post",
        { intent: "unlink-identity", identityId: "i-google" },
      ],
    ]);
  });

  it("moves focus to the list when a disconnected account's row goes away", async () => {
    const onUnlink = (): void => {};
    const { container, rerender } = render(
      <LinkedAccounts accounts={ACCOUNTS} onUnlink={onUnlink} />,
    );
    const button = screen.getByRole("button", { name: "Disconnect Google" });
    button.focus();
    await act(async () => {
      fireEvent.click(button);
    });
    rerender(<LinkedAccounts accounts={[ACCOUNTS[0]!]} onUnlink={onUnlink} />);
    expect(document.activeElement).toStrictEqual(
      container.querySelector("[data-oauth2-linked-accounts]"),
    );
  });

  it("posts, never gets, even without an action", () => {
    const { container } = render(
      <LinkedAccounts accounts={ACCOUNTS} onUnlink={() => {}} />,
    );
    expect(
      [...container.querySelectorAll("form")].map((form) =>
        form.getAttribute("method"),
      ),
    ).toStrictEqual(["post", "post"]);
  });

  it("reports a failed action's error to a render-prop child", async () => {
    let state: LinkedAccountsState | undefined;
    render(
      <LinkedAccounts
        accounts={ACCOUNTS}
        onUnlink={() => ({ error: "Add another way to sign in first." })}
      >
        {(live) => {
          state = live;
          return null;
        }}
      </LinkedAccounts>,
    );
    assert(state);
    await act(async () => {
      await state!.unlink(ACCOUNTS[0]!);
    });
    expect(state.error).toStrictEqual("Add another way to sign in first.");
  });

  it("renders the empty label when nothing is linked", () => {
    render(<LinkedAccounts accounts={[]} />);
    assert(screen.getByText("No accounts connected yet."));
  });

  it("applies per-slot classes", () => {
    const { container } = render(
      <LinkedAccounts
        accounts={[ACCOUNTS[0]!, { ...ACCOUNTS[1]!, canUnlink: false }]}
        providers={PROVIDERS}
        onUnlink={() => {}}
        onLink={() => {}}
        className="outer"
        classNames={{
          root: "root",
          list: "list",
          item: "item",
          name: "name",
          meta: "meta",
          unlink: "unlink",
          hint: "hint",
          connectSection: "connect",
          connectButton: "connect-button",
        }}
      />,
    );
    const classOf = (selector: string): string | null | undefined =>
      container.querySelector(selector)?.getAttribute("class");
    expect(classOf("[data-oauth2-linked-accounts]")).toStrictEqual(
      "outer root",
    );
    expect(classOf("[data-oauth2-linked-account-items]")).toStrictEqual("list");
    expect(classOf("[data-oauth2-linked-account]")).toStrictEqual("item");
    expect(classOf("[data-oauth2-linked-account-name]")).toStrictEqual("name");
    expect(classOf("[data-oauth2-linked-account-meta]")).toStrictEqual("meta");
    expect(classOf("[data-oauth2-unlink]")).toStrictEqual("unlink");
    expect(classOf("[data-oauth2-last-method]")).toStrictEqual("hint");
    expect(classOf("[data-oauth2-connect]")).toStrictEqual("connect");
    expect(classOf("[data-oauth2-connect-button]")).toStrictEqual(
      "connect-button",
    );
  });
});
