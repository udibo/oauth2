import { assert, describe, expect, it } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";

import { getForm } from "../_test_form.ts";
import { ChangePasswordForm } from "./change-password-form.tsx";
import type {
  ChangePasswordFormProps,
  ChangePasswordValues,
} from "./change-password-form.tsx";
import { AuthFormClassNamesProvider } from "./class-names.tsx";

function type(label: string, value: string): void {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function submit(container: HTMLElement): Promise<void> {
  await act(async () => {
    fireEvent.submit(getForm(container));
  });
}

function renderCollecting(
  props: Omit<ChangePasswordFormProps, "onSubmit"> = {},
): { container: HTMLElement; submitted: ChangePasswordValues[] } {
  const submitted: ChangePasswordValues[] = [];
  const { container } = render(
    <ChangePasswordForm
      {...props}
      onSubmit={(values) => {
        submitted.push(values);
      }}
    />,
  );
  return { container, submitted };
}

describe("ChangePasswordForm", () => {
  it("submits the current and new password, signing out other sessions by default", async () => {
    const { container, submitted } = renderCollecting();
    type("Current password", "old-secret");
    type("New password", "new-secret-1");
    type("Confirm new password", "new-secret-1");
    await submit(container);
    expect(submitted).toStrictEqual([
      {
        currentPassword: "old-secret",
        newPassword: "new-secret-1",
        confirmPassword: "new-secret-1",
        revokeOtherSessions: true,
      },
    ]);
    expect(
      container.querySelector("[data-oauth2-revoke-notice]")?.textContent,
    ).toStrictEqual("Your other sessions will be signed out.");
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("labels each field and sets password autocomplete", () => {
    render(<ChangePasswordForm onSubmit={() => {}} />);
    const autocomplete = (label: string): string | null =>
      screen.getByLabelText(label).getAttribute("autocomplete");
    expect(autocomplete("Current password")).toStrictEqual("current-password");
    expect(autocomplete("New password")).toStrictEqual("new-password");
    expect(autocomplete("Confirm new password")).toStrictEqual("new-password");
    expect(
      screen.getByRole("button", { name: "Update password" }).textContent,
    ).toStrictEqual("Update password");
  });

  it("sets a first password without asking for a current one", async () => {
    const { container, submitted } = renderCollecting({ hasPassword: false });
    expect(screen.queryByLabelText("Current password")).toBeNull();
    expect(
      container
        .querySelector("[data-oauth2-form]")
        ?.getAttribute("data-oauth2-form"),
    ).toStrictEqual("set-password");
    type("New password", "first-secret");
    type("Confirm new password", "first-secret");
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Set password" }));
    });
    expect(submitted).toStrictEqual([
      {
        currentPassword: "",
        newPassword: "first-secret",
        confirmPassword: "first-secret",
        revokeOtherSessions: true,
      },
    ]);
    expect(screen.getByRole("status").textContent).toStrictEqual(
      "Password set.",
    );
  });

  it("lets the person keep other sessions when the option is offered", async () => {
    const { container, submitted } = renderCollecting({
      revokeOtherSessions: "optional",
    });
    const checkbox = screen.getByRole("checkbox", {
      name: "Sign out of my other sessions",
    });
    assert(checkbox instanceof HTMLInputElement);
    expect(checkbox.checked).toStrictEqual(true);
    expect(container.querySelector("[data-oauth2-revoke-notice]")).toBeNull();
    fireEvent.click(checkbox);
    await submit(container);
    expect(submitted[0]!.revokeOtherSessions).toStrictEqual(false);
  });

  it("forwards revokeOtherSessions false and says nothing about sessions", async () => {
    const { container, submitted } = renderCollecting({
      revokeOtherSessions: false,
    });
    expect(container.querySelector("[data-oauth2-revoke-notice]")).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
    await submit(container);
    expect(submitted[0]!.revokeOtherSessions).toStrictEqual(false);
  });

  it("submits what the current props say, not what the fields held before they changed", async () => {
    const submitted: ChangePasswordValues[] = [];
    const onSubmit = (values: ChangePasswordValues): void => {
      submitted.push(values);
    };
    const { container, rerender } = render(
      <ChangePasswordForm revokeOtherSessions="optional" onSubmit={onSubmit} />,
    );
    type("Current password", "old-secret");
    fireEvent.click(screen.getByRole("checkbox"));
    rerender(
      <ChangePasswordForm
        hasPassword={false}
        revokeOtherSessions
        onSubmit={onSubmit}
      />,
    );
    await submit(container);
    expect(submitted).toStrictEqual([
      {
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
        revokeOtherSessions: true,
      },
    ]);
  });

  it("blocks a mismatched confirmation and focuses it", async () => {
    const { container, submitted } = renderCollecting();
    type("Current password", "old-secret");
    type("New password", "new-secret-1");
    type("Confirm new password", "new-secret-2");
    await submit(container);
    expect(submitted).toStrictEqual([]);
    const confirm = screen.getByLabelText("Confirm new password");
    expect(confirm.getAttribute("aria-invalid")).toStrictEqual("true");
    const describedBy = confirm.getAttribute("aria-describedby");
    assert(describedBy);
    expect(document.getElementById(describedBy)?.textContent).toStrictEqual(
      "Passwords do not match.",
    );
    expect(document.activeElement).toStrictEqual(confirm);
  });

  it("blocks a new password shorter than minLength", async () => {
    const { container, submitted } = renderCollecting({ minLength: 12 });
    const newPassword = screen.getByLabelText("New password");
    expect(newPassword.getAttribute("minlength")).toStrictEqual("12");
    type("Current password", "old-secret");
    type("New password", "short");
    type("Confirm new password", "short");
    await submit(container);
    expect(submitted).toStrictEqual([]);
    expect(newPassword.getAttribute("aria-invalid")).toStrictEqual("true");
    expect(screen.getByRole("alert").textContent).toStrictEqual(
      "Use at least 12 characters.",
    );
    expect(document.activeElement).toStrictEqual(newPassword);
  });

  it("shows a server field error on the current password and focuses it", async () => {
    const { container } = render(
      <ChangePasswordForm
        onSubmit={() => ({
          fieldErrors: { currentPassword: "Incorrect password." },
        })}
      />,
    );
    type("Current password", "wrong");
    type("New password", "new-secret-1");
    type("Confirm new password", "new-secret-1");
    await submit(container);
    const current = screen.getByLabelText("Current password");
    expect(current.getAttribute("aria-invalid")).toStrictEqual("true");
    expect(screen.getByRole("alert").textContent).toStrictEqual(
      "Incorrect password.",
    );
    expect(document.activeElement).toStrictEqual(current);
  });

  it("clears the passwords and announces success after a change", async () => {
    const successes: ChangePasswordValues[] = [];
    const { container } = render(
      <ChangePasswordForm
        onSubmit={() => {}}
        onSuccess={(values) => {
          successes.push(values);
        }}
      />,
    );
    type("Current password", "old-secret");
    type("New password", "new-secret-1");
    type("Confirm new password", "new-secret-1");
    await submit(container);
    expect(successes.map((values) => values.newPassword)).toStrictEqual([
      "new-secret-1",
    ]);
    const value = (label: string): string =>
      (screen.getByLabelText(label) as HTMLInputElement).value;
    expect([
      value("Current password"),
      value("New password"),
      value("Confirm new password"),
    ]).toStrictEqual(["", "", ""]);
    expect(screen.getByRole("status").textContent).toStrictEqual(
      "Password updated.",
    );
    assert(container.querySelector("form"), "the form stays in place");
  });

  it("names its fields for a no-JavaScript post", () => {
    const { container } = render(
      <ChangePasswordForm
        action="/account/password"
        revokeOtherSessions="optional"
        onSubmit={() => {}}
      />,
    );
    const form = getForm(container);
    expect(form.getAttribute("method")).toStrictEqual("post");
    expect(
      [...form.querySelectorAll("input")].map((input) => input.name),
    ).toStrictEqual([
      "currentPassword",
      "newPassword",
      "confirmPassword",
      "revokeOtherSessions",
    ]);
  });

  it("shows a current-password error in the summary when setting a first password, since that field is not rendered", async () => {
    const { container } = render(
      <ChangePasswordForm
        hasPassword={false}
        onSubmit={() => ({
          fieldErrors: { currentPassword: "Enter your current password." },
        })}
      />,
    );
    await submit(container);
    expect(screen.getByRole("alert").textContent).toStrictEqual(
      "Enter your current password.",
    );
    expect(document.activeElement).toStrictEqual(
      container.querySelector("[data-oauth2-error-summary]"),
    );
  });

  it("hands onSuccess the same values onSubmit received", async () => {
    const received: { submit?: ChangePasswordValues; success?: unknown } = {};
    const props = {
      onSubmit: (values: ChangePasswordValues) => {
        received.submit = values;
      },
      onSuccess: (values: ChangePasswordValues) => {
        received.success = values;
      },
    };
    const { container, rerender } = render(
      <ChangePasswordForm revokeOtherSessions={false} {...props} />,
    );
    type("Current password", "old-secret");
    rerender(
      <ChangePasswordForm hasPassword={false} revokeOtherSessions {...props} />,
    );
    await submit(container);
    assert(received.submit);
    expect(received.submit.currentPassword).toStrictEqual("");
    expect(received.submit.revokeOtherSessions).toStrictEqual(true);
    expect(received.success).toStrictEqual(received.submit);
  });

  it("keeps announcing the first password as set after the account reloads with one", async () => {
    const { container, rerender } = render(
      <ChangePasswordForm hasPassword={false} onSubmit={() => {}} />,
    );
    await submit(container);
    rerender(<ChangePasswordForm hasPassword onSubmit={() => {}} />);
    expect(screen.getByRole("status").textContent).toStrictEqual(
      "Password set.",
    );
  });

  it("starts the checkbox checked when the option is offered after mount", () => {
    const { rerender } = render(
      <ChangePasswordForm revokeOtherSessions={false} onSubmit={() => {}} />,
    );
    rerender(
      <ChangePasswordForm revokeOtherSessions="optional" onSubmit={() => {}} />,
    );
    const checkbox = screen.getByRole("checkbox");
    assert(checkbox instanceof HTMLInputElement);
    expect(checkbox.checked).toStrictEqual(true);
  });

  it("posts, never gets, even without an action, so passwords never reach a URL", () => {
    const { container } = render(<ChangePasswordForm onSubmit={() => {}} />);
    expect(getForm(container).getAttribute("method")).toStrictEqual("post");
  });

  it("carries the sign-out choice in a no-JavaScript post", () => {
    const posted = (
      revokeOtherSessions: boolean | "optional",
    ): FormDataEntryValue | null => {
      const { container, unmount } = render(
        <ChangePasswordForm
          action="/account/password"
          revokeOtherSessions={revokeOtherSessions}
          onSubmit={() => {}}
        />,
      );
      const value = new FormData(getForm(container)).get("revokeOtherSessions");
      unmount();
      return value;
    };
    expect(posted(true)).toStrictEqual("true");
    expect(posted(false)).toStrictEqual("false");
    expect(posted("optional")).toStrictEqual("true");
  });

  it("takes its classes from an AuthFormClassNamesProvider", () => {
    const { container } = render(
      <AuthFormClassNamesProvider
        classNames={{ input: "input", hint: "hint", submit: "submit" }}
      >
        <ChangePasswordForm onSubmit={() => {}} />
      </AuthFormClassNamesProvider>,
    );
    expect(
      container.querySelector("[data-oauth2-input]")?.getAttribute("class"),
    ).toStrictEqual("input");
    expect(
      container
        .querySelector("[data-oauth2-revoke-notice]")
        ?.getAttribute("class"),
    ).toStrictEqual("hint");
    expect(
      container.querySelector("[data-oauth2-submit]")?.getAttribute("class"),
    ).toStrictEqual("submit");
  });
});
