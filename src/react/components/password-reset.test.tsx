// deno-lint-ignore-file require-await -- act(async …) needs the async signature
import { cleanupAfterEach, getForm } from "../_test_setup.ts";

import { assert, assertEquals, assertFalse } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { act, fireEvent, render, screen } from "@testing-library/react";

import { RequestPasswordResetForm } from "./request-password-reset-form.tsx";
import { ResetPasswordForm } from "./reset-password-form.tsx";
import type { ResetPasswordValues } from "./reset-password-form.tsx";

cleanupAfterEach();

describe("RequestPasswordResetForm", () => {
  it("submits the email and swaps to a success message", async () => {
    const submitted: string[] = [];
    const { container } = render(
      <RequestPasswordResetForm
        onSubmit={({ email }) => {
          submitted.push(email);
        }}
      />,
    );
    fireEvent.change(screen.getByLabelText("Email"), {
      target: { value: "user@example.com" },
    });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals(submitted, ["user@example.com"]);
    assertFalse(container.querySelector("form"));
    assert(screen.getByRole("status").textContent?.includes("reset link"));
  });

  it("styles the success panel with the success slot, not hint", async () => {
    const { container } = render(
      <RequestPasswordResetForm
        onSubmit={() => {}}
        classNames={{ success: "success-cls", hint: "hint-cls" }}
      />,
    );
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals(
      container.querySelector("[data-oauth2-success]")?.className,
      "success-cls",
    );
  });

  it("keeps the form and shows the error when submit fails", async () => {
    const { container } = render(
      <RequestPasswordResetForm
        onSubmit={() => ({ error: "Rate limited" })}
      />,
    );
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assert(screen.getByText("Rate limited"));
    assert(container.querySelector("form"));
  });
});

describe("ResetPasswordForm", () => {
  it("forwards the token alongside the new password", async () => {
    const submitted: ResetPasswordValues[] = [];
    const { container } = render(
      <ResetPasswordForm
        token="tok-123"
        onSubmit={(values) => {
          submitted.push(values);
        }}
      />,
    );
    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "correct-horse" },
    });
    fireEvent.change(screen.getByLabelText("Confirm new password"), {
      target: { value: "correct-horse" },
    });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals(submitted[0].token, "tok-123");
    assertEquals(submitted[0].password, "correct-horse");
  });

  it("submits the current token after the token prop changes", async () => {
    const submitted: ResetPasswordValues[] = [];
    const onSubmit = (values: ResetPasswordValues) => {
      submitted.push(values);
    };
    const { container, rerender } = render(
      <ResetPasswordForm token="" onSubmit={onSubmit} />,
    );
    rerender(<ResetPasswordForm token="tok-late" onSubmit={onSubmit} />);
    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "correct-horse" },
    });
    fireEvent.change(screen.getByLabelText("Confirm new password"), {
      target: { value: "correct-horse" },
    });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals(submitted[0].token, "tok-late");
  });

  it("blocks on password mismatch", async () => {
    let called = false;
    const { container } = render(
      <ResetPasswordForm
        onSubmit={() => {
          called = true;
        }}
      />,
    );
    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "aaaa" },
    });
    fireEvent.change(screen.getByLabelText("Confirm new password"), {
      target: { value: "bbbb" },
    });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals(called, false);
    assert(screen.getByText("Passwords do not match."));
  });
});
