// deno-lint-ignore-file require-await -- act(async …) needs the async signature
import { cleanupAfterEach, getForm } from "../_test_setup.ts";

import { assert, assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { act, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import axe, { type Result } from "axe-core";

import { SignInForm } from "./sign-in-form.tsx";
import { SignUpForm } from "./sign-up-form.tsx";
import { RequestPasswordResetForm } from "./request-password-reset-form.tsx";
import { ResetPasswordForm } from "./reset-password-form.tsx";
import { MfaChallengeForm } from "./mfa-challenge-form.tsx";
import { MfaEnrollmentForm } from "./mfa-enrollment-form.tsx";
import { UserMenu } from "./user-menu.tsx";
import { createMockOAuth2Client, MockOAuth2Provider } from "../testing.tsx";
import { useAuthForm } from "./use-auth-form.ts";
import { ErrorSummary, TextField, useFocusFirstError } from "./internal.tsx";

cleanupAfterEach();

const DISABLED_UNDER_JSDOM = [
  "color-contrast",
  "region",
  "landmark-one-main",
  "landmark-unique",
  "page-has-heading-one",
  "document-title",
  "html-has-lang",
  "bypass",
  "heading-order",
];

async function assertNoViolations(container: HTMLElement): Promise<void> {
  const rules: Record<string, { enabled: false }> = {};
  for (const id of DISABLED_UNDER_JSDOM) rules[id] = { enabled: false };
  const results = await axe.run(container, { rules });
  const summary = results.violations
    .map((violation: Result) => `${violation.id}: ${violation.help}`)
    .join("\n");
  assertEquals(results.violations.length, 0, summary);
}

describe("auth component accessibility (axe-core)", () => {
  it("SignInForm has no axe violations", async () => {
    const { container } = render(
      <SignInForm
        showRemember
        forgotPasswordHref="/forgot"
        onSubmit={() => {}}
      />,
    );
    await assertNoViolations(container);
  });

  it("SignUpForm has no axe violations", async () => {
    const { container } = render(
      <SignUpForm showUsername showName onSubmit={() => {}} />,
    );
    await assertNoViolations(container);
  });

  it("RequestPasswordResetForm has no axe violations", async () => {
    const { container } = render(
      <RequestPasswordResetForm onSubmit={() => {}} />,
    );
    await assertNoViolations(container);
  });

  it("ResetPasswordForm has no axe violations", async () => {
    const { container } = render(
      <ResetPasswordForm token="t" onSubmit={() => {}} />,
    );
    await assertNoViolations(container);
  });

  it("MfaChallengeForm has no axe violations", async () => {
    const { container } = render(<MfaChallengeForm onSubmit={() => {}} />);
    await assertNoViolations(container);
  });

  it("MfaEnrollmentForm has no axe violations", async () => {
    const { container } = render(
      <MfaEnrollmentForm
        data={{
          secret: "ABCDEF",
          otpauthUri: "otpauth://totp/Udibo:me?secret=ABCDEF",
          recoveryCodes: ["aaaa-bbbb", "cccc-dddd"],
        }}
        onSubmit={() => {}}
      />,
    );
    await assertNoViolations(container);
  });

  it("UserMenu has no axe violations collapsed or expanded", async () => {
    const user = { sub: "u1", name: "Ada Lovelace" };
    const client = createMockOAuth2Client({ user, isAuthenticated: true });
    const { container } = render(
      <MockOAuth2Provider
        client={client}
        state={{ user, isAuthenticated: true }}
      >
        <UserMenu items={<a href="/profile">Profile</a>} onLogout={() => {}} />
      </MockOAuth2Provider>,
    );
    await assertNoViolations(container);

    const trigger = screen.getByRole("button", { name: "Ada Lovelace" });
    assertEquals(trigger.getAttribute("aria-expanded"), "false");
    await act(async () => {
      fireEvent.click(trigger);
    });
    assertEquals(trigger.getAttribute("aria-expanded"), "true");
    assertEquals(
      trigger.getAttribute("aria-controls"),
      container.querySelector("[data-oauth2-user-panel]")?.id,
    );
    await assertNoViolations(container);
  });
});

describe("auth form error handling", () => {
  it("moves focus to the first errored field on invalid submit", async () => {
    const { container } = render(
      <SignInForm
        onSubmit={() => ({ fieldErrors: { password: "Too short" } })}
      />,
    );
    fireEvent.change(screen.getByLabelText("Email or username"), {
      target: { value: "user@example.com" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "x" },
    });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assert(
      document.activeElement === screen.getByLabelText("Password"),
      "focus should move to the errored password field",
    );
  });

  it("focuses the error summary without the focus target being the alert", async () => {
    const { container } = render(
      <SignInForm onSubmit={() => ({ error: "Invalid credentials" })} />,
    );
    fireEvent.change(screen.getByLabelText("Email or username"), {
      target: { value: "user@example.com" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "secret" },
    });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    const summary = container.querySelector<HTMLElement>(
      "[data-oauth2-error-summary]",
    );
    assert(summary, "expected an error summary");
    assert(
      document.activeElement === summary,
      "focus should move to the error summary wrapper",
    );
    assertEquals(summary.getAttribute("role"), null);
    assertEquals(screen.getByRole("alert").textContent, "Invalid credentials");
  });

  it("does not block paste on the MFA code field", () => {
    render(<MfaChallengeForm onSubmit={() => {}} />);
    const code = screen.getByLabelText("Authentication code");
    assertEquals(fireEvent.paste(code), true);
  });

  it("composes the validate-throw trap with focus-first-error (announce, don't fight)", async () => {
    function ThrowingValidateForm(): ReactNode {
      const form = useAuthForm<{ email: string }>({
        initialValues: { email: "" },
        validate: () => {
          throw new Error("validator blew up");
        },
        onSubmit: () => {},
      });
      useFocusFirstError(form);
      return (
        <form onSubmit={form.handleSubmit} noValidate>
          <ErrorSummary
            error={form.formError}
            focusTrigger={form.submitCount}
          />
          <TextField
            fieldProps={form.getFieldProps("email")}
            label="Email"
            error={form.errors.email}
          />
          <button type="submit">Go</button>
        </form>
      );
    }

    const { container } = render(<ThrowingValidateForm />);
    fireEvent.change(screen.getByLabelText("Email"), {
      target: { value: "user@example.com" },
    });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });

    const summary = container.querySelector<HTMLElement>(
      "[data-oauth2-error-summary]",
    );
    assert(summary, "the thrown validate error should surface as a form error");
    assertEquals(screen.getByRole("alert").textContent, "validator blew up");
    assert(
      document.activeElement === summary,
      "focus should rest on the error summary, not be stolen to a field",
    );
    const email = screen.getByLabelText("Email");
    assert(
      document.activeElement !== email,
      "focus-first-error must defer to the form-level error, not fight it",
    );
    assertEquals(email.getAttribute("aria-invalid"), null);
  });
});
