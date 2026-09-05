// deno-lint-ignore-file require-await -- act(async …) needs the async signature
import { cleanupAfterEach, getForm } from "../_test_setup.ts";

import { assert, assertEquals, assertFalse } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { act, fireEvent, render, screen } from "@testing-library/react";

import { SignInForm } from "./sign-in-form.tsx";
import type { SignInValues } from "./sign-in-form.tsx";

cleanupAfterEach();

describe("SignInForm", () => {
  it("renders accessible labelled fields", () => {
    render(<SignInForm onSubmit={() => {}} />);
    const identifier = screen.getByLabelText("Email or username");
    const password = screen.getByLabelText("Password");
    assertEquals(identifier.getAttribute("autocomplete"), "username");
    assertEquals(password.getAttribute("type"), "password");
    assertEquals(password.getAttribute("autocomplete"), "current-password");
  });

  it("submits the collected values", async () => {
    const submitted: SignInValues[] = [];
    const { container } = render(
      <SignInForm
        onSubmit={(values) => {
          submitted.push(values);
        }}
      />,
    );
    fireEvent.change(screen.getByLabelText("Email or username"), {
      target: { value: "user@example.com" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "hunter2" },
    });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals(submitted.length, 1);
    assertEquals(submitted[0].identifier, "user@example.com");
    assertEquals(submitted[0].password, "hunter2");
  });

  it("shows a form-level error and per-field errors from the result", async () => {
    const { container } = render(
      <SignInForm
        onSubmit={() => ({
          error: "Invalid credentials",
          fieldErrors: { password: "Too short" },
        })}
      />,
    );
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assert(
      container.querySelector("[data-oauth2-error-summary]")?.textContent
        ?.includes("Invalid"),
    );
    assertEquals(
      screen.getByText("Too short").getAttribute("data-oauth2-error"),
      "",
    );
    assertEquals(
      screen.getByLabelText("Password").getAttribute("aria-invalid"),
      "true",
    );
  });

  it("disables the submit button while submitting", async () => {
    let resolve: (() => void) | undefined;
    const { container } = render(
      <SignInForm
        onSubmit={() =>
          new Promise<void>((r) => {
            resolve = r;
          })}
      />,
    );
    const button = screen.getByRole("button", { name: "Sign in" });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals((button as HTMLButtonElement).disabled, true);
    await act(async () => {
      resolve?.();
    });
    assertEquals((button as HTMLButtonElement).disabled, false);
  });

  it("renders social buttons from the socialProviders prop", () => {
    render(
      <SignInForm
        onSubmit={() => {}}
        socialProviders={[
          { id: "github", name: "GitHub" },
          { id: "google", name: "Google" },
        ]}
        socialHref={(p) => `/auth/login?connection=${p.id}`}
      />,
    );
    const github = screen.getByText("Continue with GitHub").closest("a");
    assertEquals(github?.getAttribute("href"), "/auth/login?connection=github");
    assertEquals(
      screen.getByText("Continue with Google").closest("a")?.getAttribute(
        "data-oauth2-social-button",
      ),
      "google",
    );
  });

  it("calls onSocialSelect when a social button without href is clicked", () => {
    const selected: string[] = [];
    render(
      <SignInForm
        onSubmit={() => {}}
        socialProviders={[{ id: "github", name: "GitHub" }]}
        onSocialSelect={(p) => selected.push(p.id)}
      />,
    );
    fireEvent.click(
      screen.getByText("Continue with GitHub").closest("button")!,
    );
    assertEquals(selected, ["github"]);
  });

  it("renders no social section when providers are absent or empty", () => {
    const { container, rerender } = render(<SignInForm onSubmit={() => {}} />);
    assertFalse(
      container.querySelector("[data-oauth2-social]"),
      "absent socialProviders must render no social section",
    );
    rerender(<SignInForm onSubmit={() => {}} socialProviders={[]} />);
    assertFalse(
      container.querySelector("[data-oauth2-social]"),
      "an empty socialProviders list must render no social section",
    );
  });

  it("renders the remember checkbox and forgot-password link when configured", () => {
    render(
      <SignInForm
        onSubmit={() => {}}
        showRemember
        forgotPasswordHref="/forgot-password"
      />,
    );
    assertEquals(
      screen.getByLabelText("Remember me").getAttribute("type"),
      "checkbox",
    );
    assertEquals(
      screen.getByText("Forgot password?").getAttribute("href"),
      "/forgot-password",
    );
  });

  it("ejects to a render prop exposing the form state", () => {
    render(
      <SignInForm onSubmit={() => {}}>
        {(form) => <p data-testid="status">{form.status}</p>}
      </SignInForm>,
    );
    assertEquals(screen.getByTestId("status").textContent, "idle");
  });

  it("applies per-slot classNames", () => {
    const { container } = render(
      <SignInForm
        onSubmit={() => {}}
        className="root-cls"
        classNames={{
          input: "input-cls",
          submit: "submit-cls",
          form: "form-cls",
        }}
      />,
    );
    const formElement = container.querySelector("[data-oauth2-form-element]");
    assert(formElement, "the form slot needs its own data attribute");
    assert(formElement.classList.contains("form-cls"));
    assert(
      container.querySelector("[data-oauth2-form]")?.classList.contains(
        "root-cls",
      ),
    );
    assert(
      screen.getByLabelText("Password").classList.contains("input-cls"),
    );
    assert(
      screen.getByRole("button", { name: "Sign in" }).classList.contains(
        "submit-cls",
      ),
    );
  });
});
