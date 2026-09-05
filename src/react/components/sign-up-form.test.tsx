// deno-lint-ignore-file require-await -- act(async …) needs the async signature
import { cleanupAfterEach, getForm } from "../_test_setup.ts";

import { assert, assertEquals, assertFalse } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { act, fireEvent, render, screen } from "@testing-library/react";

import { SignUpForm } from "./sign-up-form.tsx";
import type { SignUpValues } from "./sign-up-form.tsx";

cleanupAfterEach();

describe("SignUpForm", () => {
  it("renders email + password with new-password autocomplete", () => {
    render(<SignUpForm onSubmit={() => {}} />);
    assertEquals(screen.getByLabelText("Email").getAttribute("type"), "email");
    assertEquals(
      screen.getByLabelText("Password").getAttribute("autocomplete"),
      "new-password",
    );
  });

  it("submits values and passes optional fields when enabled", async () => {
    const submitted: SignUpValues[] = [];
    const { container } = render(
      <SignUpForm
        showUsername
        showName
        showConfirmPassword={false}
        onSubmit={(values) => {
          submitted.push(values);
        }}
      />,
    );
    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "neo" },
    });
    fireEvent.change(screen.getByLabelText("Email"), {
      target: { value: "neo@example.com" },
    });
    fireEvent.change(screen.getByLabelText("First name"), {
      target: { value: "Thomas" },
    });
    fireEvent.change(screen.getByLabelText("Last name"), {
      target: { value: "Anderson" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "matrix" },
    });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals(submitted[0].username, "neo");
    assertEquals(submitted[0].firstName, "Thomas");
    assertEquals(submitted[0].lastName, "Anderson");
  });

  it("blocks submission and shows an error on password mismatch", async () => {
    let called = false;
    const { container } = render(
      <SignUpForm
        onSubmit={() => {
          called = true;
        }}
      />,
    );
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "aaaa" },
    });
    fireEvent.change(screen.getByLabelText("Confirm password"), {
      target: { value: "bbbb" },
    });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals(called, false);
    assert(screen.getByText("Passwords do not match."));
    assertEquals(
      screen.getByLabelText("Confirm password").getAttribute("aria-invalid"),
      "true",
    );
  });

  it("renders social buttons and omits them when empty", () => {
    const { container, rerender } = render(
      <SignUpForm
        onSubmit={() => {}}
        socialProviders={[{ id: "github", name: "GitHub" }]}
        onSocialSelect={() => {}}
      />,
    );
    assert(screen.getByText("Continue with GitHub"));
    rerender(<SignUpForm onSubmit={() => {}} socialProviders={[]} />);
    assertFalse(container.querySelector("[data-oauth2-social]"));
  });
});
