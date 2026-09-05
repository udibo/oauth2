// deno-lint-ignore-file require-await -- act(async …) needs the async signature
import { cleanupAfterEach, getForm } from "../_test_setup.ts";

import { assert, assertEquals, assertFalse } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { act, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";

import {
  AuthFormClassNamesProvider,
  useAuthFormClassNames,
} from "./class-names.tsx";
import { SignInForm } from "./sign-in-form.tsx";
import { SignUpForm } from "./sign-up-form.tsx";
import { MfaChallengeForm } from "./mfa-challenge-form.tsx";
import { MfaEnrollmentForm } from "./mfa-enrollment-form.tsx";
import { RequestPasswordResetForm } from "./request-password-reset-form.tsx";
import { ResetPasswordForm } from "./reset-password-form.tsx";

cleanupAfterEach();

function classOf(container: HTMLElement, selector: string): string | null {
  return container.querySelector(selector)?.getAttribute("class") ?? null;
}

function RenderPropProbe(): ReactNode {
  const classNames = useAuthFormClassNames();
  return (
    <>
      <span data-testid="input" className={classNames.input} />
      <span data-testid="submit" className={classNames.submit} />
    </>
  );
}

const probe = () => <RenderPropProbe />;
const ownInput = { input: "own-input" };

const RENDER_PROP_FORMS: [string, () => ReactNode][] = [
  [
    "SignInForm",
    () => (
      <SignInForm onSubmit={() => {}} classNames={ownInput}>{probe}</SignInForm>
    ),
  ],
  [
    "SignUpForm",
    () => (
      <SignUpForm onSubmit={() => {}} classNames={ownInput}>{probe}</SignUpForm>
    ),
  ],
  [
    "RequestPasswordResetForm",
    () => (
      <RequestPasswordResetForm onSubmit={() => {}} classNames={ownInput}>
        {probe}
      </RequestPasswordResetForm>
    ),
  ],
  [
    "ResetPasswordForm",
    () => (
      <ResetPasswordForm token="t" onSubmit={() => {}} classNames={ownInput}>
        {probe}
      </ResetPasswordForm>
    ),
  ],
  [
    "MfaChallengeForm",
    () => (
      <MfaChallengeForm onSubmit={() => {}} classNames={ownInput}>
        {probe}
      </MfaChallengeForm>
    ),
  ],
  [
    "MfaEnrollmentForm",
    () => (
      <MfaEnrollmentForm
        data={{ secret: "ABCDEF", otpauthUri: "otpauth://totp/Udibo:me" }}
        onSubmit={() => {}}
        classNames={ownInput}
      >
        {probe}
      </MfaEnrollmentForm>
    ),
  ],
];

describe("auth form class-name context", () => {
  it("carries every slot SignInForm renders down to its element", async () => {
    const { container } = render(
      <SignInForm
        onSubmit={() => ({
          error: "Invalid credentials",
          fieldErrors: { password: "Too short" },
        })}
        forgotPasswordHref="/forgot"
        socialProviders={[{ id: "github", name: "GitHub" }]}
        socialHref={() => "/auth/github"}
        className="root-cls"
        classNames={{
          root: "root-slot-cls",
          form: "form-cls",
          errorSummary: "summary-cls",
          field: "field-cls",
          label: "label-cls",
          input: "input-cls",
          error: "error-cls",
          hint: "hint-cls",
          actions: "actions-cls",
          submit: "submit-cls",
          socialSection: "social-cls",
          socialDivider: "divider-cls",
          socialButton: "social-button-cls",
        }}
      />,
    );
    await act(async () => {
      fireEvent.submit(getForm(container));
    });

    assertEquals(
      classOf(container, "[data-oauth2-form]"),
      "root-cls root-slot-cls",
    );
    assertEquals(classOf(container, "[data-oauth2-form-element]"), "form-cls");
    assertEquals(
      classOf(container, "[data-oauth2-error-summary]"),
      "summary-cls",
    );
    assertEquals(classOf(container, "[data-oauth2-field]"), "field-cls");
    assertEquals(classOf(container, "[data-oauth2-label]"), "label-cls");
    assertEquals(classOf(container, "[data-oauth2-input]"), "input-cls");
    assertEquals(classOf(container, "[data-oauth2-error]"), "error-cls");
    assertEquals(
      classOf(container, "[data-oauth2-forgot-password]"),
      "hint-cls",
    );
    assertEquals(classOf(container, "[data-oauth2-actions]"), "actions-cls");
    assertEquals(classOf(container, "[data-oauth2-submit]"), "submit-cls");
    assertEquals(classOf(container, "[data-oauth2-social]"), "social-cls");
    assertEquals(
      classOf(container, "[data-oauth2-social-divider]"),
      "divider-cls",
    );
    assertEquals(
      classOf(container, "[data-oauth2-social-button]"),
      "social-button-cls",
    );
  });

  it("styles the remember checkbox the form builds without TextField", () => {
    const { container } = render(
      <SignInForm
        showRemember
        onSubmit={() => {}}
        classNames={{ field: "field-cls", label: "label-cls", input: "in-cls" }}
      />,
    );

    const field = container.querySelector('[data-oauth2-field="remember"]');
    assert(field, "the remember checkbox should render its own field wrapper");
    assertEquals(field.getAttribute("class"), "field-cls");
    assertEquals(
      field.querySelector("[data-oauth2-label]")?.getAttribute("class"),
      "label-cls",
    );
    assertEquals(
      field.querySelector("[data-oauth2-input]")?.getAttribute("class"),
      "in-cls",
    );
  });

  it("leaves aria wiring intact while the context supplies classes", async () => {
    const { container } = render(
      <SignInForm
        onSubmit={() => ({ fieldErrors: { password: "Too short" } })}
        classNames={{ input: "input-cls", error: "error-cls" }}
      />,
    );
    await act(async () => {
      fireEvent.submit(getForm(container));
    });

    const password = screen.getByLabelText("Password");
    assertEquals(password.getAttribute("aria-invalid"), "true");
    const describedBy = password.getAttribute("aria-describedby");
    assert(describedBy, "the errored input should point at its error node");
    const error = document.getElementById(describedBy);
    assert(error, "aria-describedby should resolve to a rendered element");
    assertEquals(error.getAttribute("role"), "alert");
    assertEquals(error.textContent, "Too short");
    assertEquals(error.getAttribute("class"), "error-cls");
    assertEquals(classOf(container, "[data-oauth2-input]"), "input-cls");
  });

  it("themes every form under a provider without a per-form classNames", () => {
    const { container } = render(
      <AuthFormClassNamesProvider
        classNames={{ input: "themed-input", submit: "themed-submit" }}
      >
        <SignInForm onSubmit={() => {}} />
        <SignUpForm onSubmit={() => {}} />
      </AuthFormClassNamesProvider>,
    );

    const inputs = container.querySelectorAll("[data-oauth2-input]");
    assertEquals(inputs.length, 5);
    for (const input of inputs) {
      assertEquals(input.getAttribute("class"), "themed-input");
    }
    const submits = container.querySelectorAll("[data-oauth2-submit]");
    assertEquals(submits.length, 2);
    for (const submit of submits) {
      assertEquals(submit.getAttribute("class"), "themed-submit");
    }
  });

  it("lets a form override the inherited map slot by slot", () => {
    const { container } = render(
      <AuthFormClassNamesProvider
        classNames={{ input: "themed-input", submit: "themed-submit" }}
      >
        <SignInForm onSubmit={() => {}} classNames={{ submit: "own-submit" }} />
      </AuthFormClassNamesProvider>,
    );

    assertEquals(classOf(container, "[data-oauth2-input]"), "themed-input");
    assertEquals(classOf(container, "[data-oauth2-submit]"), "own-submit");
  });

  it("lets a nested provider override the outer one slot by slot", () => {
    const { container } = render(
      <AuthFormClassNamesProvider
        classNames={{ input: "outer-input", submit: "outer-submit" }}
      >
        <AuthFormClassNamesProvider classNames={{ submit: "inner-submit" }}>
          <SignInForm onSubmit={() => {}} />
        </AuthFormClassNamesProvider>
      </AuthFormClassNamesProvider>,
    );

    assertEquals(classOf(container, "[data-oauth2-input]"), "outer-input");
    assertEquals(classOf(container, "[data-oauth2-submit]"), "inner-submit");
  });

  it("keeps the inherited slot when a form passes it as undefined", () => {
    const { container } = render(
      <AuthFormClassNamesProvider classNames={{ input: "themed-input" }}>
        <SignInForm onSubmit={() => {}} classNames={{ input: undefined }} />
      </AuthFormClassNamesProvider>,
    );

    assertEquals(classOf(container, "[data-oauth2-input]"), "themed-input");
  });

  it("renders no class attribute for slots nobody set", () => {
    const { container } = render(<SignInForm onSubmit={() => {}} />);

    assertFalse(container.querySelector("[data-oauth2-input][class]"));
    assertFalse(container.querySelector("[data-oauth2-submit][class]"));
  });

  it("merges the root className with a provider-supplied root slot", () => {
    const { container } = render(
      <AuthFormClassNamesProvider classNames={{ root: "themed-root" }}>
        <SignInForm onSubmit={() => {}} className="own-root" />
      </AuthFormClassNamesProvider>,
    );

    assertEquals(
      classOf(container, "[data-oauth2-form]"),
      "own-root themed-root",
    );
  });

  it("themes ResetPasswordForm from its own prop", () => {
    const { container } = render(
      <ResetPasswordForm
        token="t"
        onSubmit={() => {}}
        className="root-cls"
        classNames={{ input: "input-cls", submit: "submit-cls" }}
      />,
    );

    assertEquals(classOf(container, "[data-oauth2-form]"), "root-cls");
    assertEquals(classOf(container, "[data-oauth2-input]"), "input-cls");
    assertEquals(classOf(container, "[data-oauth2-submit]"), "submit-cls");
  });

  it("themes ResetPasswordForm from an inherited provider", () => {
    const { container } = render(
      <AuthFormClassNamesProvider
        classNames={{ label: "label-cls", input: "themed-input" }}
      >
        <ResetPasswordForm token="t" onSubmit={() => {}} />
      </AuthFormClassNamesProvider>,
    );

    const inputs = container.querySelectorAll("[data-oauth2-input]");
    assertEquals(inputs.length, 2);
    for (const input of inputs) {
      assertEquals(input.getAttribute("class"), "themed-input");
    }
    assertEquals(classOf(container, "[data-oauth2-label]"), "label-cls");
  });

  it("themes MfaChallengeForm, recovery toggle included, from a provider", () => {
    const { container } = render(
      <AuthFormClassNamesProvider
        classNames={{ input: "themed-input", secondary: "secondary-cls" }}
      >
        <MfaChallengeForm onSubmit={() => {}} />
      </AuthFormClassNamesProvider>,
    );

    assertEquals(classOf(container, "[data-oauth2-input]"), "themed-input");
    assertEquals(
      classOf(container, "[data-oauth2-toggle-recovery]"),
      "secondary-cls",
    );
  });

  it("themes the enrollment panel's own slots from the shared map", () => {
    const { container } = render(
      <AuthFormClassNamesProvider
        classNames={{
          secret: "secret-cls",
          qr: "qr-cls",
          recoveryCodes: "codes-cls",
          recoveryCode: "code-cls",
          input: "input-cls",
        }}
      >
        <MfaEnrollmentForm
          data={{
            secret: "ABCDEF",
            otpauthUri: "otpauth://totp/Udibo:me?secret=ABCDEF",
            recoveryCodes: ["aaaa-bbbb"],
          }}
          qrSlot={<svg />}
          onSubmit={() => {}}
        />
      </AuthFormClassNamesProvider>,
    );

    assertEquals(classOf(container, "[data-oauth2-secret]"), "secret-cls");
    assertEquals(classOf(container, "[data-oauth2-qr]"), "qr-cls");
    assertEquals(
      classOf(container, "[data-oauth2-recovery-codes]"),
      "codes-cls",
    );
    assertEquals(classOf(container, "[data-oauth2-recovery-code]"), "code-cls");
    assertEquals(classOf(container, "[data-oauth2-input]"), "input-cls");
  });

  it("reaches the success panel that replaces the form", async () => {
    const { container } = render(
      <AuthFormClassNamesProvider classNames={{ success: "success-cls" }}>
        <RequestPasswordResetForm onSubmit={() => {}} />
      </AuthFormClassNamesProvider>,
    );
    await act(async () => {
      fireEvent.submit(getForm(container));
    });

    assertEquals(classOf(container, "[data-oauth2-success]"), "success-cls");
  });

  for (const [name, renderForm] of RENDER_PROP_FORMS) {
    it(`publishes the form's own map to ${name}'s render prop`, () => {
      render(
        <AuthFormClassNamesProvider classNames={{ submit: "themed-submit" }}>
          {renderForm()}
        </AuthFormClassNamesProvider>,
      );

      assertEquals(
        screen.getByTestId("input").getAttribute("class"),
        "own-input",
      );
      assertEquals(
        screen.getByTestId("submit").getAttribute("class"),
        "themed-submit",
      );
    });
  }

  it("merges direct hook overrides into the inherited map instead of replacing it", () => {
    function Probe(): ReactNode {
      const classNames = useAuthFormClassNames({ submit: "own-submit" });
      return (
        <>
          <span data-testid="input" className={classNames.input} />
          <span data-testid="submit" className={classNames.submit} />
        </>
      );
    }

    render(
      <AuthFormClassNamesProvider
        classNames={{ input: "themed-input", submit: "themed-submit" }}
      >
        <Probe />
      </AuthFormClassNamesProvider>,
    );

    assertEquals(
      screen.getByTestId("input").getAttribute("class"),
      "themed-input",
    );
    assertEquals(
      screen.getByTestId("submit").getAttribute("class"),
      "own-submit",
    );
  });

  it("keeps the resolved map stable across an equal inline literal", () => {
    const seen: Readonly<Record<string, string | undefined>>[] = [];
    function Probe(): ReactNode {
      seen.push(useAuthFormClassNames({ input: "input-cls" }));
      return null;
    }
    function Host(props: { tick: number }): ReactNode {
      return (
        <AuthFormClassNamesProvider classNames={{ submit: "submit-cls" }}>
          <span data-testid="tick">{props.tick}</span>
          <Probe />
        </AuthFormClassNamesProvider>
      );
    }

    const { rerender } = render(<Host tick={1} />);
    rerender(<Host tick={2} />);

    assertEquals(screen.getByTestId("tick").textContent, "2");
    assertEquals(seen.length, 2);
    assert(
      seen[0] === seen[1],
      "an equal classNames literal should resolve to the same map",
    );
    assert(
      Object.isFrozen(seen[0]),
      "the published map should be frozen, not just typed readonly",
    );
  });

  it("resolves an empty map with no provider above", () => {
    function Probe(): ReactNode {
      const classNames = useAuthFormClassNames();
      return <p data-testid="probe" className={classNames.input}>Probe</p>;
    }

    render(<Probe />);

    assertEquals(screen.getByTestId("probe").getAttribute("class"), null);
  });
});
