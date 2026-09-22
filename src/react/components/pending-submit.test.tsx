// deno-lint-ignore-file require-await -- act(async …) needs the async signature
import { cleanupAfterEach, getForm } from "../_test_setup.ts";

import { assert, assertEquals, assertFalse } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import {
  act,
  createEvent,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import type { ReactNode } from "react";

import { SignInForm } from "./sign-in-form.tsx";
import { SignUpForm } from "./sign-up-form.tsx";
import { RequestPasswordResetForm } from "./request-password-reset-form.tsx";
import { ResetPasswordForm } from "./reset-password-form.tsx";
import { MfaChallengeForm } from "./mfa-challenge-form.tsx";
import { MfaEnrollmentForm } from "./mfa-enrollment-form.tsx";
import type { AuthFormResult } from "./types.ts";

cleanupAfterEach();

type HeldSubmit = () => Promise<AuthFormResult>;

interface FormCase {
  name: string;
  label: string;
  pendingLabel: string;
  render(onSubmit: HeldSubmit): ReactNode;
}

const FORMS: FormCase[] = [
  {
    name: "SignInForm",
    label: "Sign in",
    pendingLabel: "Signing in…",
    render: (onSubmit) => <SignInForm onSubmit={onSubmit} />,
  },
  {
    name: "SignUpForm",
    label: "Create account",
    pendingLabel: "Creating account…",
    render: (onSubmit) => <SignUpForm onSubmit={onSubmit} />,
  },
  {
    name: "RequestPasswordResetForm",
    label: "Send reset link",
    pendingLabel: "Sending…",
    render: (onSubmit) => <RequestPasswordResetForm onSubmit={onSubmit} />,
  },
  {
    name: "ResetPasswordForm",
    label: "Reset password",
    pendingLabel: "Resetting…",
    render: (onSubmit) => <ResetPasswordForm token="t" onSubmit={onSubmit} />,
  },
  {
    name: "MfaChallengeForm",
    label: "Verify",
    pendingLabel: "Verifying…",
    render: (onSubmit) => <MfaChallengeForm onSubmit={onSubmit} />,
  },
  {
    name: "MfaEnrollmentForm",
    label: "Confirm",
    pendingLabel: "Confirming…",
    render: (onSubmit) => (
      <MfaEnrollmentForm
        data={{
          secret: "ABCDEF",
          otpauthUri: "otpauth://totp/Udibo:me?secret=ABCDEF",
          recoveryCodes: ["aaaa-bbbb"],
        }}
        onSubmit={onSubmit}
      />
    ),
  },
];

function heldSubmit(): {
  onSubmit: HeldSubmit;
  calls: () => number;
  release: () => void;
} {
  let calls = 0;
  let release: () => void = () => {};
  const held = new Promise<AuthFormResult>((resolve) => {
    release = () => resolve({ error: "Try again." });
  });
  return {
    onSubmit: () => {
      calls++;
      return held;
    },
    calls: () => calls,
    release: () => release(),
  };
}

async function startPendingSubmit(
  form: FormCase,
): Promise<ReturnType<typeof heldSubmit> & { button: HTMLElement }> {
  const submit = heldSubmit();
  render(form.render(submit.onSubmit));
  const button = screen.getByRole("button", { name: form.label });
  button.focus();
  await act(async () => {
    fireEvent.click(button);
  });
  assertEquals(submit.calls(), 1, "clicking the idle button submits once");
  assert(
    screen.getByRole("button", { name: form.pendingLabel }) === button,
    "the pending state must re-render the same button",
  );
  return { ...submit, button };
}

describe("a pending submit button stays focusable and inert", () => {
  for (const form of FORMS) {
    describe(form.name, () => {
      it("announces pending with aria-disabled instead of native disabled", async () => {
        const { button, release } = await startPendingSubmit(form);

        assertEquals(button.getAttribute("aria-disabled"), "true");
        assertFalse(
          button.hasAttribute("disabled"),
          "disabling the focused button drops keyboard focus to <body> in Chromium",
        );

        await act(async () => release());
        const idle = screen.getByRole("button", { name: form.label });
        assertFalse(idle.hasAttribute("aria-disabled"));
        assertFalse(idle.hasAttribute("disabled"));
      });
    });
  }
});

describe("repeat activation while a submit is pending", () => {
  const signIn = FORMS[0];

  it("cancels a click on the pending button, the activation that Enter, Space and Enter in a field all dispatch", async () => {
    const { button, calls, release } = await startPendingSubmit(signIn);
    const form = button.closest("form");
    assert(form);
    let submitEvents = 0;
    form.addEventListener("submit", () => submitEvents++);
    const click = createEvent.click(button);

    await act(async () => {
      fireEvent(button, click);
    });

    assert(click.defaultPrevented, "the pending button must cancel activation");
    assertEquals(submitEvents, 0, "a pending button must not submit its form");
    assertEquals(calls(), 1);
    await act(async () => release());
  });

  it("cancels a second submit event that still reaches the form, so a no-JS action is not posted", async () => {
    const submit = heldSubmit();
    const { container } = render(
      <SignInForm action="/sign-in" onSubmit={submit.onSubmit} />,
    );
    const form = getForm(container);
    await act(async () => {
      fireEvent.submit(form);
    });
    assertEquals(submit.calls(), 1);

    const second = createEvent.submit(form);
    await act(async () => {
      fireEvent(form, second);
    });

    assert(second.defaultPrevented, "the repeat submit must be cancelled");
    assertEquals(submit.calls(), 1, "onSubmit must not run again");

    await act(async () => submit.release());
    await act(async () => {
      fireEvent.submit(form);
    });
    assertEquals(submit.calls(), 2, "a settled form submits again");
    await act(async () => submit.release());
  });
});
