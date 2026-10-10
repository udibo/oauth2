import { assert, describe, expect, it } from "vitest";
import { getForm } from "../_test_form.ts";
import { act, fireEvent, render } from "@testing-library/react";
import type { ReactNode, Ref } from "react";

import { SignInForm } from "./sign-in-form.tsx";
import { SignUpForm } from "./sign-up-form.tsx";
import { RequestPasswordResetForm } from "./request-password-reset-form.tsx";
import { ResetPasswordForm } from "./reset-password-form.tsx";
import { MfaChallengeForm } from "./mfa-challenge-form.tsx";
import { MfaEnrollmentForm } from "./mfa-enrollment-form.tsx";

interface HostProps {
  onSubmit: () => void;
  onSuccess?: () => void;
  action?: string;
  method?: "get" | "post";
  formRef?: Ref<HTMLFormElement>;
}

const FORMS: [name: string, render: (props: HostProps) => ReactNode][] = [
  ["SignInForm", (props) => <SignInForm {...props} />],
  ["SignUpForm", (props) => <SignUpForm {...props} />],
  [
    "RequestPasswordResetForm",
    (props) => <RequestPasswordResetForm {...props} />,
  ],
  ["ResetPasswordForm", (props) => <ResetPasswordForm token="t" {...props} />],
  ["MfaChallengeForm", (props) => <MfaChallengeForm {...props} />],
  [
    "MfaEnrollmentForm",
    (props) => (
      <MfaEnrollmentForm
        data={{
          secret: "ABCDEF",
          otpauthUri: "otpauth://totp/Udibo:me?secret=ABCDEF",
          recoveryCodes: ["aaaa-bbbb"],
        }}
        {...props}
      />
    ),
  ],
];

describe("server-rendered forms post without JavaScript", () => {
  for (const [name, renderForm] of FORMS) {
    it(`${name} puts action and method on the form element`, () => {
      const { container } = render(
        renderForm({ onSubmit: () => {}, action: "/auth/go", method: "post" }),
      );
      const form = getForm(container);
      expect(form.getAttribute("action")).toStrictEqual("/auth/go");
      expect(form.getAttribute("method")).toStrictEqual("post");
    });

    it(`${name} hands the form element to formRef`, () => {
      let captured: HTMLFormElement | null = null;
      const { container } = render(
        renderForm({
          onSubmit: () => {},
          formRef: (element) => {
            captured = element;
          },
        }),
      );
      assert(captured, "formRef should receive the rendered <form>");
      assert(
        captured === getForm(container),
        "formRef should receive the form the component rendered",
      );
    });
  }

  it("every field carries its name, so a native post sends the same keys onSubmit receives", () => {
    const { container } = render(
      <SignInForm
        showRemember
        onSubmit={() => {}}
        action="/auth/sign-in"
        method="post"
      />,
    );
    const names = [...getForm(container).querySelectorAll("input")].map(
      (input) => input.getAttribute("name"),
    );
    expect(names).toStrictEqual(["identifier", "password", "remember"]);
  });

  it("suppresses the native post once JavaScript runs, so onSubmit wins", async () => {
    let handled = 0;
    const { container } = render(
      <SignInForm
        onSubmit={() => {
          handled++;
        }}
        action="/auth/sign-in"
        method="post"
      />,
    );
    let notPrevented = true;
    await act(async () => {
      notPrevented = fireEvent.submit(getForm(container));
    });
    expect(handled).toStrictEqual(1);
    expect(
      notPrevented,
      "the submit event must be prevented so the browser does not also post",
    ).toStrictEqual(false);
  });

  it("posts by default, so credentials never reach the URL a get form would build", () => {
    const { container } = render(
      <SignInForm onSubmit={() => {}} action="/identity/signin" />,
    );
    const form = getForm(container);
    expect(form.getAttribute("method")).toStrictEqual("post");
    expect(form.method).toStrictEqual("post");
  });

  it("still honours an explicit method", () => {
    const { container } = render(
      <RequestPasswordResetForm
        onSubmit={() => {}}
        action="/identity/lookup"
        method="get"
      />,
    );
    expect(getForm(container).getAttribute("method")).toStrictEqual("get");
  });

  it("omits action and method when the app does not ask for a native post", () => {
    const { container } = render(<SignInForm onSubmit={() => {}} />);
    const form = getForm(container);
    expect(form.getAttribute("action")).toStrictEqual(null);
    expect(form.getAttribute("method")).toStrictEqual(null);
  });
});

describe("forms report success to the host app", () => {
  for (const [name, renderForm] of FORMS) {
    it(`${name} calls onSuccess after a submit that returns no error`, async () => {
      let succeeded = 0;
      const { container } = render(
        renderForm({ onSubmit: () => {}, onSuccess: () => succeeded++ }),
      );
      await act(async () => {
        fireEvent.submit(getForm(container));
      });
      expect(succeeded).toStrictEqual(1);
    });
  }

  it("does not call onSuccess when the submit reports an error", async () => {
    let succeeded = 0;
    const { container } = render(
      <SignInForm
        onSubmit={() => ({ error: "Invalid credentials" })}
        onSuccess={() => succeeded++}
      />,
    );
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    expect(succeeded).toStrictEqual(0);
  });
});
