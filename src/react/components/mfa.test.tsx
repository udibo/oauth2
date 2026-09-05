// deno-lint-ignore-file require-await -- act(async …) needs the async signature
import { cleanupAfterEach, getForm } from "../_test_setup.ts";

import { assert, assertEquals, assertFalse } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { act, fireEvent, render, screen } from "@testing-library/react";

import { MfaChallengeForm } from "./mfa-challenge-form.tsx";
import type { MfaChallengeValues } from "./mfa-challenge-form.tsx";
import { MfaEnrollmentForm } from "./mfa-enrollment-form.tsx";
import type { MfaEnrollmentValues } from "./mfa-enrollment-form.tsx";

cleanupAfterEach();

describe("MfaChallengeForm", () => {
  it("submits a totp code with the totp method", async () => {
    const submitted: MfaChallengeValues[] = [];
    const { container } = render(
      <MfaChallengeForm
        onSubmit={(values) => {
          submitted.push(values);
        }}
      />,
    );
    const input = screen.getByLabelText("Authentication code");
    assertEquals(input.getAttribute("autocomplete"), "one-time-code");
    fireEvent.change(input, { target: { value: "123456" } });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals(submitted[0], { code: "123456", method: "totp" });
  });

  it("toggles to recovery code and submits with the recovery method", async () => {
    const submitted: MfaChallengeValues[] = [];
    const { container } = render(
      <MfaChallengeForm
        onSubmit={(values) => {
          submitted.push(values);
        }}
      />,
    );
    fireEvent.click(screen.getByText("Use a recovery code"));
    const input = screen.getByLabelText("Recovery code");
    assertEquals(input.getAttribute("autocomplete"), "off");
    fireEvent.change(input, { target: { value: "abcd-efgh" } });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals(submitted[0], { code: "abcd-efgh", method: "recovery" });
  });

  it("hides the recovery toggle when allowRecoveryCode is false", () => {
    render(<MfaChallengeForm onSubmit={() => {}} allowRecoveryCode={false} />);
    assertFalse(screen.queryByText("Use a recovery code"));
  });

  it("marks the recovery toggle with the documented secondary attribute", () => {
    const { container } = render(
      <MfaChallengeForm
        onSubmit={() => {}}
        classNames={{ secondary: "link" }}
      />,
    );
    const toggle = container.querySelector("[data-oauth2-secondary]");
    assert(toggle, "the secondary slot needs its documented data attribute");
    assertEquals(toggle.className, "link");
    assert(toggle.hasAttribute("data-oauth2-toggle-recovery"));
  });
});

describe("MfaEnrollmentForm", () => {
  it("shows the secret, QR slot, and recovery codes", () => {
    render(
      <MfaEnrollmentForm
        data={{
          secret: "JBSWY3DPEHPK3PXP",
          otpauthUri: "otpauth://totp/Udibo:me?secret=JBSWY3DPEHPK3PXP",
          recoveryCodes: ["code-1", "code-2"],
        }}
        qrSlot={(uri) => <img alt="qr" data-uri={uri} />}
        onSubmit={() => {}}
      />,
    );
    assert(screen.getByText("JBSWY3DPEHPK3PXP"));
    assertEquals(
      screen.getByAltText("qr").getAttribute("data-uri"),
      "otpauth://totp/Udibo:me?secret=JBSWY3DPEHPK3PXP",
    );
    assert(screen.getByText("code-1"));
    assert(screen.getByText("code-2"));
  });

  it("confirms enrollment by submitting the code", async () => {
    const submitted: MfaEnrollmentValues[] = [];
    const { container } = render(
      <MfaEnrollmentForm
        data={{ secret: "S", otpauthUri: "otpauth://x" }}
        onSubmit={(values) => {
          submitted.push(values);
        }}
      />,
    );
    fireEvent.change(screen.getByLabelText("Authentication code"), {
      target: { value: "999111" },
    });
    await act(async () => {
      fireEvent.submit(getForm(container));
    });
    assertEquals(submitted[0], { code: "999111" });
  });

  it("ejects to a render prop that replaces the whole panel", () => {
    const { container } = render(
      <MfaEnrollmentForm
        data={{ secret: "JBSWY3DPEHPK3PXP", otpauthUri: "otpauth://x" }}
        onSubmit={() => {}}
      >
        {(form) => <p data-testid="status">{form.status}</p>}
      </MfaEnrollmentForm>,
    );
    assertEquals(screen.getByTestId("status").textContent, "idle");
    assertFalse(
      container.querySelector("[data-oauth2-form]"),
      "the render prop owns the markup, like every sibling form",
    );
    assertFalse(screen.queryByText("JBSWY3DPEHPK3PXP"));
  });

  it("puts the recoveryCodes class on the list the docs name, not the wrapper", () => {
    const { container } = render(
      <MfaEnrollmentForm
        data={{
          secret: "S",
          otpauthUri: "otpauth://x",
          recoveryCodes: ["code-1"],
        }}
        classNames={{ recoveryCodes: "codes", recoveryCode: "code" }}
        onSubmit={() => {}}
      />,
    );
    assertEquals(
      container.querySelector("[data-oauth2-recovery-codes]")?.className,
      "codes",
    );
    assertEquals(
      container.querySelector("[data-oauth2-recovery]")?.className,
      "",
    );
    assertEquals(
      container.querySelector("[data-oauth2-recovery-code]")?.className,
      "code",
    );
  });
});
