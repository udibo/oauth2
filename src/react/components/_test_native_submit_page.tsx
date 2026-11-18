/**
 * The server-rendered pages `native-submit.e2e.ts` serves: each drop-in form
 * rendered to HTML with no `action`, no `method` and no script, as a page
 * looks before its bundle loads.
 *
 * @module
 */

import type { ReactNode } from "react";
import { renderToString } from "react-dom/server";

import { MfaChallengeForm } from "./mfa-challenge-form.tsx";
import { MfaEnrollmentForm } from "./mfa-enrollment-form.tsx";
import { RequestPasswordResetForm } from "./request-password-reset-form.tsx";
import { ResetPasswordForm } from "./reset-password-form.tsx";
import { SignInForm } from "./sign-in-form.tsx";
import { SignUpForm } from "./sign-up-form.tsx";

function onSubmit(): void {}

const FORMS: Record<string, ReactNode> = {
  SignInForm: <SignInForm onSubmit={onSubmit} />,
  SignUpForm: <SignUpForm onSubmit={onSubmit} />,
  RequestPasswordResetForm: <RequestPasswordResetForm onSubmit={onSubmit} />,
  ResetPasswordForm: <ResetPasswordForm token="t" onSubmit={onSubmit} />,
  MfaChallengeForm: <MfaChallengeForm onSubmit={onSubmit} />,
  MfaEnrollmentForm: (
    <MfaEnrollmentForm
      data={{
        secret: "ABCDEF",
        otpauthUri: "otpauth://totp/Udibo:me?secret=ABCDEF",
        recoveryCodes: ["aaaa-bbbb"],
      }}
      onSubmit={onSubmit}
    />
  ),
};

/** The full HTML document for the drop-in form called `name`. */
export function renderPage(name: string): string {
  const form = FORMS[name];
  if (!form) throw new Error(`no drop-in form named "${name}"`);
  return (
    '<!doctype html><html lang="en"><body>' +
    renderToString(form) +
    "</body></html>"
  );
}
