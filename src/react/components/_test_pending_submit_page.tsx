/**
 * The browser entry `pending-submit.e2e.ts` bundles: renders the drop-in form
 * named by `?form=` with an `onSubmit` that stays pending until the test calls
 * `pendingSubmit.release()`. `pendingSubmit.calls` counts `onSubmit` calls and
 * `pendingSubmit.submits` every `submit` event a form dispatched.
 *
 * @module
 */

import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";

import { SignInForm } from "./sign-in-form.tsx";
import { SignUpForm } from "./sign-up-form.tsx";
import { RequestPasswordResetForm } from "./request-password-reset-form.tsx";
import { ResetPasswordForm } from "./reset-password-form.tsx";
import { MfaChallengeForm } from "./mfa-challenge-form.tsx";
import { MfaEnrollmentForm } from "./mfa-enrollment-form.tsx";
import type { AuthFormResult } from "./types.ts";

type HeldSubmit = () => Promise<AuthFormResult>;

const FORMS: Record<string, (onSubmit: HeldSubmit) => ReactNode> = {
  SignInForm: (onSubmit) => <SignInForm onSubmit={onSubmit} />,
  SignUpForm: (onSubmit) => <SignUpForm onSubmit={onSubmit} />,
  RequestPasswordResetForm: (onSubmit) => (
    <RequestPasswordResetForm onSubmit={onSubmit} />
  ),
  ResetPasswordForm: (onSubmit) => (
    <ResetPasswordForm token="t" onSubmit={onSubmit} />
  ),
  MfaChallengeForm: (onSubmit) => <MfaChallengeForm onSubmit={onSubmit} />,
  MfaEnrollmentForm: (onSubmit) => (
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

const pendingSubmit = {
  calls: 0,
  submits: 0,
  release: (): void => {},
};

function onSubmit(): Promise<AuthFormResult> {
  pendingSubmit.calls++;
  return new Promise((resolve) => {
    pendingSubmit.release = () => resolve({ error: "Try again." });
  });
}

const name = new URLSearchParams(location.search).get("form") ?? "";
const render = FORMS[name];
if (!render) throw new Error(`no drop-in form named "${name}"`);
Object.assign(globalThis, { pendingSubmit });
document.addEventListener("submit", () => pendingSubmit.submits++, true);
createRoot(document.getElementById("root")!).render(render(onSubmit));
