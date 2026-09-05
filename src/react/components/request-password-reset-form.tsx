/**
 * {@link RequestPasswordResetForm} — a default, accessible, unstyled
 * "forgot password" form built on {@link useAuthForm}. Collects an email and,
 * on success, swaps the form for a confirmation message (a neutral one that
 * doesn't reveal whether the address exists).
 *
 * @module
 */

import type { ReactNode } from "react";

import { useAuthForm } from "./use-auth-form.ts";
import type { AuthFormState } from "./use-auth-form.ts";
import type { BaseAuthFormProps } from "./types.ts";
import {
  AuthFormShell,
  SubmitButton,
  TextField,
  useFocusFirstError,
} from "./internal.tsx";
import { useAuthFormClassNames } from "./class-names.tsx";

/** Values collected by {@link RequestPasswordResetForm}. */
export type RequestPasswordResetValues = {
  /** The email to send the reset link to. */
  email: string;
};

/** Visible text overrides for {@link RequestPasswordResetForm}. */
export interface RequestPasswordResetLabels {
  /** Label for the email field. Default: `"Email"`. */
  email?: string;
  /** Submit button text. Default: `"Send reset link"`. */
  submit?: string;
  /** Submit button text while submitting. Default: `"Sending…"`. */
  submitting?: string;
  /** Confirmation shown after success. Default: a neutral "check your email". */
  success?: string;
}

/** Props for {@link RequestPasswordResetForm}. */
export interface RequestPasswordResetFormProps
  extends BaseAuthFormProps<RequestPasswordResetValues> {
  /** Text overrides. */
  labels?: RequestPasswordResetLabels;
  /**
   * Render-prop escape hatch. When provided, you own the markup and receive
   * the live {@link AuthFormState} (including `succeeded`).
   */
  children?: (state: AuthFormState<RequestPasswordResetValues>) => ReactNode;
}

const DEFAULT_SUCCESS =
  "If an account exists for that email, a reset link is on its way.";

/**
 * A ready-to-use "forgot password" request form. Wire `onSubmit` to your
 * reset-request endpoint. Return no error to trigger the neutral success state.
 *
 * **Enumeration safety is the endpoint's job:** the success copy is neutral
 * ("if an account exists…"), but this form renders whatever error `onSubmit`
 * returns/throws. Point it at an enumeration-safe endpoint (like
 * `IdentityService.requestPasswordReset`, which always resolves) — do **not**
 * surface a "no such account" error, or the neutral copy is undone.
 *
 * @example
 * ```tsx
 * <RequestPasswordResetForm
 *   onSubmit={async ({ email }) => {
 *     await fetch("/auth/forgot-password", {
 *       method: "POST",
 *       headers: { "content-type": "application/json" },
 *       body: JSON.stringify({ email }),
 *     });
 *   }}
 * />
 * ```
 */
export function RequestPasswordResetForm(
  props: RequestPasswordResetFormProps,
): ReactNode {
  const { onSubmit, className, labels, children } = props;

  const form = useAuthForm<RequestPasswordResetValues>({
    initialValues: { email: "" },
    onSubmit,
    onSuccess: props.onSuccess,
  });
  useFocusFirstError(form);
  const classNames = useAuthFormClassNames(props.classNames);

  return (
    <AuthFormShell
      name="request-password-reset"
      form={form}
      className={className}
      classNames={classNames}
      render={children}
      action={props.action}
      method={props.method}
      formRef={props.formRef}
      succeeded={form.succeeded
        ? (
          <div
            data-oauth2-success=""
            role="status"
            className={classNames.success}
          >
            {labels?.success ?? DEFAULT_SUCCESS}
          </div>
        )
        : null}
    >
      <TextField
        fieldProps={form.getFieldProps("email")}
        label={labels?.email ?? "Email"}
        type="email"
        autoComplete="email"
        required
        error={form.errors.email}
      />
      <SubmitButton
        isSubmitting={form.isSubmitting}
        label={labels?.submit ?? "Send reset link"}
        submittingLabel={labels?.submitting ?? "Sending…"}
      />
    </AuthFormShell>
  );
}
