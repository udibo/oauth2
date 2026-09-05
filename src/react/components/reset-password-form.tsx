/**
 * {@link ResetPasswordForm} — a default, accessible, unstyled "set a new
 * password" form built on {@link useAuthForm}. Collects a new password and its
 * confirmation, validates the match on the client, and forwards an opaque
 * reset `token` (from the reset link) to your `onSubmit`.
 *
 * @module
 */

import { type ReactNode, useEffect } from "react";

import { useAuthForm } from "./use-auth-form.ts";
import type { AuthFormState } from "./use-auth-form.ts";
import type { AuthFormErrors, BaseAuthFormProps } from "./types.ts";
import {
  AuthFormShell,
  SubmitButton,
  TextField,
  useFocusFirstError,
} from "./internal.tsx";
import { useAuthFormClassNames } from "./class-names.tsx";

/** Values collected by {@link ResetPasswordForm}. */
export type ResetPasswordValues = {
  /** The new password. */
  password: string;
  /** Confirmation of the new password. */
  confirmPassword: string;
  /** The opaque reset token from the link; passed through from `token`. */
  token: string;
};

/** Visible text overrides for {@link ResetPasswordForm}. */
export interface ResetPasswordLabels {
  /** Label for the password field. Default: `"New password"`. */
  password?: string;
  /** Label for the confirm field. Default: `"Confirm new password"`. */
  confirmPassword?: string;
  /** Submit button text. Default: `"Reset password"`. */
  submit?: string;
  /** Submit button text while submitting. Default: `"Resetting…"`. */
  submitting?: string;
  /** Password-mismatch message. Default: `"Passwords do not match."`. */
  passwordMismatch?: string;
}

/** Props for {@link ResetPasswordForm}. */
export interface ResetPasswordFormProps
  extends BaseAuthFormProps<ResetPasswordValues> {
  /** The opaque reset token, typically read from the URL by your route. */
  token?: string;
  /** Text overrides. */
  labels?: ResetPasswordLabels;
  /**
   * Render-prop escape hatch. When provided, you own the markup and receive
   * the live {@link AuthFormState}.
   */
  children?: (state: AuthFormState<ResetPasswordValues>) => ReactNode;
}

/**
 * A ready-to-use "set a new password" form. Pass the reset `token` from the
 * link; it is forwarded to `onSubmit` alongside the password. A client-side
 * check blocks submission on password mismatch.
 *
 * @example
 * ```tsx
 * <ResetPasswordForm
 *   token={new URLSearchParams(location.search).get("token") ?? ""}
 *   onSubmit={async (values) => {
 *     const res = await fetch("/auth/reset-password", {
 *       method: "POST",
 *       headers: { "content-type": "application/json" },
 *       body: JSON.stringify(values),
 *     });
 *     if (!res.ok) return await res.json();
 *   }}
 * />
 * ```
 */
export function ResetPasswordForm(props: ResetPasswordFormProps): ReactNode {
  const { onSubmit, token = "", className, labels, children } = props;

  const form = useAuthForm<ResetPasswordValues>({
    initialValues: { password: "", confirmPassword: "", token },
    onSubmit,
    onSuccess: props.onSuccess,
    validate: (values) => {
      const errors: AuthFormErrors<ResetPasswordValues> = {};
      if (values.password !== values.confirmPassword) {
        errors.confirmPassword = labels?.passwordMismatch ??
          "Passwords do not match.";
      }
      return errors;
    },
  });

  const { setValue } = form;
  useEffect(() => {
    setValue("token", token);
  }, [token, setValue]);
  useFocusFirstError(form);
  const classNames = useAuthFormClassNames(props.classNames);

  return (
    <AuthFormShell
      name="reset-password"
      form={form}
      className={className}
      classNames={classNames}
      render={children}
      action={props.action}
      method={props.method}
      formRef={props.formRef}
    >
      <TextField
        fieldProps={form.getFieldProps("password")}
        label={labels?.password ?? "New password"}
        type="password"
        autoComplete="new-password"
        required
        error={form.errors.password}
      />
      <TextField
        fieldProps={form.getFieldProps("confirmPassword")}
        label={labels?.confirmPassword ?? "Confirm new password"}
        type="password"
        autoComplete="new-password"
        required
        error={form.errors.confirmPassword}
      />
      <SubmitButton
        isSubmitting={form.isSubmitting}
        label={labels?.submit ?? "Reset password"}
        submittingLabel={labels?.submitting ?? "Resetting…"}
      />
    </AuthFormShell>
  );
}
