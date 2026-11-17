/**
 * {@link ChangePasswordForm} — a default, accessible, unstyled form for a
 * signed-in person to change their password, or to set a first one on an
 * account that signs in without a password. Built on {@link useAuthForm}: it
 * collects the passwords, checks the confirmation and length on the client,
 * and hands the values to your `onSubmit`.
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

/** Values collected by {@link ChangePasswordForm}. */
export type ChangePasswordValues = {
  /**
   * The current password. Always `""` when `hasPassword` is `false`, since
   * the field is not rendered.
   */
  currentPassword: string;
  /** The new password. */
  newPassword: string;
  /** Confirmation of the new password; the form blocks a mismatch. */
  confirmPassword: string;
  /**
   * Whether to sign out the account's other sessions with the change. Fixed
   * by the `revokeOtherSessions` prop unless it is `"optional"`, when the
   * person's checkbox decides.
   */
  revokeOtherSessions: boolean;
};

/** Visible text overrides for {@link ChangePasswordForm}. */
export interface ChangePasswordLabels {
  /** Label for the current-password field. Default: `"Current password"`. */
  currentPassword?: string;
  /** Label for the new-password field. Default: `"New password"`. */
  newPassword?: string;
  /** Label for the confirmation field. Default: `"Confirm new password"`. */
  confirmPassword?: string;
  /**
   * Submit button text. Default: `"Update password"`, or `"Set password"`
   * when `hasPassword` is `false`.
   */
  submit?: string;
  /**
   * Submit button text while submitting. Default: `"Updating…"`, or
   * `"Setting…"` when `hasPassword` is `false`.
   */
  submitting?: string;
  /** Mismatch message on the confirmation field. Default: `"Passwords do not match."`. */
  passwordMismatch?: string;
  /**
   * Message on the new-password field when it is shorter than `minLength`.
   * Default: `"Use at least {minLength} characters."`.
   */
  tooShort?: string;
  /**
   * Label of the checkbox shown when `revokeOtherSessions` is `"optional"`.
   * Default: `"Sign out of my other sessions"`.
   */
  revokeOtherSessions?: string;
  /**
   * Text under the fields when `revokeOtherSessions` is `true`. Default:
   * `"Your other sessions will be signed out."`. Pass `""` to show none.
   */
  revokeOtherSessionsNotice?: string;
  /**
   * Status message after a successful submit. Default: `"Password updated."`,
   * or `"Password set."` when `hasPassword` is `false`.
   */
  success?: string;
}

/** Props for {@link ChangePasswordForm}. */
export interface ChangePasswordFormProps extends BaseAuthFormProps<ChangePasswordValues> {
  /**
   * Whether the account has a password now. Default: `true`, which asks for
   * the current password. Pass `false` for an account that signs in another
   * way — a social account, a passkey or an emailed code — to set a first
   * password: the current-password field is dropped and the button reads
   * "Set password". Confirm it is the account owner on your server before
   * setting one, since no current password proves it.
   */
  hasPassword?: boolean;
  /**
   * What happens to the account's other sessions. Default: `true` — the
   * change signs them out, the form says so, and `onSubmit` receives
   * `revokeOtherSessions: true`. `"optional"` renders a checkbox, checked to
   * start, so the person decides. `false` keeps them and says nothing. Your
   * server performs the sign-out; this only states and forwards the intent.
   */
  revokeOtherSessions?: boolean | "optional";
  /**
   * Shortest new password to accept. Sets the field's `minlength` and blocks
   * a shorter one on the client. Enforce your password policy on the server
   * too; this only saves a round trip.
   */
  minLength?: number;
  /** Text overrides. */
  labels?: ChangePasswordLabels;
  /**
   * Render-prop escape hatch. When provided, you own the markup and receive
   * the live {@link AuthFormState}; the component still owns state, the
   * client-side checks and submit.
   */
  children?: (state: AuthFormState<ChangePasswordValues>) => ReactNode;
}

const CLEARED_PASSWORDS = {
  currentPassword: "",
  newPassword: "",
  confirmPassword: "",
} as const;

/**
 * A ready-to-use change-password form, which also sets a first password on an
 * account without one (`hasPassword={false}`). Wire `onSubmit` to your server
 * and return `{ fieldErrors: { currentPassword: "…" } }` for a wrong current
 * password, or `{ fieldErrors: { newPassword: "…" } }` for one your policy
 * refuses; focus moves to the first errored field.
 *
 * After a successful submit the password fields are cleared and a status
 * message appears above the form, which stays in place.
 *
 * @example Change a password, signing out other sessions
 * ```tsx
 * import { ChangePasswordForm } from "@udibo/oauth2/react/components";
 *
 * function ChangePassword() {
 *   return (
 *     <ChangePasswordForm
 *       minLength={12}
 *       onSubmit={async (values) => {
 *         const response = await fetch("/account/password", {
 *           method: "POST",
 *           headers: { "content-type": "application/json" },
 *           body: JSON.stringify(values),
 *         });
 *         if (!response.ok) return await response.json();
 *       }}
 *     />
 *   );
 * }
 * ```
 *
 * @example Set a first password on a social or passkey account
 * ```tsx
 * import { ChangePasswordForm } from "@udibo/oauth2/react/components";
 *
 * function SetPassword(props: { hasPassword: boolean }) {
 *   return (
 *     <ChangePasswordForm
 *       hasPassword={props.hasPassword}
 *       revokeOtherSessions="optional"
 *       onSubmit={async (values) => {
 *         const response = await fetch("/account/password", {
 *           method: "PUT",
 *           headers: { "content-type": "application/json" },
 *           body: JSON.stringify(values),
 *         });
 *         if (!response.ok) return await response.json();
 *       }}
 *     />
 *   );
 * }
 * ```
 */
export function ChangePasswordForm(props: ChangePasswordFormProps): ReactNode {
  const {
    onSubmit,
    hasPassword = true,
    revokeOtherSessions = true,
    minLength,
    className,
    labels,
    children,
  } = props;

  const form = useAuthForm<ChangePasswordValues>({
    initialValues: {
      ...CLEARED_PASSWORDS,
      revokeOtherSessions: revokeOtherSessions !== false,
    },
    onSubmit: (values) =>
      onSubmit({
        ...values,
        currentPassword: hasPassword ? values.currentPassword : "",
        revokeOtherSessions:
          revokeOtherSessions === "optional"
            ? values.revokeOtherSessions
            : revokeOtherSessions,
      }),
    onSuccess: props.onSuccess,
    validate: (values) => {
      const errors: AuthFormErrors<ChangePasswordValues> = {};
      if (minLength !== undefined && values.newPassword.length < minLength) {
        errors.newPassword =
          labels?.tooShort ?? `Use at least ${minLength} characters.`;
      }
      if (values.newPassword !== values.confirmPassword) {
        errors.confirmPassword =
          labels?.passwordMismatch ?? "Passwords do not match.";
      }
      return errors;
    },
  });

  const { setValues, succeeded, submitCount } = form;
  useEffect(() => {
    if (succeeded) setValues(CLEARED_PASSWORDS);
  }, [succeeded, submitCount, setValues]);
  useFocusFirstError(form);
  const classNames = useAuthFormClassNames(props.classNames);

  const revokeField = form.getFieldProps("revokeOtherSessions");
  const notice =
    labels?.revokeOtherSessionsNotice ??
    "Your other sessions will be signed out.";

  return (
    <AuthFormShell
      name={hasPassword ? "change-password" : "set-password"}
      form={form}
      className={className}
      classNames={classNames}
      render={children}
      action={props.action}
      method={props.method}
      formRef={props.formRef}
      aboveForm={
        form.succeeded ? (
          <div
            data-oauth2-success=""
            role="status"
            className={classNames.success}
          >
            {labels?.success ??
              (hasPassword ? "Password updated." : "Password set.")}
          </div>
        ) : null
      }
    >
      {hasPassword ? (
        <TextField
          fieldProps={form.getFieldProps("currentPassword")}
          label={labels?.currentPassword ?? "Current password"}
          type="password"
          autoComplete="current-password"
          required
          error={form.errors.currentPassword}
        />
      ) : null}
      <TextField
        fieldProps={form.getFieldProps("newPassword")}
        label={labels?.newPassword ?? "New password"}
        type="password"
        autoComplete="new-password"
        minLength={minLength}
        required
        error={form.errors.newPassword}
      />
      <TextField
        fieldProps={form.getFieldProps("confirmPassword")}
        label={labels?.confirmPassword ?? "Confirm new password"}
        type="password"
        autoComplete="new-password"
        required
        error={form.errors.confirmPassword}
      />
      {revokeOtherSessions === "optional" ? (
        <div
          data-oauth2-field="revokeOtherSessions"
          className={classNames.field}
        >
          <label
            htmlFor={revokeField.id}
            data-oauth2-label=""
            className={classNames.label}
          >
            <input
              {...revokeField}
              type="checkbox"
              data-oauth2-input=""
              className={classNames.input}
            />
            {labels?.revokeOtherSessions ?? "Sign out of my other sessions"}
          </label>
        </div>
      ) : null}
      {revokeOtherSessions === true && notice ? (
        <p data-oauth2-revoke-notice="" className={classNames.hint}>
          {notice}
        </p>
      ) : null}
      <SubmitButton
        isSubmitting={form.isSubmitting}
        label={
          labels?.submit ?? (hasPassword ? "Update password" : "Set password")
        }
        submittingLabel={
          labels?.submitting ?? (hasPassword ? "Updating…" : "Setting…")
        }
      />
    </AuthFormShell>
  );
}
