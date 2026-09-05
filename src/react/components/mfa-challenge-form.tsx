/**
 * {@link MfaChallengeForm} — a default, accessible, unstyled second-factor
 * challenge form built on {@link useAuthForm}. Collects a one-time code and,
 * when allowed, toggles to accepting a recovery code instead. The active
 * method is forwarded to `onSubmit` so your endpoint knows how to verify it.
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

/** Which credential the user is submitting. */
export type MfaChallengeMethod = "totp" | "recovery";

/** Values collected by {@link MfaChallengeForm}. */
export type MfaChallengeValues = {
  /** The one-time code or recovery code the user entered. */
  code: string;
  /** Which credential `code` represents. */
  method: MfaChallengeMethod;
};

/** Visible text overrides for {@link MfaChallengeForm}. */
export interface MfaChallengeLabels {
  /** Label for the TOTP code field. Default: `"Authentication code"`. */
  code?: string;
  /** Label for the recovery-code field. Default: `"Recovery code"`. */
  recoveryCode?: string;
  /** Submit button text. Default: `"Verify"`. */
  submit?: string;
  /** Submit button text while submitting. Default: `"Verifying…"`. */
  submitting?: string;
  /** Toggle text to switch to recovery mode. Default: `"Use a recovery code"`. */
  useRecovery?: string;
  /** Toggle text to switch back to code mode. Default: `"Use your authenticator app"`. */
  useAuthenticator?: string;
}

/** Props for {@link MfaChallengeForm}. */
export interface MfaChallengeFormProps
  extends BaseAuthFormProps<MfaChallengeValues> {
  /** Offer the "use a recovery code" toggle. Default: `true`. */
  allowRecoveryCode?: boolean;
  /** Text overrides. */
  labels?: MfaChallengeLabels;
  /**
   * Render-prop escape hatch. When provided, you own the markup and receive
   * the live {@link AuthFormState}. Toggle `method` with `setValue`.
   */
  children?: (state: AuthFormState<MfaChallengeValues>) => ReactNode;
}

/**
 * A ready-to-use MFA challenge form. Wire `onSubmit` to your verification
 * endpoint; inspect `values.method` to decide how to validate `values.code`.
 *
 * @example
 * ```tsx
 * <MfaChallengeForm
 *   onSubmit={async (values) => {
 *     const res = await fetch("/auth/mfa/verify", {
 *       method: "POST",
 *       headers: { "content-type": "application/json" },
 *       body: JSON.stringify(values),
 *     });
 *     if (!res.ok) return { error: "That code was not valid." };
 *   }}
 * />
 * ```
 */
export function MfaChallengeForm(props: MfaChallengeFormProps): ReactNode {
  const {
    onSubmit,
    className,
    allowRecoveryCode = true,
    labels,
    children,
  } = props;

  const form = useAuthForm<MfaChallengeValues>({
    initialValues: { code: "", method: "totp" },
    onSubmit,
    onSuccess: props.onSuccess,
  });
  useFocusFirstError(form);
  const classNames = useAuthFormClassNames(props.classNames);

  const isRecovery = form.values.method === "recovery";
  const toggleMethod = () => {
    form.setValues({
      method: isRecovery ? "totp" : "recovery",
      code: "",
    });
  };

  return (
    <AuthFormShell
      name="mfa-challenge"
      form={form}
      className={className}
      classNames={classNames}
      render={children}
      action={props.action}
      method={props.method}
      formRef={props.formRef}
      rootProps={{ "data-oauth2-method": form.values.method }}
    >
      <TextField
        fieldProps={form.getFieldProps("code")}
        label={isRecovery
          ? labels?.recoveryCode ?? "Recovery code"
          : labels?.code ?? "Authentication code"}
        autoComplete={isRecovery ? "off" : "one-time-code"}
        required
        error={form.errors.code}
      />
      <SubmitButton
        isSubmitting={form.isSubmitting}
        label={labels?.submit ?? "Verify"}
        submittingLabel={labels?.submitting ?? "Verifying…"}
      />
      {allowRecoveryCode
        ? (
          <button
            type="button"
            onClick={toggleMethod}
            data-oauth2-secondary=""
            data-oauth2-toggle-recovery=""
            className={classNames.secondary}
          >
            {isRecovery
              ? labels?.useAuthenticator ?? "Use your authenticator app"
              : labels?.useRecovery ?? "Use a recovery code"}
          </button>
        )
        : null}
    </AuthFormShell>
  );
}
