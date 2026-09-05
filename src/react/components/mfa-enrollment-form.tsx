/**
 * {@link MfaEnrollmentForm} — a default, accessible, unstyled TOTP enrollment
 * panel built on {@link useAuthForm}. Displays the shared secret / `otpauth://`
 * URI (with a slot for your own QR renderer) and recovery codes, then collects
 * a confirmation code to prove the authenticator is set up.
 *
 * The package ships no QR-code or crypto dependency: pass a rendered QR node
 * via `qrSlot`, and provide the secret / URI / recovery codes as data.
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

/** The enrollment secret material to display, produced server-side. */
export interface MfaEnrollmentData {
  /** Base32 shared secret for manual entry into an authenticator app. */
  secret: string;
  /** The full `otpauth://totp/...` provisioning URI (encode as a QR code). */
  otpauthUri: string;
  /** One-time recovery codes to show once and have the user save. */
  recoveryCodes?: string[];
}

/** Values collected by {@link MfaEnrollmentForm}'s confirmation step. */
export type MfaEnrollmentValues = {
  /** The code from the authenticator app confirming enrollment. */
  code: string;
};

/** Visible text overrides for {@link MfaEnrollmentForm}. */
export interface MfaEnrollmentLabels {
  /** Heading above the secret. Default: `"Scan this QR code"`. */
  secretHeading?: string;
  /** Prefix before the manual secret. Default: `"Or enter this code:"`. */
  secretHint?: string;
  /** Heading above recovery codes. Default: `"Save your recovery codes"`. */
  recoveryHeading?: string;
  /** Label for the confirmation code field. Default: `"Authentication code"`. */
  code?: string;
  /** Submit button text. Default: `"Confirm"`. */
  submit?: string;
  /** Submit button text while submitting. Default: `"Confirming…"`. */
  submitting?: string;
}

/** Props for {@link MfaEnrollmentForm}. */
export interface MfaEnrollmentFormProps
  extends BaseAuthFormProps<MfaEnrollmentValues> {
  /** The secret, URI, and recovery codes to display. */
  data: MfaEnrollmentData;
  /**
   * Your rendered QR code for `data.otpauthUri` (the package ships no QR
   * dependency). A node, or a function of the URI.
   */
  qrSlot?: ReactNode | ((otpauthUri: string) => ReactNode);
  /** Text overrides. */
  labels?: MfaEnrollmentLabels;
  /**
   * Render-prop escape hatch. When provided, you own all of the markup —
   * including the secret / QR / recovery-code display — and receive the live
   * {@link AuthFormState}; the component still owns state and submit.
   */
  children?: (state: AuthFormState<MfaEnrollmentValues>) => ReactNode;
}

/**
 * A ready-to-use TOTP enrollment panel: shows the QR/secret and recovery
 * codes, then confirms via a code. Wire `onSubmit` to your verification
 * endpoint and pass a rendered QR via `qrSlot`.
 *
 * @example
 * ```tsx
 * <MfaEnrollmentForm
 *   data={{ secret, otpauthUri, recoveryCodes }}
 *   qrSlot={(uri) => <QRCode value={uri} />}
 *   onSubmit={async ({ code }) => {
 *     const res = await fetch("/auth/mfa/enroll/confirm", {
 *       method: "POST",
 *       headers: { "content-type": "application/json" },
 *       body: JSON.stringify({ code }),
 *     });
 *     if (!res.ok) return { error: "That code was not valid." };
 *   }}
 * />
 * ```
 */
export function MfaEnrollmentForm(props: MfaEnrollmentFormProps): ReactNode {
  const { data, onSubmit, qrSlot, className, labels, children } = props;

  const form = useAuthForm<MfaEnrollmentValues>({
    initialValues: { code: "" },
    onSubmit,
    onSuccess: props.onSuccess,
  });
  useFocusFirstError(form);
  const classNames = useAuthFormClassNames(props.classNames);

  const qr = typeof qrSlot === "function" ? qrSlot(data.otpauthUri) : qrSlot;

  return (
    <AuthFormShell
      name="mfa-enrollment"
      form={form}
      className={className}
      classNames={classNames}
      render={children}
      action={props.action}
      method={props.method}
      formRef={props.formRef}
      aboveForm={
        <>
          <div data-oauth2-secret="" className={classNames.secret}>
            <p role="heading" aria-level={2} data-oauth2-secret-heading="">
              {labels?.secretHeading ?? "Scan this QR code"}
            </p>
            {qr
              ? <div data-oauth2-qr="" className={classNames.qr}>{qr}</div>
              : null}
            <p data-oauth2-secret-hint="">
              {labels?.secretHint ?? "Or enter this code:"}{" "}
              <code data-oauth2-secret-value="">{data.secret}</code>
            </p>
          </div>
          {data.recoveryCodes && data.recoveryCodes.length > 0
            ? (
              <div data-oauth2-recovery="">
                <p
                  role="heading"
                  aria-level={2}
                  data-oauth2-recovery-heading=""
                >
                  {labels?.recoveryHeading ?? "Save your recovery codes"}
                </p>
                <ul
                  data-oauth2-recovery-codes=""
                  className={classNames.recoveryCodes}
                >
                  {data.recoveryCodes.map((recoveryCode) => (
                    <li
                      key={recoveryCode}
                      data-oauth2-recovery-code=""
                      className={classNames.recoveryCode}
                    >
                      <code>{recoveryCode}</code>
                    </li>
                  ))}
                </ul>
              </div>
            )
            : null}
        </>
      }
    >
      <TextField
        fieldProps={form.getFieldProps("code")}
        label={labels?.code ?? "Authentication code"}
        autoComplete="one-time-code"
        required
        error={form.errors.code}
      />
      <SubmitButton
        isSubmitting={form.isSubmitting}
        label={labels?.submit ?? "Confirm"}
        submittingLabel={labels?.submitting ?? "Confirming…"}
      />
    </AuthFormShell>
  );
}
