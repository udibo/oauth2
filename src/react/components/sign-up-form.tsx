/**
 * {@link SignUpForm} — a default, accessible, unstyled account-creation form
 * built on {@link useAuthForm}. Collects email and password, optionally a
 * confirm-password, username, and name, validates the password match on the
 * client, and renders social buttons when providers are supplied.
 *
 * @module
 */

import type { ReactNode } from "react";

import { useAuthForm } from "./use-auth-form.ts";
import type { AuthFormState } from "./use-auth-form.ts";
import type {
  AuthFormErrors,
  BaseAuthFormProps,
  SocialProvidersProps,
} from "./types.ts";
import {
  AuthFormShell,
  SocialButtons,
  SubmitButton,
  TextField,
  useFocusFirstError,
} from "./internal.tsx";
import { useAuthFormClassNames } from "./class-names.tsx";

/** Values collected by {@link SignUpForm}. */
export type SignUpValues = {
  /** Email address. */
  email: string;
  /** The chosen password. */
  password: string;
  /** Confirmation of the password (present when `showConfirmPassword`). */
  confirmPassword: string;
  /** Username (present when `showUsername`). */
  username: string;
  /** Given name (present when `showName`). */
  firstName: string;
  /** Family name (present when `showName`). */
  lastName: string;
};

/** Visible text overrides for {@link SignUpForm}. */
export interface SignUpLabels {
  /** Label for the email field. Default: `"Email"`. */
  email?: string;
  /** Label for the username field. Default: `"Username"`. */
  username?: string;
  /** Label for the first-name field. Default: `"First name"`. */
  firstName?: string;
  /** Label for the last-name field. Default: `"Last name"`. */
  lastName?: string;
  /** Label for the password field. Default: `"Password"`. */
  password?: string;
  /** Label for the confirm-password field. Default: `"Confirm password"`. */
  confirmPassword?: string;
  /** Submit button text. Default: `"Create account"`. */
  submit?: string;
  /** Submit button text while submitting. Default: `"Creating account…"`. */
  submitting?: string;
  /** Password-mismatch message. Default: `"Passwords do not match."`. */
  passwordMismatch?: string;
}

/** Props for {@link SignUpForm}. */
export interface SignUpFormProps
  extends BaseAuthFormProps<SignUpValues>, SocialProvidersProps {
  /** Render the username field. Default: `false`. */
  showUsername?: boolean;
  /** Render the first/last name fields. Default: `false`. */
  showName?: boolean;
  /** Render the confirm-password field. Default: `true`. */
  showConfirmPassword?: boolean;
  /** Text overrides. */
  labels?: SignUpLabels;
  /**
   * Render-prop escape hatch. When provided, you own the markup and receive
   * the live {@link AuthFormState}.
   */
  children?: (state: AuthFormState<SignUpValues>) => ReactNode;
}

/**
 * A ready-to-use account-creation form. Wire `onSubmit` to your sign-up
 * endpoint. When the confirm-password field is shown, a client-side check
 * blocks submission on mismatch before `onSubmit` runs.
 *
 * @example
 * ```tsx
 * <SignUpForm
 *   showUsername
 *   showName
 *   onSubmit={async (values) => {
 *     const res = await fetch("/auth/sign-up", {
 *       method: "POST",
 *       headers: { "content-type": "application/json" },
 *       body: JSON.stringify(values),
 *     });
 *     if (!res.ok) return await res.json();
 *   }}
 * />
 * ```
 */
export function SignUpForm(props: SignUpFormProps): ReactNode {
  const {
    onSubmit,
    className,
    socialProviders,
    onSocialSelect,
    socialHref,
    showUsername = false,
    showName = false,
    showConfirmPassword = true,
    labels,
    children,
  } = props;

  const form = useAuthForm<SignUpValues>({
    initialValues: {
      email: "",
      password: "",
      confirmPassword: "",
      username: "",
      firstName: "",
      lastName: "",
    },
    onSubmit,
    onSuccess: props.onSuccess,
    validate: (values) => {
      const errors: AuthFormErrors<SignUpValues> = {};
      if (
        showConfirmPassword && values.password !== values.confirmPassword
      ) {
        errors.confirmPassword = labels?.passwordMismatch ??
          "Passwords do not match.";
      }
      return errors;
    },
  });
  useFocusFirstError(form);
  const classNames = useAuthFormClassNames(props.classNames);

  return (
    <AuthFormShell
      name="sign-up"
      form={form}
      className={className}
      classNames={classNames}
      render={children}
      action={props.action}
      method={props.method}
      formRef={props.formRef}
      aboveForm={
        <SocialButtons
          socialProviders={socialProviders}
          onSocialSelect={onSocialSelect}
          socialHref={socialHref}
        />
      }
    >
      {showUsername
        ? (
          <TextField
            fieldProps={form.getFieldProps("username")}
            label={labels?.username ?? "Username"}
            autoComplete="username"
            required
            error={form.errors.username}
          />
        )
        : null}
      <TextField
        fieldProps={form.getFieldProps("email")}
        label={labels?.email ?? "Email"}
        type="email"
        autoComplete="email"
        required
        error={form.errors.email}
      />
      {showName
        ? (
          <>
            <TextField
              fieldProps={form.getFieldProps("firstName")}
              label={labels?.firstName ?? "First name"}
              autoComplete="given-name"
              required
              error={form.errors.firstName}
            />
            <TextField
              fieldProps={form.getFieldProps("lastName")}
              label={labels?.lastName ?? "Last name"}
              autoComplete="family-name"
              required
              error={form.errors.lastName}
            />
          </>
        )
        : null}
      <TextField
        fieldProps={form.getFieldProps("password")}
        label={labels?.password ?? "Password"}
        type="password"
        autoComplete="new-password"
        required
        error={form.errors.password}
      />
      {showConfirmPassword
        ? (
          <TextField
            fieldProps={form.getFieldProps("confirmPassword")}
            label={labels?.confirmPassword ?? "Confirm password"}
            type="password"
            autoComplete="new-password"
            required
            error={form.errors.confirmPassword}
          />
        )
        : null}
      <SubmitButton
        isSubmitting={form.isSubmitting}
        label={labels?.submit ?? "Create account"}
        submittingLabel={labels?.submitting ?? "Creating account…"}
      />
    </AuthFormShell>
  );
}
