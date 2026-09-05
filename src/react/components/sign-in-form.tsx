/**
 * {@link SignInForm} — a default, accessible, unstyled sign-in form built on
 * {@link useAuthForm}. Collects an identifier and password (optionally a
 * "remember me" checkbox), renders "Continue with …" social buttons when
 * providers are supplied, and reports the outcome through the injected
 * `onSubmit`.
 *
 * @module
 */

import type { ReactNode } from "react";

import { useAuthForm } from "./use-auth-form.ts";
import type { AuthFormState } from "./use-auth-form.ts";
import type { BaseAuthFormProps, SocialProvidersProps } from "./types.ts";
import {
  AuthFormShell,
  SocialButtons,
  SubmitButton,
  TextField,
  useFocusFirstError,
} from "./internal.tsx";
import { useAuthFormClassNames } from "./class-names.tsx";

/** Values collected by {@link SignInForm}. */
export type SignInValues = {
  /** Email address or username. */
  identifier: string;
  /** The user's password. */
  password: string;
  /** Whether to keep the session beyond the browser session. */
  remember: boolean;
};

/** Visible text overrides for {@link SignInForm}. */
export interface SignInLabels {
  /** Label for the identifier field. Default: `"Email or username"`. */
  identifier?: string;
  /** Label for the password field. Default: `"Password"`. */
  password?: string;
  /** Label for the remember checkbox. Default: `"Remember me"`. */
  remember?: string;
  /** Submit button text. Default: `"Sign in"`. */
  submit?: string;
  /** Submit button text while submitting. Default: `"Signing in…"`. */
  submitting?: string;
  /** Text of the "forgot password" link. Default: `"Forgot password?"`. */
  forgotPassword?: string;
}

/** Props for {@link SignInForm}. */
export interface SignInFormProps
  extends BaseAuthFormProps<SignInValues>, SocialProvidersProps {
  /** Render the "remember me" checkbox. Default: `false`. */
  showRemember?: boolean;
  /** Href for the "forgot password?" link. Omit to hide the link. */
  forgotPasswordHref?: string;
  /** Text overrides. */
  labels?: SignInLabels;
  /**
   * Render-prop escape hatch. When provided, you own the markup and receive
   * the live {@link AuthFormState}; the component still owns state and submit.
   */
  children?: (state: AuthFormState<SignInValues>) => ReactNode;
}

/**
 * A ready-to-use sign-in form. Wire `onSubmit` to your auth endpoint; pass
 * `socialProviders` to add federated buttons. Drop to {@link useAuthForm} (or
 * pass a function as `children`) for full markup control.
 *
 * @example
 * ```tsx
 * <SignInForm
 *   showRemember
 *   forgotPasswordHref="/forgot-password"
 *   socialProviders={[{ id: "github", name: "GitHub" }]}
 *   socialHref={(p) => `/auth/login?connection=${p.id}`}
 *   onSubmit={async (values) => {
 *     const res = await fetch("/auth/sign-in", {
 *       method: "POST",
 *       headers: { "content-type": "application/json" },
 *       body: JSON.stringify(values),
 *     });
 *     if (!res.ok) return await res.json();
 *   }}
 * />
 * ```
 */
export function SignInForm(props: SignInFormProps): ReactNode {
  const {
    onSubmit,
    className,
    socialProviders,
    onSocialSelect,
    socialHref,
    showRemember = false,
    forgotPasswordHref,
    labels,
    children,
  } = props;

  const form = useAuthForm<SignInValues>({
    initialValues: { identifier: "", password: "", remember: false },
    onSubmit,
    onSuccess: props.onSuccess,
  });
  useFocusFirstError(form);
  const classNames = useAuthFormClassNames(props.classNames);

  const rememberField = form.getFieldProps("remember");

  return (
    <AuthFormShell
      name="sign-in"
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
      <TextField
        fieldProps={form.getFieldProps("identifier")}
        label={labels?.identifier ?? "Email or username"}
        autoComplete="username"
        required
        error={form.errors.identifier}
      />
      <TextField
        fieldProps={form.getFieldProps("password")}
        label={labels?.password ?? "Password"}
        type="password"
        autoComplete="current-password"
        required
        error={form.errors.password}
      >
        {forgotPasswordHref
          ? (
            <a
              href={forgotPasswordHref}
              data-oauth2-forgot-password=""
              className={classNames.hint}
            >
              {labels?.forgotPassword ?? "Forgot password?"}
            </a>
          )
          : null}
      </TextField>
      {showRemember
        ? (
          <div data-oauth2-field="remember" className={classNames.field}>
            <label
              htmlFor={rememberField.id}
              data-oauth2-label=""
              className={classNames.label}
            >
              <input
                {...rememberField}
                type="checkbox"
                data-oauth2-input=""
                className={classNames.input}
              />
              {labels?.remember ?? "Remember me"}
            </label>
          </div>
        )
        : null}
      <SubmitButton
        isSubmitting={form.isSubmitting}
        label={labels?.submit ?? "Sign in"}
        submittingLabel={labels?.submitting ?? "Signing in…"}
      />
    </AuthFormShell>
  );
}
