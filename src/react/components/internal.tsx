import { type ReactNode, type Ref, useEffect, useRef } from "react";

import type { AuthFieldProps, AuthFormState } from "./use-auth-form.ts";
import type {
  AuthFormClassNames,
  AuthFormValues,
  SocialProvider,
  SocialProvidersProps,
} from "./types.ts";
import {
  AuthFormClassNamesScope,
  useAuthFormClassNames,
} from "./class-names.tsx";

/**
 * The single exit every default form component returns through — it owns both
 * outcomes, so a form has one `return` and cannot leave a subtree unscoped.
 *
 * With no `render`, it lays out the markup the forms share: the root wrapper
 * carrying `data-oauth2-form={name}`, then the `<form>` with its error summary
 * and the caller's fields. Use `aboveForm` for content that belongs inside the
 * root but outside the form (social buttons, an enrollment secret), and
 * `succeeded` for a terminal state that replaces the form entirely. With a
 * `render` — the form's render-prop `children` — that markup is skipped for the
 * caller's own. Either way the already-resolved `classNames` is published to
 * what renders, so the elements inside take their classes from the tree.
 */
export function AuthFormShell<V extends AuthFormValues>(props: {
  name: string;
  form: AuthFormState<V>;
  className: string | undefined;
  classNames: Readonly<AuthFormClassNames>;
  render: ((state: AuthFormState<V>) => ReactNode) | undefined;
  rootProps?: Record<`data-${string}`, string>;
  aboveForm?: ReactNode;
  succeeded?: ReactNode;
  children?: ReactNode;
  action?: string;
  method?: "get" | "post";
  formRef?: Ref<HTMLFormElement>;
}): ReactNode {
  const {
    name,
    form,
    className,
    classNames,
    render,
    rootProps,
    aboveForm,
    succeeded,
    children,
    action,
    method,
    formRef,
  } = props;
  return (
    <AuthFormClassNamesScope classNames={classNames}>
      {render ? render(form) : (
        <div
          data-oauth2-form={name}
          {...rootProps}
          className={combineClassNames(className, classNames.root)}
        >
          {aboveForm}
          {succeeded ?? (
            <form
              onSubmit={form.handleSubmit}
              action={action}
              method={method ?? (action ? "post" : undefined)}
              ref={formRef}
              noValidate
              data-oauth2-form-element=""
              className={classNames.form}
            >
              <ErrorSummary
                error={form.formError}
                focusTrigger={form.submitCount}
              />
              {children}
            </form>
          )}
        </div>
      )}
    </AuthFormClassNamesScope>
  );
}

/** The actions row and its submit button, disabled while the form is in flight. */
export function SubmitButton(props: {
  isSubmitting: boolean;
  label: string;
  submittingLabel: string;
}): ReactNode {
  const { isSubmitting, label, submittingLabel } = props;
  const classNames = useAuthFormClassNames();
  return (
    <div data-oauth2-actions="" className={classNames.actions}>
      <button
        type="submit"
        disabled={isSubmitting}
        data-oauth2-submit=""
        className={classNames.submit}
      >
        {isSubmitting ? submittingLabel : label}
      </button>
    </div>
  );
}

export function TextField(props: {
  fieldProps: AuthFieldProps;
  label: string;
  type?: string;
  autoComplete?: string;
  required?: boolean;
  error?: string;
  inputRef?: Ref<HTMLInputElement>;
  children?: ReactNode;
}): ReactNode {
  const {
    fieldProps,
    label,
    type = "text",
    autoComplete,
    required,
    error,
    inputRef,
    children,
  } = props;
  const classNames = useAuthFormClassNames();
  return (
    <div data-oauth2-field={fieldProps.name} className={classNames.field}>
      <label
        htmlFor={fieldProps.id}
        data-oauth2-label=""
        className={classNames.label}
      >
        {label}
      </label>
      <input
        {...fieldProps}
        type={type}
        autoComplete={autoComplete}
        required={required}
        data-oauth2-input=""
        className={classNames.input}
        ref={inputRef}
      />
      {children}
      {error
        ? (
          <p
            id={`${fieldProps.id}-error`}
            role="alert"
            data-oauth2-error=""
            className={classNames.error}
          >
            {error}
          </p>
        )
        : null}
    </div>
  );
}

export function ErrorSummary(props: {
  error: string | null;
  focusTrigger?: number;
}): ReactNode {
  const { error, focusTrigger } = props;
  const classNames = useAuthFormClassNames();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (error) ref.current?.focus();
  }, [error, focusTrigger]);
  if (!error) return null;
  return (
    <div
      ref={ref}
      tabIndex={-1}
      data-oauth2-error-summary=""
      className={classNames.errorSummary}
    >
      <span role="alert" data-oauth2-error-summary-message="">{error}</span>
    </div>
  );
}

/**
 * Moves keyboard focus to the first field that came back with an error after a
 * failed submit, so a screen-reader / keyboard user lands on the control to fix
 * (its label + error are read via `aria-describedby`) instead of being stranded
 * on the disabled submit button. No-ops on the initial render and when the form
 * carries a form-level error ({@link ErrorSummary} owns that focus). Call it
 * once, unconditionally, from a form component built on {@link useAuthForm}.
 */
export function useFocusFirstError<V extends AuthFormValues>(
  form: AuthFormState<V>,
): void {
  const handled = useRef(0);
  useEffect(() => {
    if (form.status !== "error") return;
    if (handled.current === form.submitCount) return;
    handled.current = form.submitCount;
    if (form.formError) return;
    const names = Object.keys(form.values) as (keyof V & string)[];
    const firstErrored = names.find((name) => Boolean(form.errors[name]));
    if (!firstErrored) return;
    const { id } = form.getFieldProps(firstErrored);
    if (typeof document === "undefined") return;
    document.getElementById(id)?.focus();
  }, [form.status, form.submitCount, form.formError]);
}

export function SocialButtons(props: SocialProvidersProps): ReactNode {
  const { socialProviders, onSocialSelect, socialHref } = props;
  const classNames = useAuthFormClassNames();
  if (!socialProviders || socialProviders.length === 0) return null;
  const label = (provider: SocialProvider): ReactNode => (
    <>
      {provider.iconSlot
        ? <span data-oauth2-social-icon="">{provider.iconSlot}</span>
        : null}
      <span data-oauth2-social-label="">Continue with {provider.name}</span>
    </>
  );
  return (
    <>
      <div data-oauth2-social="" className={classNames.socialSection}>
        {socialProviders.map((provider) =>
          socialHref
            ? (
              <a
                key={provider.id}
                href={socialHref(provider)}
                data-oauth2-social-button={provider.id}
                className={classNames.socialButton}
              >
                {label(provider)}
              </a>
            )
            : (
              <button
                key={provider.id}
                type="button"
                onClick={() => onSocialSelect?.(provider)}
                data-oauth2-social-button={provider.id}
                className={classNames.socialButton}
              >
                {label(provider)}
              </button>
            )
        )}
      </div>
      <div
        data-oauth2-social-divider=""
        aria-hidden="true"
        className={classNames.socialDivider}
      />
    </>
  );
}

export function combineClassNames(
  className: string | undefined,
  slot: string | undefined,
): string | undefined {
  return [className, slot].filter(Boolean).join(" ") || undefined;
}

export function displayName(user: Record<string, unknown>): string {
  const candidates = [
    user.name,
    user.preferred_username,
    user.nickname,
    user.email,
    user.sub,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.length > 0) return candidate;
  }
  return "Account";
}
