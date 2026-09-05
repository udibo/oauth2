/**
 * Shared types for the prebuilt auth components
 * (`@udibo/oauth2/react/components`).
 *
 * These types describe the wiring contract every component shares: how a
 * submit handler reports success and errors ({@link AuthFormResult}), the
 * per-slot class hooks used for theming ({@link BaseClassNames} and
 * {@link AuthFormClassNames}), and the social-provider descriptor
 * ({@link SocialProvider}). The headless hook state ({@link AuthFormState}) is
 * defined alongside the hook in `use-auth-form.ts`.
 *
 * @module
 */

import type { ReactNode, Ref } from "react";

/**
 * A record of field values a form collects. Keys are field names; values are
 * strings for text inputs and booleans for checkboxes.
 */
export type AuthFormValues = Record<string, string | boolean>;

/**
 * Per-field error messages keyed by field name. Only fields with an error
 * appear; a missing key means the field is valid.
 */
export type AuthFormErrors<V extends AuthFormValues> = Partial<
  Record<keyof V & string, string>
>;

/**
 * The result an {@link AuthSubmitHandler} may return to drive the form's UI.
 *
 * Return nothing (or an empty object) to signal success. Populate `error`
 * and/or `fieldErrors` to surface validation problems inline without throwing.
 * A thrown error is also treated as a form-level failure, using its message.
 */
export interface AuthFormResult {
  /** A form-level error message shown in the error summary region. */
  error?: string;
  /** Per-field error messages keyed by field name. */
  fieldErrors?: Record<string, string>;
}

/**
 * The app-provided function that performs a form's action — a client-side
 * `fetch` in a plain React Router app, or a call that submits a router action
 * in Juniper. Receives the collected values; resolve/return an
 * {@link AuthFormResult} (or throw) to report the outcome.
 */
export type AuthSubmitHandler<V extends AuthFormValues> = (
  values: V,
) => Promise<AuthFormResult | void> | AuthFormResult | void;

/**
 * A social / federated identity provider to render a "Continue with …" button
 * for. Supply an array of these to a sign-in or sign-up component and the
 * buttons appear automatically; omit or pass an empty array for no social
 * section.
 */
export interface SocialProvider {
  /** Stable identifier passed back to your handler / href builder. */
  id: string;
  /** Human-readable name rendered in the button ("Continue with {name}"). */
  name: string;
  /** Optional icon node rendered before the label. */
  iconSlot?: ReactNode;
}

/**
 * Props mixed into the sign-in / sign-up components for the social section.
 * Provide `socialHref` to render anchors (full-page redirects), or
 * `onSocialSelect` to render buttons that call back. `socialHref` wins when
 * both are given.
 */
export interface SocialProvidersProps {
  /** Providers to render buttons for. Empty/absent → no social section. */
  socialProviders?: SocialProvider[];
  /** Called with the chosen provider when a social button is clicked. */
  onSocialSelect?: (provider: SocialProvider) => void;
  /** Builds the href for a provider; renders anchors instead of buttons. */
  socialHref?: (provider: SocialProvider) => string;
}

/**
 * The class hook every prebuilt component shares. Component-specific class-name
 * maps ({@link AuthFormClassNames}, `UserMenuClassNames`) extend this, so `root`
 * means the same thing everywhere.
 */
export interface BaseClassNames {
  /**
   * The component's outermost element — the one carrying its
   * `data-oauth2-form` / `data-oauth2-user-menu` marker. Merged with the
   * component's top-level `className` prop.
   */
  root?: string;
}

/**
 * Per-slot class hooks for theming the default form components — the complete
 * slot set they share, so one map themes any of them and a form simply ignores
 * the slots its markup has no element for. Every slot is optional; unset slots
 * render with no class. Each rendered element also carries a stable
 * `data-oauth2-*` attribute for CSS-only theming.
 *
 * Pass it as a component's `classNames` prop, or to
 * `AuthFormClassNamesProvider` to theme every form in a subtree at once.
 */
export interface AuthFormClassNames extends BaseClassNames {
  /** The `<form>` element (`data-oauth2-form-element`). */
  form?: string;
  /** The form-level error summary region (`data-oauth2-error-summary`). */
  errorSummary?: string;
  /** Each field wrapper (`data-oauth2-field`). */
  field?: string;
  /** Each `<label>` (`data-oauth2-label`). */
  label?: string;
  /** Each `<input>` (`data-oauth2-input`). */
  input?: string;
  /** Each inline field error (`data-oauth2-error`). */
  error?: string;
  /**
   * Inline content rendered under a field — today the sign-in form's "Forgot
   * password?" link (`data-oauth2-forgot-password`).
   */
  hint?: string;
  /** The actions row wrapping the submit button (`data-oauth2-actions`). */
  actions?: string;
  /** The submit `<button>` (`data-oauth2-submit`). */
  submit?: string;
  /**
   * A secondary action below the submit button (`data-oauth2-secondary`) — the
   * MFA challenge's recovery-code toggle is the one form that renders it, and it
   * also carries `data-oauth2-toggle-recovery`.
   */
  secondary?: string;
  /** The social section wrapper (`data-oauth2-social`). */
  socialSection?: string;
  /**
   * The divider between the social section and the form
   * (`data-oauth2-social-divider`). Rendered only when social providers are
   * present.
   */
  socialDivider?: string;
  /** Each social button/anchor (`data-oauth2-social-button`). */
  socialButton?: string;
  /**
   * The terminal success panel that replaces the form (`data-oauth2-success`) —
   * rendered by the forms that have a success state, such as
   * `RequestPasswordResetForm`.
   */
  success?: string;
  /** The secret display block (`data-oauth2-secret`), an `MfaEnrollmentForm` slot. */
  secret?: string;
  /** The QR slot wrapper (`data-oauth2-qr`), an `MfaEnrollmentForm` slot. */
  qr?: string;
  /**
   * The recovery-codes list (`data-oauth2-recovery-codes`), an
   * `MfaEnrollmentForm` slot.
   */
  recoveryCodes?: string;
  /**
   * Each recovery code item (`data-oauth2-recovery-code`), an
   * `MfaEnrollmentForm` slot.
   */
  recoveryCode?: string;
}

/**
 * Base props shared by the default form components: the injected submit
 * handler, theming hooks, and an optional render-prop escape hatch.
 *
 * Passing a function as `children` "ejects" to headless mode: you receive the
 * live {@link AuthFormState} and render your own markup, while the component
 * keeps owning state and the submit lifecycle. For full control over state as
 * well, call {@link useAuthForm} directly instead.
 */
export interface BaseAuthFormProps<V extends AuthFormValues> {
  /** The action that performs the submit. See {@link AuthSubmitHandler}. */
  onSubmit: AuthSubmitHandler<V>;
  /**
   * Called after a successful submit, with the values that were submitted —
   * the seam for navigating, redirecting, or revealing your own "done" panel
   * without ejecting to {@link useAuthForm}. A promise it returns is awaited,
   * but a throw or rejection is caught and logged rather than surfaced: the
   * form still reports success.
   */
  onSuccess?: (values: V) => void;
  /** Class for the root wrapper (merged with `classNames.root`). */
  className?: string;
  /**
   * Per-slot class hooks for theming. Overrides an inherited
   * `AuthFormClassNamesProvider` map slot by slot. See
   * {@link AuthFormClassNames}.
   */
  classNames?: AuthFormClassNames;
  /**
   * `action` for the rendered `<form>`. Set it (with {@link method}) on a
   * server-rendered page so the form still posts when JavaScript never
   * arrives; every field carries its `name`, so a native post sends the same
   * keys `onSubmit` receives. Once React is running, `onSubmit` handles the
   * submit and the native post is suppressed.
   *
   * Ignored in render-prop mode — you own the `<form>` there.
   */
  action?: string;
  /**
   * `method` for the rendered `<form>`. Defaults to `"post"` whenever
   * {@link action} is set, because the fields these forms render — passwords,
   * one-time codes, reset tokens — must never reach a URL, where a `get` form
   * would put them: browser history, the `Referer` sent to every third-party
   * asset on the destination page, and the server's access log.
   */
  method?: "get" | "post";
  /**
   * Ref to the rendered `<form>` element — for example to call its native
   * `submit()`, which bypasses `onSubmit` and posts to {@link action}.
   *
   * Ignored in render-prop mode.
   */
  formRef?: Ref<HTMLFormElement>;
}
