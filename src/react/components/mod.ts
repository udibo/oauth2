/**
 * Prebuilt React auth components for `@udibo/oauth2` — the composable,
 * headless-first, themeable form set an app assembles into its own auth
 * surface. Works in both plain React Router v7 and Juniper (SSR React).
 *
 * These components are **composed by your app**: you own the routes, storage,
 * session, and the submit wiring. Nothing here mounts routes, talks to a
 * server on its own, or assumes a design system — every component ships
 * unstyled with per-slot `className` hooks and stable `data-oauth2-*`
 * attributes, and takes its action via an injected `onSubmit` prop so the same
 * component drives a client-side `fetch` or a router action.
 *
 * ## Two integration modes
 *
 * - **Default components** — {@link SignInForm}, {@link SignUpForm},
 *   {@link RequestPasswordResetForm}, {@link ResetPasswordForm},
 *   {@link MfaEnrollmentForm}, {@link MfaChallengeForm}, {@link UserMenu} —
 *   render accessible markup with class hooks.
 * - **Headless** — {@link useAuthForm} owns values, errors, and the submit
 *   lifecycle with no markup. Every default component is built on it; "eject"
 *   by using the hook directly, or by passing a function as a component's
 *   `children` (render prop) to keep the component's wiring but own the markup.
 *
 * Social buttons appear automatically on the sign-in / sign-up components when
 * you pass a `socialProviders` array.
 *
 * ## Server-rendered pages
 *
 * Pass `action` + `method` and the rendered `<form>` carries them, so a
 * server-rendered page still posts when JavaScript never arrives — every field
 * carries its `name`, so the native post sends the same keys `onSubmit`
 * receives. Once React is running, `onSubmit` handles the submit and the
 * native post is suppressed. `formRef` hands you the same `<form>` element, for
 * example to trigger a native `submit()` yourself.
 *
 * ## Theming
 *
 * Every form takes a per-slot {@link AuthFormClassNames} map and publishes it
 * to the elements it renders. Wrap a subtree in
 * {@link AuthFormClassNamesProvider} to theme every form under it at once — a
 * form's own `classNames` overrides the inherited map slot by slot — and read
 * the map in effect from your own markup with {@link useAuthFormClassNames}.
 *
 * The claims type {@link UserMenu} hands to `renderUser` / `children` is
 * `UserInfoClaims`; import it from `@udibo/oauth2/client`, which owns it.
 *
 * ## Accessibility
 *
 * These components target **WCAG 2.2 level AA** and are accessible by default,
 * so dropping them in does not quietly ship a barrier:
 *
 * - Every field is programmatically labelled (`<label htmlFor>` ↔ input `id`);
 *   errors set `aria-invalid` + `aria-describedby` and render `role="alert"`.
 * - A failed submit moves focus to the first errored field (or the form-level
 *   error summary), so a keyboard / screen-reader user lands on what to fix.
 * - One-time-code fields use `autocomplete="one-time-code"` and **never block
 *   paste** (WCAG 2.2 §3.3.8 Accessible Authentication).
 * - Section titles carry heading semantics; the components ship unstyled, so
 *   **contrast and visible focus are yours to satisfy** with your own theme —
 *   the ratios and focus rules Udibo uses are in its `DESIGN.md`.
 *
 * @example Plain React Router v7
 * ```tsx
 * import { SignInForm } from "@udibo/oauth2/react/components";
 *
 * function SignIn() {
 *   return (
 *     <SignInForm
 *       onSubmit={async (values) => {
 *         const res = await fetch("/auth/sign-in", {
 *           method: "POST",
 *           headers: { "content-type": "application/json" },
 *           body: JSON.stringify(values),
 *         });
 *         if (!res.ok) return await res.json();
 *       }}
 *     />
 *   );
 * }
 * ```
 *
 * @module
 */

export { useAuthForm } from "./use-auth-form.ts";
export type {
  AuthFieldProps,
  AuthFormState,
  AuthFormStatus,
  UseAuthFormOptions,
} from "./use-auth-form.ts";

export type {
  AuthFormClassNames,
  AuthFormErrors,
  AuthFormResult,
  AuthFormValues,
  AuthSubmitHandler,
  BaseAuthFormProps,
  BaseClassNames,
  SocialProvider,
  SocialProvidersProps,
} from "./types.ts";

export {
  AuthFormClassNamesProvider,
  useAuthFormClassNames,
} from "./class-names.tsx";
export type { AuthFormClassNamesProviderProps } from "./class-names.tsx";

export { SignInForm } from "./sign-in-form.tsx";
export type {
  SignInFormProps,
  SignInLabels,
  SignInValues,
} from "./sign-in-form.tsx";

export { SignUpForm } from "./sign-up-form.tsx";
export type {
  SignUpFormProps,
  SignUpLabels,
  SignUpValues,
} from "./sign-up-form.tsx";

export { RequestPasswordResetForm } from "./request-password-reset-form.tsx";
export type {
  RequestPasswordResetFormProps,
  RequestPasswordResetLabels,
  RequestPasswordResetValues,
} from "./request-password-reset-form.tsx";

export { ResetPasswordForm } from "./reset-password-form.tsx";
export type {
  ResetPasswordFormProps,
  ResetPasswordLabels,
  ResetPasswordValues,
} from "./reset-password-form.tsx";

export { MfaEnrollmentForm } from "./mfa-enrollment-form.tsx";
export type {
  MfaEnrollmentData,
  MfaEnrollmentFormProps,
  MfaEnrollmentLabels,
  MfaEnrollmentValues,
} from "./mfa-enrollment-form.tsx";

export { MfaChallengeForm } from "./mfa-challenge-form.tsx";
export type {
  MfaChallengeFormProps,
  MfaChallengeLabels,
  MfaChallengeMethod,
  MfaChallengeValues,
} from "./mfa-challenge-form.tsx";

export { UserMenu } from "./user-menu.tsx";
export type {
  UserMenuClassNames,
  UserMenuLabels,
  UserMenuProps,
} from "./user-menu.tsx";
