/**
 * {@link useAuthForm} — the headless hook backing every default auth form
 * component in `@udibo/oauth2/react/components`.
 *
 * It owns field values, per-field and form-level errors, and the submit
 * lifecycle, and stays entirely presentation-free: no markup, no styling, no
 * router or network assumptions. The action is injected as `onSubmit`, so the
 * same hook drives a client-side `fetch` in a plain React Router app or a
 * router-action submit in Juniper. Reach for it directly when you want to own
 * the markup completely (the "eject to headless" path); otherwise use a
 * default component, which is built on this hook.
 *
 * @module
 */

import {
  type ChangeEvent,
  useCallback,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";

import type {
  AuthFormErrors,
  AuthFormResult,
  AuthFormValues,
  AuthSubmitHandler,
} from "./types.ts";

/** Lifecycle status of an {@link useAuthForm} instance. */
export type AuthFormStatus = "idle" | "submitting" | "success" | "error";

/**
 * Props spread onto a field's `<input>` to wire value, change handling, and
 * accessibility. Produced by {@link AuthFormState.getFieldProps}.
 */
export interface AuthFieldProps {
  /** The input's `id`, also referenced by its label's `htmlFor`. */
  id: string;
  /** The field name (form key). */
  name: string;
  /** Current string value (checkboxes read `checked` instead — see below). */
  value: string;
  /** Whether a checkbox field is checked (omitted for text fields). */
  checked?: boolean;
  /** Change handler that reads `value`/`checked` and updates form state. */
  onChange: (event: ChangeEvent<HTMLInputElement>) => void;
  /** `true` when the field currently has an error, else `undefined`. */
  "aria-invalid"?: true;
  /** The id of this field's error element when errored, else `undefined`. */
  "aria-describedby"?: string;
}

/** Options for {@link useAuthForm}. */
export interface UseAuthFormOptions<V extends AuthFormValues> {
  /** Starting values; also defines the set of fields. */
  initialValues: V;
  /** The injected action that performs the submit. */
  onSubmit: AuthSubmitHandler<V>;
  /**
   * Optional synchronous client-side validation run before `onSubmit`. Return
   * a map of field errors to block submission, or `null`/`undefined` to allow.
   * A throw is trapped like an `onSubmit` throw — surfaced as a form-level
   * error (`status: "error"`) rather than an unhandled rejection.
   */
  validate?: (values: V) => AuthFormErrors<V> | null | undefined;
  /**
   * Called after a successful submit (no `error`/`fieldErrors` returned). A
   * promise it returns is awaited, but a throw or rejection is caught and
   * logged to `console.error` rather than surfaced: `status` stays `"success"`
   * and no form error appears.
   */
  onSuccess?: (values: V) => void;
}

/**
 * The live state and actions returned by {@link useAuthForm}. This is also the
 * value passed to a form component's render-prop `children`.
 */
export interface AuthFormState<V extends AuthFormValues> {
  /** Current field values. */
  values: V;
  /** Current per-field errors. */
  errors: AuthFormErrors<V>;
  /** Current form-level error, or `null`. */
  formError: string | null;
  /** Lifecycle status. */
  status: AuthFormStatus;
  /** `true` while a submit is in flight (`status === "submitting"`). */
  isSubmitting: boolean;
  /** `true` once a submit has completed successfully. */
  succeeded: boolean;
  /** Increments on every submit attempt; useful as a focus-effect trigger. */
  submitCount: number;
  /** Set a single field's value. */
  setValue<K extends keyof V & string>(name: K, value: V[K]): void;
  /** Merge a partial set of field values. */
  setValues(next: Partial<V>): void;
  /** Reset values to `initialValues` and clear all errors/status. */
  reset(): void;
  /** Submit handler for a `<form onSubmit>` (calls `preventDefault`). */
  handleSubmit(event?: { preventDefault(): void }): Promise<void>;
  /** Build the props to spread onto a field's `<input>`. */
  getFieldProps<K extends keyof V & string>(name: K): AuthFieldProps;
}

/**
 * Headless form engine: owns values, errors, and the submit lifecycle for an
 * auth form, delegating the actual action to the injected `onSubmit`.
 *
 * @example Eject to fully custom markup
 * ```tsx
 * const form = useAuthForm({
 *   initialValues: { identifier: "", password: "" },
 *   onSubmit: async (values) => {
 *     const res = await fetch("/auth/sign-in", {
 *       method: "POST",
 *       body: JSON.stringify(values),
 *     });
 *     if (!res.ok) return { error: "Invalid credentials" };
 *   },
 * });
 * return (
 *   <form onSubmit={form.handleSubmit}>
 *     <input {...form.getFieldProps("identifier")} />
 *     <input {...form.getFieldProps("password")} type="password" />
 *     {form.formError ? <p role="alert">{form.formError}</p> : null}
 *     <button type="submit" disabled={form.isSubmitting}>Sign in</button>
 *   </form>
 * );
 * ```
 */
export function useAuthForm<V extends AuthFormValues>(
  options: UseAuthFormOptions<V>,
): AuthFormState<V> {
  const { initialValues, onSubmit, validate, onSuccess } = options;
  const idBase = useId();

  const [values, setValuesState] = useState<V>(initialValues);
  const [errors, setErrors] = useState<AuthFormErrors<V>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [status, setStatus] = useState<AuthFormStatus>("idle");
  const [submitCount, setSubmitCount] = useState(0);
  // Synchronous re-entrancy lock: `status` is a render-closure value, so it
  // can't block a same-tick double submit (Enter racing autofill, etc.).
  const submittingRef = useRef(false);

  const setValue = useCallback(
    <K extends keyof V & string>(name: K, value: V[K]) => {
      setValuesState((prev) => ({ ...prev, [name]: value }));
    },
    [],
  );

  const setValues = useCallback((next: Partial<V>) => {
    setValuesState((prev) => ({ ...prev, ...next }));
  }, []);

  const reset = useCallback(() => {
    setValuesState(initialValues);
    setErrors({});
    setFormError(null);
    setStatus("idle");
  }, [initialValues]);

  const handleSubmit = useCallback(
    async (event?: { preventDefault(): void }) => {
      event?.preventDefault();
      if (submittingRef.current) return;
      submittingRef.current = true;
      try {
        setSubmitCount((count) => count + 1);
        setFormError(null);
        setErrors({});

        if (validate) {
          let validationErrors: AuthFormErrors<V> | null | undefined;
          try {
            validationErrors = validate(values);
          } catch (error) {
            setFormError(
              error instanceof Error ? error.message : "Something went wrong.",
            );
            setStatus("error");
            return;
          }
          if (validationErrors && Object.keys(validationErrors).length > 0) {
            setErrors(validationErrors);
            setStatus("error");
            return;
          }
        }

        setStatus("submitting");
        let result: AuthFormResult | void;
        try {
          result = await onSubmit(values);
        } catch (error) {
          setFormError(
            error instanceof Error ? error.message : "Something went wrong.",
          );
          setStatus("error");
          return;
        }

        const fieldErrors = result?.fieldErrors;
        const hasFieldErrors = fieldErrors &&
          Object.keys(fieldErrors).length > 0;
        if (result?.error || hasFieldErrors) {
          if (result?.error) setFormError(result.error);
          if (hasFieldErrors) setErrors(fieldErrors as AuthFormErrors<V>);
          setStatus("error");
          return;
        }

        setStatus("success");
        // An integrator's onSuccess side effect must not become an unhandled
        // rejection (form onSubmit doesn't await handleSubmit).
        try {
          await onSuccess?.(values);
        } catch (error) {
          console.error("[@udibo/oauth2] auth form onSuccess failed:", error);
        }
      } finally {
        submittingRef.current = false;
      }
    },
    [values, validate, onSubmit, onSuccess],
  );

  const getFieldProps = useCallback(
    <K extends keyof V & string>(name: K): AuthFieldProps => {
      const raw = values[name];
      const hasError = Boolean(errors[name]);
      const id = `${idBase}-${name}`;
      const base: AuthFieldProps = {
        id,
        name,
        value: typeof raw === "boolean" ? "" : String(raw ?? ""),
        onChange: (event: ChangeEvent<HTMLInputElement>) => {
          const target = event.target;
          const next = target.type === "checkbox"
            ? target.checked
            : target.value;
          setValue(name, next as V[K]);
        },
        "aria-invalid": hasError ? true : undefined,
        "aria-describedby": hasError ? `${id}-error` : undefined,
      };
      if (typeof raw === "boolean") base.checked = raw;
      return base;
    },
    [values, errors, idBase, setValue],
  );

  return useMemo<AuthFormState<V>>(() => ({
    values,
    errors,
    formError,
    status,
    isSubmitting: status === "submitting",
    succeeded: status === "success",
    submitCount,
    setValue,
    setValues,
    reset,
    handleSubmit,
    getFieldProps,
  }), [
    values,
    errors,
    formError,
    status,
    submitCount,
    setValue,
    setValues,
    reset,
    handleSubmit,
    getFieldProps,
  ]);
}
