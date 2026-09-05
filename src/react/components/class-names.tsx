/**
 * The styling seam shared by the prebuilt auth forms
 * (`@udibo/oauth2/react/components`): a React context carrying the per-slot
 * class map ({@link AuthFormClassNames}), so the elements inside a form read
 * their classes from the tree rather than from a `classNames` prop threaded
 * through every wrapper.
 *
 * Wrap a subtree in {@link AuthFormClassNamesProvider} to theme every form
 * under it at once, and read the map in effect from your own components with
 * {@link useAuthFormClassNames}.
 *
 * @module
 */

import { createContext, type ReactNode, useContext, useRef } from "react";

import type { AuthFormClassNames } from "./types.ts";

const EMPTY_CLASS_NAMES: Readonly<AuthFormClassNames> = Object.freeze({});

const AuthFormClassNamesContext = createContext<Readonly<AuthFormClassNames>>(
  EMPTY_CLASS_NAMES,
);

function merge(
  inherited: Readonly<AuthFormClassNames>,
  overrides: AuthFormClassNames,
): Readonly<AuthFormClassNames> {
  const resolved: AuthFormClassNames = { ...inherited };
  for (const [slot, value] of Object.entries(overrides)) {
    if (value !== undefined) {
      resolved[slot as keyof AuthFormClassNames] = value;
    }
  }
  return Object.freeze(resolved);
}

interface ResolvedClassNames {
  inherited: Readonly<AuthFormClassNames>;
  key: string;
  resolved: Readonly<AuthFormClassNames>;
}

function slotKey(classNames: AuthFormClassNames): string {
  const slots = Object.entries(classNames)
    .filter(([, value]) => value !== undefined)
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  return JSON.stringify(slots);
}

/**
 * Resolves the per-slot class map for this position in the tree: the nearest
 * {@link AuthFormClassNamesProvider}'s map with `overrides` applied slot by
 * slot. An absent or `undefined` slot in `overrides` keeps the inherited value,
 * and with no provider above the map is empty (every slot `undefined`), so the
 * hook is safe to call anywhere. This is the only place the precedence rule is
 * implemented.
 *
 * The result is cached on the slot values, so passing a fresh `overrides`
 * literal every render returns the identical map.
 *
 * Call it with no argument from a component rendered **inside** a form to read
 * the theme in effect; call it with a component's own `classNames` prop to
 * resolve the map that component should both render with and publish.
 *
 * @param overrides Per-slot classes that win over the inherited map.
 * @returns The resolved map, keyed by {@link AuthFormClassNames} slot.
 *
 * @example Theme a custom field to match the form around it
 * ```tsx
 * function TenantField(props: { fieldProps: AuthFieldProps }) {
 *   const classNames = useAuthFormClassNames();
 *   return (
 *     <div className={classNames.field}>
 *       <label className={classNames.label} htmlFor={props.fieldProps.id}>
 *         Tenant
 *       </label>
 *       <input {...props.fieldProps} className={classNames.input} />
 *     </div>
 *   );
 * }
 * ```
 */
export function useAuthFormClassNames(
  overrides?: AuthFormClassNames,
): Readonly<AuthFormClassNames> {
  const inherited = useContext(AuthFormClassNamesContext);
  const key = overrides ? slotKey(overrides) : "";
  const held = useRef<ResolvedClassNames | null>(null);
  if (
    held.current === null || held.current.inherited !== inherited ||
    held.current.key !== key
  ) {
    held.current = {
      inherited,
      key,
      resolved: overrides ? merge(inherited, overrides) : inherited,
    };
  }
  return held.current.resolved;
}

/**
 * Publishes an already-resolved map verbatim, without merging. A form and
 * `AuthFormShell` resolve once through {@link useAuthFormClassNames} and
 * publish through this, so the precedence rule keeps exactly one
 * implementation. App code wants {@link AuthFormClassNamesProvider}.
 */
export function AuthFormClassNamesScope(props: {
  classNames: Readonly<AuthFormClassNames>;
  children?: ReactNode;
}): ReactNode {
  const { classNames, children } = props;
  return (
    <AuthFormClassNamesContext.Provider value={classNames}>
      {children}
    </AuthFormClassNamesContext.Provider>
  );
}

/** Props for {@link AuthFormClassNamesProvider}. */
export interface AuthFormClassNamesProviderProps {
  /** Per-slot classes to publish to `children`. See {@link AuthFormClassNames}. */
  classNames: AuthFormClassNames;
  /** The subtree the map applies to. */
  children?: ReactNode;
}

/**
 * Publishes a per-slot class map to every prebuilt auth form in `children`, so
 * an app themes its whole auth surface once instead of repeating the same
 * `classNames` on each form. Providers nest: an inner provider — or a form's
 * own `classNames` prop — overrides the inherited map slot by slot, leaving the
 * slots it does not name intact.
 *
 * It themes the auth **forms**; `UserMenu` is deliberately outside its reach
 * and takes its classes from its own `className` / `classNames` props.
 *
 * An inline `classNames` literal is fine here — the published map is cached on
 * the slot values rather than on the object's identity, so re-rendering with an
 * equal literal hands the forms below the identical map.
 *
 * @example
 * ```tsx
 * <AuthFormClassNamesProvider
 *   classNames={{ input: "input", submit: "btn btn-primary" }}
 * >
 *   <SignInForm onSubmit={signIn} />
 *   <SignUpForm onSubmit={signUp} />
 * </AuthFormClassNamesProvider>
 * ```
 */
export function AuthFormClassNamesProvider(
  props: AuthFormClassNamesProviderProps,
): ReactNode {
  const { classNames, children } = props;
  const resolved = useAuthFormClassNames(classNames);
  return (
    <AuthFormClassNamesScope classNames={resolved}>
      {children}
    </AuthFormClassNamesScope>
  );
}
