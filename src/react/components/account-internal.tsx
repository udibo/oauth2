import {
  type FormEvent,
  type MouseEvent,
  type ReactNode,
  type RefObject,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import type { AccountActionResult } from "./types.ts";

export interface AccountActionRunner {
  pendingKey: string | null;
  error: string | null;
  successCount: number;
  run(
    key: string,
    action: () =>
      | Promise<AccountActionResult | void>
      | AccountActionResult
      | void,
  ): Promise<void>;
}

/**
 * One in-flight action at a time across a list's buttons: a second activation
 * while one is pending is ignored, and a returned `error` or a throw becomes
 * the list's error message.
 */
export function useAccountAction(): AccountActionRunner {
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successCount, setSuccessCount] = useState(0);
  const runningRef = useRef(false);

  const run = useCallback<AccountActionRunner["run"]>(async (key, action) => {
    if (runningRef.current) return;
    runningRef.current = true;
    setPendingKey(key);
    setError(null);
    let message: string | null = null;
    try {
      const result = await action();
      if (result?.error) message = result.error;
    } catch (thrown) {
      message =
        thrown instanceof Error ? thrown.message : "Something went wrong.";
    } finally {
      runningRef.current = false;
      setPendingKey(null);
    }
    if (message) setError(message);
    else setSuccessCount((count) => count + 1);
  }, []);

  return { pendingKey, error, successCount, run };
}

/**
 * Moves focus to the list root when the control focused at a successful
 * action leaves the page with the next data change (a removed row's button
 * drops focus to `<body>`). A data change that keeps that control, or any
 * change without a success before it, leaves focus alone.
 */
export function useFocusAfterRemoval(
  runner: AccountActionRunner,
  items: unknown,
): RefObject<HTMLDivElement | null> {
  const rootRef = useRef<HTMLDivElement>(null);
  const handled = useRef(0);
  const heldControl = useRef<Element | null>(null);
  const itemsAtSuccess = useRef<unknown>(null);
  useEffect(() => {
    if (typeof document === "undefined") return;
    const active = document.activeElement;
    const onBody = active === null || active === document.body;
    if (runner.successCount !== handled.current) {
      handled.current = runner.successCount;
      itemsAtSuccess.current = items;
      heldControl.current = onBody ? null : active;
      if (onBody) rootRef.current?.focus();
      return;
    }
    const control = heldControl.current;
    if (!control || items === itemsAtSuccess.current) return;
    heldControl.current = null;
    if (!control.isConnected && onBody) rootRef.current?.focus();
  }, [runner.successCount, items]);
  return rootRef;
}

export function AccountActionError(props: {
  error: string | null;
  className: string | undefined;
}): ReactNode {
  const { error, className } = props;
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (error) ref.current?.focus();
  }, [error]);
  if (!error) return null;
  return (
    <div
      ref={ref}
      tabIndex={-1}
      data-oauth2-error-summary=""
      className={className}
    >
      <span role="alert" data-oauth2-error-summary-message="">
        {error}
      </span>
    </div>
  );
}

function ignoreActivation(event: MouseEvent<HTMLButtonElement>): void {
  event.preventDefault();
}

/**
 * A one-button `<form>`: its hidden `fields` post natively to `action` before
 * JavaScript runs, and `onActivate` handles the submit once it does. Always
 * `post`, so a pre-hydration submit never puts the fields in a URL.
 */
export function ActionForm(props: {
  fields: Record<string, string>;
  action: string | undefined;
  onActivate: () => void;
  pending: boolean;
  label: string;
  pendingLabel: string;
  accessibleName?: string;
  dataAttribute: `data-oauth2-${string}`;
  dataValue?: string;
  className: string | undefined;
}): ReactNode {
  const {
    fields,
    action,
    onActivate,
    pending,
    label,
    pendingLabel,
    accessibleName,
    dataAttribute,
    dataValue = "",
    className,
  } = props;
  const onSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    onActivate();
  };
  const text = pending ? pendingLabel : label;
  return (
    <form
      onSubmit={onSubmit}
      action={action}
      method="post"
      data-oauth2-action-form=""
    >
      {Object.entries(fields).map(([name, value]) => (
        <input key={name} type="hidden" name={name} value={value} />
      ))}
      <button
        type="submit"
        aria-disabled={pending ? true : undefined}
        aria-label={accessibleName ? `${text} ${accessibleName}` : undefined}
        onClick={pending ? ignoreActivation : undefined}
        {...{ [dataAttribute]: dataValue }}
        className={className}
      >
        {text}
      </button>
    </form>
  );
}

export function formatAccountDate(date: Date): string {
  return date.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
