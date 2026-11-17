import {
  type FormEvent,
  type MouseEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import type { AccountActionResult } from "./types.ts";

export interface AccountActionRunner {
  pendingKey: string | null;
  error: string | null;
  errorCount: number;
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
  const [errorCount, setErrorCount] = useState(0);
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
    if (message) {
      setError(message);
      setErrorCount((count) => count + 1);
    }
  }, []);

  return { pendingKey, error, errorCount, run };
}

export function AccountActionError(props: {
  error: string | null;
  focusTrigger: number;
  className: string | undefined;
}): ReactNode {
  const { error, focusTrigger, className } = props;
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
 * JavaScript runs, and `onActivate` handles the submit once it does.
 */
export function ActionForm(props: {
  fields: Record<string, string>;
  action: string | undefined;
  method: "get" | "post" | undefined;
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
    method,
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
      method={method ?? (action ? "post" : undefined)}
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
