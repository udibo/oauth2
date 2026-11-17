/**
 * {@link SessionList} — a default, accessible, unstyled list of the places an
 * account is signed in, with "Sign out" on each other session and "Sign out
 * everywhere else". The sessions come in as data and each action goes out
 * through a callback; the component never loads or revokes anything itself.
 *
 * @module
 */

import type { ReactNode } from "react";

import type {
  AccountActionHandler,
  AccountActionResult,
  BaseClassNames,
} from "./types.ts";
import {
  AccountActionError,
  ActionForm,
  formatAccountDate,
  useAccountAction,
} from "./account-internal.tsx";
import { combineClassNames } from "./internal.tsx";

/** One signed-in session, as {@link SessionList} renders it. */
export interface SessionListItem {
  /**
   * The session's identifier. It is handed back to `onRevoke` and posted as
   * `sessionId` by a no-JavaScript submit, so it must identify the session to
   * your server; it is never shown.
   */
  id: string;
  /**
   * `true` for the session making this request. It is badged, listed with the
   * others, and never offered a "Sign out" button: signing yourself out is
   * the sign-out action's job.
   */
  current?: boolean;
  /**
   * What the person recognizes the session by, such as `"Firefox on Linux"`.
   * Summarize the user agent on your server; the component shows this text as
   * given, or the `unknownDevice` label when it is absent.
   */
  device?: string;
  /** The IP address the session was last seen from. */
  ipAddress?: string | null;
  /** When the session signed in. */
  createdAt?: Date;
  /** When the session was last used. */
  lastActiveAt?: Date;
}

/**
 * Per-slot class hooks for {@link SessionList}: the shared
 * {@link BaseClassNames} `root` plus the list's own slots. Each element also
 * carries the stable `data-oauth2-*` attribute named here.
 */
export interface SessionListClassNames extends BaseClassNames {
  /** The `<ul>` of sessions (`data-oauth2-session-items`). */
  list?: string;
  /**
   * Each `<li>` (`data-oauth2-session`, whose value is the session id; the
   * current session also carries `data-oauth2-current-session`).
   */
  item?: string;
  /** The device text of each session (`data-oauth2-session-device`). */
  device?: string;
  /** The current-session badge (`data-oauth2-session-badge`). */
  badge?: string;
  /** The IP and time line under the device (`data-oauth2-session-meta`). */
  meta?: string;
  /** Each per-session "Sign out" button (`data-oauth2-revoke-session`). */
  revoke?: string;
  /** The wrapper of the "Sign out everywhere else" form (`data-oauth2-actions`). */
  actions?: string;
  /**
   * The "Sign out everywhere else" button
   * (`data-oauth2-revoke-other-sessions`).
   */
  revokeOthers?: string;
  /** The error summary shown after a failed action (`data-oauth2-error-summary`). */
  errorSummary?: string;
  /** The text shown when there are no sessions (`data-oauth2-empty`). */
  empty?: string;
}

/** Visible text overrides for {@link SessionList}. */
export interface SessionListLabels {
  /** Badge on the current session. Default: `"Current session"`. */
  current?: string;
  /** Device text when a session has none. Default: `"Unknown device"`. */
  unknownDevice?: string;
  /** Prefix of the sign-in time. Default: `"Signed in"`. */
  signedIn?: string;
  /** Prefix of the last-used time. Default: `"Last active"`. */
  lastActive?: string;
  /**
   * Per-session button text. Default: `"Sign out"`. Its accessible name adds
   * the session's device, such as "Sign out Firefox on Linux".
   */
  revoke?: string;
  /** Per-session button text while pending. Default: `"Signing out…"`. */
  revoking?: string;
  /** Text of the button for every other session. Default: `"Sign out everywhere else"`. */
  revokeOthers?: string;
  /** That button's text while pending. Default: `"Signing out…"`. */
  revokingOthers?: string;
  /** Shown when `sessions` is empty. Default: `"No active sessions."`. */
  empty?: string;
}

/**
 * The live state {@link SessionList} hands to a render-prop `children`: the
 * sessions, which action is pending, the last error, and the two actions with
 * the component's single-flight guard applied.
 */
export interface SessionListState {
  /** The sessions passed to the component. */
  sessions: readonly SessionListItem[];
  /** The id of the session whose sign-out is pending, else `null`. */
  pendingSessionId: string | null;
  /** `true` while "Sign out everywhere else" is pending. */
  revokingOthers: boolean;
  /** The message from the last failed action, else `null`. */
  error: string | null;
  /**
   * Runs `onRevoke` for a session. Ignored while any action is pending or
   * when `onRevoke` was not passed.
   */
  revoke(session: SessionListItem): Promise<void>;
  /**
   * Runs `onRevokeOthers`. Ignored while any action is pending or when
   * `onRevokeOthers` was not passed.
   */
  revokeOthers(): Promise<void>;
}

/** Props for {@link SessionList}. */
export interface SessionListProps {
  /** The account's live sessions, in the order to list them. */
  sessions: readonly SessionListItem[];
  /**
   * Signs out one session other than the current one. Omit it, with
   * `onRevokeOthers`, for a read-only list — for example while an
   * administrator views someone else's account.
   */
  onRevoke?: AccountActionHandler<SessionListItem>;
  /**
   * Signs out every session except the current one. The button shows only
   * when this is passed and at least one other session is listed.
   */
  onRevokeOthers?: () =>
    | Promise<AccountActionResult | void>
    | AccountActionResult
    | void;
  /**
   * Formats `createdAt` and `lastActiveAt`. Defaults to the runtime's locale
   * and time zone, which can differ between server and browser; pass a
   * formatter with a fixed locale and `timeZone` on a server-rendered page so
   * hydration matches.
   */
  formatDate?: (date: Date) => string;
  /**
   * `action` for each button's `<form>`. Set it on a server-rendered page so
   * the buttons still post when JavaScript never arrives: a session's
   * "Sign out" posts `intent=revoke-session` and `sessionId`, and "Sign out
   * everywhere else" posts `intent=revoke-other-sessions`. Once React is
   * running, the callbacks handle the submit and the native post is
   * suppressed.
   */
  action?: string;
  /** `method` for each button's `<form>`. Defaults to `"post"` whenever `action` is set. */
  method?: "get" | "post";
  /** Class for the root wrapper (merged with `classNames.root`). */
  className?: string;
  /** Per-slot class hooks for theming. See {@link SessionListClassNames}. */
  classNames?: SessionListClassNames;
  /** Text overrides. */
  labels?: SessionListLabels;
  /**
   * Render-prop escape hatch. When provided, you own the markup and receive
   * the live {@link SessionListState}; the component still owns the pending
   * and error state.
   */
  children?: (state: SessionListState) => ReactNode;
}

const OTHERS_KEY = "\u0000revoke-other-sessions";

/**
 * A ready-to-use list of an account's signed-in sessions. Pass the sessions
 * your loader read and wire `onRevoke` / `onRevokeOthers` to your server;
 * after an action succeeds, pass the updated `sessions` so the list follows.
 *
 * Each session shows its device, the current-session badge, its IP address
 * and its sign-in and last-active times. A failed action shows its message in
 * an error summary that takes focus, and a pending button keeps focus with
 * `aria-disabled="true"`.
 *
 * @example
 * ```tsx
 * import {
 *   SessionList,
 *   type SessionListItem,
 * } from "@udibo/oauth2/react/components";
 *
 * function Sessions(props: { sessions: SessionListItem[] }) {
 *   return (
 *     <SessionList
 *       sessions={props.sessions}
 *       onRevoke={async (session) => {
 *         const response = await fetch(`/account/sessions/${session.id}`, {
 *           method: "DELETE",
 *         });
 *         if (!response.ok) return { error: "Couldn't sign out that session." };
 *       }}
 *       onRevokeOthers={async () => {
 *         const response = await fetch("/account/sessions", { method: "DELETE" });
 *         if (!response.ok) return { error: "Couldn't sign out other sessions." };
 *       }}
 *     />
 *   );
 * }
 * ```
 */
export function SessionList(props: SessionListProps): ReactNode {
  const {
    sessions,
    onRevoke,
    onRevokeOthers,
    formatDate = formatAccountDate,
    action,
    method,
    className,
    classNames,
    labels,
    children,
  } = props;
  const runner = useAccountAction();

  const revoke = async (session: SessionListItem): Promise<void> => {
    if (!onRevoke || session.current) return;
    await runner.run(session.id, () => onRevoke(session));
  };
  const revokeOthers = async (): Promise<void> => {
    if (!onRevokeOthers) return;
    await runner.run(OTHERS_KEY, () => onRevokeOthers());
  };

  if (children) {
    return (
      <>
        {children({
          sessions,
          pendingSessionId:
            runner.pendingKey === OTHERS_KEY ? null : runner.pendingKey,
          revokingOthers: runner.pendingKey === OTHERS_KEY,
          error: runner.error,
          revoke,
          revokeOthers,
        })}
      </>
    );
  }

  const otherCount = sessions.filter((session) => !session.current).length;
  const deviceOf = (session: SessionListItem): string =>
    session.device || (labels?.unknownDevice ?? "Unknown device");

  return (
    <div
      data-oauth2-session-list=""
      className={combineClassNames(className, classNames?.root)}
    >
      <AccountActionError
        error={runner.error}
        focusTrigger={runner.errorCount}
        className={classNames?.errorSummary}
      />
      {sessions.length === 0 ? (
        <p data-oauth2-empty="" className={classNames?.empty}>
          {labels?.empty ?? "No active sessions."}
        </p>
      ) : (
        <ul data-oauth2-session-items="" className={classNames?.list}>
          {sessions.map((session) => {
            const device = deviceOf(session);
            const meta = [
              session.ipAddress || null,
              session.createdAt
                ? `${labels?.signedIn ?? "Signed in"} ${formatDate(session.createdAt)}`
                : null,
              session.lastActiveAt
                ? `${labels?.lastActive ?? "Last active"} ${formatDate(session.lastActiveAt)}`
                : null,
            ].filter((part): part is string => part !== null);
            return (
              <li
                key={session.id}
                data-oauth2-session={session.id}
                {...(session.current
                  ? { "data-oauth2-current-session": "" }
                  : {})}
                className={classNames?.item}
              >
                <span
                  data-oauth2-session-device=""
                  className={classNames?.device}
                >
                  {device}
                </span>
                {session.current ? (
                  <span
                    data-oauth2-session-badge=""
                    className={classNames?.badge}
                  >
                    {labels?.current ?? "Current session"}
                  </span>
                ) : null}
                {meta.length > 0 ? (
                  <span
                    data-oauth2-session-meta=""
                    className={classNames?.meta}
                  >
                    {meta.join(" · ")}
                  </span>
                ) : null}
                {onRevoke && !session.current ? (
                  <ActionForm
                    fields={{ intent: "revoke-session", sessionId: session.id }}
                    action={action}
                    method={method}
                    onActivate={() => {
                      void revoke(session);
                    }}
                    pending={runner.pendingKey === session.id}
                    label={labels?.revoke ?? "Sign out"}
                    pendingLabel={labels?.revoking ?? "Signing out…"}
                    accessibleName={device}
                    dataAttribute="data-oauth2-revoke-session"
                    dataValue={session.id}
                    className={classNames?.revoke}
                  />
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
      {onRevokeOthers && otherCount > 0 ? (
        <div data-oauth2-actions="" className={classNames?.actions}>
          <ActionForm
            fields={{ intent: "revoke-other-sessions" }}
            action={action}
            method={method}
            onActivate={() => {
              void revokeOthers();
            }}
            pending={runner.pendingKey === OTHERS_KEY}
            label={labels?.revokeOthers ?? "Sign out everywhere else"}
            pendingLabel={labels?.revokingOthers ?? "Signing out…"}
            dataAttribute="data-oauth2-revoke-other-sessions"
            className={classNames?.revokeOthers}
          />
        </div>
      ) : null}
    </div>
  );
}
