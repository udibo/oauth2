/**
 * {@link UserMenu} — a default, accessible, unstyled signed-in user menu. Reads
 * the current user and `logout` from {@link useOAuth2}, renders a disclosure
 * button showing the user's name, and exposes a logout action plus a slot for
 * your own menu items.
 *
 * Renders `null` (or a `signedOut` slot) when no user is authenticated, so it
 * is safe to mount unconditionally in a nav bar.
 *
 * The claims type its `renderUser` / `children` callbacks receive is
 * `UserInfoClaims`, imported from `@udibo/oauth2/client` — it belongs to the
 * client, not to this component.
 *
 * @module
 */

import { type ReactNode, useEffect, useId, useRef, useState } from "react";

import type { UserInfoClaims } from "../../client/mod.ts";
import { useOAuth2 } from "../use-oauth2.ts";
import type { BaseClassNames } from "./types.ts";
import { combineClassNames, displayName } from "./internal.tsx";

/**
 * Per-slot class hooks for {@link UserMenu}: the shared {@link BaseClassNames}
 * `root` plus the menu's own slots.
 */
export interface UserMenuClassNames extends BaseClassNames {
  /** The disclosure trigger button (`data-oauth2-user-trigger`). */
  trigger?: string;
  /** The display-name element inside the trigger. */
  name?: string;
  /** The menu panel revealed on open (`data-oauth2-user-panel`). */
  menu?: string;
  /** Each menu item wrapper. */
  menuItem?: string;
  /** The logout button (`data-oauth2-logout`). */
  logout?: string;
}

/** Visible text overrides for {@link UserMenu}. */
export interface UserMenuLabels {
  /** Logout action text. Default: `"Sign out"`. */
  logout?: string;
}

/** Props for {@link UserMenu}. */
export interface UserMenuProps {
  /** Extra menu content rendered above the logout action (links, etc.). */
  items?: ReactNode;
  /**
   * Override the logout behaviour. Defaults to `useOAuth2().logout()`, which
   * ends the session and (in the browser) navigates to the logout URL.
   */
  onLogout?: () => void | Promise<void>;
  /** Custom renderer for the trigger's user display. */
  renderUser?: (user: UserInfoClaims) => ReactNode;
  /** Rendered when no user is authenticated. Default: `null`. */
  signedOut?: ReactNode;
  /** Class for the root wrapper (merged with `classNames.root`). */
  className?: string;
  /** Per-slot class hooks for theming. */
  classNames?: UserMenuClassNames;
  /** Text overrides. */
  labels?: UserMenuLabels;
  /**
   * Render-prop escape hatch. Receives the current user and a `logout`
   * callback so you can render an entirely custom menu.
   */
  children?: (state: {
    user: UserInfoClaims;
    logout: () => void | Promise<void>;
  }) => ReactNode;
}

/**
 * A ready-to-use signed-in user menu. Mount it in your nav; it reads auth
 * state from the surrounding `<OAuth2Provider>`.
 *
 * @example
 * ```tsx
 * <UserMenu
 *   items={<a href="/profile">Profile</a>}
 * />
 * ```
 */
export function UserMenu(props: UserMenuProps): ReactNode {
  const {
    items,
    onLogout,
    renderUser,
    signedOut = null,
    className,
    classNames,
    labels,
    children,
  } = props;
  const { user, logout } = useOAuth2();
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    const onPointerDown = (event: Event) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("pointerdown", onPointerDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("pointerdown", onPointerDown);
    };
  }, [open]);

  if (!user) return <>{signedOut}</>;

  const runLogout = onLogout ?? (async (): Promise<void> => {
    await logout();
  });

  if (children) return <>{children({ user, logout: runLogout })}</>;

  return (
    <div
      ref={rootRef}
      data-oauth2-user-menu=""
      className={combineClassNames(className, classNames?.root)}
    >
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((value) => !value)}
        data-oauth2-user-trigger=""
        className={classNames?.trigger}
      >
        {renderUser
          ? renderUser(user)
          : (
            <span data-oauth2-user-name="" className={classNames?.name}>
              {displayName(user)}
            </span>
          )}
      </button>
      {open
        ? (
          <div
            id={panelId}
            data-oauth2-user-panel=""
            className={classNames?.menu}
          >
            {items
              ? (
                <div data-oauth2-user-items="" className={classNames?.menuItem}>
                  {items}
                </div>
              )
              : null}
            <button
              type="button"
              onClick={() => {
                void Promise.resolve(runLogout()).catch((error) => {
                  console.error("[@udibo/oauth2] logout failed:", error);
                });
              }}
              data-oauth2-logout=""
              className={classNames?.logout}
            >
              {labels?.logout ?? "Sign out"}
            </button>
          </div>
        )
        : null}
    </div>
  );
}
