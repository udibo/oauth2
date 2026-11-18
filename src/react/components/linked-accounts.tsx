/**
 * {@link LinkedAccounts} — a default, accessible, unstyled list of the social
 * and federated accounts linked to an account, with "Disconnect" on each and
 * "Connect …" for the providers it can still link. The accounts come in as
 * data and each action goes out through a callback; the component never loads,
 * links or unlinks anything itself.
 *
 * @module
 */

import type { ReactNode } from "react";

import type {
  AccountActionHandler,
  BaseClassNames,
  SocialProvider,
} from "./types.ts";
import {
  AccountActionError,
  ActionForm,
  formatAccountDate,
  useAccountAction,
  useFocusAfterRemoval,
} from "./account-internal.tsx";
import { combineClassNames } from "./internal.tsx";

/** One linked account, as {@link LinkedAccounts} renders it. */
export interface LinkedAccount {
  /**
   * The link's identifier: an opaque, non-secret id such as a public row id,
   * never a provider token. It is handed back to `onUnlink`, and although it
   * is not displayed as text, it is written into the page — `data-oauth2-*`
   * attributes and the hidden `identityId` input a no-JavaScript submit posts.
   */
  id: string;
  /** The provider's name, such as `"GitHub"`. */
  providerName: string;
  /** The email address the provider reported for this account. */
  email?: string | null;
  /** When the account was linked. */
  linkedAt?: Date;
  /**
   * Set `false` when disconnecting this account would leave no way to sign in,
   * so the row shows the `lastMethod` text instead of a "Disconnect" button.
   * Your server must still refuse that unlink: this only keeps the button
   * from being offered.
   */
  canUnlink?: boolean;
}

/**
 * Per-slot class hooks for {@link LinkedAccounts}: the shared
 * {@link BaseClassNames} `root` plus the list's own slots. Each element also
 * carries the stable `data-oauth2-*` attribute named here.
 */
export interface LinkedAccountsClassNames extends BaseClassNames {
  /** The `<ul>` of linked accounts (`data-oauth2-linked-account-items`). */
  list?: string;
  /** Each `<li>` (`data-oauth2-linked-account`, whose value is the link id). */
  item?: string;
  /** The provider name of each account (`data-oauth2-linked-account-name`). */
  name?: string;
  /** The email and date line under the name (`data-oauth2-linked-account-meta`). */
  meta?: string;
  /** Each "Disconnect" button (`data-oauth2-unlink`). */
  unlink?: string;
  /**
   * The text shown in place of "Disconnect" on an account that cannot be
   * unlinked (`data-oauth2-last-method`).
   */
  hint?: string;
  /** The wrapper of the "Connect …" controls (`data-oauth2-connect`). */
  connectSection?: string;
  /** Each "Connect …" button or link (`data-oauth2-connect-button`). */
  connectButton?: string;
  /** The error summary shown after a failed action (`data-oauth2-error-summary`). */
  errorSummary?: string;
  /** The text shown when no account is linked (`data-oauth2-empty`). */
  empty?: string;
}

/** Visible text overrides for {@link LinkedAccounts}. */
export interface LinkedAccountsLabels {
  /** Prefix of the linked date. Default: `"Connected"`. */
  linked?: string;
  /**
   * "Disconnect" button text. Default: `"Disconnect"`. Its accessible name adds
   * the provider, such as "Disconnect GitHub".
   */
  unlink?: string;
  /** "Disconnect" button text while pending. Default: `"Disconnecting…"`. */
  unlinking?: string;
  /**
   * Text before a provider's name on its connect control. Default:
   * `"Connect"`, rendering "Connect GitHub".
   */
  link?: string;
  /** Connect button text while pending. Default: `"Connecting…"`. */
  linking?: string;
  /**
   * Shown on an account whose `canUnlink` is `false`. Default:
   * `"This is your only way to sign in, so it can't be disconnected."`.
   */
  lastMethod?: string;
  /** Shown when `accounts` is empty. Default: `"No accounts connected yet."`. */
  empty?: string;
}

/**
 * The live state {@link LinkedAccounts} hands to a render-prop `children`:
 * the data, which action is pending, the last error, and the two actions with
 * the component's single-flight guard applied.
 */
export interface LinkedAccountsState {
  /** The linked accounts passed to the component. */
  accounts: readonly LinkedAccount[];
  /** The providers passed to the component. */
  providers: readonly SocialProvider[];
  /** The id of the account whose unlink is pending, else `null`. */
  pendingAccountId: string | null;
  /** The id of the provider whose link is pending, else `null`. */
  pendingProviderId: string | null;
  /** The message from the last failed action, else `null`. */
  error: string | null;
  /**
   * Runs `onUnlink` for an account. Ignored while any action is pending, when
   * `onUnlink` was not passed, or when the account's `canUnlink` is `false`.
   */
  unlink(account: LinkedAccount): Promise<void>;
  /**
   * Runs `onLink` for a provider. Ignored while any action is pending or when
   * `onLink` was not passed.
   */
  link(provider: SocialProvider): Promise<void>;
}

/** Props for {@link LinkedAccounts}. */
export interface LinkedAccountsProps {
  /** The accounts linked to this account, in the order to list them. */
  accounts: readonly LinkedAccount[];
  /**
   * Disconnects one linked account. Omit it for a read-only list. Refuse an
   * unlink that would leave no way to sign in on your server, whatever
   * `canUnlink` says.
   */
  onUnlink?: AccountActionHandler<LinkedAccount>;
  /**
   * Providers the account can still link. Each gets a "Connect …" control
   * when `onLink` or `linkHref` is passed. Empty or absent renders no connect
   * section.
   */
  providers?: readonly SocialProvider[];
  /**
   * Starts linking a provider. Its pending label shows until the returned
   * promise settles; a flow that navigates away can simply not resolve.
   */
  onLink?: AccountActionHandler<SocialProvider>;
  /**
   * Builds the href that starts linking a provider, rendering links instead of
   * buttons. Wins over `onLink` when both are passed.
   */
  linkHref?: (provider: SocialProvider) => string;
  /**
   * Formats `linkedAt`. Defaults to the runtime's locale and time zone, which
   * can differ between server and browser; pass a formatter with a fixed
   * locale and `timeZone` on a server-rendered page so hydration matches.
   */
  formatDate?: (date: Date) => string;
  /**
   * `action` for each "Disconnect" button's `<form>`. Set it on a
   * server-rendered page so the button still posts when JavaScript never
   * arrives, with `intent=unlink-identity` and `identityId`. Once React is
   * running, `onUnlink` handles the submit and the native post is
   * suppressed. The forms always use `post`. A native post cannot carry a
   * CSRF header, so check `Origin` or `Sec-Fetch-Site` on the route that
   * receives it. Connect controls never post: use `linkHref` for a link that
   * works without JavaScript.
   */
  action?: string;
  /** Class for the root wrapper (merged with `classNames.root`). */
  className?: string;
  /** Per-slot class hooks for theming. See {@link LinkedAccountsClassNames}. */
  classNames?: LinkedAccountsClassNames;
  /** Text overrides. */
  labels?: LinkedAccountsLabels;
  /**
   * Render-prop escape hatch. When provided, you own the markup and receive
   * the live {@link LinkedAccountsState}; the component still owns the
   * pending and error state.
   */
  children?: (state: LinkedAccountsState) => ReactNode;
}

const LINK_KEY_PREFIX = "\u0000link:";

/**
 * A ready-to-use list of the social and federated accounts linked to an
 * account. Pass the accounts your loader read and wire `onUnlink` to your
 * server; pass `providers` with `onLink` or `linkHref` to offer the ones not
 * yet linked. After an action succeeds, pass the updated data so the list
 * follows.
 *
 * Set `canUnlink: false` on an account that is the last way to sign in. A
 * failed action shows its message in an error summary that takes focus, and a
 * pending button keeps focus with `aria-disabled="true"`.
 *
 * @example
 * ```tsx
 * import {
 *   type LinkedAccount,
 *   LinkedAccounts,
 * } from "@udibo/oauth2/react/components";
 *
 * function Connected(props: { accounts: LinkedAccount[]; hasPassword: boolean }) {
 *   return (
 *     <LinkedAccounts
 *       accounts={props.accounts.map((account) => ({
 *         ...account,
 *         canUnlink: props.hasPassword || props.accounts.length > 1,
 *       }))}
 *       onUnlink={async (account) => {
 *         const response = await fetch(`/account/identities/${account.id}`, {
 *           method: "DELETE",
 *         });
 *         if (!response.ok) return { error: "Couldn't disconnect that account." };
 *       }}
 *       providers={[{ id: "github", name: "GitHub" }]}
 *       linkHref={(provider) => `/auth/link/${provider.id}`}
 *     />
 *   );
 * }
 * ```
 */
export function LinkedAccounts(props: LinkedAccountsProps): ReactNode {
  const {
    accounts,
    onUnlink,
    providers = [],
    onLink,
    linkHref,
    formatDate = formatAccountDate,
    action,
    className,
    classNames,
    labels,
    children,
  } = props;
  const runner = useAccountAction();
  const rootRef = useFocusAfterRemoval(runner, accounts);

  const unlink = async (account: LinkedAccount): Promise<void> => {
    if (!onUnlink || account.canUnlink === false) return;
    await runner.run(account.id, () => onUnlink(account));
  };
  const link = async (provider: SocialProvider): Promise<void> => {
    if (!onLink) return;
    await runner.run(LINK_KEY_PREFIX + provider.id, () => onLink(provider));
  };
  const pendingProviderId = runner.pendingKey?.startsWith(LINK_KEY_PREFIX)
    ? runner.pendingKey.slice(LINK_KEY_PREFIX.length)
    : null;
  const pendingAccountId =
    pendingProviderId === null ? runner.pendingKey : null;

  if (children) {
    return (
      <>
        {children({
          accounts,
          providers,
          pendingAccountId,
          pendingProviderId,
          error: runner.error,
          unlink,
          link,
        })}
      </>
    );
  }

  const linkText = labels?.link ?? "Connect";
  const showConnect = providers.length > 0 && Boolean(linkHref || onLink);

  return (
    <div
      ref={rootRef}
      tabIndex={-1}
      data-oauth2-linked-accounts=""
      className={combineClassNames(className, classNames?.root)}
    >
      <AccountActionError
        error={runner.error}
        className={classNames?.errorSummary}
      />
      {accounts.length === 0 ? (
        <p data-oauth2-empty="" className={classNames?.empty}>
          {labels?.empty ?? "No accounts connected yet."}
        </p>
      ) : (
        <ul data-oauth2-linked-account-items="" className={classNames?.list}>
          {accounts.map((account) => {
            const meta = [
              account.email || null,
              account.linkedAt
                ? `${labels?.linked ?? "Connected"} ${formatDate(account.linkedAt)}`
                : null,
            ].filter((part): part is string => part !== null);
            return (
              <li
                key={account.id}
                data-oauth2-linked-account={account.id}
                className={classNames?.item}
              >
                <span
                  data-oauth2-linked-account-name=""
                  className={classNames?.name}
                >
                  {account.providerName}
                </span>
                {meta.length > 0 ? (
                  <span
                    data-oauth2-linked-account-meta=""
                    className={classNames?.meta}
                  >
                    {meta.join(" · ")}
                  </span>
                ) : null}
                {onUnlink && account.canUnlink === false ? (
                  <span data-oauth2-last-method="" className={classNames?.hint}>
                    {labels?.lastMethod ??
                      "This is your only way to sign in, so it can't be disconnected."}
                  </span>
                ) : null}
                {onUnlink && account.canUnlink !== false ? (
                  <ActionForm
                    fields={{
                      intent: "unlink-identity",
                      identityId: account.id,
                    }}
                    action={action}
                    onActivate={() => {
                      void unlink(account);
                    }}
                    pending={pendingAccountId === account.id}
                    label={labels?.unlink ?? "Disconnect"}
                    pendingLabel={labels?.unlinking ?? "Disconnecting…"}
                    accessibleName={account.providerName}
                    dataAttribute="data-oauth2-unlink"
                    dataValue={account.id}
                    className={classNames?.unlink}
                  />
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
      {showConnect ? (
        <div data-oauth2-connect="" className={classNames?.connectSection}>
          {providers.map((provider) => {
            const content = (
              <>
                {provider.iconSlot ? (
                  <span data-oauth2-social-icon="">{provider.iconSlot}</span>
                ) : null}
                <span data-oauth2-social-label="">
                  {pendingProviderId === provider.id
                    ? (labels?.linking ?? "Connecting…")
                    : `${linkText} ${provider.name}`}
                </span>
              </>
            );
            return linkHref ? (
              <a
                key={provider.id}
                href={linkHref(provider)}
                data-oauth2-connect-button={provider.id}
                className={classNames?.connectButton}
              >
                {content}
              </a>
            ) : (
              <button
                key={provider.id}
                type="button"
                aria-disabled={
                  pendingProviderId === provider.id ? true : undefined
                }
                aria-label={
                  pendingProviderId === provider.id
                    ? `${labels?.linking ?? "Connecting…"} ${provider.name}`
                    : undefined
                }
                onClick={() => {
                  void link(provider);
                }}
                data-oauth2-connect-button={provider.id}
                className={classNames?.connectButton}
              >
                {content}
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}
