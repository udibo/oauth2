import {
  MemorySessionStore,
  type RefreshLockStore,
  type SessionData,
  type SessionStore,
} from "./session-store.ts";

/**
 * A shared-store stand-in whose refresh lock expires after a second but which
 * runs the refresh with no lease, so a holder that stalls past the expiry
 * still writes and destroys the session.
 */
export class LeaselessLockStore implements SessionStore, RefreshLockStore {
  readonly #store = new MemorySessionStore({
    refreshLeaseMs: 1000,
    refreshLockWaitMs: 5000,
  });

  create(data: SessionData): Promise<string> {
    return this.#store.create(data);
  }

  read(cookieValue: string): Promise<SessionData | null> {
    return this.#store.read(cookieValue);
  }

  update(cookieValue: string, data: SessionData): Promise<string> {
    return this.#store.update(cookieValue, data);
  }

  destroy(cookieValue: string): Promise<void> {
    return this.#store.destroy(cookieValue);
  }

  withRefreshLock<T>(
    cookieValue: string,
    refresh: () => Promise<T>,
  ): Promise<T> {
    return this.#store.withRefreshLock(cookieValue, () => refresh());
  }
}
