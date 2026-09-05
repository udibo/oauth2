/**
 * Event types emitted by the OAuth2 clients.
 *
 * Framework adapters (React, Vue, etc.) subscribe to these to re-render on
 * authentication state changes without having to poll the client for state.
 *
 * @module
 */

import type { TokenBundle } from "./storage.ts";

/** The authenticated user has been resolved or has changed. */
export interface AuthenticatedEvent {
  /** Discriminant tag for this event variant. */
  type: "authenticated";
  /** The token bundle that was just persisted for the session. */
  tokens: TokenBundle;
}

/** The client has cleared its session and the user is no longer authenticated. */
export interface LoggedOutEvent {
  /** Discriminant tag for this event variant. */
  type: "logged_out";
  /** Why the session ended. */
  reason: "user" | "refresh_failed" | "invalid_grant" | "session_expired";
}

/** A refresh has just completed; the access token has rotated. */
export interface TokenRefreshedEvent {
  /** Discriminant tag for this event variant. */
  type: "token_refreshed";
  /** The rotated token bundle now in effect. */
  tokens: TokenBundle;
}

/** An operation failed. Subscribers can surface this to the user. */
export interface ErrorEvent {
  /** Discriminant tag for this event variant. */
  type: "error";
  /** The thrown value; an {@linkcode OAuth2Error} when the failure was protocol-level. */
  error: unknown;
}

/** Every event type the client emits. */
export type OAuth2ClientEvent =
  | AuthenticatedEvent
  | LoggedOutEvent
  | TokenRefreshedEvent
  | ErrorEvent;

/** Subscriber callback. Return values are ignored. */
export type OAuth2ClientEventListener = (event: OAuth2ClientEvent) => void;

/** Minimal event bus for the client to avoid pulling in a dependency. */
export class EventBus {
  #listeners = new Set<OAuth2ClientEventListener>();

  /** Registers `listener` and returns a function that removes it. */
  subscribe(listener: OAuth2ClientEventListener): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  /**
   * Delivers `event` to every subscriber. A listener that throws is isolated
   * so delivery to the remaining subscribers still completes.
   */
  emit(event: OAuth2ClientEvent): void {
    for (const listener of this.#listeners) {
      try {
        listener(event);
      } catch {
        // One bad subscriber must not break delivery to others.
      }
    }
  }

  /** Removes all subscribers. */
  clear(): void {
    this.#listeners.clear();
  }
}
