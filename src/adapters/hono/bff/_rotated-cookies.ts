/**
 * Per-instance memory of session cookies a refresh replaced, used by
 * `HonoBff`'s `rotatedCookieGrace`.
 *
 * @module
 */

import { sha256Hash } from "../../../server/utils/hash.ts";

/** A refresh {@link RotatedCookies.start} began, to hand to `finish`. */
export interface PendingReplacement {
  readonly key: string;
  ended: boolean;
}

interface Successor {
  cookieValue: string;
  digest: string;
  expiresAt: number;
}

/**
 * Maps a replaced session cookie, by its SHA-256 digest, to the cookie that
 * replaced it, for `ttlMs` and at most `maxEntries` cookies. The oldest entry
 * is evicted first.
 */
export class RotatedCookies {
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #successors = new Map<string, Successor>();
  readonly #pending = new Set<PendingReplacement>();

  constructor(ttlMs: number, maxEntries: number) {
    this.#ttlMs = ttlMs;
    this.#maxEntries = maxEntries;
  }

  /** Records that `successor` replaced `previous`. */
  async remember(previous: string, successor: string): Promise<void> {
    await this.finish(await this.start(previous), successor);
  }

  /**
   * Starts a refresh of `previous`. If its chain is forgotten before
   * {@link finish}, the replacement is not remembered.
   */
  async start(previous: string): Promise<PendingReplacement> {
    const pending = { key: await sha256Hash(previous), ended: false };
    this.#pending.add(pending);
    return pending;
  }

  /** Ends a refresh, remembering `successor` unless its chain was forgotten. */
  async finish(
    pending: PendingReplacement,
    successor: string | undefined,
  ): Promise<void> {
    this.#pending.delete(pending);
    if (pending.ended || successor === undefined) return;
    const key = pending.key;
    this.#successors.delete(key);
    this.#successors.set(key, {
      cookieValue: successor,
      digest: await sha256Hash(successor),
      expiresAt: Date.now() + this.#ttlMs,
    });
    this.#evict();
  }

  /** The cookie that replaced `cookieValue` within the window, if any. */
  async successor(cookieValue: string): Promise<string | undefined> {
    const key = await sha256Hash(cookieValue);
    const entry = this.#successors.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= Date.now()) {
      this.#successors.delete(key);
      return undefined;
    }
    return entry.cookieValue;
  }

  /**
   * Drops every entry on the chain of replacements `cookieValue` belongs to,
   * so no cookie of a session that ended leads to another.
   */
  async forget(cookieValue: string): Promise<void> {
    const ended = new Set([await sha256Hash(cookieValue)]);
    let dropped = true;
    while (dropped) {
      dropped = false;
      for (const [key, entry] of this.#successors) {
        if (ended.has(key) || ended.has(entry.digest)) {
          this.#successors.delete(key);
          ended.add(key);
          ended.add(entry.digest);
          dropped = true;
        }
      }
    }
    for (const pending of this.#pending) {
      if (ended.has(pending.key)) pending.ended = true;
    }
  }

  #evict(): void {
    const now = Date.now();
    for (const [key, entry] of this.#successors) {
      if (this.#successors.size <= this.#maxEntries && entry.expiresAt > now) {
        return;
      }
      this.#successors.delete(key);
    }
  }
}
