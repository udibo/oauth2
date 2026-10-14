/**
 * Per-instance memory of session cookies a refresh replaced, used by
 * `HonoBff`'s `rotatedCookieGrace`.
 *
 * @module
 */

import { sha256Hash } from "../../../server/utils/hash.ts";

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

  constructor(ttlMs: number, maxEntries: number) {
    this.#ttlMs = ttlMs;
    this.#maxEntries = maxEntries;
  }

  /** Records that `successor` replaced `previous`. */
  async remember(previous: string, successor: string): Promise<void> {
    const key = await sha256Hash(previous);
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
