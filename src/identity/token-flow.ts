/**
 * One token-flow primitive for the single-use, expiring links an identity layer
 * needs — **email verification** and **password reset** are the same mechanics:
 * mint a high-entropy token, store only its hash, hand the raw token to the app
 * to deliver, then validate / single-use-consume it later.
 *
 * The app reimplements this once per flow today (random bytes → sha256 → store
 * with expiry → consume). This collapses it into one tested, enumeration-safe
 * building block. Storage is an app-owned {@link TokenFlowStore} (a
 * {@link MemoryTokenFlowStore} ships for dev/tests); the package owns the
 * lifecycle, not the database.
 *
 * @module
 */

import { sha256Hash } from "../server/utils/hash.ts";
import { randomToken } from "../utils/crypto.ts";

/** Common token purposes. `purpose` is a free string; these are conventions. */
export const TokenPurpose = {
  EmailVerification: "email-verification",
  PasswordReset: "password-reset",
  AccountUnlock: "account-unlock",
  SignIn: "signin",
} as const;

/**
 * A stored token record. Holds the token's **hash**, never the raw token — a
 * leaked record (or log line) can't be replayed as a working link.
 */
export interface TokenFlowRecord {
  /** sha256-hex of the raw token; the storage key and at-rest form. */
  tokenHash: string;
  /** What the token authorizes (e.g. {@link TokenPurpose.PasswordReset}). */
  purpose: string;
  /** The subject the token acts on (typically a user id). */
  subject: string;
  /** Optional extra payload (e.g. the email being verified). */
  data?: Record<string, unknown>;
  /** Expiry, epoch ms. */
  expiresAt: number;
  /** When consumed (epoch ms), or `undefined` while still usable. */
  consumedAt?: number;
  /** Created, epoch ms. */
  createdAt: number;
}

/** App-owned persistence for {@link TokenFlowService}, keyed by `tokenHash`. */
export interface TokenFlowStore {
  /** Persist a new record. */
  save(record: TokenFlowRecord): Promise<void>;
  /**
   * Look up a record by token hash, or `null` when no record was ever stored
   * under it.
   *
   * Return the record **whatever its state** — expired and already-consumed
   * records included. {@link TokenFlowService.inspect} classifies them
   * (`expired` vs `consumed` vs `invalid`) after this read, so a store that
   * filters them out in SQL (`... AND consumed_at IS NULL AND expires_at >
   * now()`) collapses both into `invalid` and costs the caller the message it
   * would otherwise show.
   */
  get(tokenHash: string): Promise<TokenFlowRecord | null>;
  /**
   * Atomically claim a record as consumed (single-use): stamp `consumedAt` and
   * return `true` only when the record existed and was still unconsumed
   * (`UPDATE … SET consumed_at = $now WHERE token_hash = $hash AND consumed_at
   * IS NULL`, checking the row count). Return `false` without changing anything
   * otherwise.
   *
   * This **must** be a conditional write, not a read-then-write.
   * {@link TokenFlowService.consume} reads the record before calling this and
   * treats a `false` as "someone else got it", which is the only thing making a
   * link single-use under concurrent redemption — an unconditional overwrite
   * that always reports success lets two requests racing one link both proceed.
   */
  markConsumed(tokenHash: string, consumedAt: number): Promise<boolean>;
  /**
   * Optional: delete every still-pending token for a `(purpose, subject)` — e.g.
   * invalidate outstanding reset links once one succeeds, or when a new one is
   * issued. Implement it to harden the flow; the service calls it only if present.
   *
   * Delete the **pending** records only. Leaving the consumed ones keeps
   * {@link TokenFlowService.inspect} able to answer `consumed` for a token that
   * really was used, instead of the generic `invalid`.
   */
  deleteBySubject?(purpose: string, subject: string): Promise<void>;
}

/** Options for {@link TokenFlowService.create}. */
export interface CreateTokenOptions {
  /** What the token authorizes (e.g. {@link TokenPurpose.PasswordReset}). */
  purpose: string;
  /** The subject the token acts on (typically a user id). */
  subject: string;
  /** Optional extra payload to carry on the record (e.g. the email being verified). */
  data?: Record<string, unknown>;
  /** Lifetime in milliseconds. */
  ttlMs: number;
  /**
   * Invalidate any existing pending tokens for this `(purpose, subject)` first
   * (requires {@link TokenFlowStore.deleteBySubject}). Defaults to `false`.
   */
  invalidateExisting?: boolean;
}

/** The raw token to deliver, available only at creation time. */
export interface CreatedToken {
  /** The raw token — send it to the user; it is never stored or recoverable. */
  token: string;
  /** When the token expires, epoch ms. */
  expiresAt: number;
}

/** The result of validating/consuming a token. */
export interface ResolvedToken {
  /** The subject the token acts on (typically a user id). */
  subject: string;
  /** The extra payload supplied at creation, if any. */
  data?: Record<string, unknown>;
}

/**
 * The detailed outcome of {@link TokenFlowService.inspect}. Unlike the
 * `null`-returning {@link TokenFlowService.validate}/{@link TokenFlowService.consume},
 * this distinguishes **why** a token failed — so a verify/reset UI can say
 * "this link has expired, request a new one" vs. a generic error. (A 32-byte
 * random token isn't enumerable, so reporting `expired` vs `invalid` for the
 * token is not a meaningful leak — distinct from email enumeration.)
 */
export type TokenStatus =
  | { status: "valid"; subject: string; data?: Record<string, unknown> }
  | { status: "invalid" }
  | { status: "expired" }
  | { status: "consumed" };

/**
 * Issues, validates, and single-use-consumes purpose-scoped tokens.
 *
 * @example
 * ```ts
 * const tokens = new TokenFlowService(store);
 * const { token } = await tokens.create({
 *   purpose: TokenPurpose.PasswordReset, subject: user.id, ttlMs: 3_600_000,
 * });
 * // …email a link containing `token`…
 * const resolved = await tokens.consume(TokenPurpose.PasswordReset, token);
 * if (resolved) await resetPassword(resolved.subject, newPassword);
 * ```
 */
export class TokenFlowService {
  readonly #store: TokenFlowStore;

  /** Wraps an app-owned {@linkcode TokenFlowStore} that persists the token records. */
  constructor(store: TokenFlowStore) {
    this.#store = store;
  }

  /**
   * Drop every pending token for a `(purpose, subject)` without redeeming one —
   * e.g. voiding outstanding sign-in links when the user resets their password,
   * so a link an attacker already has stops working.
   *
   * Best-effort by design: {@link TokenFlowStore.deleteBySubject} is optional.
   * Returns `true` when the store implements it and the deletion ran, and
   * `false` when the store does not, in which case those tokens stay redeemable
   * until they expire — check the result if that gap matters to you. A store
   * that throws propagates the error.
   */
  async invalidate(purpose: string, subject: string): Promise<boolean> {
    if (!this.#store.deleteBySubject) return false;
    await this.#store.deleteBySubject(purpose, subject);
    return true;
  }

  /** Mint a token; stores its hash and returns the raw token (once). */
  async create(opts: CreateTokenOptions): Promise<CreatedToken> {
    if (opts.invalidateExisting) {
      await this.invalidate(opts.purpose, opts.subject);
    }
    const token = randomToken();
    const now = Date.now();
    const expiresAt = now + opts.ttlMs;
    await this.#store.save({
      tokenHash: await sha256Hash(token),
      purpose: opts.purpose,
      subject: opts.subject,
      data: opts.data,
      expiresAt,
      createdAt: now,
    });
    return { token, expiresAt };
  }

  /**
   * Validate a token **without** consuming it (e.g. to render a reset form
   * before the user submits). Returns the subject/data, or `null` if the token
   * is unknown, wrong-purpose, expired, or already consumed — never reveals which.
   */
  async validate(
    purpose: string,
    token: string,
  ): Promise<ResolvedToken | null> {
    const status = await this.inspect(purpose, token);
    return status.status === "valid"
      ? { subject: status.subject, data: status.data }
      : null;
  }

  /**
   * Validate **and** consume a token (single-use). Returns the subject/data, or
   * `null` (see {@link validate} for the failure cases). A second `consume` of
   * the same token returns `null` — including when the second one races the
   * first, since only the caller whose {@link TokenFlowStore.markConsumed}
   * claimed the record is handed the token.
   */
  async consume(purpose: string, token: string): Promise<ResolvedToken | null> {
    const tokenHash = await sha256Hash(token);
    const status = this.#statusOf(await this.#store.get(tokenHash), purpose);
    if (status.status !== "valid") return null;
    if (!await this.#store.markConsumed(tokenHash, Date.now())) return null;
    return { subject: status.subject, data: status.data };
  }

  /**
   * Inspect a token **without** consuming it, reporting the detailed
   * {@link TokenStatus} — `valid` (with subject/data), `invalid` (unknown or
   * wrong-purpose), `expired`, or `consumed`. Use this when the UI needs to tell
   * "expired" apart from "invalid" (e.g. an email-verification page that offers
   * to resend). {@link validate} is the `null`-returning shorthand.
   */
  async inspect(purpose: string, token: string): Promise<TokenStatus> {
    return this.#statusOf(
      await this.#store.get(await sha256Hash(token)),
      purpose,
    );
  }

  #statusOf(record: TokenFlowRecord | null, purpose: string): TokenStatus {
    if (!record || record.purpose !== purpose) return { status: "invalid" };
    if (record.consumedAt !== undefined) return { status: "consumed" };
    if (record.expiresAt <= Date.now()) return { status: "expired" };
    return { status: "valid", subject: record.subject, data: record.data };
  }
}

/**
 * In-memory {@link TokenFlowStore} for development and tests. Records are lost
 * on restart; back the contract with a database for production.
 *
 * Nothing is reclaimed: a consumed record is kept so
 * {@link TokenFlowService.inspect} can still answer `consumed`, and no sweep
 * ever removes it, so the map grows by one entry per token minted. That is
 * fine for a fixture and wrong in a database-backed port — give the rows a TTL
 * or a purge job that drops records already past `expiresAt`. Purge only
 * records that are *also* consumed: dropping an expired-but-unconsumed record
 * collapses `expired` into `invalid` and loses the distinction `inspect`
 * reports.
 */
export class MemoryTokenFlowStore implements TokenFlowStore {
  #byHash = new Map<string, TokenFlowRecord>();

  /** Persist a record, keyed by its token hash. */
  save(record: TokenFlowRecord): Promise<void> {
    this.#byHash.set(record.tokenHash, record);
    return Promise.resolve();
  }

  /** Return the record for a token hash, or `null` if none is stored. */
  get(tokenHash: string): Promise<TokenFlowRecord | null> {
    return Promise.resolve(this.#byHash.get(tokenHash) ?? null);
  }

  /** Claim the record if still unconsumed; `false` when unknown or already spent. */
  markConsumed(tokenHash: string, consumedAt: number): Promise<boolean> {
    const record = this.#byHash.get(tokenHash);
    if (!record || record.consumedAt !== undefined) {
      return Promise.resolve(false);
    }
    record.consumedAt = consumedAt;
    return Promise.resolve(true);
  }

  /**
   * Drop every still-pending record matching the given `(purpose, subject)`.
   * Already-consumed records are kept so {@link TokenFlowService.inspect} can
   * still report `consumed` rather than the generic `invalid`.
   */
  deleteBySubject(purpose: string, subject: string): Promise<void> {
    for (const [hash, record] of this.#byHash) {
      if (
        record.purpose === purpose && record.subject === subject &&
        record.consumedAt === undefined
      ) {
        this.#byHash.delete(hash);
      }
    }
    return Promise.resolve();
  }
}
