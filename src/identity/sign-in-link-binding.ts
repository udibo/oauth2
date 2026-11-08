/**
 * Binds an emailed sign-in link to the browser that asked for it.
 *
 * When a browser asks for a sign-in email, {@link createSignInLinkBinding}
 * returns a random `nonce` for your app to keep in that browser (an `HttpOnly`
 * cookie) and its `binding`, the SHA-256 of the nonce, for the link to carry
 * (pass it to {@link IdentityService.requestSignInLink}). When the link is
 * opened, {@link verifySignInLinkBinding} checks the browser's nonce against
 * the link's binding before you hand the token to
 * {@link IdentityService.consumeSignInLink}, so a refusal leaves the link
 * unspent and still usable in the browser that asked for it.
 *
 * The binding is not a secret: it keeps a link from signing in a browser that
 * did not ask for it, and is no protection once someone else holds the link.
 * Keep the nonce in a `__Host-` prefixed cookie so another subdomain cannot
 * plant one.
 *
 * @module
 */

import { createHash } from "node:crypto";

import { randomToken, timingSafeEqualString } from "../utils/crypto.ts";

/**
 * The query parameter {@link IdentityService.requestSignInLink} puts a link's
 * binding in, beside its `token`.
 */
export const SIGN_IN_LINK_BINDING_PARAM = "binding";

const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** A browser's sign-in link nonce and the binding its links carry. */
export interface SignInLinkBinding {
  /**
   * The secret the requesting browser keeps, 43 base64url characters. Store it
   * where only that browser sends it back, such as an `HttpOnly` cookie; never
   * put it in the link or the email.
   */
  nonce: string;
  /** The nonce's SHA-256, base64url-encoded: what the emailed link carries. */
  binding: string;
}

function isSignInLinkNonce(value: unknown): value is string {
  return typeof value === "string" && NONCE_PATTERN.test(value);
}

function bindingOf(nonce: string): string {
  return createHash("sha256").update(nonce).digest("base64url");
}

/**
 * The nonce and binding for a sign-in email a browser asks for. Pass the nonce
 * the browser already holds, if any: a well-formed one is kept, so every link
 * that browser was sent while it holds the nonce still works there. Anything
 * else — none, or a malformed value — is replaced by a fresh random nonce.
 *
 * @param nonce The nonce the requesting browser already holds, if any.
 * @returns The nonce to (re)store in the browser and the binding for its link.
 *
 * @example
 * ```ts
 * import { createSignInLinkBinding } from "@udibo/oauth2/identity";
 *
 * const fresh = createSignInLinkBinding();
 * const again = createSignInLinkBinding(fresh.nonce);
 * again.binding === fresh.binding; // true
 * ```
 */
export function createSignInLinkBinding(
  nonce?: string | null,
): SignInLinkBinding {
  const kept = isSignInLinkNonce(nonce) ? nonce : randomToken(32);
  return { nonce: kept, binding: bindingOf(kept) };
}

/**
 * Whether a link carrying `binding` was asked for by the browser holding
 * `nonce`. Compares in constant time and is `false` when either value is
 * missing or the nonce is malformed. Call it before
 * {@link IdentityService.consumeSignInLink}, so a link opened elsewhere is
 * refused without its token being read or spent.
 *
 * @param nonce The nonce the opening browser holds, if any.
 * @param binding The binding the link carries, if any.
 * @returns `true` only when `binding` is the SHA-256 of `nonce`.
 *
 * @example
 * ```ts
 * import {
 *   createSignInLinkBinding,
 *   verifySignInLinkBinding,
 * } from "@udibo/oauth2/identity";
 *
 * const { nonce, binding } = createSignInLinkBinding();
 * verifySignInLinkBinding(nonce, binding); // true
 * verifySignInLinkBinding(createSignInLinkBinding().nonce, binding); // false
 * ```
 */
export function verifySignInLinkBinding(
  nonce: string | null | undefined,
  binding: string | null | undefined,
): boolean {
  if (!isSignInLinkNonce(nonce) || typeof binding !== "string") return false;
  return timingSafeEqualString(binding, bindingOf(nonce));
}
