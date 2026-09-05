/**
 * React hook exposing the signed-in user's {@link Authorization} — the same
 * checkable object the resource server derives from an access token, built
 * here from the session's id_token claims.
 *
 * @module
 */

import { useMemo } from "react";

import {
  type Authorization,
  authorizationFromClaims,
} from "../models/authorization.ts";
import { useOAuth2 } from "./use-oauth2.ts";

/**
 * The signed-in user's authorization, derived from the session's claims.
 *
 * Browser checks are **rendering hints only** — show or hide an affordance,
 * never gate the action itself; the API's middleware is the enforcement. An
 * unauthenticated session yields an empty authorization (every predicate
 * `false`), and id_token claims carry no OAuth2 scope, so
 * {@link Authorization.hasScope} answers `false` here — scope is the API's
 * check, not the browser's.
 *
 * @throws {Error} when called outside an `<OAuth2Provider>`.
 *
 * @example
 * ```tsx
 * import { useAuthorization } from "@udibo/oauth2/react";
 *
 * function PostActions() {
 *   const authorization = useAuthorization();
 *   return authorization.can("posts:write") ? <button>Edit</button> : null;
 * }
 * ```
 */
export function useAuthorization(): Authorization {
  const { user } = useOAuth2();
  return useMemo(() => authorizationFromClaims(user), [user]);
}
