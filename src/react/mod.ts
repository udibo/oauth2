/**
 * React adapter for `@udibo/oauth2/client`.
 *
 * Wraps a `BffClient` or a `DirectClient` in a React context and ships
 * components / hooks for the common SPA patterns:
 *
 * - {@link OAuth2Provider} — install once near the app root.
 * - {@link useOAuth2} — read state and bound auth helpers.
 * - {@link RequireAuth} — gate a subtree behind authentication.
 * - {@link OAuth2Callback} — callback route for a `DirectClient` app.
 *
 * The adapter is framework- and server-neutral: it works against any
 * RFC 6749-compliant authorization server, and everything above is written
 * against the clients' shared base, so the same components and hooks work
 * whichever one the app is wired with. Reach for {@link useBffClient} or
 * {@link useDirectClient} when a component needs one transport's specifics.
 *
 * @module
 */

export {
  OAuth2Context,
  type OAuth2ContextValue,
  type OAuth2State,
} from "./context.ts";
export { OAuth2Provider, type OAuth2ProviderProps } from "./provider.tsx";
export {
  useBffClient,
  useDirectClient,
  useOAuth2,
  type UseOAuth2Result,
} from "./use-oauth2.ts";
export { useAuthorization } from "./use-authorization.ts";
export { RequireAuth, type RequireAuthProps } from "./require-auth.tsx";
export { OAuth2Callback, type OAuth2CallbackProps } from "./callback.tsx";
