/**
 * Passkeys (WebAuthn) for apps that own their login: registration and
 * sign-in ceremonies over app-owned stores, usable as a first factor and as a
 * second factor. Verification is delegated to `@simplewebauthn/server`; this
 * module applies a consumer-friendly policy on top:
 *
 * - **No attestation.** Any passkey manager, platform, or FIDO2 security key
 *   works; nothing is allow-listed by authenticator model.
 * - **Discoverable credentials**, so a person can sign in without typing an
 *   identifier, and sign-in without a known user lists no credentials and so
 *   reveals nothing about which accounts exist.
 * - **User verification preferred and reported**, so the app decides whether a
 *   passkey alone satisfies its MFA policy.
 * - **Single-use challenges**, a per-user cap (25 by default), sign-count clone
 *   detection, rate limiting, and `passkey.*` events.
 *
 * - {@link PasskeyService} — `startRegistration` / `finishRegistration`,
 *   `startAuthentication` / `finishAuthentication`, and list, rename, remove.
 * - {@link PasskeyStore} and {@link PasskeyChallengeStore} — the app's
 *   persistence seams, with {@link MemoryPasskeyStore} and
 *   {@link MemoryPasskeyChallengeStore} for development and tests.
 * - {@link PASSKEY_AMR} — the `amr` value a passkey contributes.
 *
 * The browser side is `navigator.credentials.create()` / `.get()` with the
 * returned options; `@simplewebauthn/browser` or the native
 * `PublicKeyCredential.parseCreationOptionsFromJSON` handle the conversion.
 * `TestPasskeyAuthenticator` in `@udibo/oauth2/testing` produces real
 * responses for tests.
 *
 * @example Serve a passkey sign-in
 * ```ts
 * import {
 *   MemoryPasskeyChallengeStore,
 *   MemoryPasskeyStore,
 *   PasskeyService,
 * } from "@udibo/oauth2/identity/passkeys";
 *
 * const passkeys = new PasskeyService({
 *   store: new MemoryPasskeyStore(),
 *   challenges: new MemoryPasskeyChallengeStore(),
 * });
 * const relyingParty = {
 *   id: "login.example.com",
 *   name: "Example",
 *   origins: ["https://login.example.com"],
 * };
 * const { ceremonyId, options } = await passkeys.startAuthentication({
 *   relyingParty,
 * });
 * // set ceremonyId in an HttpOnly cookie and send options to the browser
 * ```
 *
 * @module
 */

export {
  type FinishPasskeyAuthenticationOptions,
  type FinishPasskeyRegistrationOptions,
  MemoryPasskeyChallengeStore,
  MemoryPasskeyStore,
  type Passkey,
  PASSKEY_AMR,
  type PasskeyAddResult,
  type PasskeyAuthenticationOptions,
  type PasskeyAuthenticationResponse,
  type PasskeyCeremony,
  type PasskeyChallenge,
  type PasskeyChallengeStore,
  type PasskeyRegistration,
  type PasskeyRegistrationFailureReason,
  type PasskeyRegistrationOptions,
  type PasskeyRegistrationResponse,
  type PasskeyRelyingParty,
  PasskeyService,
  type PasskeyServiceOptions,
  type PasskeyStore,
  type PasskeyUse,
  type PasskeyUser,
  type PasskeyVerification,
  type PasskeyVerifyFailureReason,
  type StartPasskeyAuthenticationOptions,
  type StartPasskeyRegistrationOptions,
} from "./service.ts";
