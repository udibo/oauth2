/**
 * MFA primitives for apps that own their login: TOTP (RFC 6238) and single-use
 * recovery codes, plus a small orchestrator over an app-owned store — the same
 * thin-seam philosophy as the rest of the identity layer. Built entirely on
 * Web Crypto and `@std`; no other dependencies.
 *
 * - {@link generateTotpSecret} / {@link buildOtpauthUri} /
 *   {@link generateTotpCode} / {@link verifyTotpCode} — the TOTP math, with a
 *   constant-time verify that reports the matched time step for replay
 *   rejection.
 * - {@link generateRecoveryCodes} / {@link hashRecoveryCode} /
 *   {@link verifyRecoveryCode} — readable single-use fallback codes, hashed at
 *   rest.
 * - {@link MfaService} over an app-implemented {@link MfaStore} — enrollment
 *   (pending → confirmed), verification with atomic replay and burn handling,
 *   regeneration, disable, plus the layer's usual seams (`rateLimiter`,
 *   `onEvent` for `mfa.*` audit events). {@link MemoryMfaStore} ships for
 *   dev/tests.
 *
 * The library stops at the primitives: whether MFA is optional or required,
 * where challenges happen, and sessions are the app's policy and belong in
 * its routes.
 *
 * @example Wire MFA into an app
 * ```ts
 * import { MemoryMfaStore, MfaService } from "@udibo/oauth2/identity/mfa";
 *
 * const mfa = new MfaService({ store: new MemoryMfaStore() });
 * const { otpauthUri } = await mfa.startEnrollment(user.id, {
 *   issuer: "Example",
 *   accountName: user.email,
 * });
 * // render otpauthUri as a QR, then:
 * const confirmation = await mfa.confirmEnrollment(user.id, submittedCode);
 * ```
 *
 * @module
 */

export {
  buildOtpauthUri,
  decodeTotpSecret,
  type GeneratedTotpSecret,
  generateTotpCode,
  type GenerateTotpCodeOptions,
  generateTotpSecret,
  type OtpauthUriOptions,
  type TotpAlgorithm,
  type TotpVerification,
  verifyTotpCode,
  type VerifyTotpCodeOptions,
} from "./totp.ts";
export {
  type GeneratedRecoveryCodes,
  generateRecoveryCodes,
  type GenerateRecoveryCodesOptions,
  hashRecoveryCode,
  normalizeRecoveryCode,
  RECOVERY_CODE_LENGTH,
  type RecoveryCodeVerification,
  verifyRecoveryCode,
  type VerifyRecoveryCodeOptions,
} from "./recovery-codes.ts";
export {
  MemoryMfaStore,
  type MfaEnrollmentConfirmation,
  type MfaEnrollmentStart,
  type MfaEnrollmentStatus,
  MfaService,
  type MfaServiceOptions,
  type MfaStore,
  type MfaTotpOptions,
  type MfaTotpRecord,
  type MfaVerification,
  type MfaVerifyFailureReason,
  type MfaVerifyOptions,
  type StartEnrollmentOptions,
} from "./service.ts";
