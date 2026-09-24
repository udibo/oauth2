/**
 * Contract test suites for the framework's service and store interfaces.
 *
 * These runners register `describe` / `it` blocks that verify a
 * consumer's implementation of `UserServiceInterface`,
 * `ClientServiceInterface`, `TokenServiceInterface`,
 * `TokenReaderInterface`, `AuthorizationCodeServiceInterface`, or
 * `DeviceAuthorizationServiceInterface` satisfies what the framework
 * expects. The same suites run against the library's `Memory*Service`
 * fixtures and shipped token readers internally, so consumers and the
 * library are tested by the exact same checks.
 *
 * The identity layer's storage seams — `MfaStore`, `TokenFlowStore`,
 * `OtpStore`, `RateLimitStore`, `LockoutStore` — and the client's
 * `AuthRequestStorage` have runners of their own. Those interfaces document
 * methods that **must be atomic** (single-use recovery codes, single-use
 * links, the TOTP replay guard, the guess and failure budgets, the
 * single-use claim of a login's `state`), and each suite checks that claim
 * with overlapping calls: a read-modify-write implementation passes every
 * sequential case and fails the concurrent one, which is the whole
 * reason the suites exist.
 *
 * The service runners take a factory plus seed helpers because `add` /
 * `register` methods aren't part of the public service interfaces — the
 * consumer tells the runner how to populate test data.
 *
 * @module
 */

export {
  runUserServiceContractTests,
  type UserServiceContractOptions,
} from "./user.ts";
export {
  type ClientServiceContractOptions,
  runClientServiceContractTests,
} from "./client.ts";
export {
  runTokenServiceContractTests,
  type TokenServiceContractOptions,
} from "./token.ts";
export {
  runTokenReaderContractTests,
  type TokenReaderContractFixture,
  type TokenReaderContractOptions,
} from "./token-reader.ts";
export {
  type AuthorizationCodeServiceContractOptions,
  runAuthorizationCodeServiceContractTests,
} from "./authorization-code.ts";
export {
  type DeviceAuthorizationServiceContractOptions,
  runDeviceAuthorizationServiceContractTests,
} from "./device-authorization.ts";
export {
  type MfaStoreContractOptions,
  runMfaStoreContractTests,
} from "./mfa-store.ts";
export {
  runTokenFlowStoreContractTests,
  type TokenFlowStoreContractOptions,
} from "./token-flow-store.ts";
export {
  type OtpStoreContractOptions,
  runOtpStoreContractTests,
} from "./otp-store.ts";
export {
  type RateLimitStoreContractOptions,
  runRateLimitStoreContractTests,
} from "./rate-limit-store.ts";
export {
  type LockoutStoreContractOptions,
  runLockoutStoreContractTests,
} from "./lockout-store.ts";
export {
  type AuthRequestStorageContractOptions,
  runAuthRequestStorageContractTests,
} from "./auth-request-storage.ts";
export {
  runTenantContractTests,
  type TenantContractFixture,
  type TenantContractOptions,
  type TenantContractTokens,
} from "./tenant.ts";
