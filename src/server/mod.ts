/**
 * Shared types for OAuth2 servers (both resource and authorization servers).
 *
 * This module exports errors, models, service interfaces, and utilities
 * common to both server types. Import server-specific classes from:
 * - `@udibo/oauth2/server/resource` for ResourceServer
 * - `@udibo/oauth2/server/authorization` for AuthorizationServer
 *
 * @module
 */

export type { ClientCredentials, ClientInterface } from "../models/client.ts";
export type {
  IntrospectionResponse,
  RefreshToken,
  Token,
  TokenResponse,
} from "../models/token.ts";
export { AbstractScope, BasicScope } from "../models/scope.ts";
export type { ScopeConstructor } from "../models/scope.ts";
export {
  Authorization,
  authorizationFromClaims,
} from "../models/authorization.ts";
export type {
  AuthorizationFailure,
  AuthorizationInit,
  OrganizationContext,
  RequireConditions,
} from "../models/authorization.ts";

export {
  AccessDeniedError,
  AuthorizationPendingError,
  ExpiredTokenError,
  InsufficientPermissionsError,
  InsufficientScopeError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTokenError,
  isOAuth2Error,
  OAuth2Error,
  ServerError,
  SlowDownError,
  TemporarilyUnavailableError,
  toOAuth2Error,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
  UnsupportedTokenTypeError,
} from "../errors.ts";
export type {
  OAuth2ErrorClass,
  OAuth2ProblemDetailsExtensions,
} from "../errors.ts";

export type { TokenReaderInterface } from "./services/token.ts";

export {
  checkRedirectUriPattern,
  isRedirectUriPattern,
  matchRedirectUri,
} from "./redirect-uri.ts";
export type {
  IsPublicSuffix,
  RedirectUriPatternRule,
  RedirectUriPatternViolation,
} from "./redirect-uri.ts";
