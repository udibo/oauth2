import { InvalidRequestError } from "../errors.ts";
import type {
  AuthenticationContext,
  AuthenticationRequest,
} from "../models/authentication.ts";

/** The `prompt` values the authorization server enforces on its own. */
export const DEFAULT_PROMPT_VALUES_SUPPORTED: readonly string[] = Object.freeze(
  ["none", "login", "consent"],
);

/**
 * What an `authenticateUser` callback reports about the authentication behind
 * the user it returns, as {@linkcode satisfiesAuthenticationRequest} reads it.
 */
export interface AuthenticationOutcome {
  /** The verified authentication event, when known. */
  authenticationContext?: AuthenticationContext;
  /**
   * `true` only when the user actively authenticated in response to this
   * authorization request, which is what `prompt=login` and `max_age=0` ask
   * for. A session that merely exists, or was refreshed, is not that.
   */
  reauthenticated?: boolean;
}

const MAX_AUTH_TIME_SKEW_SECONDS = 60;

function spaceDelimited(value: string | null): string[] {
  return [...new Set((value ?? "").split(" ").filter(Boolean))];
}

export function assertSupportedValues(
  name: string,
  values: readonly string[],
): readonly string[] {
  if (
    values.some(
      (value) => typeof value !== "string" || !/^[\x21-\x7e]+$/.test(value),
    )
  ) {
    throw new TypeError(
      `${name} entries must be non-empty strings of visible ASCII without spaces`,
    );
  }
  return Object.freeze([...new Set(values)]);
}

/**
 * Validates the `prompt`, `max_age` and `acr_values` of an authorization
 * request. Parameters sent without a value are treated as omitted (OIDC Core
 * §3.1.2.1).
 *
 * @throws {InvalidRequestError} For a repeated parameter, a `prompt` value not
 *   in `promptValuesSupported`, `none` combined with another `prompt` value, or
 *   a `max_age` that is not a non-negative integer.
 */
export function parseAuthenticationRequest(
  params: URLSearchParams,
  promptValuesSupported: readonly string[],
): AuthenticationRequest {
  for (const name of ["prompt", "max_age", "acr_values"]) {
    if (params.getAll(name).length > 1) {
      throw new InvalidRequestError(`${name} parameter must not be repeated`);
    }
  }
  const prompt = spaceDelimited(params.get("prompt"));
  if (prompt.some((value) => !promptValuesSupported.includes(value))) {
    throw new InvalidRequestError("prompt value not supported");
  }
  if (prompt.includes("none") && prompt.length > 1) {
    throw new InvalidRequestError(
      "prompt=none cannot be combined with other prompt values",
    );
  }
  const rawMaxAge = params.get("max_age") || undefined;
  if (
    rawMaxAge !== undefined &&
    (!/^\d+$/.test(rawMaxAge) || !Number.isSafeInteger(Number(rawMaxAge)))
  ) {
    throw new InvalidRequestError("max_age must be a non-negative integer");
  }
  return Object.freeze({
    prompt: Object.freeze(prompt),
    ...(rawMaxAge === undefined ? {} : { maxAge: Number(rawMaxAge) }),
    acrValues: Object.freeze(spaceDelimited(params.get("acr_values"))),
  });
}

/**
 * Why `outcome` does not satisfy `request`, as an `error_description`, or
 * `undefined` when it does.
 */
export function authenticationShortfall(
  request: AuthenticationRequest,
  outcome: AuthenticationOutcome,
  now: number,
): string | undefined {
  const reauthenticated = outcome.reauthenticated === true;
  if (request.prompt.includes("login") && !reauthenticated) {
    return "prompt=login requires the user to authenticate again";
  }
  if (request.maxAge === 0 && !reauthenticated) {
    return "max_age=0 requires the user to authenticate again";
  }
  if (request.maxAge === undefined) return undefined;
  const authTime = outcome.authenticationContext?.auth_time;
  if (typeof authTime !== "number" || !Number.isFinite(authTime)) {
    return "max_age requires the time the user authenticated";
  }
  const age = Math.floor(now / 1000) - authTime;
  if (age < -MAX_AUTH_TIME_SKEW_SECONDS) {
    return "the user's authentication time is in the future";
  }
  if (reauthenticated) return undefined;
  if (age > request.maxAge) {
    return "the user's last authentication is older than max_age";
  }
  return undefined;
}

/**
 * Whether an authentication meets the request's `prompt=login` and `max_age`
 * controls — the check the authorization server applies to what
 * `authenticateUser` returns before it issues a code. Call it from
 * `authenticateUser` with the session's event to decide whether to send the
 * user to sign in again instead of returning them.
 *
 * `prompt=login` and `max_age=0`, which OIDC Core makes equivalent, need
 * `reauthenticated: true`. Any `max_age` needs a recorded `auth_time`, since
 * the ID token must carry one, no older than `max_age` seconds unless the user
 * re-authenticated for this request, and never more than a minute in the
 * future. `acr_values` is a preference and never fails the check.
 *
 * @param now The current time in epoch milliseconds. Defaults to `Date.now()`.
 *
 * @example
 * ```ts
 * import { satisfiesAuthenticationRequest } from "@udibo/oauth2/server";
 *
 * const fresh = satisfiesAuthenticationRequest(
 *   { prompt: [], maxAge: 300, acrValues: [] },
 *   { authenticationContext: { auth_time: Math.floor(Date.now() / 1000) } },
 * );
 * ```
 */
export function satisfiesAuthenticationRequest(
  request: AuthenticationRequest,
  outcome: AuthenticationOutcome,
  now: number = Date.now(),
): boolean {
  return authenticationShortfall(request, outcome, now) === undefined;
}
