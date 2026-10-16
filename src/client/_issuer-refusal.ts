import { InvalidRequestError, type OAuth2Error } from "../errors.ts";

const refusals = new WeakSet<Error>();

export function issuerRefusal(message: string): OAuth2Error {
  const error = new InvalidRequestError(message);
  refusals.add(error);
  return error;
}

export function isIssuerRefusal(error: unknown): error is OAuth2Error {
  return error instanceof Error && refusals.has(error);
}

export const DUPLICATE_ISS_PROBLEM =
  "the authorization response carries more than one `iss` (RFC 9207)";

/**
 * Why an authorization response's `iss` values (RFC 9207 §2.4) are refused, or
 * `undefined` when they are accepted: more than one value, none when
 * `required`, or one that is not exactly one of `accepted`.
 */
export function authorizationResponseIssuerProblem(
  received: readonly string[],
  accepted: readonly string[],
  required: boolean,
): string | undefined {
  if (received.length > 1) return DUPLICATE_ISS_PROBLEM;
  const [iss] = received;
  if (iss === undefined) {
    if (!required) return undefined;
    return (
      "the authorization response is missing `iss`, which the issuer " +
      "advertises with `authorization_response_iss_parameter_supported` " +
      "(RFC 9207 §2.4)"
    );
  }
  if (accepted.includes(iss)) return undefined;
  return (
    "the authorization response `iss` does not match the issuer the " +
    "request was sent to (RFC 9207 §2.4)"
  );
}
