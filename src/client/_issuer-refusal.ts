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
