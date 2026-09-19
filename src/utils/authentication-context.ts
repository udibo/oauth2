import type { AuthenticationContext } from "../models/authentication.ts";

/** Copies verified event claims without sharing mutable method arrays. */
export function snapshotAuthenticationContext(
  context: AuthenticationContext | undefined,
): AuthenticationContext | undefined {
  if (context === undefined) return undefined;
  return Object.freeze({
    ...(context.auth_time === undefined
      ? {}
      : { auth_time: context.auth_time }),
    ...(context.acr === undefined ? {} : { acr: context.acr }),
    ...(context.amr === undefined
      ? {}
      : { amr: Object.freeze([...context.amr]) }),
  });
}
