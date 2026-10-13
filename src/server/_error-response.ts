/**
 * Serializes OAuth2 errors into responses for the resource and authorization
 * servers.
 *
 * @module
 */

import type { OAuth2Error } from "../errors.ts";

/** Copies the error's headers onto the response, except `Content-Type`, which the serializer owns. */
export function copyErrorHeaders(
  oauth2Error: OAuth2Error,
  response: Response,
): Response {
  for (const [key, value] of oauth2Error.headers) {
    if (key.toLowerCase() === "content-type") continue;
    response.headers.set(key, value);
  }
  return response;
}

/** The RFC 6749 §5.2 error response: `{ error, error_description?, error_uri? }` as `application/json`, carrying the error's headers. */
export function oauth2ErrorResponse(oauth2Error: OAuth2Error): Response {
  const body: Record<string, string> = {
    error: oauth2Error.extensions.error ?? "server_error",
  };
  const description =
    oauth2Error.extensions.error_description ?? oauth2Error.exposedMessage;
  if (description) {
    body.error_description = description;
  }
  const errorUri = oauth2Error.extensions.error_uri ?? oauth2Error.type;
  if (errorUri) {
    body.error_uri = errorUri;
  }
  return copyErrorHeaders(
    oauth2Error,
    new Response(JSON.stringify(body), {
      status: oauth2Error.status,
      headers: { "Content-Type": "application/json;charset=UTF-8" },
    }),
  );
}
