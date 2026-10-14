/**
 * Not part of the public API. The bounded JSON read the token readers apply
 * to the responses of the authorization server they call.
 *
 * @module
 */

import { ServerError, TemporarilyUnavailableError } from "../errors.ts";
import { readBoundedBody } from "../utils/_body.ts";

/**
 * Parses `response`'s body as JSON, reading at most `maxBytes`. `label`
 * names the response in error messages.
 *
 * @throws {ServerError} When the body exceeds `maxBytes` (the read stops and
 *   the body is cancelled) or is not JSON.
 * @throws {TemporarilyUnavailableError} When the body stops arriving before it
 *   is complete: the deadline fired or the connection dropped mid-body.
 */
export async function readResponseJson(
  response: Response,
  maxBytes: number,
  label: string,
): Promise<unknown> {
  let bytes: Uint8Array | null;
  try {
    bytes = await readBoundedBody(response, maxBytes);
  } catch (cause) {
    throw new TemporarilyUnavailableError(`${label} request failed`, { cause });
  }
  if (!bytes) {
    throw new ServerError(`${label} response exceeded ${maxBytes} bytes`);
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (cause) {
    throw new ServerError(`${label} response was not JSON`, { cause });
  }
}
