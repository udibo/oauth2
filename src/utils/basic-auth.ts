/**
 * HTTP Basic Authentication utilities.
 * @module
 */

import { InvalidClientError } from "../errors.ts";

const CREDENTIALS = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([\w-.~+/]+=*) *$/;
const NAME_PASS = /^([^:]+):(.*)$/;
const NOT_FORM_SAFE = /[!'()~]/g;
const ENCODED_SPACE = /%20/g;
const PLUS = /\+/g;

function formUrlEncode(value: string): string {
  return encodeURIComponent(value)
    .replace(
      NOT_FORM_SAFE,
      (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
    )
    .replace(ENCODED_SPACE, "+");
}

function formUrlDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(PLUS, " "));
  } catch {
    return value;
  }
}

/** Parsed basic authentication credentials. */
export interface BasicAuth {
  /** Username portion (the segment before the first colon). */
  name: string;
  /** Password portion (everything after the first colon). */
  pass: string;
}

/**
 * Parses basic authentication credentials from an Authorization header.
 *
 * Both segments are decoded from `application/x-www-form-urlencoded` form, as
 * RFC 6749 section 2.3.1 requires of client credentials, so a client id or
 * secret containing `+`, a space, `%`, `:`, or non-ASCII survives the round
 * trip. A segment that is not valid percent-encoding is taken verbatim, so a
 * client that sends such characters un-encoded still authenticates.
 *
 * @param authorization The Authorization header value
 * @returns The parsed credentials
 * @throws {InvalidClientError} If the header is missing or malformed
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
 */
export function parseBasicAuth(authorization: string | null): BasicAuth {
  if (!authorization) {
    throw new InvalidClientError("authorization header required");
  }
  let match = CREDENTIALS.exec(authorization);
  if (!match) {
    throw new InvalidClientError("unsupported authorization header");
  }
  let value: string;
  try {
    value = atob(match[1]);
  } catch {
    throw new InvalidClientError(
      "authorization header is not correctly encoded",
    );
  }
  match = NAME_PASS.exec(value);
  if (!match) {
    throw new InvalidClientError("authorization header is malformed");
  }
  return {
    name: formUrlDecode(match[1]),
    pass: formUrlDecode(match[2]),
  };
}

/**
 * Encodes client credentials for HTTP Basic Authentication.
 *
 * Both values are `application/x-www-form-urlencoded` before base64, as RFC
 * 6749 section 2.3.1 requires: that keeps `+`, spaces, `%`, and `:` unambiguous
 * on the wire and makes a non-ASCII secret encodable at all. Credentials made
 * only of `A-Z`, `a-z`, `0-9`, `-`, `_`, `.` and `*` encode byte-identically to
 * their raw form; every other character, `~` included, is percent-encoded.
 *
 * @param clientId The client ID
 * @param clientSecret The client secret
 * @returns The encoded Authorization header value
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
 */
export function encodeBasicAuth(
  clientId: string,
  clientSecret: string,
): string {
  return `Basic ${
    btoa(`${formUrlEncode(clientId)}:${formUrlEncode(clientSecret)}`)
  }`;
}

/**
 * Tries to parse basic authentication credentials from an Authorization header.
 * Returns undefined if the header is missing or not Basic auth. Decodes both
 * segments the same way {@link parseBasicAuth} does.
 *
 * @param authorization The Authorization header value
 * @returns The parsed credentials or undefined
 */
export function tryParseBasicAuth(
  authorization: string | null,
): BasicAuth | undefined {
  if (!authorization) return undefined;
  const match = CREDENTIALS.exec(authorization);
  if (!match) return undefined;
  try {
    const value = atob(match[1]);
    const namePass = NAME_PASS.exec(value);
    if (!namePass) return undefined;
    return {
      name: formUrlDecode(namePass[1]),
      pass: formUrlDecode(namePass[2]),
    };
  } catch {
    return undefined;
  }
}
