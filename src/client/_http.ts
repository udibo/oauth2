/**
 * The response ladder every {@link DirectClient} network call climbs: bounded
 * read, deadline, redirect refusal, JSON validation, RFC 6749 §5.2 error
 * mapping.
 *
 * Not part of the public API. The authorization server's bytes become either a
 * typed {@link OAuth2Error} or a validated JSON object here and nowhere else,
 * so the guards sit next to the tests that pin them.
 *
 * @module
 */

import {
  AccessDeniedError,
  AuthorizationPendingError,
  ExpiredTokenError,
  InsufficientScopeError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTokenError,
  type OAuth2Error,
  OAuth2Error as OAuth2ErrorClass,
  type OAuth2ErrorClass as OAuth2ErrorClassType,
  ServerError,
  SlowDownError,
  TemporarilyUnavailableError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
  UnsupportedTokenTypeError,
} from "../errors.ts";
import { sanitizeProviderText } from "../utils/text.ts";

/** Response bytes accepted from an endpoint before the call is refused. */
export const MAX_RESPONSE_BYTES = 64 * 1024;

/** Wall-clock budget for one call, covering the connect and the body read. */
export const REQUEST_TIMEOUT_MS = 10_000;

/**
 * Maps an OAuth2 error code to the specific error class so callers can
 * `catch (e) { if (e instanceof InvalidGrantError) … }` instead of
 * inspecting `e.extensions.error` at every call site.
 */
const ERROR_CLASS_BY_CODE: Record<string, OAuth2ErrorClassType> = {
  access_denied: AccessDeniedError,
  authorization_pending: AuthorizationPendingError,
  expired_token: ExpiredTokenError,
  insufficient_scope: InsufficientScopeError,
  invalid_client: InvalidClientError,
  invalid_grant: InvalidGrantError,
  invalid_request: InvalidRequestError,
  invalid_scope: InvalidScopeError,
  invalid_token: InvalidTokenError,
  server_error: ServerError,
  slow_down: SlowDownError,
  temporarily_unavailable: TemporarilyUnavailableError,
  unauthorized_client: UnauthorizedClientError,
  unsupported_grant_type: UnsupportedGrantTypeError,
  unsupported_response_type: UnsupportedResponseTypeError,
  unsupported_token_type: UnsupportedTokenTypeError,
};

/** How a call describes itself in an error message, e.g. `"token endpoint"`. */
export type Endpoint = string;

/** How {@link sendGuarded} treats a `3xx`. */
export type RedirectPolicy = "refuse" | "follow";

/**
 * Sends one request with a deadline.
 *
 * With the default `"refuse"` policy a `3xx` throws rather than being
 * followed: these requests carry client credentials, an authorization code, a
 * refresh token, or a bearer token, and replaying any of them at whatever host
 * the response names would hand the secret to that host. Discovery passes
 * `"follow"` — it sends no credential, and the mix-up it could otherwise
 * enable is closed by validating the `issuer` the document reports.
 *
 * @param fetchImpl The client's resolved `fetch`.
 * @param url Where to send it.
 * @param init Request options; `redirect` and `signal` are supplied here. A
 * caller-supplied `signal` is honoured *in addition to* the deadline.
 * @param what The endpoint's name, for error messages.
 * @param options `redirect` policy and `timeoutMs` deadline.
 * @returns The response, which may still be a non-OK status.
 * @throws {ServerError} when the request cannot be made, times out, or (under
 * `"refuse"`) answers with a redirect.
 */
export async function sendGuarded(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  what: Endpoint,
  options: { redirect?: RedirectPolicy; timeoutMs?: number } = {},
): Promise<Response> {
  const redirect: RedirectPolicy = options.redirect ?? "refuse";
  const deadline = AbortSignal.timeout(options.timeoutMs ?? REQUEST_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetchImpl(url, {
      ...init,
      redirect: redirect === "refuse" ? "manual" : "follow",
      signal: init.signal ? AbortSignal.any([init.signal, deadline]) : deadline,
    });
  } catch (error) {
    throw new ServerError(
      `could not reach the ${what} (${describeError(error)})`,
      { cause: error },
    );
  }
  if (redirect === "refuse" && res.status >= 300 && res.status < 400) {
    await res.body?.cancel();
    throw new ServerError(
      `the ${what} answered with a redirect (HTTP ${res.status}), which this ` +
        `client refuses to follow — replaying the request to another host ` +
        `would leak the credentials it carries`,
    );
  }
  return res;
}

/**
 * Reads a response as a JSON object, refusing anything else.
 *
 * A non-OK status becomes the typed {@link OAuth2Error} the body names, or a
 * {@link ServerError} carrying the status when it names nothing.
 *
 * @param res The response from {@link sendGuarded}.
 * @param what The endpoint's name, for error messages.
 * @returns The parsed JSON object.
 * @throws {OAuth2Error} on a non-OK status, an oversized body, a body that is
 * not valid JSON, or JSON that is not an object.
 */
export async function receiveJson(
  res: Response,
  what: Endpoint,
): Promise<Record<string, unknown>> {
  const body = await readBounded(res);

  if (!res.ok) throw errorFromBody(res, safeParse(body.text), what, body.text);

  if (body.truncated) {
    throw new ServerError(
      `the ${what} response exceeded ${MAX_RESPONSE_BYTES} bytes — refusing ` +
        `to parse a response this large`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body.text);
  } catch (error) {
    throw new ServerError(
      `the ${what} returned ${describeMediaType(res)} that was not valid ` +
        `JSON (${describeError(error)})`,
      { cause: error },
    );
  }
  if (!isJsonObject(parsed)) {
    throw new ServerError(
      `the ${what} returned ${describeJsonValue(parsed)} where a JSON ` +
        `object was required`,
    );
  }
  return parsed;
}

/**
 * Turns a non-OK response into the typed error its body names. Use for
 * endpoints whose success case carries no JSON (RFC 7009 revocation).
 *
 * @param res A non-OK response from {@link sendGuarded}.
 * @param what The endpoint's name, for error messages.
 * @returns The error to throw.
 */
export async function errorFromResponse(
  res: Response,
  what: Endpoint,
): Promise<OAuth2Error> {
  const body = await readBounded(res);
  return errorFromBody(res, safeParse(body.text), what, body.text);
}

/**
 * Enforces RFC 6749 §5.2 on a token response that arrived with a `2xx`.
 *
 * A server may report a failure in the body of a `200`; and a body with no
 * usable `access_token` is not a token response no matter what it says. Both
 * must throw here, because the alternative is persisting a bundle whose
 * `accessToken` is `undefined` and then sending every subsequent request with
 * no `Authorization` header at all.
 *
 * @param body The parsed token-endpoint response.
 * @param what The endpoint's name, for error messages.
 * @throws {OAuth2Error} when the body reports an error or carries no non-empty
 * string `access_token`.
 */
export function assertTokenResponse(
  body: Record<string, unknown>,
  what: Endpoint,
): void {
  const reported = reportedError(body);
  if (reported) throw buildError(reported);
  const accessToken = body.access_token;
  if (typeof accessToken !== "string" || accessToken.length === 0) {
    throw new ServerError(
      `the ${what} returned a success response with no "access_token"`,
    );
  }
}

/**
 * Requires a named non-empty string field on a `2xx` response body, and
 * rejects a body that reports an OAuth2 error alongside its `200`.
 *
 * @param body The parsed response.
 * @param field The field the caller cannot proceed without.
 * @param what The endpoint's name, for error messages.
 * @throws {OAuth2Error} when the body reports an error or lacks the field.
 */
export function assertField(
  body: Record<string, unknown>,
  field: string,
  what: Endpoint,
): void {
  const reported = reportedError(body);
  if (reported) throw buildError(reported);
  const value = body[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new ServerError(
      `the ${what} returned a success response with no "${field}"`,
    );
  }
}

/** As much of a body as the cap allows, and whether the cap cut it short. */
interface BoundedBody {
  text: string;
  truncated: boolean;
}

/**
 * Reads up to {@link MAX_RESPONSE_BYTES} and reports whether more was coming.
 *
 * Never throws for being too large: on a **failed** response the bytes are the
 * only place the OAuth2 error code lives, and refusing to look would turn a
 * `invalid_grant` that happens to arrive oversized into a generic transport
 * error — which reads as "retry later" instead of "this grant is dead", so the
 * client would keep presenting a revoked refresh token forever. Truncation is
 * reported instead, and the success path refuses it.
 */
async function readBounded(res: Response): Promise<BoundedBody> {
  if (!res.body) return { text: "", truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > MAX_RESPONSE_BYTES) {
        const room = MAX_RESPONSE_BYTES - size;
        if (room > 0) {
          chunks.push(value.subarray(0, room));
          size += room;
        }
        truncated = true;
        break;
      }
      chunks.push(value);
      size += value.byteLength;
    }
  } catch {
    return { text: decode(chunks, size), truncated: true };
  } finally {
    await reader.cancel().catch(() => {});
  }
  return { text: decode(chunks, size), truncated };
}

function decode(chunks: Uint8Array[], size: number): string {
  const buffer = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(buffer);
}

interface ReportedError {
  error: string;
  description?: string;
  uri?: string;
}

function reportedError(value: unknown): ReportedError | null {
  if (!isJsonObject(value)) return null;
  const error = value.error;
  if (typeof error !== "string" || error.length === 0) return null;
  return {
    error: sanitizeProviderText(error),
    description: typeof value.error_description === "string"
      ? sanitizeProviderText(value.error_description)
      : undefined,
    uri: typeof value.error_uri === "string"
      ? sanitizeProviderText(value.error_uri)
      : undefined,
  };
}

/**
 * `status` is passed through only when it is a real error status: a server
 * that reports `error` inside a `200` still needs a throwable, and `HttpError`
 * refuses to carry a 2xx.
 */
function buildError(reported: ReportedError, status?: number): OAuth2Error {
  const ErrorClass = ERROR_CLASS_BY_CODE[reported.error] ?? OAuth2ErrorClass;
  return new ErrorClass(reported.description ?? reported.error, {
    status: status !== undefined && status >= 400 ? status : undefined,
    extensions: {
      error: reported.error,
      error_description: reported.description,
      error_uri: reported.uri,
    },
  });
}

/**
 * Recovers the `error` code from a body that did not parse.
 *
 * The realistic reason a failed token response is unparseable here is that the
 * cap cut it mid-string — a server padding `error_description`, or a proxy
 * appending a page of HTML. The code itself is short and near the front, and
 * losing it costs the caller the difference between "this grant is dead" and
 * "something went wrong", so it is worth one bounded scan. Restricted to the
 * lowercase-underscore shape RFC 6749 §5.2 defines, so nothing else matches.
 */
function scanErrorCode(text: string): ReportedError | null {
  const match = /"error"\s*:\s*"([a-z_]{1,64})"/.exec(text);
  return match ? { error: match[1] } : null;
}

function errorFromBody(
  res: Response,
  parsed: unknown,
  what: Endpoint,
  raw = "",
): OAuth2Error {
  const reported = reportedError(parsed) ?? scanErrorCode(raw);
  if (reported) return buildError(reported, res.status);
  return new ServerError(
    `${what}: HTTP ${res.status}`,
    res.status >= 400 ? { status: res.status } : undefined,
  );
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function describeJsonValue(value: unknown): string {
  if (value === null) return "JSON null";
  if (Array.isArray(value)) return "a JSON array";
  return `a JSON ${typeof value}`;
}

function describeMediaType(res: Response): string {
  const contentType = sanitizeProviderText(
    res.headers.get("content-type")?.split(";")[0] ?? "",
  );
  return contentType ? `a "${contentType}" response` : "a response";
}

function describeError(error: unknown): string {
  if (error instanceof Error) {
    if (error.name === "TimeoutError") return "timed out";
    return sanitizeProviderText(error.message);
  }
  return sanitizeProviderText(String(error));
}
