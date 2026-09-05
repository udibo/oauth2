/**
 * The `authorization_code` token exchange the plain-OAuth2 connectors post
 * through — {@link githubProvider}, {@link oauth2Provider} (and its
 * {@link discordProvider} preset), and {@link appleProvider}.
 * {@link oidcProvider}, and {@link googleProvider} on top of it, exchange via
 * `OAuth2Client` instead and do not reach this module.
 *
 * Not part of the public API. Split out of `_shared.ts` so the ladder — the one
 * place a provider's bytes become an error message or a token — sits next to
 * the tests that pin it.
 *
 * @module
 */

import { describeError, sanitizeProviderText } from "./_shared.ts";
import { ExternalAuthError } from "./errors.ts";

/** Response bytes accepted from a token endpoint before the exchange is refused. */
export const MAX_TOKEN_RESPONSE_BYTES = 64 * 1024;

/** Wall-clock budget for the exchange, covering the connect and the body read. */
export const TOKEN_EXCHANGE_TIMEOUT_MS = 10_000;

/** Input for {@link runTokenExchange}. */
export interface TokenExchangeInput {
  /** Provider id carried on every thrown {@link ExternalAuthError}. */
  provider: string;
  /** Human-readable provider name used in the error messages. */
  displayName: string;
  /** The provider's token endpoint. */
  endpoint: string;
  /** The form body to POST; client authentication must already be in it. */
  body: URLSearchParams;
  /**
   * The token-response field the connector cannot proceed without — usually
   * `"access_token"`, or `"id_token"` for a connector that only reads claims.
   */
  requiredField: string;
  /**
   * Fetch implementation for the exchange. A wrapper **must forward the whole
   * `RequestInit`** — `redirect` and `signal` in particular. They are the only
   * channel the redirect refusal and the deadline reach the transport, so a
   * wrapper that rebuilds `init` from scratch silently reopens the credential
   * replay hole. `createGuardedFetch` forwards both.
   */
  fetch: typeof fetch;
  /** Guidance appended when a failure carries no OAuth2 error code. */
  httpErrorHint: string;
  /** Guidance appended for the OAuth2 error code the provider reported. */
  tokenErrorHint: (code: string | undefined) => string;
  /** Exchange deadline. Defaults to {@link TOKEN_EXCHANGE_TIMEOUT_MS}. */
  timeoutMs?: number;
}

/** A token response that cleared every step of {@link runTokenExchange}. */
export interface TokenExchangeResult {
  /** The value of {@link TokenExchangeInput.requiredField}, non-empty. */
  value: string;
  /** The full token-response body, for provider-specific fields. */
  raw: Record<string, unknown>;
}

/**
 * Posts the authorization code and returns a token response known to be a JSON
 * object carrying `requiredField`. Every failure throws
 * {@link ExternalAuthError} `provider_error`; a redirect is refused rather than
 * followed, so the client credentials are never replayed to another host.
 */
export async function runTokenExchange(
  input: TokenExchangeInput,
): Promise<TokenExchangeResult> {
  const { provider, displayName, requiredField } = input;
  const fail = (message: string, options?: ErrorOptions) =>
    new ExternalAuthError(provider, "provider_error", message, options);

  let res: Response;
  try {
    res = await input.fetch(input.endpoint, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: input.body,
      redirect: "manual",
      signal: AbortSignal.timeout(input.timeoutMs ?? TOKEN_EXCHANGE_TIMEOUT_MS),
    });
  } catch (error) {
    throw fail(
      `could not reach the ${displayName} token endpoint ` +
        `(${describeError(error)}). Try again.`,
      { cause: error },
    );
  }

  if (isRedirect(res)) {
    await res.body?.cancel();
    throw fail(
      `token endpoint answered with a redirect (HTTP ${res.status}), which ` +
        `this exchange refuses to follow — replaying the client credentials ` +
        `to another host would leak them. Point the connector at the ` +
        `${displayName} token endpoint directly.`,
    );
  }

  let body: BoundedBody = { text: "", oversized: false };
  let readError: unknown;
  try {
    body = await readBoundedBody(res);
  } catch (error) {
    readError = error;
  }

  if (!res.ok) {
    const reported = reportedOAuth2Error(safeParseJson(body.text));
    if (reported) {
      throw fail(
        `token endpoint responded with HTTP ${res.status}: ` +
          `"${reported.code}"${reported.description}${reported.uri}. ` +
          `${input.tokenErrorHint(reported.code)} ${input.httpErrorHint}`,
      );
    }
    throw fail(
      `token endpoint responded with HTTP ${res.status}` +
        `${errorBodySuffix(body.text)}${body.oversized ? " (truncated)" : ""}` +
        `. ${input.httpErrorHint}`,
    );
  }

  if (readError) {
    throw fail(
      `the ${displayName} token endpoint response could not be read ` +
        `(${describeError(readError)}).`,
      { cause: readError },
    );
  }
  if (body.oversized) {
    throw fail(
      `the ${displayName} token endpoint response exceeded ` +
        `${MAX_TOKEN_RESPONSE_BYTES} bytes — refusing to parse a token ` +
        `response this large.`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body.text);
  } catch (error) {
    throw fail(
      `the ${displayName} token endpoint returned ` +
        `${describeMediaType(res)} that was not valid JSON ` +
        `(${describeError(error)}).`,
      { cause: error },
    );
  }
  if (!isJsonObject(parsed)) {
    throw fail(
      `the ${displayName} token endpoint returned ` +
        `${describeJsonValue(parsed)} where a JSON object was required.`,
    );
  }

  const reported = reportedOAuth2Error(parsed);
  const value = parsed[requiredField];
  if (reported || typeof value !== "string" || value.length === 0) {
    const code = reported?.code ?? `missing ${requiredField}`;
    throw fail(
      `token exchange failed: "${code}"${reported?.description ?? ""}` +
        `${reported?.uri ?? ""}. ${input.tokenErrorHint(reported?.code)}`,
    );
  }
  return { value, raw: parsed };
}

interface BoundedBody {
  text: string;
  oversized: boolean;
}

async function readBoundedBody(res: Response): Promise<BoundedBody> {
  if (!res.body) return { text: "", oversized: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let oversized = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > MAX_TOKEN_RESPONSE_BYTES) {
        oversized = true;
        break;
      }
      chunks.push(value);
      size += value.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const buffer = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { text: new TextDecoder().decode(buffer), oversized };
}

interface ReportedOAuth2Error {
  code: string;
  description: string;
  uri: string;
}

function reportedOAuth2Error(value: unknown): ReportedOAuth2Error | null {
  if (!isJsonObject(value)) return null;
  const code = sanitizeProviderText(asString(value.error) ?? "");
  if (!code) return null;
  const description = sanitizeProviderText(
    asString(value.error_description) ?? "",
  );
  const uri = sanitizeProviderText(asString(value.error_uri) ?? "");
  return {
    code,
    description: description ? ` (${description})` : "",
    uri: uri ? ` [${uri}]` : "",
  };
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function errorBodySuffix(text: string): string {
  const snippet = sanitizeProviderText(text);
  return snippet ? `: ${snippet}` : "";
}

function safeParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function isRedirect(res: Response): boolean {
  return res.status >= 300 && res.status < 400;
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
