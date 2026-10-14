/**
 * Internal bounded body reader for the request bodies the endpoints parse
 * before they have authenticated the caller, and for the responses the
 * package reads from the servers it calls.
 *
 * @module
 */

/**
 * The default cap on those bodies: 64 KiB. The largest legitimate field is a
 * JWT (`id_token_hint`, `logout_token`, an introspected access token), and a
 * token that also travels in an `Authorization` header already has to fit
 * the 8–16 KiB header limits common to servers and proxies.
 */
export const DEFAULT_MAX_BODY_BYTES: number = 64 * 1024;

/**
 * The default cap on a form body searched for an RFC 6750 §2.2
 * `access_token`: 16 KiB, Node's default limit on a request's whole header
 * block, so any token a client could send as `Authorization: Bearer` fits.
 */
export const DEFAULT_MAX_TOKEN_BODY_BYTES: number = 16 * 1024;

/**
 * The default cap on an introspection response: 64 KiB, the same cap the
 * clients apply to every authorization-server response.
 */
export const DEFAULT_MAX_RESPONSE_BYTES: number = 64 * 1024;

/**
 * The default cap on a discovery document or JWKS: 256 KiB, room for dozens
 * of RSA keys that each carry an X.509 certificate chain.
 */
export const DEFAULT_MAX_KEY_SET_BYTES: number = 256 * 1024;

/**
 * Throws a `RangeError` naming `option` unless `maxBodyBytes` is a positive
 * safe integer.
 */
export function assertMaxBodyBytes(maxBodyBytes: number, option: string): void {
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1) {
    throw new RangeError(
      `${option} must be a positive integer, got ${maxBodyBytes}`,
    );
  }
}

/**
 * Reads `request`'s body — or a response's — counting bytes as they arrive,
 * and returns `null` once it exceeds `maxBytes`, cancelling the stream rather
 * than draining it. A `Content-Length` over the cap is refused without
 * reading; one under it is not trusted. Consumes the body unless
 * `keepReadable` is set, which reads a clone and leaves the original readable
 * (a refusal cancels both). Rejects if the stream errors or was already read.
 */
export async function readBoundedBody(
  request: Request | Response,
  maxBytes: number,
  options: { keepReadable?: boolean } = {},
): Promise<Uint8Array<ArrayBuffer> | null> {
  if (!request.body) return new Uint8Array();
  if (Number(request.headers.get("content-length")) > maxBytes) {
    request.body.cancel().catch(() => {});
    return null;
  }

  const body = options.keepReadable ? request.clone().body! : request.body;
  const bytes = await readUpTo(body, maxBytes);
  if (!bytes && options.keepReadable) request.body.cancel().catch(() => {});
  return bytes;
}

/**
 * Reads at most `maxBytes` of `request`'s body from a clone and returns
 * `null` once it exceeds `maxBytes`, cancelling only the clone. The original
 * stays readable either way, holding no more than what the clone pulled, so
 * the caller's own handling of the body — or of its absence — is unchanged.
 * A `Content-Length` over the cap returns `null` without reading. Rejects if
 * the body was already read.
 */
export async function peekBoundedBody(
  request: Request,
  maxBytes: number,
): Promise<Uint8Array<ArrayBuffer> | null> {
  if (!request.body) return new Uint8Array();
  if (Number(request.headers.get("content-length")) > maxBytes) return null;
  return await readUpTo(request.clone().body!, maxBytes);
}

async function readUpTo(
  body: ReadableStream<Uint8Array>,
  maxBytes: number,
): Promise<Uint8Array<ArrayBuffer> | null> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > maxBytes) {
      reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
