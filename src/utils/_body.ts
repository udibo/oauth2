/**
 * Internal bounded request-body reader for the endpoints that parse a body
 * before they have authenticated the caller.
 *
 * @module
 */

/**
 * The default cap on those bodies: 64 KiB. The largest legitimate field is a
 * JWT (`id_token_hint`, `logout_token`, an introspected access token), and a
 * token that also travels in an `Authorization` header already has to fit
 * the 8–16 KiB header limits common to servers and proxies.
 */
export const DEFAULT_MAX_BODY_BYTES = 64 * 1024;

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
 * Reads `request`'s body, counting bytes as they arrive, and returns `null`
 * once it exceeds `maxBytes` — cancelling the stream rather than draining it.
 * A `Content-Length` over the cap is refused without reading; one under it is
 * not trusted. Consumes the body unless `keepReadable` is set, which reads a
 * clone and leaves the original readable (a refusal cancels both). Rejects if
 * the stream errors or was already read.
 */
export async function readBoundedBody(
  request: Request,
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
