/**
 * Internal buffer conversion shared by the modules that call Web Crypto.
 *
 * @module
 */

/**
 * Copy to a standalone `ArrayBuffer` to satisfy `BufferSource` on runtimes that
 * narrow `Uint8Array<ArrayBufferLike>` away from `ArrayBuffer`.
 */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}
