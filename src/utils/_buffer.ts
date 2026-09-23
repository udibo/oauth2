/**
 * Internal buffer conversion shared by the modules that call Web Crypto.
 *
 * @module
 */

/**
 * Copies the viewed bytes into a standalone `ArrayBuffer`, for passing a
 * `Uint8Array<ArrayBufferLike>` where Web Crypto's `BufferSource` type does not
 * accept it.
 */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}
