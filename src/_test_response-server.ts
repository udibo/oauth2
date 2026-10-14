import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";

/**
 * How a route answers. `"length"` sends the whole body with an accurate
 * `Content-Length`; `"chunked"` sends it in 1 KiB chunks with none;
 * `"declared"` sends `declaredLength` as the `Content-Length` but writes
 * only `body` and then hangs; `"endless"` writes `body` and then 16 KiB of
 * JSON whitespace every millisecond, chunked, until the client goes away —
 * paced so a reader that never stops buffers megabytes, not gigabytes,
 * before its deadline. `"stall"` sends the headers at once, then `body`
 * (chunked, so an empty one stalls before the first body byte), then nothing
 * more; `"silent"` never answers at all.
 */
export type Reply =
  | {
      status?: number;
      contentType?: string;
      body: string;
      transfer: "length" | "chunked" | "endless" | "stall";
    }
  | { transfer: "silent" }
  | {
      status?: number;
      contentType?: string;
      body: string;
      transfer: "declared";
      declaredLength: number;
    };

/** A local server answering each path with the {@link Reply} it names. */
export interface ReplyServer extends AsyncDisposable {
  readonly origin: string;
  /** Requests the server has received. */
  readonly requests: number;
  /**
   * Resolves once the client has closed a response before it finished: the
   * reader cancelled the body rather than draining it.
   */
  readonly abandoned: Promise<void>;
}

const CHUNK_BYTES = 1024;
const PADDING_BURST = " ".repeat(16 * CHUNK_BYTES);

/**
 * Starts a server on an ephemeral loopback port whose responses come from
 * `route`. Declare it with `await using` so no socket outlives the test.
 */
export async function serveReplies(
  route: (pathname: string) => Reply,
): Promise<ReplyServer> {
  let requests = 0;
  let markAbandoned!: () => void;
  const abandoned = new Promise<void>((resolve) => {
    markAbandoned = resolve;
  });

  const server: Server = createServer(
    (request: IncomingMessage, response: ServerResponse) => {
      requests++;
      const reply = route(new URL(request.url ?? "/", "http://x").pathname);
      response.on("close", () => {
        if (!response.writableFinished) markAbandoned();
      });
      if (reply.transfer === "silent") return;
      const headers: Record<string, string> = {
        "content-type": reply.contentType ?? "application/json",
      };
      const status = reply.status ?? 200;
      if (reply.transfer === "length") {
        headers["content-length"] = String(Buffer.byteLength(reply.body));
        response.writeHead(status, headers);
        response.end(reply.body);
      } else if (reply.transfer === "declared") {
        headers["content-length"] = String(reply.declaredLength);
        response.writeHead(status, headers);
        response.write(reply.body);
      } else if (reply.transfer === "chunked") {
        response.writeHead(status, headers);
        const bytes = Buffer.from(reply.body);
        for (let offset = 0; offset < bytes.byteLength; offset += CHUNK_BYTES) {
          response.write(bytes.subarray(offset, offset + CHUNK_BYTES));
        }
        response.end();
      } else if (reply.transfer === "stall") {
        response.writeHead(status, headers);
        response.flushHeaders();
        if (reply.body) response.write(reply.body);
      } else {
        response.writeHead(status, headers);
        response.write(reply.body);
        const pump = setInterval(() => {
          if (response.destroyed) clearInterval(pump);
          else response.write(PADDING_BURST);
        }, 1);
        response.on("close", () => clearInterval(pump));
      }
    },
  );
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    get requests() {
      return requests;
    },
    abandoned,
    async [Symbol.asyncDispose]() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/**
 * A JSON object of exactly `bytes` bytes, padded inside a string member so
 * it stays valid JSON: `{"pad":"xxx…"}` merged with `fields`.
 */
export function jsonOfSize(
  bytes: number,
  fields: Record<string, unknown> = {},
): string {
  const base = JSON.stringify({ ...fields, pad: "" });
  const padding = bytes - Buffer.byteLength(base);
  if (padding < 0) throw new RangeError(`${base} is already over ${bytes}`);
  return JSON.stringify({ ...fields, pad: "x".repeat(padding) });
}
