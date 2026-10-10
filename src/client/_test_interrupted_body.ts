import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";

/** A local endpoint whose response never finishes arriving. */
export interface InterruptedBodyServer extends AsyncDisposable {
  url: string;
  /** Requests the server has received. */
  readonly requests: number;
}

async function listen(
  onRequest: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<InterruptedBodyServer> {
  let requests = 0;
  const server: Server = createServer((request, response) => {
    requests++;
    onRequest(request, response);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/`,
    get requests() {
      return requests;
    },
    async [Symbol.asyncDispose]() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/**
 * Accepts every request and never sends response headers: each request hangs
 * until the client gives up or the server is disposed.
 */
export function serveNoHeaders(): Promise<InterruptedBodyServer> {
  return listen(() => {});
}

/**
 * Serves a `200` JSON response that sends its headers and the first bytes of
 * the body, then stalls until the server is disposed.
 */
export function serveStalledBody(
  partial: string,
): Promise<InterruptedBodyServer> {
  return listen((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.write(partial);
  });
}

/**
 * Answers every connection with a `200` whose `content-length` promises more
 * body than it sends, then closes the connection.
 */
export function serveDroppedBody(
  partial: string,
): Promise<InterruptedBodyServer> {
  return listen((_request, response) => {
    response.writeHead(200, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(partial) + 1024,
      connection: "close",
    });
    response.write(partial, () => response.socket?.destroy());
  });
}
