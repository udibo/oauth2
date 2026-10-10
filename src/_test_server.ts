import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { serve as serveNode } from "@hono/node-server";

/** An HTTP server bound to an ephemeral loopback port for one test. */
export interface TestServer extends AsyncDisposable {
  readonly hostname: string;
  readonly port: number;
  /** `http://<hostname>:<port>`, with no trailing slash. */
  readonly origin: string;
  /** Closes the listener and every open connection. */
  shutdown(): Promise<void>;
}

/**
 * Starts `handler` on an ephemeral port of `hostname` and resolves once it
 * accepts connections. Declare it with `await using`, or call `shutdown()`
 * in a `finally`, so no socket outlives the test.
 */
export async function serve(
  handler: (request: Request) => Response | Promise<Response>,
  hostname = "127.0.0.1",
): Promise<TestServer> {
  const server = serveNode({
    fetch: handler,
    port: 0,
    hostname,
    overrideGlobalObjects: false,
  }) as Server;
  if (!server.listening) {
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
  }
  const { port } = server.address() as AddressInfo;
  let closed: Promise<void> | undefined;
  const shutdown = (): Promise<void> => {
    closed ??= new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
      server.closeAllConnections();
    });
    return closed;
  };
  return {
    hostname,
    port,
    origin: `http://${hostname}:${port}`,
    shutdown,
    [Symbol.asyncDispose]: shutdown,
  };
}
