/**
 * Node entrypoint: serves {@linkcode app} with `@hono/node-server`.
 *
 * `pnpm start` runs it; `pnpm dev` restarts it on file changes. Tests import
 * {@linkcode startServer} to bind a real socket on port 0.
 *
 * @module
 */

import { serve, type ServerType } from "@hono/node-server";
import type { AddressInfo } from "node:net";

import { config } from "./config.ts";
import app from "./main.ts";

/** A listening server and the origin it is reachable at. */
export interface RunningServer {
  server: ServerType;
  url: string;
  close(): Promise<void>;
}

/** Starts the example on `port` (default from config; `0` picks a free port). */
export function startServer(
  port: number = config.port,
): Promise<RunningServer> {
  return new Promise((resolve, reject) => {
    const server = serve({ fetch: app.fetch, port }, (info: AddressInfo) => {
      resolve({
        server,
        url: `http://localhost:${info.port}`,
        close: () =>
          new Promise<void>((done, fail) => {
            server.close((error) => (error ? fail(error) : done()));
          }),
      });
    });
    server.once("error", reject);
  });
}

if (import.meta.main) {
  const running = await startServer();
  console.log(`Open ${running.url}/ for the endpoint walkthrough.`);
  console.log(`Expecting the authorization server at ${config.authServerUrl}.`);
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.once(
      signal,
      () => void running.close().then(() => process.exit(0)),
    );
  }
}
