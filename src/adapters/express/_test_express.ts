/**
 * Shared fixtures for the Express adapter tests: both supported Express
 * majors, and a real HTTP listener on an ephemeral port.
 *
 * @module
 */

import { once } from "node:events";
import type { AddressInfo } from "node:net";

import express from "express";

/** The `express` factory, whichever major is under test. */
export type ExpressFactory = typeof express;

/** Express 4 and 5, so every adapter test runs against both. */
export const EXPRESS_VERSIONS: [string, ExpressFactory][] = [
  ["Express 5", express],
  [
    "Express 4",
    ((await import("express4" as string)) as { default: ExpressFactory })
      .default,
  ],
];

/** A listening app and its origin; `close` ends open connections too. */
export interface Listening {
  origin: string;
  close(): Promise<void>;
}

/** Serves `app` on `127.0.0.1` at an ephemeral port. */
export async function listen(app: express.Express): Promise<Listening> {
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    async close() {
      server.closeAllConnections();
      server.close();
      await once(server, "close");
    },
  };
}

/**
 * An Express error handler recording what reached it and answering 500 with
 * the error's message, so a test can assert the adapter passed an error on.
 */
export function recordErrors(): {
  errors: unknown[];
  handler: express.ErrorRequestHandler;
} {
  const errors: unknown[] = [];
  return {
    errors,
    handler: (error, _req, res, _next) => {
      errors.push(error);
      res.status(500).send(error instanceof Error ? error.message : "error");
    },
  };
}
