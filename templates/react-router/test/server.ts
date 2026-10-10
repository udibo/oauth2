import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll } from "vitest";

/**
 * Registers an MSW server for the current test file. Any request without a
 * handler fails the test, so a component can't quietly call an endpoint the
 * test didn't describe.
 */
export function useMockServer(): ReturnType<typeof setupServer> {
  const server = setupServer();
  beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());
  return server;
}
