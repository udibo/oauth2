import { vi } from "vitest";

/** A `Deno.createHttpClient` client the code under test opened. */
export interface FakeHttpClient {
  closed: boolean;
  close(): void;
}

/** The fake `Deno` runtime and `fetch` installed by {@link stubDenoRuntime}. */
export interface FakeDenoRuntime extends Disposable {
  /** Every `Deno.createHttpClient()` result, in creation order. */
  clients: FakeHttpClient[];
  /** Every call to the global `fetch`, in order. */
  requests: { input: RequestInfo | URL; init: RequestInit | undefined }[];
}

type Handler = (
  input: RequestInfo | URL,
  init: RequestInit | undefined,
) => Promise<Response>;

/**
 * Installs a global `Deno.createHttpClient` and a global `fetch` that answers
 * with `handler`, so code that adapts to Deno's pooled HTTP/2 connections can
 * be driven on any runtime. Declare it with `using`: disposing restores the
 * globals.
 */
export function stubDenoRuntime(
  handler: Handler,
  options: { createHttpClient?: () => FakeHttpClient } = {},
): FakeDenoRuntime {
  const clients: FakeHttpClient[] = [];
  const requests: FakeDenoRuntime["requests"] = [];
  vi.stubGlobal("Deno", {
    createHttpClient:
      options.createHttpClient ??
      (() => {
        const client: FakeHttpClient = {
          closed: false,
          close() {
            client.closed = true;
          },
        };
        clients.push(client);
        return client;
      }),
  });
  vi.stubGlobal(
    "fetch",
    (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      requests.push({ input, init });
      return handler(input, init);
    },
  );
  return {
    clients,
    requests,
    [Symbol.dispose]: () => {
      vi.unstubAllGlobals();
    },
  };
}

/**
 * A response promise that stays pending until `signal` aborts, then rejects
 * with the signal's reason, as the global `fetch` does for a hung request.
 */
export function hangUntilAborted(
  signal: AbortSignal | null | undefined,
): Promise<Response> {
  return new Promise((_resolve, reject) => {
    if (!signal) return;
    if (signal.aborted) reject(signal.reason);
    else
      signal.addEventListener("abort", () => reject(signal.reason), {
        once: true,
      });
  });
}
